#!/usr/bin/env python3
"""Read two fixed original float artifacts without executing their contents."""
from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import zipfile

REPO = "TrillionniumFoundation/Hepta"
REPO_ID = 1432132756
SOURCE = "44dd9edebacdf1a7c22b9c8a4df0d0828ef1edd8"
TREE = "225da55f38c3c97bb6227ad8f6b12b5ed8d32a27"
RUN = 41644357962
BRANCH = "refs/heads/research/float-artifact-readback-20261104-gpt6"
PREFIX = "qualification/float-artifact-readback-20261104"
WORKFLOW = ".github/workflows/hepta-float-artifact-readback.yml"
SOURCE_PATHS = {
    "tests/test_c_float_literals.py",
    "tests/test_source_float_rounding.py",
    "tests/test_c_backend.py",
    ".github/workflows/hepta-c-float-literals.yml",
}
ARTIFACT_IDS = {13235045775, 13234511947}
MEMBER_NAMES = {"compilers.txt", "tests.log"}
COMPRESSED_CAP = 64 * 1024
DECODED_CAP = 256 * 1024
MEMBER_CAP = 64 * 1024
OUTPUT_CAP = 128 * 1024


class Rejected(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise Rejected(code)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def parse_json(data):
    def bad_constant(_value):
        raise Rejected("NONFINITE_JSON")
    return json.loads(data, object_pairs_hook=unique_object,
                      parse_constant=bad_constant)


def fingerprint(data):
    return {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "git_blob_sha": hashlib.sha1(
            b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest(),
    }


def match_bytes(data, expected):
    found = fingerprint(data)
    require(all(found[key] == expected[key] for key in found), "SOURCE_BYTES")
    return found


def https_url(url):
    parts = urllib.parse.urlsplit(url)
    require(parts.scheme == "https" and parts.hostname
            and parts.username is None and parts.password is None
            and parts.port in (None, 443) and not parts.fragment, "HTTPS_REQUIRED")
    return url


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpsRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        https_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def api_request(path, token):
    require(path.startswith("/repos/" + REPO + "/"), "API_REPOSITORY")
    return urllib.request.Request("https://api.github.com" + path, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + token,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "hepta-original-float-readback",
    })


def api_json(path, token):
    with urllib.request.build_opener(NoRedirect()).open(
            api_request(path, token), timeout=45) as response:
        data = response.read(1024 * 1024 + 1)
    require(len(data) <= 1024 * 1024, "API_RESPONSE_CAP")
    return parse_json(data)


def archive_request(location):
    # A fresh request: the API Authorization header is never forwarded.
    return urllib.request.Request(https_url(location), headers={
        "User-Agent": "hepta-original-float-readback"})


def download(spec, token, budget):
    path = f"/repos/{REPO}/actions/artifacts/{spec['artifact_id']}/zip"
    try:
        with urllib.request.build_opener(NoRedirect()).open(
                api_request(path, token), timeout=45):
            raise Rejected("ARCHIVE_REDIRECT_REQUIRED")
    except urllib.error.HTTPError as error:
        try:
            require(error.code in (302, 303, 307), "ARCHIVE_REDIRECT_STATUS")
            location = error.headers.get("Location")
            require(isinstance(location, str), "ARCHIVE_REDIRECT_LOCATION")
            request = archive_request(location)
        finally:
            error.close()
    require(spec["bytes"] <= budget["compressed"], "COMPRESSED_CAP")
    with urllib.request.build_opener(HttpsRedirect()).open(
            request, timeout=45) as response:
        data = response.read(spec["bytes"] + 1)
    budget["compressed"] -= len(data)
    require(budget["compressed"] >= 0 and len(data) == spec["bytes"],
            "ARCHIVE_SIZE")
    require(hashlib.sha256(data).hexdigest() == spec["sha256"], "ARCHIVE_SHA256")
    return data


def inspect_zip(data, budget):
    result = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        require(len(infos) == 2 and {x.filename for x in infos} == MEMBER_NAMES,
                "EXACT_TWO_MEMBERS")
        require(sum(x.file_size for x in infos) <= budget["decoded"],
                "DECLARED_DECODED_CAP")
        for info in infos:
            require(not info.is_dir() and not (info.flag_bits & 1),
                    "REGULAR_UNENCRYPTED_MEMBER")
            mode = info.external_attr >> 16
            require(stat.S_IFMT(mode) in (0, stat.S_IFREG), "MEMBER_TYPE")
            require(info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                    "MEMBER_COMPRESSION")
            require(0 <= info.file_size <= MEMBER_CAP, "MEMBER_CAP")
            with archive.open(info) as stream:
                payload = stream.read(min(MEMBER_CAP, budget["decoded"]) + 1)
            budget["decoded"] -= len(payload)
            require(budget["decoded"] >= 0 and len(payload) == info.file_size,
                    "RETURNED_DECODED_CAP")
            # Reaching EOF verifies zipfile's member CRC; no extraction occurs.
            result[info.filename] = {
                "data": payload,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "crc32": f"{info.CRC:08x}",
            }
    return result


def test_inventory(data, module):
    # Parsing syntax only. No imports, evaluation or test execution.
    result = []
    parsed = ast.parse(data.decode("utf-8"))
    for item in parsed.body:
        if not isinstance(item, ast.ClassDef):
            continue
        if not any(isinstance(base, ast.Attribute)
                   and isinstance(base.value, ast.Name)
                   and base.value.id == "unittest" and base.attr == "TestCase"
                   for base in item.bases):
            continue
        for method in item.body:
            if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                    and method.name.startswith("test_"):
                result.append(module + "." + item.name + "." + method.name)
    require(result and len(set(result)) == len(result), "SOURCE_TEST_INVENTORY")
    return result


def parse_tests(data, expected):
    require(len(data) <= MEMBER_CAP, "TEST_LOG_CAP")
    lines = data.decode("utf-8").splitlines()
    seen, summaries, final_ok = [], 0, 0
    stage = "cases"
    for line in lines:
        if not line:
            continue
        require(len(line) <= 1024, "TEST_LOG_LINE_CAP")
        case = re.fullmatch(r"(test_[A-Za-z0-9_]+) \(([A-Za-z0-9_.]+)\) \.\.\. ok", line)
        if case:
            require(stage == "cases", "CASE_AFTER_SUMMARY")
            method, test_id = case.groups()
            require(test_id.endswith("." + method), "CASE_ID_METHOD")
            require(test_id in expected and test_id not in seen, "EXACT_CASE_SET")
            seen.append(test_id)
        elif line == "-" * 70:
            require(stage == "cases" and len(seen) == len(expected), "SUMMARY_SEPARATOR")
            stage = "summary"
        elif re.fullmatch(r"Ran [0-9]+ tests in [0-9]+\.[0-9]+s", line):
            require(stage == "summary", "SUMMARY_ORDER")
            require(int(line.split()[1]) == len(expected), "SUMMARY_COUNT")
            summaries += 1
            stage = "verdict"
        elif line == "OK":
            require(stage == "verdict", "VERDICT_ORDER")
            final_ok += 1
            stage = "done"
        else:
            raise Rejected("UNEXPECTED_TEST_LOG_LINE")
    require(stage == "done" and summaries == 1 and final_ok == 1
            and len(seen) == len(expected) and set(seen) == set(expected),
            "COMPLETE_TEST_LOG")
    return {"passed": len(seen), "failed": 0, "errors": 0, "skipped": 0,
            "test_ids": sorted(seen)}


def parse_compilers(data, host):
    text = data.decode("utf-8")
    require(len(data) <= MEMBER_CAP, "COMPILER_LOG_CAP")
    lines = text.splitlines()
    gcc = [re.fullmatch(r"gcc \(.{1,160}\) ([0-9]+(?:\.[0-9]+){1,3})", x)
           for x in lines]
    gcc = [x for x in gcc if x]
    rust = [x for x in lines if re.fullmatch(
        r"rustc 1\.90\.0 \([a-f0-9]{7,40} [0-9]{4}-[0-9]{2}-[0-9]{2}\)", x)]
    require(len(gcc) == 1 and len(rust) == 1, "PINNED_COMPILER_VERSIONS")
    binaries = {}
    for line in lines:
        match = re.fullmatch(r"([a-f0-9]{64})  (/[^\r\n]+)", line)
        if not match:
            continue
        digest, path = match.groups()
        if path == "/usr/bin/gcc":
            kind = "gcc"
        elif path.endswith("/toolchains/1.90.0-" + host + "/bin/rustc"):
            kind = "rustc"
        else:
            raise Rejected("UNEXPECTED_COMPILER_PATH")
        require(kind not in binaries, "DUPLICATE_COMPILER_DIGEST")
        binaries[kind] = digest
    require(set(binaries) == {"gcc", "rustc"}, "TWO_COMPILER_DIGESTS")
    return {"gcc_version": gcc[0].group(1), "rustc_version": "1.90.0",
            "rust_toolchain_host_from_recorded_path": host,
            "recorded_binary_sha256": binaries,
            "compiler_binaries_reexecuted_or_rehashed_by_reader": False}


def checked_git(*args):
    result = subprocess.run(["git", "--no-replace-objects", *args],
                            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout


def bind_reader(root):
    expected = os.environ.get("GITHUB_SHA", "")
    require(re.fullmatch(r"[a-f0-9]{40}", expected) is not None, "READER_HEAD_FORMAT")
    require(checked_git("rev-parse", "HEAD").decode().strip() == expected,
            "READER_HEAD")
    checked_git("diff", "--exit-code", "HEAD", "--")
    records = []
    for path in (PREFIX + "/readback.py", PREFIX + "/inputs.json", WORKFLOW):
        worktree = (root / path).read_bytes()
        tracked = checked_git("show", "HEAD:" + path)
        require(worktree == tracked, "READER_TRACKED_BYTES")
        records.append({"path": path, **fingerprint(tracked)})
    return {"commit": expected, "tree": checked_git("rev-parse", "HEAD^{tree}").decode().strip(),
            "files": records}


def verify_source(specs, token):
    require({x["path"] for x in specs} == SOURCE_PATHS and len(specs) == 4,
            "FOUR_PINNED_SOURCE_PATHS")
    source = api_json(f"/repos/{REPO}/git/commits/{SOURCE}", token)
    require(source.get("sha") == SOURCE
            and source.get("tree", {}).get("sha") == TREE, "ORIGINAL_COMMIT_TREE")
    records, test_ids = [], []
    for spec in specs:
        path = spec["path"]
        item = api_json(
            f"/repos/{REPO}/contents/{urllib.parse.quote(path, safe='/')}?ref={SOURCE}", token)
        require(item.get("type") == "file" and item.get("path") == path
                and item.get("sha") == spec["git_blob_sha"]
                and item.get("size") == spec["bytes"]
                and item.get("encoding") == "base64", "ORIGINAL_SOURCE_PATH")
        encoded = re.sub(rb"[ \t\r\n]", b"", item["content"].encode("ascii"))
        raw = base64.b64decode(encoded, validate=True)
        records.append({"path": path, **match_bytes(raw, spec)})
        if spec["module"] is not None:
            test_ids.extend(test_inventory(raw, spec["module"]))
    require(len(test_ids) == 23 and len(set(test_ids)) == 23,
            "ORIGINAL_23_TEST_INVENTORY")
    return records, sorted(test_ids)


def verify_run(inputs, token):
    run = api_json(f"/repos/{REPO}/actions/runs/{RUN}/attempts/1", token)
    require(run.get("id") == RUN and run.get("head_sha") == SOURCE
            and run.get("run_attempt") == 1 and run.get("event") == "pull_request"
            and run.get("status") == "completed" and run.get("conclusion") == "success"
            and run.get("workflow_id") == inputs["original_workflow_id"]
            and run.get("path") == inputs["original_workflow_path"],
            "ORIGINAL_SUCCESSFUL_ATTEMPT")
    response = api_json(f"/repos/{REPO}/actions/runs/{RUN}/attempts/1/jobs?per_page=100", token)
    jobs = response.get("jobs")
    require(response.get("total_count") == 2 and isinstance(jobs, list) and len(jobs) == 2,
            "ORIGINAL_TWO_JOBS")
    by_id = {job["id"]: job for job in jobs}
    require(len(by_id) == 2, "DUPLICATE_JOB")
    for spec in inputs["artifacts"]:
        job = by_id.get(spec["job_id"], {})
        require(job.get("run_id") == RUN and job.get("run_attempt") == 1
                and job.get("head_sha") == SOURCE and job.get("name") == spec["job_name"]
                and spec["runner_label"] in job.get("labels", [])
                and job.get("status") == "completed" and job.get("conclusion") == "success",
                "ORIGINAL_NATIVE_JOB")
        steps = {step["name"]: step for step in job.get("steps", [])}
        require(steps.get("Bind compilers and execute complete no-skip controls", {})
                .get("conclusion") == "success", "ORIGINAL_TEST_STEP")


def artifact_metadata(spec, token):
    item = api_json(f"/repos/{REPO}/actions/artifacts/{spec['artifact_id']}", token)
    workflow = item.get("workflow_run", {})
    require(item.get("id") == spec["artifact_id"]
            and item.get("name") == spec["artifact_name"]
            and item.get("size_in_bytes") == spec["bytes"]
            and item.get("digest") == "sha256:" + spec["sha256"]
            and item.get("expired") is False, "ORIGINAL_ARTIFACT_METADATA")
    require(workflow.get("id") == RUN and workflow.get("head_sha") == SOURCE
            and workflow.get("repository_id") == REPO_ID
            and workflow.get("head_repository_id") == REPO_ID, "ARTIFACT_SOURCE")


def self_test():
    count = 0
    def rejects(function, code):
        nonlocal count
        try:
            function()
        except Rejected as error:
            require(str(error) == code, "CONTROL_WRONG_REJECTION")
        else:
            raise Rejected("CONTROL_ACCEPTED_NEGATIVE")
        count += 1

    expected = ["tests.fixture.Case.test_a", "tests.fixture.Case.test_b"]
    body = "\n".join("test_" + x[-1] + " (" + x + ") ... ok" for x in expected)
    good = (body + "\n\n" + "-" * 70 + "\nRan 2 tests in 0.001s\n\nOK\n").encode()
    require(parse_tests(good, expected)["passed"] == 2, "CONTROL_LOG_POSITIVE")
    count += 1
    rejects(lambda: parse_tests(good.replace(b"test_b", b"test_a"), expected), "EXACT_CASE_SET")
    rejects(lambda: parse_tests(good.replace(b"... ok", b"... skipped", 1), expected),
            "UNEXPECTED_TEST_LOG_LINE")
    rejects(lambda: parse_tests(good.replace(b"Ran 2 tests", b"Ran 0 tests"), expected),
            "SUMMARY_COUNT")
    rejects(lambda: parse_tests(good.replace(b"\nOK\n", b"\n"), expected), "COMPLETE_TEST_LOG")
    rejects(lambda: parse_tests(good.replace(b"tests.fixture", b"tests.other"), expected),
            "EXACT_CASE_SET")
    rejects(lambda: parse_json(b'{"x":1,"x":2}'), "DUPLICATE_JSON_KEY")
    rejects(lambda: https_url("http://example.invalid/file"), "HTTPS_REQUIRED")
    require(not archive_request("https://example.invalid/file?temporary=opaque")
            .has_header("Authorization"), "CONTROL_NO_FORWARDED_TOKEN")
    count += 1
    require(test_inventory(b"import unittest\nclass C(unittest.TestCase):\n"
                           b"    def test_a(self): pass\n", "tests.fixture")
            == ["tests.fixture.C.test_a"], "CONTROL_AST_ONLY")
    count += 1
    def make_zip(extra=False, symlink=False):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as archive:
            info = zipfile.ZipInfo("compilers.txt")
            if symlink:
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, b"artifact control")
            archive.writestr("tests.log", good)
            if extra:
                archive.writestr("unexpected", b"extra")
        return buf.getvalue()
    raw = make_zip()
    require(len(inspect_zip(raw, {"decoded": DECODED_CAP})) == 2, "CONTROL_ZIP_POSITIVE")
    count += 1
    rejects(lambda: inspect_zip(make_zip(extra=True), {"decoded": DECODED_CAP}),
            "EXACT_TWO_MEMBERS")
    rejects(lambda: inspect_zip(make_zip(symlink=True), {"decoded": DECODED_CAP}), "MEMBER_TYPE")
    corrupt = bytearray(raw)
    corrupt[raw.index(b"artifact control")] ^= 1
    try:
        inspect_zip(bytes(corrupt), {"decoded": DECODED_CAP})
    except zipfile.BadZipFile:
        count += 1
    else:
        raise Rejected("CONTROL_CRC_NOT_REJECTED")
    print(json.dumps({"reader_controls_passed": count,
                      "synthetic_controls_only": True, "native_tests_executed": 0}))
    return count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    require(args.out is not None, "OUTPUT_REQUIRED")
    require(os.environ.get("GITHUB_REPOSITORY") == REPO
            and os.environ.get("GITHUB_REF") == BRANCH
            and os.environ.get("GITHUB_EVENT_NAME") == "push", "READ_ONLY_JOB_SCOPE")
    token = os.environ.get("GH_TOKEN")
    require(isinstance(token, str) and bool(token), "READ_TOKEN")
    root = Path(__file__).resolve().parents[2]
    os.chdir(root)
    before = bind_reader(root)
    inputs = parse_json(Path(__file__).with_name("inputs.json").read_bytes())
    require(inputs["repository"] == REPO and inputs["repository_id"] == REPO_ID
            and inputs["source"] == SOURCE and inputs["source_tree"] == TREE
            and inputs["original_run_id"] == RUN and inputs["original_run_attempt"] == 1,
            "INPUT_SCOPE")
    require(len(inputs["artifacts"]) == 2
            and {x["artifact_id"] for x in inputs["artifacts"]} == ARTIFACT_IDS,
            "EXACT_TWO_ORIGINAL_ARTIFACTS")
    sources, expected = verify_source(inputs["sources"], token)
    require(expected == inputs["expected_tests"], "EXPECTED_TESTS_SOURCE_BOUND")
    verify_run(inputs, token)
    budget = {"compressed": COMPRESSED_CAP, "decoded": DECODED_CAP}
    results = []
    for spec in inputs["artifacts"]:
        artifact_metadata(spec, token)
        raw = download(spec, token, budget)
        members = inspect_zip(raw, budget)
        result = {
            "artifact_id": spec["artifact_id"], "archive_bytes": len(raw),
            "archive_sha256": hashlib.sha256(raw).hexdigest(),
            "original_job_id": spec["job_id"], "original_job_name": spec["job_name"],
            "original_runner_label": spec["runner_label"],
            "members": {name: {k: v for k, v in row.items() if k != "data"}
                        for name, row in members.items()},
            "original_test_log": parse_tests(members["tests.log"]["data"], expected),
            "original_compiler_record": parse_compilers(
                members["compilers.txt"]["data"], spec["rust_host"]),
            "archive_member_code_executed": False,
            "new_native_tests_executed": 0,
        }
        results.append(result)
    after = bind_reader(root)
    require(before == after, "READER_SOURCE_CHANGED")
    report = {
        "schema": "hepta-original-float-artifact-readback-v1",
        "reader_source_before": before, "reader_source_after": after,
        "original_source_commit": SOURCE, "original_source_tree": TREE,
        "original_run": RUN, "original_run_attempt": 1,
        "original_source_paths_verified": sources,
        "artifacts": results, "remaining_returned_byte_budgets": budget,
        "complete_readback_success": True,
        "original_cases_verified_per_artifact": 23,
        "new_native_tests_executed": 0, "archived_source_executed": False,
        "all_original_transitive_compiler_inputs_independently_replayed": False,
        "all_HIA_P0_P7_accepted": False, "all_HCSN_P0_P6_accepted": False,
        "production_activation": False, "library_clearance": False,
        "scope": "Integrity/source-bound readback of two historical finite float-control artifacts.",
    }
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    require(len(encoded) <= OUTPUT_CAP, "REPORT_OUTPUT_CAP")
    args.out.mkdir(parents=True, exist_ok=False)
    with (args.out / "readback.json").open("xb") as out:
        out.write(encoded)
    print(json.dumps({"readback_success": True, "artifacts": 2,
                      "original_passed_cases": [23, 23],
                      "new_native_tests_executed": 0,
                      "report_bytes": len(encoded),
                      "report_sha256": hashlib.sha256(encoded).hexdigest()}))


if __name__ == "__main__":
    try:
        main()
    except Rejected as error:
        print(json.dumps({"readback_failed": str(error), "new_native_tests_executed": 0}))
        raise SystemExit(1) from None
    except Exception as error:
        # Never print signed redirect URLs, Authorization, response bodies or raw member data.
        print(json.dumps({"readback_failed": type(error).__name__,
                          "new_native_tests_executed": 0}))
        raise SystemExit(1) from None
