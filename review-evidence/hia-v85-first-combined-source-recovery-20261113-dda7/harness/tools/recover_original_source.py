#!/usr/bin/env python3
"""Recover one failed run's exact source bytes. No product imports or execution."""
from __future__ import annotations

import base64
import concurrent.futures
import datetime
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import traceback
import urllib.error
import urllib.request

REPO = "TrillionniumFoundation/Hepta"
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")


def check(value, message):
    if not value:
        raise RuntimeError(message)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            check(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def oid(kind, raw):
    return hashlib.sha1(kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def identity(raw):
    return {"bytes": len(raw), "sha256": sha(raw), "blob": oid("blob", raw)}


def matches(raw, pin, label):
    for field, actual in identity(raw).items():
        check(type(pin[field]) is type(actual) and pin[field] == actual, label + ": " + field + " differs")


def relpath(value):
    check(type(value) is str and value and "\0" not in value and "\\" not in value, "bad path")
    path = PurePosixPath(value)
    check(not path.is_absolute() and path.as_posix() == value and
          all(part not in ("", ".", "..", ".git") for part in path.parts), "unsafe path: " + value)
    return path


def write_new(path, raw, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)
    path.chmod(mode)
    check(path.read_bytes() == raw and stat.S_IMODE(path.stat().st_mode) == mode, "write/readback differs")


def file_digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def api_blob(blob, token):
    check(HEX40.fullmatch(blob) is not None, "bad blob id")
    url = "https://api.github.com/repos/" + REPO + "/git/blobs/" + blob
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + token,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "hepta-fixed-original-source-recovery"})
    raw_response = None
    attempts = []
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                raw_response = response.read()
                attempts.append({"status": response.status, "bytes": len(raw_response)})
            break
        except urllib.error.HTTPError as error:
            error_raw = error.read()
            attempts.append({"status": error.code, "bytes": len(error_raw), "sha256": sha(error_raw)})
            if error.code not in (429, 500, 502, 503, 504) or attempt == 2:
                raise RuntimeError("blob GET failed: " + blob + " HTTP " + str(error.code)) from None
            time.sleep(attempt + 1)
    check(raw_response is not None, "blob response absent")
    value = strict_json(raw_response)
    check(value.get("sha") == blob and value.get("encoding") == "base64", "unexpected blob response")
    check(type(value.get("size")) is int and type(value.get("content")) is str, "unexpected blob fields")
    compact = "".join(value["content"].split())
    raw = base64.b64decode(compact, validate=True)
    check(len(raw) == value["size"] and oid("blob", raw) == blob, "Git blob full-byte verification failed")
    return raw, {"blob": blob, "bytes": len(raw), "sha256": sha(raw),
                 "attempts": attempts, "response_sha256": sha(raw_response)}


def tree_from_entries(entries):
    root = {}
    for row in entries:
        if row.get("type") == "tree":
            continue
        parts = relpath(row["path"]).parts
        node = root
        for part in parts[:-1]:
            check(not isinstance(node.get(part), tuple), "tree/file prefix collision")
            node = node.setdefault(part, {})
        check(parts[-1] not in node, "duplicate tree path")
        node[parts[-1]] = (row["mode"], row["oid"])
    def recurse(node):
        records = []
        for name, value in node.items():
            if isinstance(value, dict):
                mode, digest, key = "40000", recurse(value), (name + "/").encode()
            else:
                mode, digest = value
                key = name.encode()
            records.append((key, mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(digest)))
        return oid("tree", b"".join(record for _, record in sorted(records)))
    return recurse(root)


def git_env(work, token=None):
    env = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR",
           "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy") if key in os.environ}
    env.update({"HOME": str(work / "home"), "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0",
                "GIT_OPTIONAL_LOCKS": "0", "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.hooksPath", "GIT_CONFIG_VALUE_0": os.devnull})
    if token is not None:
        auth = base64.b64encode(("x-access-token:" + token).encode()).decode()
        env.update({"GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_1": "http.https://github.com/.extraheader",
                    "GIT_CONFIG_VALUE_1": "AUTHORIZATION: basic " + auth})
    return env


def run_git(arguments, work, output, label, token=None, stdin=None, limit=600):
    check(all(type(item) is str for item in arguments), "invalid Git argument")
    started = time.monotonic()
    proc = subprocess.run(["git", *arguments], cwd=work, env=git_env(work, token),
                          input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=limit)
    write_new(output / "git" / (label + ".stderr"), proc.stderr)
    write_new(output / "git" / (label + ".json"), canonical({
        "argv": ["git", *arguments], "returncode": proc.returncode,
        "elapsed_seconds": time.monotonic() - started,
        "stdout": identity(proc.stdout), "stderr": identity(proc.stderr),
        "authentication_supplied": token is not None}))
    check(proc.returncode == 0, "Git failed: " + label)
    return proc.stdout


def load_fixed_objects(inputs, member_raw, work, output, token, report):
    bare = work / "fixed-originals.git"
    run_git(["init", "--bare", "--object-format=sha1", str(bare)], work, output, "init")
    commits = [row["commit"] for row in inputs["fixed_originals"]]
    run_git(["--git-dir=" + str(bare), "fetch", "--no-tags", "--depth=1", "--no-write-fetch-head",
             "https://github.com/" + REPO + ".git", *commits],
            work, output, "fetch-fixed-four", token=token)
    all_known = set()
    original_rows = []
    for original in inputs["fixed_originals"]:
        commit = original["commit"]
        commit_raw = run_git(["--git-dir=" + str(bare), "cat-file", "commit", commit],
                             work, output, "commit-" + commit)
        check(oid("commit", commit_raw) == commit, "commit object differs")
        check(commit_raw.splitlines()[0] == ("tree " + original["tree"]).encode(), "commit tree differs")
        write_new(output / "original-commits" / (commit + ".txt"), commit_raw)
        tree_raw = run_git(["--git-dir=" + str(bare), "ls-tree", "-r", "-t", "-z", "--full-tree", commit],
                           work, output, "tree-" + commit)
        entries = []
        for record in tree_raw.split(b"\0"):
            if not record:
                continue
            header, raw_path = record.split(b"\t", 1)
            mode, kind, blob = header.decode("ascii").split(" ")
            path = raw_path.decode("utf-8", errors="strict")
            relpath(path)
            check(((kind == "blob" and mode in ("100644", "100755", "120000")) or
                   (kind == "tree" and mode == "040000")) and
                  HEX40.fullmatch(blob) is not None, "unsupported fixed tree entry")
            entries.append({"mode": mode, "oid": blob, "type": kind, "path": path,
                            "path_base64": base64.b64encode(raw_path).decode()})
        expected = strict_json(member_raw["sources/" + original["label"] + ".json"])
        check(expected["commit"] == commit and expected["tree"] == original["tree"] and
              expected["files"] == original["files"] == sum(row["type"] == "blob" for row in entries),
              "fixed tree metadata differs")
        check(sorted(entries, key=lambda row: row["path"]) ==
              sorted(expected["entries"], key=lambda row: row["path"]), "fixed tree full entries differ")
        check(tree_from_entries(entries) == original["tree"], "independent fixed tree hash differs")
        all_known.update(row["oid"] for row in entries if row["type"] == "blob")
        original_rows.append({**original, "entries_match_original_archive": True,
                              "independent_tree_hash_match": True})
    report["fixed_originals"] = original_rows
    return bare, all_known


def batch_blobs(bare, blobs, work, output):
    wanted = sorted(set(blobs))
    response = run_git(["--git-dir=" + str(bare), "cat-file", "--batch"],
                       work, output, "read-original-blobs",
                       stdin=("".join(blob + "\n" for blob in wanted)).encode())
    cursor = 0
    result = {}
    for expected in wanted:
        end = response.index(b"\n", cursor)
        fields = response[cursor:end].decode("ascii").split(" ")
        check(len(fields) == 3 and fields[0] == expected and fields[1] == "blob", "bad cat-file header")
        size = int(fields[2])
        check(size >= 0, "bad cat-file size")
        start = end + 1
        raw = response[start:start + size]
        check(len(raw) == size and response[start + size:start + size + 1] == b"\n", "truncated cat-file output")
        check(oid("blob", raw) == expected, "cat-file object hash differs")
        result[expected] = raw
        cursor = start + size + 1
    check(cursor == len(response), "extra cat-file output")
    return result


def restore(inputs, manifest, members, work, output, token, report):
    index_raw = members[inputs["terminal_index"]["path"]]
    matches(index_raw, inputs["terminal_index"], "terminal INDEX")
    index = strict_json(index_raw)
    check(index["self_contained"] is False and index["changed_or_new_content_bytes_included"] is True,
          "original custody scope differs")
    check(index["fixed_original_dependency_commits"] ==
          [row["commit"] for row in inputs["fixed_originals"]], "fixed original list differs")
    rows = index["files"]
    check(type(rows) is list and len(rows) == inputs["source"]["files"], "terminal source count differs")
    check(len({row["path"] for row in rows}) == len(rows), "duplicate terminal source path")
    check(sum(row["bytes"] for row in rows) == inputs["source"]["bytes"], "source byte count differs")
    for row in rows:
        relpath(row["path"])
        check(row["kind"] == "regular" and type(row["mode"]) is int and
              row["mode"] == inputs["source"]["regular_mode"], "unexpected terminal kind/mode")
        check(type(row["bytes"]) is int and row["bytes"] >= 0 and HEX40.fullmatch(row["blob"]) and
              HEX64.fullmatch(row["sha256"]), "bad terminal identity")
    bare, known = load_fixed_objects(inputs, members, work, output, token, report)
    dependent = [row for row in rows if row["content_custody"].get("kind") == "exact_fixed_original_git_blob"]
    check(len(dependent) == inputs["source"]["original_git_files"] and
          len(rows) - len(dependent) == inputs["source"]["captured_files"], "source origin counts differ")
    for row in dependent:
        check(row["content_custody"]["blob"] == row["blob"] and row["blob"] in known,
              "terminal dependency is not reachable from the four fixed trees")
    raw_objects = batch_blobs(bare, [row["blob"] for row in dependent], work, output)
    source = work / "source"
    source.mkdir()
    final = []
    for row in sorted(rows, key=lambda item: item["path"]):
        custody = row["content_custody"]
        if custody.get("kind") == "exact_fixed_original_git_blob":
            raw = raw_objects[row["blob"]]
            origin = {"kind": "fixed_original_git_blob", "blob": row["blob"]}
        else:
            check("kind" not in custody and custody.get("file") ==
                  "terminal-worktree-bytes/" + row["blob"] + ".blob", "unexpected captured-source reference")
            raw = members[custody["file"]]
            matches(raw, custody, "captured source " + row["path"])
            origin = {"kind": "verified_original_archive_member", "file": custody["file"]}
        matches(raw, row, row["path"])
        path = source.joinpath(*relpath(row["path"]).parts)
        write_new(path, raw, row["mode"])
        final.append({key: row[key] for key in ("path", "kind", "mode", "bytes", "sha256", "blob")} | {"origin": origin})
    actual_paths = sorted(path.relative_to(source).as_posix() for path in source.rglob("*") if path.is_file())
    check(actual_paths == [row["path"] for row in final], "filesystem path set differs")
    for row in final:
        path = source / row["path"]
        check(stat.S_ISREG(path.lstat().st_mode) and stat.S_IMODE(path.stat().st_mode) == row["mode"],
              "filesystem kind/mode differs")
        matches(path.read_bytes(), row, "final filesystem " + row["path"])
    recovered_tree = tree_from_entries([{"path": row["path"], "mode": "100644", "oid": row["blob"]} for row in final])
    source_manifest = {"schema": "hepta.recovered-original-terminal-source.v1",
        "scope": "ORIGINAL_FAILED_R1_TERMINAL_BYTES_NOT_QUALIFICATION", "self_contained": True,
        "original": inputs["original"], "original_evidence_manifest": inputs["evidence_manifest"],
        "original_index": inputs["terminal_index"], "files": final,
        "file_count": len(final), "total_bytes": sum(row["bytes"] for row in final),
        "computed_tree": recovered_tree, "published_source_commit": None,
        "fixed_originals": report["fixed_originals"]}
    manifest_raw = canonical(source_manifest)
    write_new(output / "SOURCE-MANIFEST.json", manifest_raw)
    write_new(output / "ORIGINAL-TERMINAL-INDEX.json", index_raw)
    archive = output / "RECOVERED-SOURCE.tar.gz"
    with archive.open("xb") as raw_stream:
        with gzip.GzipFile(fileobj=raw_stream, mode="wb", compresslevel=1, mtime=0, filename="") as zipped:
            with tarfile.open(fileobj=zipped, mode="w|", format=tarfile.PAX_FORMAT) as tar:
                for row in final:
                    raw = (source / row["path"]).read_bytes()
                    matches(raw, row, "archive input " + row["path"])
                    info = tarfile.TarInfo("source/" + row["path"])
                    info.size, info.mode, info.mtime = len(raw), row["mode"], 0
                    info.uid = info.gid = 0
                    tar.addfile(info, io.BytesIO(raw))
    with gzip.open(archive, "rb") as zipped:
        while zipped.read(1024 * 1024):
            pass
    by_path = {"source/" + row["path"]: row for row in final}
    seen = set()
    with tarfile.open(archive, "r:gz") as tar:
        for item in tar:
            check(item.isfile() and item.name in by_path and item.name not in seen, "archive path/type differs")
            row = by_path[item.name]
            check(item.size == row["bytes"] and item.mode == row["mode"], "archive size/mode differs")
            matches(tar.extractfile(item).read(), row, "archive readback " + item.name)
            seen.add(item.name)
    check(seen == set(by_path), "recovered archive missing source paths")
    report["recovery"] = {"files": len(final), "bytes": sum(row["bytes"] for row in final),
                          "original_git_files": len(dependent), "captured_files": len(rows) - len(dependent),
                          "computed_tree": recovered_tree, "filesystem_all_bytes_modes_verified": True,
                          "archive_all_members_bytes_modes_verified": True, "archive_gzip_crc_verified": True,
                          "source_manifest": identity(manifest_raw),
                          "archive": {"file": archive.name, "bytes": archive.stat().st_size, "sha256": file_digest(archive)}}


def main():
    started = time.monotonic()
    output = Path(os.environ["RUNNER_TEMP"]) / "r1-source-recovery"
    work = Path(os.environ["RUNNER_TEMP"]) / "r1-source-recovery-work"
    output.mkdir()
    work.mkdir()
    (work / "home").mkdir()
    token = os.environ.pop("GITHUB_TOKEN", "")
    report = {"schema": "hepta.original-terminal-source-recovery-result.v1", "status": "INCOMPLETE",
              "scope": "READ_ONLY_EVIDENCE_AND_FIXED_GIT_SOURCE_RECOVERY",
              "original_business_status": "FAIL", "product_executions": 0, "generators_executed": 0,
              "tests_executed": 0, "qualification_transferred": False, "api_writes": 0,
              "product_or_audit_ref_changes": 0, "failures": []}
    receipts = []
    try:
        check(bool(token), "missing read-only repository credential")
        inputs_raw = Path("inputs/RECOVERY.json").read_bytes()
        driver_raw = Path(__file__).read_bytes()
        check(oid("blob", inputs_raw) == os.environ["EXPECTED_INPUTS_GIT_BLOB"], "input source pin differs")
        check(oid("blob", driver_raw) == os.environ["EXPECTED_DRIVER_GIT_BLOB"], "driver source pin differs")
        inputs = strict_json(inputs_raw)
        check(inputs["repository"] == REPO, "repository differs")
        write_new(output / "RECOVERY-INPUTS.json", inputs_raw)
        write_new(output / "RECOVERY-DRIVER.py", driver_raw)
        manifest_raw, receipt = api_blob(inputs["evidence_manifest"]["blob"], token)
        receipts.append(receipt)
        matches(manifest_raw, inputs["evidence_manifest"], "evidence manifest")
        write_new(output / "ORIGINAL-EVIDENCE-MANIFEST.json", manifest_raw)
        manifest = strict_json(manifest_raw)
        check(manifest["schema"] == "hepta.combined-source-build-evidence.v1" and
              manifest["encoding"] == "ordered-gzip-tar-chunks", "evidence schema differs")
        check(manifest["bytes"] == inputs["archive"]["bytes"] and
              manifest["sha256"] == inputs["archive"]["sha256"], "original archive identity differs")
        check(manifest["result"]["status"] == "FAIL" and
              manifest["result"]["product_tests_executed"] == 0 and
              manifest["result"]["terminal_source_snapshot"]["files"] == inputs["source"]["files"],
              "original run/result differs")
        chunks = manifest["chunks"]
        check(len(chunks) == inputs["archive"]["chunks"], "chunk count differs")
        cursor = 0
        for number, chunk in enumerate(chunks):
            check(type(chunk["index"]) is int and chunk["index"] == number and chunk["offset"] == cursor and
                  type(chunk["bytes"]) is int and 0 < chunk["bytes"] <= 524288 and
                  chunk["full_readback_equal"] is True, "chunk sequence differs")
            cursor += chunk["bytes"]
        check(cursor == manifest["bytes"], "chunk coverage differs")
        compressed = work / "original-evidence.tar.gz"
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(api_blob, chunk["blob"], token) for chunk in chunks]
            with compressed.open("xb") as stream:
                for number, (chunk, future) in enumerate(zip(chunks, futures)):
                    raw, receipt = future.result()
                    matches(raw, chunk, "chunk " + str(number))
                    stream.write(raw)
                    receipts.append(receipt)
                    if (number + 1) % 10 == 0:
                        print("VERIFIED_ORIGINAL_CHUNKS", number + 1, flush=True)
        check(compressed.stat().st_size == manifest["bytes"] and
              file_digest(compressed) == manifest["sha256"], "complete original compressed bytes differ")
        tar_path = work / "original-evidence.tar"
        with gzip.open(compressed, "rb") as zipped, tar_path.open("xb") as target:
            shutil.copyfileobj(zipped, target, 1024 * 1024)
        expected = {}
        for row in manifest["members"]:
            relpath(row["path"])
            check(row["path"] not in expected, "duplicate original manifest member")
            expected[row["path"]] = row
        check(len(expected) == inputs["archive"]["members"], "original member count differs")
        selected = {}
        seen = set()
        total_bytes = 0
        with tarfile.open(tar_path, "r:") as tar:
            for item in tar:
                check(item.isfile() and item.name in expected and item.name not in seen,
                      "unexpected original archive entry")
                row = expected[item.name]
                raw = tar.extractfile(item).read()
                check(item.size == row["bytes"], "original tar declared size differs")
                matches(raw, row, "original tar " + item.name)
                seen.add(item.name)
                total_bytes += len(raw)
                if item.name == "terminal-worktree/INDEX.json" or item.name.startswith(
                        ("terminal-worktree-bytes/", "sources/")) or item.name in {
                        "harness/INPUTS.json", "RESULT.json", "commands/0038-pre-generation-0.json",
                        "commands/0038-pre-generation-0.stderr"}:
                    selected[item.name] = raw
        check(seen == set(expected), "original tar missing members")
        for row in [inputs["terminal_index"], *inputs["required_members"]]:
            check(expected[row["path"]] == row, "selected original pin differs")
            matches(selected[row["path"]], row, "selected original")
        original_inputs = strict_json(selected["harness/INPUTS.json"])
        check(original_inputs["ours"]["commit"] == inputs["fixed_originals"][0]["commit"] and
              original_inputs["theirs"]["commit"] == inputs["fixed_originals"][1]["commit"] and
              original_inputs["best_merge_bases"] == [row["commit"] for row in inputs["fixed_originals"][2:]],
              "original four-head inputs differ")
        report["original_archive"] = {"chunks": len(chunks), "members": len(seen),
            "member_bytes": total_bytes, "gzip_crc_verified": True, "all_member_git_sha_size_verified": True,
            "compressed_bytes": compressed.stat().st_size, "compressed_sha256": file_digest(compressed)}
        write_new(output / "ORIGINAL-RESULT.json", selected["RESULT.json"])
        for suffix in ("json", "stderr"):
            name = "commands/0038-pre-generation-0." + suffix
            write_new(output / ("ORIGINAL-PRE-GENERATION-0." + suffix), selected[name])
        print("ORIGINAL_BUSINESS_FAILURE_RETAINED", flush=True)
        restore(inputs, manifest, selected, work, output, token, report)
        report["status"] = "RECOVERED_ORIGINAL_TERMINAL_SOURCE"
        print(json.dumps({"status": report["status"], "recovery": report["recovery"],
                          "original_business_status": "FAIL"}, sort_keys=True), flush=True)
    except BaseException as error:
        report["status"] = "RECOVERY_FAILED"
        report["failures"].append({"type": type(error).__name__, "error": str(error),
                                   "traceback": traceback.format_exc()})
        print("RECOVERY_FAILED", type(error).__name__, str(error), flush=True)
    finally:
        report["elapsed_seconds"] = time.monotonic() - started
        report["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        write_new(output / "API-READ-RECEIPTS.json", canonical(receipts))
        write_new(output / "REPORT.json", canonical(report))
    return 0 if report["status"] == "RECOVERED_ORIGINAL_TERMINAL_SOURCE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
