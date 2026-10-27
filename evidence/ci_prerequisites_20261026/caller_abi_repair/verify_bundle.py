#!/usr/bin/env python3
"""Verify preserved caller ABI controls offline; never execute retained code."""
import argparse
import base64
from collections import Counter
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile

BASE = "44cb32576f0ee8b0d9f01aa5a4fa44ea0848c314"
SCANNED = "3a424e427b378400802c9e3c2fef558c0a352756"
ATTEMPTS = {"composed_5b1eb709": ("composed", "5b1eb7096062a9b8619aadbeafa06d7bc9c568cb"),
            "owned_a1ade3cc": ("owned", "a1ade3cc2bf4a3b3eabd87f82ba6c8c515215e49")}
STRICT = ["-Werror=implicit-function-declaration", "-Werror=implicit-int", "-Werror=strict-prototypes"]
WRAP = ["-fno-builtin-calloc", "-fno-builtin-malloc", "-fno-builtin-free",
        "-Wl,--wrap=calloc", "-Wl,--wrap=malloc", "-Wl,--wrap=free"]
PATTERN = re.compile(r"implicit declaration|conflicting types|incompatible pointer|implicit-int|pointer from integer|integer from pointer", re.I)


def require(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def git_oid(kind, raw):
    return hashlib.sha1(kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def parse(raw):
    def pairs(rows):
        result = {}
        for name, value in rows:
            require(name not in result, "duplicate JSON key")
            result[name] = value
        return result
    def invalid(_):
        raise ValueError("non-finite JSON")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def same(left, right):
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)


def safe(name):
    require(type(name) is str and name and "\\" not in name and "\0" not in name, "unsafe path")
    path = PurePosixPath(name)
    require(not path.is_absolute() and ".." not in path.parts and str(path) == name and name != ".", "unsafe path")
    return name


def read(directory, name, limit=4 * 1024 * 1024):
    path = Path(directory)
    for part in PurePosixPath(safe(name)).parts:
        path /= part
        require(not path.is_symlink(), "symlink input")
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit, "nonregular or oversized input")
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as stream:
        require(identity(os.fstat(stream.fileno())) == identity(before), "input changed before read")
        raw = stream.read(limit + 1)
        require(identity(os.fstat(stream.fileno())) == identity(before), "input changed during read")
    require(len(raw) == before.st_size and identity(path.stat()) == identity(before), "input changed after read")
    return raw


def check_bytes(raw, row):
    require(len(raw) == row["bytes"] and sha(raw) == row["sha256"], "retained bytes differ")


def unpack(directory):
    manifest = parse(read(directory, "archive.manifest.json"))
    require(manifest["schema"] == "hepta.caller-abi.archive.v1"
            and manifest["compression"] == "xz-preset-6-default-dictionary"
            and manifest["encoding"] == "base64", "archive encoding")
    encoded = read(directory, manifest["archive"], 3_500_000)
    require(len(encoded) == manifest["encoded_bytes"] and sha(encoded) == manifest["encoded_sha256"], "base64 identity")
    packed = base64.b64decode(b"".join(encoded.split()), validate=True)
    require(len(packed) == manifest["decoded_bytes"] and sha(packed) == manifest["decoded_sha256"], "xz identity")
    decoder = lzma.LZMADecompressor(memlimit=32 * 1024 * 1024)
    raw = decoder.decompress(packed, max_length=4 * 1024 * 1024 + 1)
    require(len(raw) <= 4 * 1024 * 1024 and decoder.eof and not decoder.unused_data, "bounded single xz stream")
    require(len(raw) == manifest["tar_bytes"] and sha(raw) == manifest["tar_sha256"], "tar identity")
    expected = {safe(row["path"]): row for row in manifest["members"]}
    require(len(expected) == len(manifest["members"]) == manifest["member_count"] == 70, "archive denominator")
    found, end = {}, 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive:
            name = safe(member.name)
            require(member.type == tarfile.REGTYPE and not member.pax_headers and not archive.pax_headers
                    and member.offset == end and raw[end + 257:end + 265] == b"ustar\00000", "ordinary USTAR required")
            require(name in expected and name not in found and 0 <= member.size <= 1024 * 1024, "archive member")
            require(member.uid == member.gid == member.mtime == 0 and member.uname == member.gname == ""
                    and member.mode == expected[name]["mode"], "archive metadata")
            with archive.extractfile(member) as stream:
                data = stream.read(member.size + 1)
            check_bytes(data, expected[name]); found[name] = data
            end = member.offset_data + (member.size + 511) // 512 * 512
    require(set(found) == set(expected) and sum(map(len, found.values())) == manifest["uncompressed_bytes"], "archive inventory")
    require(len(raw) >= end + 1024 and not any(raw[end:]), "trailing tar data")
    return found


def source_proof(directory, members):
    proof = parse(read(directory, "source-proof.json")); roots = {}; trees = {}
    require(proof["schema"] == "hepta.caller-abi.git-proof.v1"
            and set(proof["commits"]) == {BASE, *(value[1] for value in ATTEMPTS.values())}, "Git commit inventory")
    for commit, data in proof["commits"].items():
        body = base64.b64decode(data["commit_object_base64"], validate=True)
        require(git_oid("commit", body) == commit and body.splitlines()[0] == ("tree " + data["root_tree"]).encode(), "Git commit object")
        roots[commit] = data["root_tree"]; trees[commit] = {}
        for oid, text in data["tree_objects_base64"].items():
            raw = base64.b64decode(text, validate=True)
            require(git_oid("tree", raw) == oid, "Git tree object")
            offset, entries = 0, {}
            while offset < len(raw):
                zero = raw.index(b"\0", offset); mode, name = raw[offset:zero].split(b" ", 1)
                name = name.decode()
                require(zero + 21 <= len(raw) and name not in entries and "/" not in name and name not in {".", ".."}, "Git tree member")
                entries[name] = mode.decode(), raw[zero + 1:zero + 21].hex(); offset = zero + 21
            trees[commit][oid] = entries
    require(len(proof["bindings"]) == 20, "Git binding denominator")
    used = {commit: set() for commit in roots}; bindings = {}
    for row in proof["bindings"]:
        commit = row["commit"]; parts = PurePosixPath(safe(row["git_path"])).parts; tree = roots[commit]
        for part in parts[:-1]:
            used[commit].add(tree); mode, tree = trees[commit][tree][part]
            require(mode == "40000", "Git ancestor mode")
        used[commit].add(tree); mode, oid = trees[commit][tree][parts[-1]]
        raw = members[safe(row["archive_path"])]; check_bytes(raw, row)
        require(mode in {"100644", "100755"} and oid == row["git_blob_sha1"] == git_oid("blob", raw), "Git source blob binding")
        require(row["archive_path"] not in bindings, "duplicate source binding")
        bindings[row["archive_path"]] = row
    require(all(used[commit] == set(trees[commit]) for commit in roots), "Git tree proof denominator")
    return roots, bindings


def word(state, value):
    for shift in range(0, 64, 8):
        state = ((state ^ ((value >> shift) & 255)) * 1099511628211) & ((1 << 64) - 1)
    return state


def review_attempt(label, kind, commit, members, roots, bindings):
    prefix = label + "/probe/"; report = parse(members[prefix + "report.json"])
    require(report["ok"] is True and report["baseline_commit"] == BASE
            and same(report["source_before"], report["source_after"]), "probe result/source changed")
    source = report["source_before"]
    require(source["commit"] == commit and source["tree"] == roots[commit] and source["tracked_status"] == "", "frozen probe source")
    require(set(source["files"]) == {"docs/CPP_" + kind.upper() + "_MIGRATION.md",
        "examples/cpp/" + kind + "_migration/harness.c", "tests/test_cpp_composed_harness.py",
        "tools/qualify_cpp_" + kind + "_llvm.py", "tools/validate_cpp_owned.py", "tools/validate_cpp_composed.py"},
        "recorded source-file denominator")
    require(same(report["scope"], {"caller_abi_controls_only": True, "resource_workload_changed": False,
                                 "performance_samples_collected": 0, "full_candidate_qualified": False}), "probe scope")
    for name, row in source["files"].items():
        member = prefix + "inputs/" + name.replace("/", "__")
        check_bytes(members[member], row)
        require(bindings[member]["commit"] == commit and bindings[member]["git_path"] == name, "probe/Git source correspondence")
    for name, expected_commit in (("fixed", commit), ("legacy", BASE)):
        binding = bindings[prefix + name + "/harness.c"]
        require(binding["commit"] == expected_commit
                and binding["git_path"] == "examples/cpp/" + kind + "_migration/harness.c", "legacy/fixed harness source identity")
    records = report["processes"]
    codes = {"compiler-version": 0, "compile-callee": 0, "legacy-link": 0, "legacy-run": 2,
             "fixed-link": 0, "fixed-run": 0, "strict-untyped-link": 1}
    require(set(records) == set(codes), "probe process denominator")
    original_root = str(PurePosixPath(records["fixed-run"]["argv"][0]).parent.parent)
    def relative(path):
        require(path.startswith(original_root + "/"), "process artifact outside retained probe")
        return prefix + safe(path[len(original_root) + 1:])
    for name, record in records.items():
        require(set(record) == {"argv", "returncode", "stdout", "stderr"}
                and type(record["returncode"]) is int and record["returncode"] == codes[name], "probe process outcome")
        for field in ("stdout", "stderr"):
            row = record[field]; raw = members[relative(row["path"])]; check_bytes(raw, row)
            require(raw.decode() == row["text"], "raw/text stream correspondence")
    cc = report["compiler"]["selected"]
    require(records["compiler-version"]["argv"] == [cc, "--version"]
            and records["compile-callee"]["argv"] == [cc, "-std=c11", "-O2", "-fno-lto", "-c",
                original_root + "/callee.c", "-o", original_root + "/callee.o"]
            and records["legacy-run"]["argv"] == [original_root + "/legacy/native"]
            and records["fixed-run"]["argv"] == [original_root + "/fixed/native"], "probe process command identity")
    for name, folder, strict in (("legacy-link", "legacy", False), ("fixed-link", "fixed", True),
                                  ("strict-untyped-link", "legacy", True)):
        output = "rejected" if name == "strict-untyped-link" else "native"
        command = [cc, "-std=c11", "-O2", "-fno-lto", *(STRICT if strict else []), *WRAP,
                   "-I" + original_root, original_root + "/" + folder + "/harness.c", original_root + "/callee.o",
                   "-o", original_root + "/" + folder + "/" + output]
        require(records[name]["argv"] == command, "legacy/strict link command identity")
    require("warning: implicit declaration" in records["legacy-link"]["stderr"]["text"]
            and "error: implicit declaration" in records["strict-untyped-link"]["stderr"]["text"]
            and prefix + "legacy/rejected" not in members, "diagnostic/failed artifact evidence")
    require(len(report["retained_native"]) == 3, "native artifact denominator")
    require({relative(row["path"]) for row in report["retained_native"]}
            == {prefix + name for name in ("callee.o", "legacy/native", "fixed/native")}, "retained binary identity set")
    for row in report["retained_native"]:
        data = members[relative(row["path"])]; check_bytes(data, row)
        require(data.startswith(b"\x7fELF"), "native artifact format")
    vectors = report["vectors"]; require(len(vectors) == 2, "ABI vector denominator")
    digest = 14695981039346656037; expected_values = []
    for index, row in enumerate(vectors):
        value = (row["value"] << 56) ^ row["index"] ^ (row["reject"] << 32) ^ row["early"]
        value ^= row["left"] ^ (row["right"] << 1) if kind == "composed" else row["size"]
        value &= (1 << 64) - 1
        require(value == row["expected"] and value > 0xffffffff and row["allocated"] == row["refusals"] == 0, "independent ABI oracle")
        expected_values.append(value)
        values = [index, value, *([row["trace"]] if kind == "composed" else []), 0, 0, 0]
        for value in values:
            digest = word(digest, value)
    fixed = {"ok": True, "cases": 2, "observations_fnv64": f"{digest:016x}", "allocations": 0, "frees": 0, "refusals": 0, "live": 0}
    require(same(fixed, report["fixed_observed"]) and same(fixed, parse(records["fixed-run"]["stdout"]["text"])), "fixed native observation digest")
    low = expected_values[0] & 0xffffffff
    truncated = (low if low < 0x80000000 else low - (1 << 32)) & ((1 << 64) - 1)
    legacy = {"ok": False, "failure": "value", "case": 0, "expected": expected_values[0], "actual": truncated}
    require(truncated != expected_values[0] and same(legacy, report["legacy_observed"])
            and same(legacy, parse(records["legacy-run"]["stdout"]["text"])), "actual legacy sign extension")
    logs = {}
    for name, raw in members.items():
        if not name.startswith(label + "/logs/"):
            continue
        terminal = re.search(rb"Ran (\d+) tests in ([\d.]+)s\s+OK\s*\Z", raw)
        if terminal:
            logs[PurePosixPath(name).name] = {"tests": int(terminal[1]), "seconds": float(terminal[2]), "skipped": 0,
                "failures": 0, "errors": 0, "bytes": len(raw), "sha256": sha(raw), "embedded_source_commit": False}
    require(sorted(row["tests"] for row in logs.values()) == ([2, 25] if kind == "composed" else [4, 21]), "actual test-run denominator")
    return {"source_commit": commit, "source_tree": roots[commit], "baseline_commit": BASE, "report_sha256": sha(members[prefix + "report.json"]),
            "source_files_checked": len(source["files"]), "process_records": 7, "raw_streams_checked": 14, "ELF_files_checked": 3,
            "expected_returns": [hex(value) for value in expected_values], "legacy_actual_return": hex(truncated),
            "legacy_exit": 2, "fixed_exit": 0, "strict_missing_prototype_compile_exit": 1,
            "fixed_observation_digest": f"{digest:016x}", "test_runs": logs,
            "scope": "two caller ABI vectors with a separate C callee; no complete candidate, migrated workload or performance qualification"}


def scan_report(value, name, pointer=""):
    result = []
    if isinstance(value, dict):
        for key, item in value.items():
            current = pointer + "/" + key.replace("~", "~0").replace("/", "~1")
            if key == "stderr":
                text = item if isinstance(item, str) else item.get("text", "") if isinstance(item, dict) else ""
                lines = [line for line in text.splitlines() if PATTERN.search(line)]
                if lines:
                    result.append({"report": name, "json_pointer": current, "matching_lines": lines, "stderr_utf8_sha256": sha(text.encode())})
            if isinstance(item, (dict, list)):
                result += scan_report(item, name, current)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            if isinstance(item, (dict, list)):
                result += scan_report(item, name, pointer + "/" + str(index))
    return result


def warning_review(directory, original_reports=None):
    audit = parse(read(directory, "originals/warning-audit.json"))
    archived = parse(read(directory, "originals/source-candidate-archive.manifest.json"))
    entries = {row["path"]: row for row in archived["members"]}
    require(audit["commit"] == SCANNED and len(audit["reports"]) == 46
            and audit["matching_stderr_records"] == len(audit["findings"]) == 10, "warning audit scope")
    for row in audit["reports"]:
        target = entries["artifacts/composition-candidate-20261026-run1/" + safe(row["name"])]
        require(target["bytes"] == row["bytes"] and target["sha256"] == row["sha256"], "existing source-candidate report binding")
    counts = dict(Counter(row["report"] for row in audit["findings"]))
    require(counts == {"cpp_composed_llvm.json": 9, "cpp_owned_llvm.json": 1}, "warning report denominator")
    if original_reports is not None:
        names = sorted(path.name for path in Path(original_reports).glob("*.json"))
        require(names == [row["name"] for row in audit["reports"]], "top-level original JSON denominator")
        findings = []
        for row in audit["reports"]:
            raw = read(original_reports, row["name"], 32 * 1024 * 1024); check_bytes(raw, row)
            findings += scan_report(parse(raw), row["name"])
        require(same(findings, audit["findings"]), "independent warning scan differs")
    return {"source_commit": SCANNED, "top_level_reports": 46, "matching_stderr_records": 10, "by_report": counts,
            "original_reports_rechecked": original_reports is not None,
            "scope": "retained top-level qualification JSON stderr fields only; missing/hidden compile logs were not scanned"}


def review(directory, original_reports=None):
    members = unpack(directory); roots, bindings = source_proof(directory, members)
    require({name.split("/", 1)[0] for name in members} == set(ATTEMPTS), "attempt inventory")
    attempts = {label: review_attempt(label, kind, commit, members, roots, bindings)
                for label, (kind, commit) in ATTEMPTS.items()}
    for label, (kind, _) in ATTEMPTS.items():
        require(read(directory, "originals/" + kind + "-report.json") == members[label + "/probe/report.json"], "original report copy")
    return {"schema": "hepta.caller-abi.review.v1", "attempts": attempts,
            "archive_members": len(members), "archive_member_bytes": sum(map(len, members.values())),
            "ELF_files": sum(raw.startswith(b"\x7fELF") for raw in members.values()),
            "Git_commits_verified": len(roots), "Git_source_bindings_verified": len(bindings),
            "warning_audit": warning_review(directory, original_reports),
            "native_execution_repeated": False, "performance_samples_collected_by_review": 0,
            "compiler_or_qualifier_imported": False, "full_candidate_qualified": False, "whole_project_blockers_closed": False}


def verify(directory, original_reports=None):
    manifest = parse(read(directory, "MANIFEST.json"))
    require(manifest["schema"] == "hepta.caller-abi.bundle.v1", "bundle schema")
    actual = {path.relative_to(directory).as_posix() for path in Path(directory).rglob("*") if not path.is_dir()}
    require(actual == set(manifest["files"]) | {"MANIFEST.json"}, "sidecar inventory")
    for name, row in manifest["files"].items():
        check_bytes(read(directory, name), row)
    result = review(directory, original_reports)
    expected = parse(read(directory, "review.json"))
    require(same({**result, "warning_audit": {**result["warning_audit"], "original_reports_rechecked": False}}, expected), "independent review differs")
    return {"verified": True, **result, "archive_extracted": False, "network_used": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--warning-report-root", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory.resolve(), args.warning_report_root), indent=2, sort_keys=True))
