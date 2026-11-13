#!/usr/bin/env python3
"""Check fixed authored source syntax and original selfhost AST custody only."""
import argparse
import ast
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import runpy
import subprocess
import sys
import traceback
import urllib.request

def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()

def identity(raw):
    return {"bytes": len(raw), "git_blob": git_blob(raw),
            "sha256": hashlib.sha256(raw).hexdigest()}

def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result

def parse_json(raw):
    return json.loads(raw, object_pairs_hook=no_duplicate_keys)

def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)

def json_new(path, value):
    write_new(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"))

def safe_path(value):
    path = PurePosixPath(value)
    if not isinstance(value, str) or value != str(path) or path.is_absolute() or not path.parts:
        raise ValueError("invalid source path")
    if any(part in ("", ".", "..") for part in path.parts) or "\\" in value or "\0" in value:
        raise ValueError("unsafe source path")
    return path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    args.root.mkdir(parents=True, exist_ok=False)
    evidence = args.root / "evidence"
    evidence.mkdir()
    result = {
        "schema": "hepta.fixed_combined_source_static_result.v2",
        "scope": "COMBINED_SOURCE_STATIC_ONLY",
        "status": "INCOMPLETE",
        "python": {"version": sys.version, "executable": sys.executable,
                   "implementation": platform.python_implementation()},
        "packets": [], "failures": [],
        "product_imports_executed": False, "product_tests_executed": 0,
        "HIA_generated": False, "native_executions": 0,
        "cold_qualifications": 0, "whole_native": False,
    }
    try:
        input_raw = args.inputs.read_bytes()
        driver_raw = Path(__file__).read_bytes()
        for label, raw, key in (
                ("inputs", input_raw, "EXPECTED_INPUTS_GIT_BLOB"),
                ("driver", driver_raw, "EXPECTED_DRIVER_GIT_BLOB")):
            if git_blob(raw) != os.environ[key]:
                raise ValueError(label + " harness source differs")
            result[label] = identity(raw)
        inputs = parse_json(input_raw)
        write_new(evidence / "FIXED-INPUTS.json", input_raw)
        write_new(evidence / "DRIVER.py", driver_raw)
        validator_path = Path(__file__).with_name("validate_selfhost_merge.py")
        validator_raw = validator_path.read_bytes()
        validator_pin = inputs["selfhost_validator"]
        if git_blob(validator_raw) != validator_pin["blob"] or len(validator_raw) != validator_pin["bytes"]:
            raise ValueError("fixed selfhost validator differs")
        write_new(evidence / "SELFHOST-VALIDATOR.py", validator_raw)
        token = os.environ["HIA_SYNTAX_READ_TOKEN"]
        repository = inputs["repository"]
        if repository != "TrillionniumFoundation/Hepta":
            raise ValueError("unexpected repository")
        cache = {}
        def fetch_blob(sha):
            if len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha):
                raise ValueError("invalid Git blob pin")
            if sha in cache:
                return cache[sha]
            request = urllib.request.Request(
                "https://api.github.com/repos/" + repository + "/git/blobs/" + sha,
                headers={"Accept": "application/vnd.github+json",
                         "Authorization": "Bearer " + token,
                         "X-GitHub-Api-Version": "2022-11-28",
                         "User-Agent": "hepta-fixed-draft-syntax"})
            with urllib.request.urlopen(request, timeout=30) as response:
                api_raw = response.read()
            write_new(evidence / "api" / (sha + ".json"), api_raw)
            value = parse_json(api_raw)
            if value["sha"] != sha or value["encoding"] != "base64":
                raise ValueError("Git blob response identity differs")
            raw = base64.b64decode("".join(value["content"].splitlines()), validate=True)
            if len(raw) != value["size"] or git_blob(raw) != sha:
                raise ValueError("Git blob bytes differ")
            write_new(evidence / "blobs" / (sha + ".blob"), raw)
            cache[sha] = raw
            return raw

        root_validator_path = Path(__file__).with_name("validate_root_merge.py")
        root_validator_raw = root_validator_path.read_bytes()
        root_validator_pin = inputs["root_validator"]
        if git_blob(root_validator_raw) != root_validator_pin["blob"] or len(root_validator_raw) != root_validator_pin["bytes"]:
            raise ValueError("fixed root AST validator differs")
        write_new(evidence / "ROOT-VALIDATOR.py", root_validator_raw)
        selfhost = None
        final = {}
        origins = {}
        observed_overrides = []
        seen_packet_rows = 0
        for pin in inputs["packets"]:
            raw = fetch_blob(pin["blob"])
            if len(raw) != pin["bytes"] or (
                    "sha256" in pin and hashlib.sha256(raw).hexdigest() != pin["sha256"]):
                raise ValueError("packet pin differs: " + pin["label"])
            packet = parse_json(raw)
            packet_path = evidence / "packets" / (pin["label"] + ".json")
            write_new(packet_path, raw)
            rows = []
            layout = pin["layout"]
            if layout == "array-byte":
                for row in packet["files"]:
                    rows.append((row["path"], row["text"], row["bytes"], row["blob"], None))
            elif layout == "object-text-after":
                for path, row in packet["files"].items():
                    after = row["after"]
                    rows.append((path, row["text"], after["bytes"], after["git_blob_sha1"], after.get("sha256")))
            elif layout == "object-after":
                for path, row in packet["files"].items():
                    after = row["after"]
                    rows.append((path, after["text"], after["bytes"], after["git_blob"], after.get("sha256")))
                if pin["label"] == "selfhost-r1":
                    selfhost = (packet, packet_path)
            elif layout == "array-identity":
                for row in packet["files"]:
                    after = row["identity"]
                    rows.append((row["path"], row["text"], after["bytes"], after["git_blob"], after.get("sha256")))
            elif layout == "array-after":
                for row in packet["files"]:
                    after = row["after"]
                    rows.append((row["path"], after["text"], after["bytes"], after["git_blob"], after.get("sha256")))
            else:
                raise ValueError("unrecognized explicit packet layout")
            if len(rows) != pin["files"]:
                raise ValueError("packet file count differs")
            seen = set()
            file_reports = []
            for path, text, size, blob, sha256 in rows:
                relative = safe_path(path)
                if path in seen:
                    raise ValueError("duplicate packet path: " + path)
                seen.add(path)
                body = text.encode("utf-8")
                actual = identity(body)
                if size != actual["bytes"] or blob != actual["git_blob"] or (
                        sha256 is not None and sha256 != actual["sha256"]):
                    raise ValueError("source identity differs: " + path)
                write_new(evidence / "sources-by-packet" / pin["label"] / relative, body)
                if path in final:
                    change = {"path": path, "from_packet": origins[path]["packet"], "to_packet": pin["label"],
                              "from": origins[path]["git_blob"], "to": blob}
                    if change not in inputs["allowed_overrides"] or change in observed_overrides:
                        raise ValueError("unapproved composition collision: " + repr(change))
                    observed_overrides.append(change)
                final[path] = text
                origins[path] = {"packet": pin["label"], **actual}
                file_reports.append({"path": path, **actual})
                seen_packet_rows += 1
            result["packets"].append({"label": pin["label"], **identity(raw), "files": file_reports})
        if seen_packet_rows != inputs["expected_packet_rows"] or len(final) != inputs["expected_final_files"]:
            raise ValueError("combined source inventory differs")
        if sorted(observed_overrides, key=lambda x:x["path"]) != sorted(inputs["allowed_overrides"], key=lambda x:x["path"]):
            raise ValueError("exact composition override set differs")
        result["overrides"] = observed_overrides
        result["final_files"] = []
        for path in sorted(final):
            body = final[path].encode("utf-8")
            write_new(evidence / "final-sources" / safe_path(path), body)
            entry = {"path": path, **origins[path]}
            if path.endswith(".py"):
                try:
                    tree = ast.parse(body, filename=path)
                    compile(tree, path, "exec", dont_inherit=True)
                except (SyntaxError, ValueError, TypeError) as error:
                    entry.update({"status": "FAIL", "error_type": type(error).__name__,
                                  "error": str(error), "traceback": traceback.format_exc()})
                    result["failures"].append({"stage": "combined-source-syntax", **entry})
                else:
                    entry.update({"status": "PASS", "AST_parsed": True, "code_compiled": True, "code_executed": False})
            else:
                entry["status"] = "NOT_CHECKED_NON_PYTHON"
            result["final_files"].append(entry)
        result["python_files_checked"] = sum(path.endswith(".py") for path in final)
        if result["python_files_checked"] != inputs["expected_python_files"]:
            raise ValueError("final Python source count differs")
        originals = {}
        for head, paths in inputs["originals"].items():
            originals[head] = {}
            for path, pin in paths.items():
                body = fetch_blob(pin["blob"])
                if len(body) != pin["bytes"]:
                    raise ValueError("original source byte count differs")
                originals[head][path] = body.decode("utf-8")
                write_new(evidence / "root-original-sources" / head / safe_path(path), body)
        try:
            ast_report = runpy.run_path(str(root_validator_path))["validate"](final, originals)
        except BaseException as error:
            ast_report = {"status": "FAIL", "error_type": type(error).__name__,
                          "error": str(error), "traceback": traceback.format_exc()}
            result["failures"].append({"stage": "root-structural-AST", **ast_report})
        json_new(evidence / "ROOT-AST-CUSTODY.json", ast_report)
        result["root_structural_AST"] = ast_report
        if selfhost is None:
            raise ValueError("missing fixed selfhost packet")
        packet, packet_path = selfhost
        source_roots = {name: evidence / "original-sources" / name for name in ("main", "a733")}
        for path, row in packet["files"].items():
            relative = safe_path(path)
            for name, source_root in source_roots.items():
                before = row["before"][name]
                if before is not None:
                    write_new(source_root / relative, fetch_blob(before["blob"]))
        for path, blob in inputs["held_cold_supervisors"].items():
            relative = safe_path(path)
            body = fetch_blob(blob)
            for source_root in source_roots.values():
                write_new(source_root / relative, body)
        command = [sys.executable, "-I", "-B", str(validator_path),
                   "--packet", str(packet_path),
                   "--main-source", str(source_roots["main"]),
                   "--a733-source", str(source_roots["a733"]),
                   "--output", str(evidence / "SELFHOST-AST-CUSTODY.json")]
        with (evidence / "SELFHOST-VALIDATOR.stdout").open("xb") as stdout, (
                evidence / "SELFHOST-VALIDATOR.stderr").open("xb") as stderr:
            completed = subprocess.run(command, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, timeout=60, check=False)
        result["original_selfhost_r1_validator"] = {
            "command": command, "returncode": completed.returncode,
            "source": identity(validator_raw), "product_imports_executed": False}
        if completed.returncode != 0:
            result["failures"].append({"stage": "selfhost-original-AST-custody",
                                       "returncode": completed.returncode})
        result["unique_original_blobs_fetched"] = len(cache)
        result["status"] = "FAIL" if result["failures"] else "PASS"
    except BaseException as error:
        result["status"] = "FAIL"
        result["failures"].append({"stage": "harness", "error_type": type(error).__name__,
                                   "error": str(error), "traceback": traceback.format_exc()})
    finally:
        json_new(evidence / "RESULT.json", result)
        print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1

if __name__ == "__main__":
    raise SystemExit(main())
