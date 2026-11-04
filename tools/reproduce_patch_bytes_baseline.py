"""Observe the original Windows writeback mismatch with real native validation.

Run only in the dedicated Windows lane against a separate immutable base
worktree. No production modules are replaced and no validation is mocked.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

BASE = "f2b76f5741c83822be2e12cf5a50b50a8d27b96a"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("baseline_root", type=Path)
    args = parser.parse_args()
    root = args.baseline_root.resolve()
    if os.name != "nt":
        raise SystemExit("The original default-newline witness requires actual Windows")
    head = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    status = subprocess.check_output(["git", "-C", str(root), "status", "--porcelain"], text=True)
    if head != BASE or status:
        raise SystemExit("Require the exact unchanged baseline worktree")
    sys.path.insert(0, str(root))
    from hepta import protocol
    from hepta.backend import sha256, toolchain_info
    from hepta.modules import load_project
    from hepta.parser import parse
    from hepta.pipeline import interface_hash
    if Path(protocol.__file__).resolve() != root / "hepta" / "protocol.py":
        raise SystemExit("The imported protocol is not the frozen baseline")
    rustc = os.environ["RUSTC"]
    print("BASELINE_SOURCE", head, flush=True)
    print("BASELINE_RUST_TOOLCHAIN", json.dumps(toolchain_info(rustc), sort_keys=True), flush=True)
    observations = []
    with tempfile.TemporaryDirectory(prefix="hepta-original-patch-bytes-") as tmp:
        directory = Path(tmp)
        for version in (1, 2):
            entry, target = directory / "main.hepta", directory / "dep.hepta"
            if version == 1:
                target = entry
            else:
                entry.write_bytes(b"import dep; fn main() -> i32 effects {} { return 0; }\r\n")
            source = "// preserved\r\npub fn value() -> i64 effects {} { return 7; }\r\n"
            body = "{\nreturn 8;\n}"
            target.write_bytes(source.encode("utf-8"))
            expected = source.replace("{ return 7; }", body).encode("utf-8")
            request = {"schema": "hepta.patch.v" + str(version), "symbol": "value",
                       "replacement_body": body, "expected_source_sha256": sha256(target.read_bytes())}
            if version == 1:
                request["expected_interface_sha256"] = interface_hash(parse(source))
                report = protocol.apply_patch(entry, request, apply=True, rustc=rustc)
            else:
                project = load_project(entry)
                request.update(expected_project_sha256=project.identity, target="dep.hepta",
                               expected_interface_sha256=interface_hash(project.program))
                report = protocol.apply_project_patch(entry, request, apply=True, rustc=rustc)
            actual = target.read_bytes()
            if (not report["ok"] or not report["applied"]
                    or report["validation"]["checks"]["rust_borrows_types"] != "rustc_checked"
                    or report["after_sha256"] != sha256(expected)
                    or actual != expected.replace(b"\n", b"\r\n")
                    or sha256(actual) == report["after_sha256"]):
                raise SystemExit("The original native Windows mismatch was not reproduced: " + repr(report))
            if version == 2 and load_project(entry).identity == report["project_candidate_sha256"]:
                raise SystemExit("Expected the original project identity mismatch")
            observations.append({"schema": request["schema"], "native": "rustc_checked",
                                 "reported_applied": report["applied"],
                                 "reported_after_sha256": report["after_sha256"],
                                 "actual_sha256": sha256(actual),
                                 "expected_hex": expected.hex(), "actual_hex": actual.hex()})
    if subprocess.check_output(["git", "-C", str(root), "status", "--porcelain"], text=True):
        raise SystemExit("Baseline worktree changed")
    print("ORIGINAL_WINDOWS_MISMATCHES", json.dumps(observations, sort_keys=True), flush=True)
    print("BASELINE_WITNESSES_CONFIRMED", len(observations), flush=True)


if __name__ == "__main__":
    main()
