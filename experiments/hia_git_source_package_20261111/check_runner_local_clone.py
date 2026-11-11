#!/usr/bin/env python3
"""One actual v7/v8 local-clone compatibility control, separate from r3."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback


def run(source, evidence):
    source = source.resolve(strict=True)
    evidence.mkdir(mode=0o700, exist_ok=False)
    destination = evidence / "copy"
    report = {"schema": "hepta.hia.source-package-runner-local-clone.v1", "status": "HOLD",
              "scope": "ONE_ADDITIONAL_SYNTHETIC_GIT_CONTROL_NO_PRODUCT_EXECUTION",
              "source": str(source), "destination": str(destination), "commands": [],
              "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "python": sys.version, "executable": sys.executable}
    started = time.monotonic()

    def command(argv, cwd):
        result = subprocess.run(argv, cwd=cwd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=False)
        report["commands"].append({"argv": list(map(str, argv)), "cwd": str(cwd),
                                   "returncode": result.returncode,
                                   "stdout": result.stdout.decode("utf-8", "backslashreplace"),
                                   "stderr": result.stderr.decode("utf-8", "backslashreplace")})
        if result.returncode:
            raise RuntimeError("original runner command failed: " + str(argv))
        return result.stdout

    def state(root):
        helper = root / "tools/hia_core_source_identity.py"
        return json.loads(command([sys.executable, "-I", "-S", "-B", "-c",
            "import json,runpy,sys; print(json.dumps(runpy.run_path(sys.argv[1])['_source_state'](),sort_keys=True))",
            str(helper)], root))

    try:
        before = state(source)
        report["source_state_before"] = before
        command(["git", "--no-replace-objects", "clone", "--quiet", "--no-hardlinks",
                 "--no-checkout", str(source), str(destination)], evidence)
        command(["git", "--no-replace-objects", "checkout", "--quiet", "--detach", "HEAD"], destination)
        reproduced = state(destination)
        after = state(source)
        report.update({"clone_source_state": reproduced, "source_state_after": after})
        assert before == reproduced == after and before["status"] == ""
        original = command(["git", "--no-replace-objects", "cat-file", "commit", before["head"]], source)
        copied = command(["git", "--no-replace-objects", "cat-file", "commit", before["head"]], destination)
        assert original == copied
        shallow = (source / ".git/shallow").read_bytes()
        assert (destination / ".git/shallow").read_bytes() == shallow == (before["head"] + "\n").encode()
        object_sets = []
        for root in (source, destination):
            object_sets.append(set(command(["git", "--no-replace-objects", "cat-file",
                "--batch-all-objects", "--unordered", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
                root).splitlines()))
        assert object_sets[0] == object_sets[1]
        shared = []
        for root in (source, destination):
            ids = set()
            for current, _, names in os.walk(root / ".git/objects"):
                for name in names:
                    value = (Path(current) / name).lstat()
                    ids.add((value.st_dev, value.st_ino))
            shared.append(ids)
        assert not shared[0].intersection(shared[1])
        command(["git", "--no-replace-objects", "fsck", "--full", "--strict",
                 "--no-reflogs", "--no-dangling", before["head"]], destination)
        report.update({"status": "PASS", "tests_run": 1, "all_original_source_state_fields_equal": True,
                       "original_commit_bytes_equal": True, "object_inventory_equal": True,
                       "object_storage_hardlinks": 0, "shallow_boundary": shallow.decode().splitlines(),
                       "ancestor_history_included": False, "qualification_executed": False})
    except BaseException as exc:
        report["exception"] = {"type": type(exc).__name__, "message": str(exc),
                               "traceback": traceback.format_exc()}
        raise
    finally:
        report["wall_seconds"] = time.monotonic() - started
        (evidence / "report.json").write_text(json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2) + "\n")
        print(json.dumps({k: report[k] for k in ("status", "scope", "wall_seconds")}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    run(args.source, args.evidence_dir.absolute())
