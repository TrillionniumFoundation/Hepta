#!/usr/bin/env python3
"""Run bounded offline stages after the explicitly released model window."""
from pathlib import Path
from hashlib import sha256
import json
import subprocess
import time
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
RAW = HERE.parent / "p1-p2-scoped-cleanup-final-launches-20261030"
PYTHON = str(HERE.parent / "hepta-native-venv/bin/python")
SOURCE = "953fa62dee5aa563551d57b1374ab95b6d548b45"


def identity(path):
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": sha256(data).hexdigest()}


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def retain_json(path, value, errors, label):
    try:
        save(path, value)
        return True
    except BaseException as error:
        errors.append({"operation": label, "type": type(error).__name__, "message": str(error)})
        print(json.dumps({"persistence_error": errors[-1], "record": value}, sort_keys=True), file=sys.stderr)
        return False


def command(row):
    directory = HERE / row["label"]
    started = time.monotonic_ns()
    row["persistence_errors"] = []
    outputs = {"stdout": None, "stderr": None}
    try:
        directory.mkdir(exist_ok=False)
        if not retain_json(directory / "EXECUTION.json", row, row["persistence_errors"], "initial receipt"):
            raise RuntimeError("initial execution receipt could not be retained")
        result = subprocess.run(row["argv"], capture_output=True, timeout=row["timeout_seconds"])
        row.update(returncode=result.returncode, status="completed" if result.returncode == 0 else "failed")
        outputs.update(stdout=result.stdout, stderr=result.stderr)
    except BaseException as error:
        row.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
        for field in outputs:
            value = getattr(error, field, None)
            if value is not None:
                outputs[field] = value.encode() if isinstance(value, str) else value
    finally:
        for field, value in outputs.items():
            if value is None:
                continue
            try:
                (directory / field).write_bytes(value)
                row[field] = identity(directory / field)
            except BaseException as error:
                row["persistence_errors"].append({"operation": "raw " + field,
                    "type": type(error).__name__, "message": str(error)})
                row[field + "_observed_bytes"] = len(value)
                row[field + "_observed_sha256"] = sha256(value).hexdigest()
                row[field + "_observed_utf8_with_replacement"] = value.decode(errors="replace")
        if row["persistence_errors"]:
            row["status"] = "failed"
        row["outer_wall_ns"] = time.monotonic_ns() - started
        row["wall_scope"] = "through direct-child wait and raw persistence; terminal receipt serialization is outside interval"
        row["cleanup_scope"] = "subprocess.run direct child wait/reap, including timeout kill; escaped descendants not attested"
        terminal_ok = retain_json(directory / "EXECUTION.json", row, row["persistence_errors"], "terminal receipt")
        if not terminal_ok:
            row["status"] = "failed"
    return row["status"] == "completed" and not row["persistence_errors"]


def main():
    outer = {"schema": "hepta.scoped-cleanup.953-post-model-executions.v1", "source_head": SOURCE,
             "stages": [], "status": "starting", "nested_costs_not_added": True,
             "full_human_agent_development_cost": None, "persistence_errors": [],
             "native_model_or_archived_code_executed": False}
    started = time.monotonic_ns()
    try:
        if len(sys.argv) != 1:
            raise ValueError("no arguments accepted")
        if (HERE / "evidence.tar.xz").exists() or (HERE / "directory-readback").exists() or (HERE / "POST_MODEL_EXECUTIONS.json").exists():
            raise ValueError("retained executions are never overwritten")
        source = json.loads((RAW / "PLAN.json").read_bytes())
        if source["source_head"] != SOURCE:
            raise ValueError("frozen final source differs")
        specifications = [
            ("directory-readback", [PYTHON, "-B", str(RAW / "verify.py"), str(RAW)], 30),
            ("bundle-execution", [PYTHON, "-B", str(HERE / "build_bundle.py")], 60),
            ("archive-readback", None, 30),
        ]
        for label, argv, timeout in specifications:
            if label == "archive-readback":
                manifest_sha = identity(HERE / "MANIFEST.json")["sha256"]
                argv = [PYTHON, "-B", str(HERE / "verify_archive.py"), str(HERE / "evidence.tar.xz"),
                        str(HERE / "MANIFEST.json"), manifest_sha]
            row = {"label": label, "argv": argv, "timeout_seconds": timeout, "status": "starting",
                   "native_model_or_archived_code_executed": False}
            outer["stages"].append(row)
            if not retain_json(HERE / "POST_MODEL_EXECUTIONS.json", outer, outer["persistence_errors"], "pre-stage outer receipt"):
                raise RuntimeError("outer receipt could not be retained")
            if not command(row):
                raise RuntimeError(label + " failed; retained attempt is not overwritten")
        outer.update(status="completed", archive=identity(HERE / "evidence.tar.xz"),
                     manifest_sha256=identity(HERE / "MANIFEST.json")["sha256"])
    except BaseException as error:
        outer.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
    finally:
        outer["outer_wall_ns"] = time.monotonic_ns() - started
        outer["wall_scope"] = "includes nested offline stage intervals; terminal outer receipt is outside interval"
        if not retain_json(HERE / "POST_MODEL_EXECUTIONS.json", outer, outer["persistence_errors"], "terminal outer receipt"):
            outer["status"] = "failed"
        if outer["persistence_errors"]:
            outer["status"] = "failed"
    print(json.dumps({k: outer.get(k) for k in ("status", "archive", "manifest_sha256", "outer_wall_ns", "error")}, sort_keys=True))
    return 0 if outer["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
