#!/usr/bin/env python3
"""Pure-data validation using an explicitly supplied immutable source export.

The caller selects LF or CRLF Git-checkout bytes. This script never changes a
report, reconstructs native execution, or runs any of its recorded commands.
"""
import hashlib
import json
from pathlib import Path
import sys


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inventory(root):
    return {str(path.relative_to(root)): sha(path.read_bytes())
            for directory in ("hepta", "tools")
            for path in sorted((root / directory).rglob("*.py"))}


def forbid_execution(event, arguments):
    if event in {"subprocess.Popen", "os.system", "os.posix_spawn", "os.exec"}:
        raise RuntimeError("native command execution is forbidden during receipt replay")


if __name__ == "__main__":
    root, report_path = (Path(value).resolve() for value in sys.argv[1:3])
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(root))
    before = inventory(root)
    raw = report_path.read_bytes()
    report = json.loads(raw)
    result = {"schema": "hepta.host-receipt-replay.v1", "source_root": str(root),
              "input_path": str(report_path), "input_sha256": sha(raw),
              "source_files": before, "validated": False,
              "native_commands_executed": False, "error": None}
    sys.addaudithook(forbid_execution)
    try:
        from tools.validate_native_host import validate_report
        from hepta.pipeline import compiler_hash
        result["actual_compiler_sha256"] = compiler_hash()
        result["reported_compiler_sha256"] = report.get("compiler_sha256")
        validate_report(report)
        if before != inventory(root) or report_path.read_bytes() != raw:
            raise ValueError("source or report bytes changed during validation")
        result["validated"] = True
    except Exception as error:
        result["error"] = {"type": type(error).__name__, "message": str(error)}
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["validated"] else 1)
