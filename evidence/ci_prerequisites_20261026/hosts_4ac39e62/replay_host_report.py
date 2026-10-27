#!/usr/bin/env python3
"""Replay one existing host receipt against an immutable Python source export.

The LF/CRLF source profile is chosen before validation. This helper runs only
source generation and receipt checks; an audit hook blocks process creation and
network access. No recorded compiler or native command is executed.
"""
import hashlib
import json
from pathlib import Path
import sys


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def inventory(root):
    return {path.relative_to(root).as_posix(): sha(path.read_bytes())
            for directory in ("hepta", "tools")
            for path in sorted((root / directory).rglob("*.py"))}


if __name__ == "__main__":
    root, report_path = (Path(value).resolve() for value in sys.argv[1:3])
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(root))
    before = inventory(root)
    raw = report_path.read_bytes()
    report = json.loads(raw)
    blocked_events = []

    def forbid_execution(event, arguments):
        if event in {"subprocess.Popen", "os.system", "os.posix_spawn", "os.posix_spawnp",
                     "os.exec", "os.fork", "os.forkpty", "socket.connect", "socket.getaddrinfo"}:
            blocked_events.append(event)
            raise RuntimeError("process creation and network access are forbidden during receipt replay")

    result = {"schema": "hepta.host-receipt-replay.v2", "source_root": str(root),
              "input_path": str(report_path), "input_sha256": sha(raw),
              "source_files": before, "validated": False,
              "native_commands_executed": False, "network_access_performed": False,
              "blocked_audit_events": blocked_events, "source_and_report_unchanged": False,
              "error": None}
    sys.addaudithook(forbid_execution)
    try:
        from tools.validate_native_host import validate_report
        from hepta.pipeline import compiler_hash
        result["actual_compiler_sha256"] = compiler_hash()
        result["reported_compiler_sha256"] = report.get("compiler_sha256")
        validate_report(report)
        if before != inventory(root) or report_path.read_bytes() != raw:
            raise ValueError("source or report bytes changed during validation")
        if blocked_events:
            raise ValueError("replay attempted a forbidden process or network operation")
        result["source_and_report_unchanged"] = True
        result["validated"] = True
    except Exception as error:
        result["error"] = {"type": type(error).__name__, "message": str(error)}
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["validated"] else 1)
