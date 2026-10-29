#!/usr/bin/env python3
"""Source-bound, read-only structural payload analysis; no native admission."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from hepta.hia_heap_bound import analyze_entry_payload_bound
from hepta.hia_program_tools import read_bounded


DEPENDENCIES = (
    "hepta/hia_heap_bound.py", "hepta/hia_static_budget.py",
    "hepta/hia_program.py", "hepta/hia_program_runtime.py",
    "hepta/hia_schema.py", "hepta/hia_json_preflight.py",
    "hepta/hia_program_tools.py", "tools/analyze_hia_entry_payload.py",
)


def source_snapshot():
    def git(*arguments):
        return subprocess.check_output(["git", *arguments], cwd=ROOT,
                                       timeout=10, text=True).strip()
    return {
        "commit": git("rev-parse", "HEAD"),
        "tree": git("rev-parse", "HEAD^{tree}"),
        "status": git("status", "--porcelain=v1", "--untracked-files=normal"),
        "dependencies_sha256": {name: sha256(read_bounded(ROOT / name)).hexdigest()
                                for name in DEPENDENCIES},
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("program", type=Path)
    parser.add_argument("function")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-clean-source", action="store_true")
    options = parser.parse_args(argv)
    started = time.monotonic()
    try:
        before = source_snapshot()
        if options.require_clean_source and before["status"]:
            raise ValueError("source checkout must be clean: " + before["status"])
        raw = read_bounded(options.program)
        report = analyze_entry_payload_bound(raw, options.function)
        after = source_snapshot()
        if before != after:
            raise ValueError("source changed during analysis")
        receipt = {
            "schema": "hepta.hia.entry-payload-analysis-run.v1",
            "status": "completed", "source": before, "source_unchanged": True,
            "input_path": str(options.program.resolve()),
            "input_file_sha256": sha256(raw).hexdigest(),
            "input_bytes": len(raw), "analysis": report,
            "python": {"executable": sys.executable, "version": sys.version},
            "finished_utc": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": time.monotonic() - started,
            "no_native_compilation_or_model_request": True,
            "environment": "shared-cloud-scratch-not-user-dot",
        }
        encoded = json.dumps(receipt, indent=2, sort_keys=True, allow_nan=False) + "\n"
        if options.output is None:
            sys.stdout.write(encoded)
        else:
            # No overwrite of an earlier evidence attempt. Analysis never
            # edits the Core or publishes an executable artifact.
            with options.output.open("x", encoding="utf-8") as stream:
                stream.write(encoded)
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        sys.stderr.write(json.dumps({"status": "refused", "error": str(error),
                                    "code": getattr(error, "code", None)}) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
