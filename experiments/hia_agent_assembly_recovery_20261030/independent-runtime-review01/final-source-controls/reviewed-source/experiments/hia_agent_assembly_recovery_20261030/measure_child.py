#!/usr/bin/env python3
"""Fresh-process outer cost receipt; never alter the measured command."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import resource
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        raise ValueError("an explicit measured command is required")
    destination = Path(args.receipt)
    if destination.exists():
        raise ValueError("a measured run receipt already exists")
    started = time.monotonic_ns()
    record = {"argv": command, "started_unix_ns": time.time_ns(), "rerun": False}
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    try:
        # Inherit the recovery wrapper's private process group. Its outer
        # cancellation can therefore signal the harness and owned servers.
        # The frozen native object compiler may create its own bounded session;
        # this receipt never asserts that an outer kill closed all descendants.
        result = subprocess.run(command)
        record["returncode"] = result.returncode
        return result.returncode
    except BaseException as error:
        record["error"] = {"type": type(error).__name__, "message": str(error)}
        record["returncode"] = None
        raise
    finally:
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        record.update(wall_ns=time.monotonic_ns()-started,
            child_user_seconds=after.ru_utime-before.ru_utime,
            child_system_seconds=after.ru_stime-before.ru_stime,
            child_maxrss_kib=after.ru_maxrss,
            maxrss_scope="maximum completed descendant-process RSS in this fresh observer; not simultaneous aggregate RSS")
        with destination.open("x") as stream:
            json.dump(record, stream, indent=2, sort_keys=True)
            stream.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
