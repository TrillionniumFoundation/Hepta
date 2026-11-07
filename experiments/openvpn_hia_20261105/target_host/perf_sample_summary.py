#!/usr/bin/env python3
"""Publish bounded perf-script counters and a digest, never raw sample stacks."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile


SCHEMA = "hepta.openvpn-hia.perf-sample-summary.v1"
HEADER = re.compile(rb"\bcpu-clock(?:\:[ukhp]+)?:")
OVPN_SYMBOL = re.compile(rb"\bovpn_[a-zA-Z_]")


class PerfScriptSummary:
    def __init__(self, client_pid: int, server_pid: int):
        for name, value in (("client_pid", client_pid), ("server_pid", server_pid)):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(name + " must be a positive process ID")
        if client_pid == server_pid:
            raise ValueError("client and server process IDs must differ")
        self.client_pid = client_pid
        self.server_pid = server_pid
        self.raw_hash = hashlib.sha256()
        self.raw_bytes = 0
        self.sample_headers = 0
        self.openvpn_sample_headers_by_role = {"client": 0, "server": 0}
        self.kernel_symbol_lines = 0
        self.ovpn_symbol_lines = 0

    def feed(self, line: bytes):
        if not isinstance(line, bytes):
            raise TypeError("perf script lines must be bytes")
        self.raw_hash.update(line)
        self.raw_bytes += len(line)
        if HEADER.search(line):
            self.sample_headers += 1
            if re.search(rb"\b" + str(self.client_pid).encode("ascii") + rb"(?:/|\s)", line):
                self.openvpn_sample_headers_by_role["client"] += 1
            if re.search(rb"\b" + str(self.server_pid).encode("ascii") + rb"(?:/|\s)", line):
                self.openvpn_sample_headers_by_role["server"] += 1
        if b"[kernel.kallsyms]" in line or b"[ovpn]" in line:
            self.kernel_symbol_lines += 1
        if OVPN_SYMBOL.search(line):
            self.ovpn_symbol_lines += 1

    def result(self):
        return {
            "schema": SCHEMA,
            "raw_stdout_sha256": self.raw_hash.hexdigest(),
            "raw_stdout_bytes": self.raw_bytes,
            "sample_headers": self.sample_headers,
            "openvpn_sample_headers_by_role": dict(self.openvpn_sample_headers_by_role),
            "kernel_symbol_lines": self.kernel_symbol_lines,
            "ovpn_symbol_lines": self.ovpn_symbol_lines,
            "raw_sample_content_published": False,
        }


def summarize_perf_script_bytes(raw: bytes, client_pid: int, server_pid: int) -> dict:
    if not isinstance(raw, bytes):
        raise TypeError("perf script output must be bytes")
    summary = PerfScriptSummary(client_pid, server_pid)
    for line in raw.splitlines(keepends=True):
        summary.feed(line)
    return summary.result()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--perf", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--client-pid", type=int, required=True)
    parser.add_argument("--server-pid", type=int, required=True)
    args = parser.parse_args(argv)
    command = [
        args.perf, "script", "--input", args.input,
        "-F", "comm,pid,tid,time,event,ip,sym,dso",
    ]
    summary = PerfScriptSummary(args.client_pid, args.server_pid)
    with tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=stderr)
        assert process.stdout is not None
        for line in process.stdout:
            summary.feed(line)
        exit_code = process.wait()
        stderr.seek(0)
        stderr_hash = hashlib.sha256()
        stderr_bytes = 0
        while True:
            chunk = stderr.read(65536)
            if not chunk:
                break
            stderr_hash.update(chunk)
            stderr_bytes += len(chunk)
    result = summary.result()
    result.update(
        perf_exit_code=exit_code,
        perf_timed_out=False,
        raw_stderr_sha256=stderr_hash.hexdigest(),
        raw_stderr_bytes=stderr_bytes,
    )
    print(json.dumps(result, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
