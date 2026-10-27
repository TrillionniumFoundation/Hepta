#!/usr/bin/env python3
"""Replay captured LLVM optimization only; no native execution or timing."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT))

from hepta.clang_capture import run_bounded
from hepta.native_tool_identity import digest_executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", default="/usr/lib/llvm-20/bin/clang")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error("--output must be a new directory")
    manifest = json.loads((HERE / "manifest.json").read_text())
    for name, digest in manifest["files"].items():
        if sha256((HERE / name).read_bytes()).hexdigest() != digest:
            raise ValueError("retained diagnostic file changed: " + name)
    compiler = Path(args.clang).resolve(strict=True)
    before = digest_executable(compiler)
    version = run_bounded([str(compiler), "--version"], timeout=10,
                          stdout_limit=65536, stderr_limit=65536)
    if version.returncode:
        raise ValueError("compiler identity unavailable")
    args.output.mkdir()
    report = {"native_executions": 0, "timing_samples": 0, "performance_qualified": False,
              "compiler_sha256": before, "compiler_version": version.stdout, "files": {}}
    for name in ("original.ll", "candidate.ll", "experiment-malloc-plus-memset.ll"):
        source, output = HERE / name, args.output / (source_name := name.replace(".ll", "-optimized.ll"))
        command = [str(compiler), "-x", "ir", "-O3", "-S", "-emit-llvm", str(source), "-o", str(output)]
        result = run_bounded(command, timeout=30, stdout_limit=65536, stderr_limit=1048576)
        if result.returncode:
            raise ValueError("static optimization failed: " + result.stderr)
        if output.is_symlink() or not 0 < output.stat().st_size <= 1048576:
            raise ValueError("unexpected optimized LLVM artifact")
        text = output.read_text()
        start = text.index("@constructor_error(")
        stop = text.index("\n}", start) + 2
        report["files"][source_name] = {"sha256": sha256(text.encode()).hexdigest(),
                                        "constructor": text[start:stop]}
    if digest_executable(compiler) != before:
        raise ValueError("compiler identity changed during static comparison")
    (args.output / "static-comparison.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"optimized_modules": len(report["files"]), "native_executions": 0, "timing_samples": 0}))


if __name__ == "__main__":
    main()
