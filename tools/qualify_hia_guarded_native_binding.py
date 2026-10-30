#!/usr/bin/env python3
"""Run guarded artifact regressions without counting skipped native tests as passes."""
from __future__ import annotations

import argparse
from hashlib import sha256
import io
import json
from pathlib import Path
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.successful_ids = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.successful_ids.append(test.id())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-native", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    names = [
        "tests.test_hia_guarded_native_binding.GuardedArtifactBoundaryTests",
        "tests.test_hia_guarded_native_binding.GuardedNativeBindingQualificationTests",
    ]
    source_paths = (
        "hepta/hia_guarded_native_binding.py", "hepta/hia_guarded_optimization.py",
        "hepta/hia_inductive.py", "hepta/hia_optimization.py",
        "hepta/hia_program.py", "hepta/hia_program_llvm.py", "hepta/hia_semantic_kernel.py",
        "hepta/artifact_publication.py", "hepta/native_tool_identity.py",
        "tests/test_hia_guarded_native_binding.py", "tools/qualify_hia_guarded_native_binding.py",
    )
    source_hashes = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in source_paths}
    loader = unittest.TestLoader()
    native_count = loader.loadTestsFromName(names[1]).countTestCases()
    suite = loader.loadTestsFromNames(names)
    stream = io.StringIO()
    started = time.monotonic_ns()
    result = unittest.TextTestRunner(stream=stream, verbosity=2,
                                    resultclass=RecordedResult).run(suite)
    native_prefix = names[1] + "."
    native_passes = [name for name in result.successful_ids if name.startswith(native_prefix)]
    stable = all(sha256((ROOT / name).read_bytes()).hexdigest() == digest
                 for name, digest in source_hashes.items())
    native_qualified = bool(native_count and len(native_passes) == native_count
                            and result.wasSuccessful() and stable)
    ok = result.wasSuccessful() and stable and (native_qualified or not args.require_native)
    report = {
        "schema": "hepta.hia.guarded-native-binding-qualification.v1",
        "status": ("source_changed" if not stable else "native_and_boundary_qualified" if native_qualified else
                   "boundary_pass_native_pending" if result.wasSuccessful() else "failed"),
        "ok": ok, "require_native": args.require_native,
        "source_sha256": source_hashes, "sources_stable_during_tests": stable,
        "elapsed_ns": time.monotonic_ns() - started,
        "tests_run": result.testsRun, "tests_passed": len(result.successful_ids),
        "skipped": [{"test": test.id(), "reason": reason} for test, reason in result.skipped],
        "failures": [{"test": test.id(), "traceback": trace} for test, trace in result.failures],
        "errors": [{"test": test.id(), "traceback": trace} for test, trace in result.errors],
        "native_tests_required": native_count, "native_tests_passed": len(native_passes),
        "claims": {"native_execution_qualified": native_qualified,
                   "backend_refinement_proved": False, "whole_language_soundness_proved": False,
                   "performance_qualified": False},
        "test_log": stream.getvalue(),
    }
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
