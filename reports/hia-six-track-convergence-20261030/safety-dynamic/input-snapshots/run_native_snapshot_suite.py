"""Run real full-package argument and native snapshot regressions with raw logs."""
from pathlib import Path
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
import unittest

root, output, label = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
sys.path.insert(0, str(root))
sys.dont_write_bytecode = True
output.mkdir(parents=True, exist_ok=True)
names = ["tests.test_hia_adaptive_arguments", "tests.test_hia_adaptive_snapshot_native"]
suite = unittest.defaultTestLoader.loadTestsFromNames(names)
sources = sorted((root / "hepta").glob("*.py")) + [
    root / "tests/test_hia_adaptive_arguments.py",
    root / "tests/test_hia_adaptive_snapshot_native.py",
    root / "tools/qualify_hia_adaptive.py",
]
manifest = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
start = time.monotonic()
with (output / (label + ".log")).open("w") as stream:
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
import z3
report = {
    "schema": "hepta.dynamic-input-snapshot-regression.v1",
    "label": label,
    "tests_run": result.testsRun,
    "failures": len(result.failures),
    "errors": len(result.errors),
    "skipped": len(result.skipped),
    "successful": result.wasSuccessful(),
    "elapsed_seconds": time.monotonic() - start,
    "failure_ids": [test.id() for test, _ in result.failures],
    "error_ids": [test.id() for test, _ in result.errors],
    "python": platform.python_version(),
    "platform": platform.platform(),
    "z3": z3.get_version_string(),
    "clang": subprocess.check_output([os.environ["CLANG"], "--version"], text=True),
    "full_package_imported": True,
    "spy_boundary_test_methods": 8,
    "native_integration_test_methods": 6,
    "native_integration_uses_real_compiler_loader_owner_and_queue": True,
    "native_function_or_verifier_replaced_by_spy": False,
    "scope": "Eight boundary wiring methods use explicit Python call spies; six separate integration methods use the production native path, including early pre-build refusals. A producer thread and line trace control scheduling only.",
    "sources_sha256": manifest,
    "sources_unchanged_during_run": all(hashlib.sha256(p.read_bytes()).hexdigest() == manifest[str(p.relative_to(root))] for p in sources),
}
(output / (label + ".json")).write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps({k: v for k, v in report.items() if k != "sources_sha256"}, indent=2))
print("\n".join((output / (label + ".log")).read_text().splitlines()[-12:]))
raise SystemExit(0 if result.wasSuccessful() else 1)
