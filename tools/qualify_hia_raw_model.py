#!/usr/bin/env python3
"""Run actual raw-model/DP/NDU differential checks, retaining original streams.

This is correctness/architecture qualification, not a performance campaign.
The declared cost model remains the old finite v2 model, not physical evidence.
"""
from __future__ import annotations

import argparse
import gzip
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--include-stream", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    start = time.monotonic_ns()
    binary = args.binary.resolve(strict=True)
    build = args.build.resolve(strict=True)
    original = {str(p): sha256(p.read_bytes()).hexdigest() for p in (binary, build)}
    tracked = [ROOT / "hepta/hia_ndu_raw_model.py", ROOT / "hepta/hia_ndu_cost.py",
               ROOT / "hepta/hia_ndu.py", ROOT / "hepta/hia_native_differential.py",
               ROOT / "tests/test_hia_ndu_raw_model.py", ROOT / "tests/test_hia_ndu_cost.py", Path(__file__)]
    tracked += list((ROOT / "rust/hia-ndu-raw-model").rglob("*"))
    if args.include_stream:
        tracked += [ROOT / name for name in ("hepta/hia_ndu_raw_session.py", "hepta/hia_ndu_session.py",
                    "tests/test_hia_ndu_raw_session.py")]
    source = {str(p.relative_to(ROOT)): sha256(p.read_bytes()).hexdigest() for p in tracked if p.is_file()}
    transcript = args.output / "native-original.jsonl"
    transcript.touch(exist_ok=False)
    os.environ.update(HEPTA_RAW_MODEL_BRIDGE=str(binary), HEPTA_RAW_MODEL_BUILD=str(build),
                      HEPTA_RAW_MODEL_TRANSCRIPT=str(transcript))
    from tests import test_hia_ndu_raw_model as tests
    suite = unittest.defaultTestLoader.loadTestsFromModule(tests)
    if args.include_stream:
        from tests import test_hia_ndu_raw_session as stream_tests
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(stream_tests))
    with (args.output / "unittest.log").open("x") as log:
        result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    unchanged = original == {str(p): sha256(p.read_bytes()).hexdigest() for p in (binary, build)}
    unchanged = unchanged and all(sha256((ROOT / path).read_bytes()).hexdigest() == value for path, value in source.items())
    raw = transcript.read_bytes()
    compressed = gzip.compress(raw, mtime=0)
    (args.output / "native-original.jsonl.gz").write_bytes(compressed)
    registered_count = 22 if args.include_stream else 11
    complete = result.testsRun == registered_count and tests.RANDOM_MODELS_COMPLETED == list(range(128))
    report = {"schema": "hepta.hia.ndu.raw-model.qualification.v1", "status": "passed" if result.wasSuccessful() and not result.skipped and unchanged and complete else "failed",
              "tests": result.testsRun, "failures": len(result.failures), "errors": len(result.errors), "skipped": len(result.skipped),
              "native_calls": len(tests.OBSERVATIONS), "native_rejections": sum(o["returncode"] != 0 for o in tests.OBSERVATIONS),
              "registered_random_models": 128, "completed_random_model_ids": tests.RANDOM_MODELS_COMPLETED,
              "registered_test_count": registered_count, "stream_included": args.include_stream,
              "native_call_count_scope": "original one-shot transcript; stream controls are separately named in unittest.log",
              "complete_registered_scope": complete,
              "fixed_seed": 86028121, "inputs_unchanged": unchanged,
              "source_files": source, "binary_and_build": original,
              "native_original": {"file": "native-original.jsonl.gz", "uncompressed_bytes": len(raw),
                  "uncompressed_sha256": sha256(raw).hexdigest(), "compressed_sha256": sha256(compressed).hexdigest()},
              "wall_ns": time.monotonic_ns() - start, "performance_advantage_established": False,
              "scope": "full-cost-v2 bounded recurrence and witness semantics; exact DP and unchanged original NDU; no program execution",
              "authority": "DENY_ALL", "safety_certificate": False, "production_activation_allowed": False}
    (args.output / "qualification.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: report[k] for k in ("status", "tests", "failures", "errors", "skipped", "native_calls", "native_rejections", "inputs_unchanged")}, indent=2))
    raise SystemExit(0 if report["status"] == "passed" else 1)


if __name__ == "__main__":
    main()
