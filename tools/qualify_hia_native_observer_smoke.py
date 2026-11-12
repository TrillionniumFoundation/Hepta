#!/usr/bin/env python3
"""Retain reproducible *C echo*, not HIA/NDU, native-process measurements.

Run this scoped demonstration only on Linux with a genuine GCC executable.
The actual binary, compiler identity, raw trial samples, registered expectations
and cost verdict are retained as distinct hashed files. DENY_ALL throughout.
"""
from __future__ import annotations

import argparse
import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.hia_native_process_observer import (
    ARMS, COST_KEYS, SCHEMA, observe,
)

SOURCE = """#include <stdio.h>
int main(void) {
    unsigned char buffer[4096];
    size_t got;
    while ((got = fread(buffer, 1, sizeof buffer, stdin)) != 0) {
        if (fwrite(buffer, 1, got, stdout) != got) return 11;
    }
    return ferror(stdin) || ferror(stdout);
}
"""


def _digest(value):
    return sha256(value).hexdigest()


def _json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def _put(path, content):
    with path.open("xb") as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())


def smoke(output):
    if sys.platform != "linux":
        raise RuntimeError("Linux is required")
    compiler = shutil.which("gcc")
    if compiler is None:
        raise RuntimeError("real GCC is required; no compiler fallback")
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    source = output / "observed_c11_source.c"
    source_bytes = SOURCE.encode()
    _put(source, source_bytes)
    compiler_path = Path(compiler).resolve(strict=True)
    compiler_digest = _digest(compiler_path.read_bytes())
    profiles = ("-O0", "-O2", "-O0", "-O2")
    arms = []
    for name, profile in zip(ARMS, profiles):
        binary = output / (name + ".elf")
        command = [str(compiler_path), "-std=c11", profile, str(source), "-o", str(binary)]
        began = time.monotonic_ns()
        subprocess.run(command, capture_output=True, check=True, timeout=60)
        build_ns = max(1, time.monotonic_ns() - began)
        costs = {key: 0 for key in COST_KEYS}
        costs["candidate_build"] = build_ns
        arms.append({"strategy": name, "binary_path": str(binary.resolve()),
                     "binary_digest": _digest(binary.read_bytes()),
                     "core_digest": _digest(source_bytes),
                     "toolchain_digest": compiler_digest, "argv": [],
                     "one_time_ns": costs,
                     "unknown_costs": ["external_controller_cost",
                                       "external_proof_cost", "human_work"]})

    trials = []
    for index in range(8):
        payload = ("observed-trial-%02d\n" % index).encode()
        trials.append({"id": "task%02d" % index,
                       "stdin_base64": base64.b64encode(payload).decode(),
                       "input_digest": _digest(payload),
                       "expected_result_digest": _digest(payload)})
    registration = {"schema": SCHEMA, "source_digest": _digest(source_bytes),
                    "objective_digest": _digest(b"c11-echo-identity-not-ndu"),
                    "hardware_digest": _digest(platform.platform().encode()),
                    "workload_digest": _digest(_json_bytes(trials)),
                    "candidate_bank_digest": _digest(_json_bytes(profiles)),
                    "generation": 1, "trials": trials, "arms": arms,
                    "repetitions": 8, "timeout_ms": 1000,
                    "max_output_bytes": 4096,
                    "minimum_gain_ppm": 10000, "minimum_gain_ns": 1000000,
                    "maximum_peak_rss_bytes": 1 << 39,
                    "maximum_p99_ns": 2_000_000_000}
    raw = _json_bytes(registration)
    _put(output / "registration.json", raw)
    result = observe(raw)
    report = _json_bytes(result)
    _put(output / "observations.json", report)
    if not result["complete"] or result["authority"] != "DENY_ALL":
        raise RuntimeError("negative native execution; raw report has been retained")
    verdict = result["full_cost_verdict"]
    if verdict["economic_scope_positive"] or verdict["production_activation_allowed"]:
        raise RuntimeError("C-only fixture must not qualify NDU or production")
    if sum(len(samples) for strategy in result["raw_samples"].values()
           for samples in strategy.values()) != 8 * 8 * 4:
        raise RuntimeError("missing native execution observations")
    tracked = sorted(path for path in output.iterdir() if path.is_file())
    manifest = {"schema": "hepta.hia.native-observer-evidence.v1",
                "profile": "real-c11-echo-no-hia-no-ndu",
                "observer_claims": result["claims"],
                "authority": "DENY_ALL",
                "production_activation_allowed": False,
                "files": {path.name: {"bytes": path.stat().st_size,
                                      "sha256": _digest(path.read_bytes())}
                          for path in tracked}}
    _put(output / "EVIDENCE_MANIFEST.json", _json_bytes(manifest))
    return {"complete": True, "raw_process_samples": 256,
            "verdict_positive": False, "directory": str(output),
            "manifest_sha256": _digest((output / "EVIDENCE_MANIFEST.json").read_bytes())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(smoke(args.output_dir), sort_keys=True))
        return 0
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as exc:
        print("E_HIA_NATIVE_SMOKE: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
