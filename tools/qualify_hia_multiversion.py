#!/usr/bin/env python3
"""Execute a finite real native scalar-generation lifecycle and retain results."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import errno
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hepta.hia_multiversion import MultiversionRejected, ScalarMultiversionRuntime
from hepta.hia_program import SCHEMA


def program(op, constant):
    parameter = {"name": "x", "type": "u64"}
    return {"schema": SCHEMA, "module": "generation_qualification", "functions": [
        {"name": "calculate", "params": [parameter], "returns": ["u64"], "effects": [],
         "entry": "entry", "blocks": [{"id": "entry", "params": [parameter], "ops": [
             {"op": "const", "args": [], "out": [{"name": "c", "type": "u64"}],
              "attrs": {"value": constant}},
             {"op": op, "args": ["x", "c"], "out": [{"name": "answer", "type": "u64"}], "attrs": {}},
         ], "term": {"op": "ret", "values": ["answer"]}}]}]}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def qualify(clang):
    started = time.perf_counter_ns()
    observations, generations = [], []
    def observe(lease, value, label):
        actual = lease.call("calculate", [value])
        require(type(actual) is int and actual == value, "native identity result differs")
        observations.append({"case": label, "generation": lease.info.generation,
                             "selection_epoch": lease.selection_epoch,
                             "argument": value, "result": actual})
    with tempfile.TemporaryDirectory(prefix="hia-generation-qualification-") as directory:
        with ScalarMultiversionRuntime(program("int.add.wrap", 0), directory, clang=clang) as runtime:
            with runtime.lease() as lease:
                generations.append(lease.info.as_dict())
                for value in (0, 1, 2**63, 2**64 - 1):
                    observe(lease, value, "baseline")
            first = runtime.publish(program("int.mul.wrap", 1))
            generations.append(first.as_dict())
            state = runtime._states[first.generation]
            try:
                os.pwrite(state.fd, b"x", 0)
            except OSError as exc:
                require(exc.errno == errno.EPERM, "write failed for a reason other than kernel sealing")
            else:
                raise RuntimeError("sealed generation accepted an in-place write")
            entered, release = threading.Event(), threading.Event()
            def old_call():
                with runtime.lease() as lease:
                    require(lease.info.generation == first.generation, "wrong prepublication snapshot")
                    observe(lease, 7, "old_before_publication")
                    entered.set()
                    require(release.wait(20), "publication did not release old lease")
                    observe(lease, 11, "old_after_publication")
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(old_call)
                try:
                    require(entered.wait(20), "native caller did not enter old generation")
                    second = runtime.publish(program("bit.or", 0))
                    generations.append(second.as_dict())
                    during = runtime.snapshot()
                    old = next(g for g in during["generations"] if g["generation"] == first.generation)
                    require(old["retired"] and old["active_leases"] == 1, "old generation was not retained")
                    require(state.artifact.is_file(), "old disk artifact reclaimed before lease exit")
                    os.fstat(state.fd)
                    with runtime.lease() as lease:
                        require(lease.info.generation == second.generation, "new lease saw old generation")
                        for value in (0, 3, 2**63, 2**64 - 1):
                            observe(lease, value, "new_generation")
                finally:
                    release.set()
                future.result(timeout=20)
            require(first.generation not in runtime._states, "released generation not retired")
            before_rejection = runtime.snapshot()
            try:
                runtime.publish(program("int.add.wrap", 1))
            except MultiversionRejected as exc:
                rejection = str(exc)
                require("disproved" in rejection, "wrong candidate did not obtain an actual counterexample")
            else:
                raise RuntimeError("behavior-changing candidate was selected")
            after_rejection = runtime.snapshot()
            require(before_rejection["current_generation"] == after_rejection["current_generation"]
                    and before_rejection["selection_epoch"] == after_rejection["selection_epoch"],
                    "failed admission changed current selection")
            runtime.rollback()
            with runtime.lease() as lease:
                require(lease.info.generation == 0, "rollback did not select baseline")
                for value in (0, 13, 2**63, 2**64 - 1):
                    observe(lease, value, "rollback")
            final = runtime.snapshot()
        closed = runtime.snapshot()
        require(not closed["generations"] and closed["closed"], "runtime close leaked generations")
    root = Path(__file__).resolve().parents[1]
    files = ("hepta/hia_multiversion.py", "hepta/hia_translation_validation.py",
             "hepta/hia_program.py", "hepta/hia_program_runtime.py", "hepta/hia_program_llvm.py",
             "tools/qualify_hia_multiversion.py")
    return {"schema": "hepta.hia.scalar-multiversion-qualification.v1",
            "qualified_for_declared_finite_lifecycle": True,
            "observed_utc": datetime.now(timezone.utc).isoformat(),
            "host": {"system": platform.system(), "machine": platform.machine(),
                     "python": sys.version.split()[0]},
            "source_sha256": {name: sha256((root / name).read_bytes()).hexdigest() for name in files},
            "generations": generations, "native_observations": observations,
            "native_probe_calls": sum(g["native_probe_calls"] for g in generations),
            "independent_export_translation_proofs": sum(g["translation_proofs"] for g in generations),
            "rejected_behavior_change": rejection,
            "snapshot_during_old_lease": during, "snapshot_after_rollback": final,
            "snapshot_after_close": closed,
            "wall_ns": time.perf_counter_ns() - started,
            "claims": {"actual_native_execution": True, "kernel_sealed_write_rejected": True,
                       "concurrent_retention_observed": True, "performance_improvement_established": False,
                       "backend_refinement_proved": False, "general_live_patch_qualified": False,
                       "state_layout_migration_qualified": False, "whole_language_soundness_proved": False}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", default=os.environ.get("HEPTA_CLANG", "clang"))
    parser.add_argument("--output", type=Path, help="new JSON receipt path; existing files are never replaced")
    options = parser.parse_args()
    result = qualify(options.clang)
    packed = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if options.output:
        with options.output.open("x", encoding="utf-8") as stream:
            stream.write(packed)
        print(json.dumps({"output": str(options.output), "sha256": sha256(packed.encode()).hexdigest(),
                          "qualified_for_declared_finite_lifecycle": True}, sort_keys=True))
    else:
        print(packed, end="")


if __name__ == "__main__":
    main()
