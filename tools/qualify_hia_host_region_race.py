"""Actual native readers and competing recovery with a delayed old caller.

This is a bounded Linux x86_64 hosted-memory schedule, not a general concurrent
language proof, device/DMA experiment, or process-crash recovery guarantee.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import threading
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_host_region import (HostRegion, HostRegionRejected, HostRegionUncertain,
                                  NativeRegionLibrary, TrustedRegionContract, retained_host_regions)
from tools.qualify_hia_host_region import build_fixture, ENTRIES, bindings as base_bindings
from tools.qualify_hia_native_ndu import file_identity, run_command, source_state, wire

GATES = tuple((name, "read") for name in
              ("region_gate_arm", "region_gate_count", "region_gate_release", "region_gate_sum"))


def bindings():
    rows = base_bindings()
    rows[str(Path(__file__).relative_to(ROOT))] = file_identity(__file__)["sha256"]
    return rows


def exercise(path, digest):
    library = NativeRegionLibrary(path, digest, TrustedRegionContract(ENTRIES + GATES, True))
    region, control = HostRegion(4096), HostRegion(1)
    parked, release_old = threading.Event(), threading.Event()
    old_results, recoveries, denials = [], [], []
    original_join = threading.Thread.join
    old = None

    def denied(label, action):
        try:
            action()
        except (HostRegionRejected, HostRegionUncertain) as error:
            denials.append({"case": label, "type": type(error).__name__, "message": str(error)})
        else:
            raise AssertionError("expected denial: " + label)

    def delay_old_caller(thread, *args, **kwargs):
        result = original_join(thread, *args, **kwargs)
        if threading.current_thread().name == "hia-race-outer-caller" and not thread.is_alive():
            parked.set()
            if not release_old.wait(5):
                raise RuntimeError("old caller scheduling rendezvous expired")
        return result

    def caller():
        try:
            value = region.call(library, "region_gate_sum", generation=0, timeout=3)
            old_results.append({"status": "committed", "value": value})
        except BaseException as error:
            old_results.append({"status": "denied", "type": type(error).__name__, "message": str(error)})

    try:
        expected = bytes((17+i) % 256 for i in range(4096))
        assert region.call(library, "region_fill", generation=0, argument=17) == sum(expected)
        control.call(library, "region_gate_arm", generation=0)
        with patch.object(threading.Thread, "join", delay_old_caller):
            old = threading.Thread(target=caller, name="hia-race-outer-caller")
            old.start()
            deadline = time.monotonic() + 2
            while control.call(library, "region_gate_count", generation=0) < 1:
                if time.monotonic() > deadline:
                    raise RuntimeError("native first reader did not enter")
            denied("second_reader_timeout", lambda: region.call(library, "region_gate_sum", generation=0, timeout=.002))
            native_count = control.call(library, "region_gate_count", generation=0)
            assert native_count == 2
            blocked = region.snapshot()
            assert blocked["state"] == "quarantined" and blocked["live_native_workers"] == 2
            denied("recover_while_two_native_readers_live", lambda: region.recover(timeout=0))
            denied("unmap_while_native_readers_live", region.close)
            denied("unload_while_native_readers_live", library.close)
            control.call(library, "region_gate_release", generation=0)
            assert parked.wait(2)
            start = threading.Barrier(3)

            def recoverer():
                start.wait(timeout=2)
                try:
                    receipt = region.recover(timeout=2)
                    recoveries.append({"status": "committed", "receipt": receipt})
                except HostRegionRejected as error:
                    recoveries.append({"status": "denied", "message": str(error)})
                except BaseException as error:
                    recoveries.append({"status": "error", "type": type(error).__name__, "message": str(error)})

            threads = [threading.Thread(target=recoverer) for _ in range(2)]
            for thread in threads:
                thread.start()
            start.wait(timeout=2)
            for thread in threads:
                thread.join(3)
                assert not thread.is_alive()
            assert sorted(row["status"] for row in recoveries) == ["committed", "denied"]
            recovered = region.snapshot()
            assert recovered["state"] == "ready" and recovered["native_jobs"] == 0
            assert recovered["read_leases"] == recovered["write_leases"] == 0
            generation = recovered["generation"]
            with region.borrow("read", generation=generation) as lease:
                assert lease.read() == bytes(4096)
            denied("old_generation_after_winning_recovery", lambda: region.borrow("read", generation=0))
            # Publish a new valid result before allowing the old caller to finish.
            fresh = bytes((31+i) % 256 for i in range(4096))
            assert region.call(library, "region_fill", generation=generation, argument=31) == sum(fresh)
            release_old.set(); old.join(3)
            assert not old.is_alive()
            assert len(old_results) == 1 and old_results[0]["type"] == "HostRegionUncertain"
            after = region.snapshot()
            assert after["state"] == "ready" and after["generation"] == generation
            with region.borrow("read", generation=generation) as lease:
                assert lease.read() == fresh
        result = {"native_reader_entries": native_count, "quarantined_with_live_readers": blocked,
                  "recoveries": recoveries, "recovered": recovered, "late_caller": old_results,
                  "new_epoch_after_old_caller": after, "denials": denials,
                  "old_caller_cannot_commit_or_revoke_recovered_epoch": True,
                  "all_native_workers_joined": True}
    finally:
        release_old.set()
        try:
            control.call(library, "region_gate_release", generation=0)
        finally:
            if old is not None:
                original_join(old, 6)
            if region.snapshot()["state"] == "quarantined":
                region.recover(timeout=6)
            region.close(); control.close(); library.close()
    result["retained_after"] = retained_host_regions()
    assert not result["retained_after"]["regions"] and not result["retained_after"]["libraries"]
    return result


def run(output, clang):
    output = Path(output).resolve(); output.mkdir(parents=True, exist_ok=False)
    start = time.monotonic_ns()
    report = {"schema": "hepta.hia.host-region-native-race.v1", "status": "running",
              "source_before": source_state(), "bindings_before": bindings(),
              "compiler_before": file_identity(clang),
              "scope": "one native Linux x86_64 hosted-RAM recovery schedule",
              "scheduling_hook": "delay only the outer caller after its actual native Thread.join; native workers, locks, mapping protection and recovery execute unchanged",
              "claims": {"whole_language_concurrency_proved": False, "mmio_dma_supported": False,
                         "all_schedules_exhausted": False, "process_crash_recovery": False}}
    (output / "REGISTRATION.json").write_bytes(wire(report) + b"\n")
    try:
        build_fixture(output, clang, report)
        binary = output / "race-bridge.so"
        run_command([clang, "-O2", "-fPIC", "-shared", "-std=c11", "-pthread",
                     ROOT / "benchmarks/hia_host_region/bridge.c",
                     ROOT / "benchmarks/hia_host_region/concurrency.c", output / "scalars.o", "-o", binary],
                    output, report["build_commands"])
        report["race_artifact"] = file_identity(binary)
        report["execution"] = exercise(binary, report["race_artifact"]["sha256"])
        report["status"] = "completed"
    except BaseException as error:
        report.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
    report["source_after"], report["bindings_after"] = source_state(), bindings()
    report["compiler_after"] = file_identity(clang)
    report["artifact_after"] = file_identity(report["race_artifact"]["path"]) if "race_artifact" in report else None
    report["source_unchanged"] = report["source_before"] == report["source_after"] and report["bindings_before"] == report["bindings_after"]
    report["identities_unchanged"] = report["compiler_before"] == report["compiler_after"] and report.get("race_artifact") == report["artifact_after"]
    report["qualification_valid"] = report["status"] == "completed" and report["source_unchanged"] and report["identities_unchanged"]
    report["whole_lifecycle_wall_ns"] = time.monotonic_ns() - start
    (output / "RESULT.json").write_bytes(wire(report) + b"\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True); parser.add_argument("--clang", required=True)
    args = parser.parse_args()
    result = run(args.output, args.clang)
    print(json.dumps({k: result.get(k) for k in ("status", "qualification_valid", "error", "whole_lifecycle_wall_ns")}))
    return 0 if result["qualification_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
