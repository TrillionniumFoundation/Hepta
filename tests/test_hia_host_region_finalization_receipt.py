"""Actual Linux/Clang P7 regression for interrupted native completion receipts.

A joined C worker is NOT a committed HIA result if lease-release, worker-join,
or native-result evidence fails. Preserve ownership, fail closed, and require a
quiescent zeroing recovery before new work. Fault injection targets host receipts,
not the C binary or the kernel. No durable crash recovery claim.
"""
from __future__ import annotations

import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests.hia_host_region_fixture import build_fixture


PROBE = r'''
import sys
from unittest.mock import patch
from hepta.hia_host_region import (
    HostRegion, HostRegionRejected, HostRegionUncertain,
    NativeRegionLibrary, TrustedRegionContract
)

path, digest, failed_kind = sys.argv[1:]
region = HostRegion(7, max_leases=3, max_native_calls=2)
library = NativeRegionLibrary(
    path, digest,
    TrustedRegionContract((("region_fill", "write"),), True)
)
original_event = region._event
injected = []

def faulty_event(kind, **fields):
    if kind == failed_kind and not injected:
        injected.append(kind)
        raise RuntimeError("injected native completion receipt failure: " + kind)
    return original_event(kind, **fields)

with patch.object(region, "_event", side_effect=faulty_event):
    try:
        region.call(library, "region_fill", generation=0, argument=13)
    except HostRegionUncertain:
        pass
    else:
        raise AssertionError("completion receipt failure was wrongly committed")

assert injected == [failed_kind], injected
state = region.snapshot()
assert state["state"] == "quarantined", state
assert state["observed_mapping_permissions"] == "---s", state
try:
    region.call(library, "region_fill", generation=state["generation"], argument=7)
except HostRegionRejected:
    pass
else:
    raise AssertionError("uncommitted native result allowed another C execution")
assert state["live_native_workers"] == 0, state

recovered = region.recover(timeout=2)
assert recovered["state"] == "ready", recovered
assert recovered["native_jobs"] == 0 and recovered["write_leases"] == 0, recovered
assert recovered["observed_mapping_permissions"] == "---s", recovered
assert library.snapshot()["active_calls"] == 0, library.snapshot()
new_gen = recovered["generation"]
with region.borrow("read", generation=new_gen) as lease:
    assert lease.read() == b"\x00" * 7, "recovery must zero possible native changes"
assert region.call(library, "region_fill", generation=new_gen, argument=13) == sum(range(13, 20))
assert region.snapshot()["observed_mapping_permissions"] == "---s"
region.close()
library.close()
print("PASS native receipt fail-closed, quiescent recovery, real C re-entry", failed_kind)
'''


class NativeFinalizeReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
            raise AssertionError("real Linux x86-64 host required; no silent skip")
        compiler = shutil.which(os.environ.get("HEPTA_TEST_CLANG", "clang"))
        if not compiler:
            raise AssertionError("actual Clang required; no silent skip")
        cls.temp = tempfile.TemporaryDirectory()
        cls.path, cls.digest = build_fixture(Path(cls.temp.name), Path(compiler).resolve(), {})

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def _probe(self, kind):
        outcome = subprocess.run(
            [sys.executable, "-B", "-c", PROBE, str(self.path), self.digest, kind],
            capture_output=True, text=True, timeout=25, check=False,
        )
        self.assertEqual(
            outcome.returncode, 0,
            f"receipt={kind} stdout={outcome.stdout}\nstderr={outcome.stderr}",
        )
        self.assertIn("PASS native receipt fail-closed", outcome.stdout)

    def test_lease_release_event_failure_is_recoverable_only_after_quarantine(self):
        self._probe("released")

    def test_worker_join_event_failure_keeps_uncommitted_job_for_recovery(self):
        self._probe("worker_join_confirmed")

    def test_native_result_event_failure_requires_zeroing_before_reuse(self):
        self._probe("native_returned")


if __name__ == "__main__":
    unittest.main()
