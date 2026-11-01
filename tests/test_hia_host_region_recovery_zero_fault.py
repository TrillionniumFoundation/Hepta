"""P7 Linux/Clang regression: recovery zero-copy fault must never leave writable unmanned pages.

A real C worker runs before a native receipt fault initiates quarantine.
We inject two *host memory zeroing* faults, before and after the actual mmap
slice write, and observe Linux /proc permissions. No physical power-loss claim.
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

from tools.qualify_hia_host_region import build_fixture


PROBE = r'''
import sys
from unittest.mock import patch
from hepta.hia_host_region import (
    HostRegion, HostRegionRejected, HostRegionUncertain,
    NativeRegionLibrary, TrustedRegionContract,
)
path, digest, stage = sys.argv[1:]
region = HostRegion(7, max_leases=3, max_native_calls=2)
library = NativeRegionLibrary(path, digest, TrustedRegionContract(
    (("region_fill", "write"),), True
))
original_event = region._event
lost = []

def lose_native_receipt(kind, **fields):
    if kind == "native_returned" and not lost:
        lost.append(kind)
        raise RuntimeError("injected native completion receipt loss")
    return original_event(kind, **fields)

with patch.object(region, "_event", side_effect=lose_native_receipt):
    try:
        region.call(library, "region_fill", generation=0, argument=13)
    except HostRegionUncertain:
        pass
    else:
        raise AssertionError("actual native return receipt loss unexpectedly committed")
assert lost == ["native_returned"]
assert region.snapshot()["state"] == "quarantined"
assert region.snapshot()["observed_mapping_permissions"] == "---s"

class FaultingZeroMemory:
    def __init__(self, actual, stage):
        self.actual = actual
        self.stage = stage
        self.faults = 0
    def __setitem__(self, key, value):
        self.faults += 1
        if self.stage == "post_write":
            self.actual[key] = value
        raise OSError("injected mmap zeroing failure: " + self.stage)
    def __getitem__(self, key):
        return self.actual[key]
    def __getattr__(self, name):
        return getattr(self.actual, name)

real_memory = region._memory
faulting = FaultingZeroMemory(real_memory, stage)
with patch.object(region, "_memory", faulting):
    try:
        region.recover(timeout=2)
    except BaseException as error:
        failure = error
    else:
        raise AssertionError("lost zeroing result unexpectedly accepted")

assert faulting.faults == 1, faulting.faults
state = region.snapshot()
assert isinstance(failure, HostRegionUncertain), (
    "zeroing error leaked raw or was misclassified: " + repr(failure)
)
assert state["state"] == "quarantined", (
    "unconfirmed zeroing exposed reusable state: " + repr(state)
)
assert state["observed_mapping_permissions"] == "---s", (
    "failed recovery leaked unwitnessed writable memfd page: " + repr(state)
)
assert state["native_jobs"] == 0 and state["write_leases"] == 0, state
try:
    region.call(library, "region_fill", generation=state["generation"], argument=7)
except HostRegionRejected:
    pass
else:
    raise AssertionError("native C admitted after zeroing without receipt")

recovered = region.recover(timeout=2)
assert recovered["state"] == "ready", recovered
with region.borrow("read", generation=recovered["generation"]) as lease:
    assert lease.read() == bytes(7), lease.read()
assert region.call(
    library, "region_fill", generation=recovered["generation"], argument=13
) == sum(range(13, 20))
assert region.snapshot()["observed_mapping_permissions"] == "---s"
region.close()
library.close()
print("PASS fenced unreceipted zeroing", stage)
'''


class RecoveryZeroFaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
            raise AssertionError("actual Linux x86-64 required, no skip")
        compiler = shutil.which(os.environ.get("HEPTA_TEST_CLANG", "clang"))
        if not compiler:
            raise AssertionError("real Clang required, no skip")
        cls.temp = tempfile.TemporaryDirectory()
        cls.path, cls.digest = build_fixture(
            Path(cls.temp.name), Path(compiler).resolve(), {}
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def _probe(self, stage):
        result = subprocess.run(
            [sys.executable, "-B", "-c", PROBE, str(self.path), self.digest, stage],
            capture_output=True, text=True, timeout=25, check=False,
        )
        self.assertEqual(
            result.returncode, 0,
            f"stage={stage} stdout={result.stdout}\nstderr={result.stderr}",
        )
        self.assertIn("PASS fenced unreceipted zeroing", result.stdout)

    def test_failure_before_mmap_zeroing(self):
        self._probe("pre_write")

    def test_failure_after_mmap_zeroing(self):
        self._probe("post_write")


if __name__ == "__main__":
    unittest.main()
