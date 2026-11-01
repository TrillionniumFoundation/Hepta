"""Real Linux/Clang regression: a failed P7 recovery receipt must never open an epoch.

The native C worker actually runs. Its completion receipt is deliberately
interrupted to enter quarantine; recovery's final audit receipt then fails
before or after event append. These are host receipt faults, not power loss,
and they do not qualify durable recovery or arbitrary FFI.
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
library = NativeRegionLibrary(
    path, digest, TrustedRegionContract((("region_fill", "write"),), True)
)
original_event = region._event
failed_native = []

def lose_native_receipt(kind, **fields):
    if kind == "native_returned" and not failed_native:
        failed_native.append(kind)
        raise RuntimeError("injected native result receipt failure")
    return original_event(kind, **fields)

with patch.object(region, "_event", side_effect=lose_native_receipt):
    try:
        region.call(library, "region_fill", generation=0, argument=13)
    except HostRegionUncertain:
        pass
    else:
        raise AssertionError("missing native receipt incorrectly committed")

assert failed_native == ["native_returned"], failed_native
assert region.snapshot()["state"] == "quarantined"
failed_recovery = []

def lose_recovery_receipt(kind, **fields):
    if kind == "recovered_zeroed" and not failed_recovery:
        failed_recovery.append(kind)
        if stage == "after_append":
            original_event(kind, **fields)
        raise RuntimeError("injected recovery receipt failure " + stage)
    return original_event(kind, **fields)

with patch.object(region, "_event", side_effect=lose_recovery_receipt):
    try:
        region.recover(timeout=2)
    except BaseException as error:
        observed_error = error
    else:
        raise AssertionError("recovery returned despite lost receipt")

assert failed_recovery == ["recovered_zeroed"], failed_recovery
state = region.snapshot()
assert state["state"] == "quarantined", (
    "lost recovery audit receipt exposed reusable epoch: " + repr(state)
)
assert isinstance(observed_error, HostRegionUncertain), (
    "lost recovery receipt emitted non-uncertain exception: " + repr(observed_error)
)
assert state["observed_mapping_permissions"] == "---s", state
assert state["native_jobs"] == 0 and state["write_leases"] == 0, state
try:
    region.call(library, "region_fill", generation=state["generation"], argument=7)
except HostRegionRejected:
    pass
else:
    raise AssertionError("unreceipted recovery admitted another real native C call")

recovered = region.recover(timeout=2)
assert recovered["state"] == "ready", recovered
assert recovered["observed_mapping_permissions"] == "---s", recovered
assert recovered["native_jobs"] == 0 and recovered["write_leases"] == 0, recovered
assert library.snapshot()["active_calls"] == 0
generation = recovered["generation"]
with region.borrow("read", generation=generation) as lease:
    assert lease.read() == b"\\x00" * 7, "native-mutated memory not zeroed"
assert region.call(library, "region_fill", generation=generation, argument=13) == sum(range(13, 20))
assert region.snapshot()["observed_mapping_permissions"] == "---s"
region.close()
library.close()
print("PASS native receipt recovery refuses unreceipted epoch", stage)
'''


class RecoveryReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
            raise AssertionError("actual Linux x86-64 host required; no skip")
        compiler = shutil.which(os.environ.get("HEPTA_TEST_CLANG", "clang"))
        if not compiler:
            raise AssertionError("real Clang is required; no skip")
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
            f"stage={stage} stdout={result.stdout}\\nstderr={result.stderr}",
        )
        self.assertIn("PASS native receipt recovery refuses", result.stdout)

    def test_recovery_event_fails_before_append(self):
        self._probe("before_append")

    def test_recovery_event_fails_after_append(self):
        self._probe("after_append")


if __name__ == "__main__":
    unittest.main()
