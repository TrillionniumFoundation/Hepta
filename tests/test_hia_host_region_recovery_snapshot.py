"""Real Linux/Clang P7: no ready epoch without the successful recovery result receipt.

A C worker actually executes before its native completion receipt is injected
as lost. The subsequent recovery has its *final observable snapshot* fail
after the audit event was appended. These are controlled host observation
failures, not physical power-loss or durable exactly-once evidence.
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
    NativeRegionLibrary, TrustedRegionContract,
)

path, digest, stage = sys.argv[1:]
region = HostRegion(7, max_leases=3, max_native_calls=2)
library = NativeRegionLibrary(
    path, digest, TrustedRegionContract((("region_fill", "write"),), True)
)
original_event = region._event
lost_native = []

def break_native_receipt(kind, **fields):
    if kind == "native_returned" and not lost_native:
        lost_native.append(kind)
        raise RuntimeError("injected native result receipt failure")
    return original_event(kind, **fields)

with patch.object(region, "_event", side_effect=break_native_receipt):
    try:
        region.call(library, "region_fill", generation=0, argument=13)
    except HostRegionUncertain:
        pass
    else:
        raise AssertionError("lost actual native result receipt was accepted")

assert lost_native == ["native_returned"], lost_native
assert region.snapshot()["state"] == "quarantined"
assert library.snapshot()["active_calls"] == 0

def observed_snapshot_fails():
    if stage == "maps_unavailable":
        with patch.object(
            region, "_observed_permissions",
            side_effect=OSError("injected /proc/self/maps read failure")
        ):
            region.recover(timeout=2)
    elif stage == "post_observation":
        original_snapshot = region.snapshot
        def fail_after_observation():
            actual = original_snapshot()
            assert actual["observed_mapping_permissions"] == "---s", actual
            raise OSError("injected post-observation snapshot failure")
        with patch.object(region, "snapshot", side_effect=fail_after_observation):
            region.recover(timeout=2)
    else:
        raise AssertionError("unknown fault stage " + stage)

try:
    observed_snapshot_fails()
except BaseException as error:
    failure = error
else:
    raise AssertionError("lost recovery response unexpectedly succeeded")

state = region.snapshot()
assert isinstance(failure, HostRegionUncertain), (
    "recovery snapshot fault was not normalized as uncertain: " + repr(failure)
)
assert state["state"] == "quarantined", (
    "recovery response failed but the owner opened a ready epoch: " + repr(state)
)
assert state["observed_mapping_permissions"] == "---s", state
assert state["native_jobs"] == 0 and state["write_leases"] == 0, state
try:
    region.call(library, "region_fill", generation=state["generation"], argument=7)
except HostRegionRejected:
    pass
else:
    raise AssertionError("no-result recovery allowed new native C execution")

result = region.recover(timeout=2)
assert result["state"] == "ready", result
assert result["reason"] is None, result
assert result["generation"] == region.snapshot()["generation"], result
with region.borrow("read", generation=result["generation"]) as lease:
    assert lease.read() == b"\x00" * 7
assert region.call(library, "region_fill", generation=result["generation"], argument=13) == sum(range(13, 20))
assert region.snapshot()["observed_mapping_permissions"] == "---s"
region.close()
library.close()
print("PASS refused unreceipted recovery result", stage)
'''


class RecoverySnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
            raise AssertionError("actual Linux x86-64 host required; no skip")
        compiler = shutil.which(os.environ.get("HEPTA_TEST_CLANG", "clang"))
        if not compiler:
            raise AssertionError("real Clang required; no skip")
        cls.temp = tempfile.TemporaryDirectory()
        cls.path, cls.digest = build_fixture(
            Path(cls.temp.name), Path(compiler).resolve(), {}
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def _probe(self, stage):
        observed = subprocess.run(
            [sys.executable, "-B", "-c", PROBE, str(self.path), self.digest, stage],
            capture_output=True, text=True, timeout=25, check=False,
        )
        self.assertEqual(
            observed.returncode, 0,
            f"stage={stage} stdout={observed.stdout}\nstderr={observed.stderr}",
        )
        self.assertIn("PASS refused unreceipted recovery result", observed.stdout)

    def test_maps_observation_failure(self):
        self._probe("maps_unavailable")

    def test_snapshot_fails_after_observation(self):
        self._probe("post_observation")


if __name__ == "__main__":
    unittest.main()
