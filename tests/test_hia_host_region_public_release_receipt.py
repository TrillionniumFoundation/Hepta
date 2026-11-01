"""P7 public loan-release receipt faults must fence a completed host generation.

Native Clang C execution after a witnessed recovery is real; the before/after
receipt exceptions are deliberately injected in-process, not a power-loss test.
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
    NativeRegionLibrary, TrustedRegionContract
)

path, digest, stage = sys.argv[1:]
region = HostRegion(7, max_leases=2, max_native_calls=2)
library = NativeRegionLibrary(
    path, digest, TrustedRegionContract((("region_fill", "write"),), True)
)
lease = region.borrow("write", generation=0)
lease.write(b"abcdefg")
original_event = region._event
injected = []

def interrupted_release(kind, **fields):
    if kind == "released" and not injected:
        injected.append(kind)
        if stage == "post_event":
            original_event(kind, **fields)
        raise RuntimeError("controlled public lease release receipt loss")
    return original_event(kind, **fields)

with patch.object(region, "_event", side_effect=interrupted_release):
    try:
        lease.close()
    except BaseException as error:
        failure = error
    else:
        raise AssertionError("public release receipt fault returned success")

assert injected == ["released"], injected
assert isinstance(failure, HostRegionUncertain), (
    "public release lost receipt without normalized uncertainty: " + repr(failure)
)
state = region.snapshot()
assert state["state"] == "quarantined", state
assert state["generation"] > 0, state
assert state["write_leases"] == state["read_leases"] == state["native_jobs"] == 0, state
assert state["observed_mapping_permissions"] == "---s", state
assert any(e["kind"] == "quarantined" for e in state["events"]), state

# An unreceipted release must never leave the old epoch able to run C.
try:
    region.call(library, "region_fill", generation=state["generation"], argument=13)
except HostRegionRejected:
    pass
else:
    raise AssertionError("public release receipt failure admitted new native execution")
assert library.snapshot()["active_calls"] == 0, library.snapshot()

recovered = region.recover(timeout=2)
assert recovered["state"] == "ready" and recovered["generation"] > state["generation"], recovered
with region.borrow("read", generation=recovered["generation"]) as loan:
    assert loan.read() == bytes(7), loan.read()
assert region.call(
    library, "region_fill", generation=recovered["generation"], argument=13
) == sum(range(13, 20))
assert library.snapshot()["active_calls"] == 0
assert region.snapshot()["observed_mapping_permissions"] == "---s"
region.close()
library.close()
print("PASS public release receipt fault fences and recovers actual Clang C", stage)
'''


class PublicReleaseReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
            raise AssertionError("actual Linux x86-64 host required; no silent skip")
        compiler = shutil.which(os.environ.get("HEPTA_TEST_CLANG", "clang"))
        if not compiler:
            raise AssertionError("actual Clang required; no silent skip")
        cls.temp = tempfile.TemporaryDirectory()
        cls.path, cls.digest = build_fixture(Path(cls.temp.name), Path(compiler).resolve(), {})

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def _probe(self, stage):
        outcome = subprocess.run(
            [sys.executable, "-B", "-c", PROBE, str(self.path), self.digest, stage],
            capture_output=True, text=True, timeout=25, check=False,
        )
        self.assertEqual(
            outcome.returncode, 0,
            f"stage={stage} stdout={outcome.stdout}\nstderr={outcome.stderr}",
        )
        self.assertIn("PASS public release receipt", outcome.stdout)

    def test_public_lease_release_receipt_fails_before_append(self):
        self._probe("pre_event")

    def test_public_lease_release_receipt_fails_after_append(self):
        self._probe("post_event")


if __name__ == "__main__":
    unittest.main()
