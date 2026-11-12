"""P7 prestart cleanup receipt faults must not leak an unowned native library pin.

A real Linux memfd + Clang C worker is exercised after recovery. Injected
host receipt errors before/after append are not physical power-loss tests.
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
    HostRegion, HostRegionUncertain, NativeRegionLibrary, TrustedRegionContract
)

path, digest, stage = sys.argv[1:]
region = HostRegion(7, max_leases=2, max_native_calls=2)
library = NativeRegionLibrary(
    path, digest, TrustedRegionContract((("region_fill", "write"),), True)
)
original_event = region._event
injected = []

def interrupted_release(kind, **fields):
    if kind == "released" and not injected:
        injected.append(kind)
        if stage == "post_event":
            original_event(kind, **fields)
        raise RuntimeError("controlled prestart lease release receipt loss")
    return original_event(kind, **fields)

# The first minted value is the lease; the second (the native job ID)
# is deliberately malformed. No Thread object can have been started.
with patch("hepta.hia_host_region.secrets.token_hex", side_effect=["f" * 32, None]):
    with patch.object(region, "_event", side_effect=interrupted_release):
        try:
            region.call(library, "region_fill", generation=0, argument=13)
        except BaseException as error:
            failure = error
        else:
            raise AssertionError("malformed native job was admitted")
assert injected == ["released"], injected
assert isinstance(failure, HostRegionUncertain), (
    "prestart release lost a receipt without normalized uncertainty: "
    + repr(failure)
)
state = region.snapshot()
assert state["state"] == "quarantined", state
assert state["native_jobs"] == state["write_leases"] == state["read_leases"] == 0, state
assert state["observed_mapping_permissions"] == "---s", state
assert library.snapshot()["active_calls"] == 0, (
    "prestart library pin leaked after lease retirement receipt failure",
    library.snapshot()
)
assert any(e["kind"] == "quarantined" for e in state["events"]), state

# The release fault was process-local. A fresh, witnessed zero/recovery is
# required, after which the actual Clang-built C entry must still execute.
receipt = region.recover(timeout=2)
assert receipt["state"] == "ready" and receipt["generation"] > 0, receipt
with region.borrow("read", generation=receipt["generation"]) as loan:
    assert loan.read() == bytes(7), loan.read()
result = region.call(
    library, "region_fill", generation=receipt["generation"], argument=13
)
assert result == sum(range(13, 20)), result
assert region.snapshot()["observed_mapping_permissions"] == "---s"
assert library.snapshot()["active_calls"] == 0
region.close()
library.close()
print("PASS prestart receipt fault balances native code owner", stage)
'''

class PrestartRetirementReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
            raise AssertionError("actual Linux x86-64 host required; no silent skip")
        compiler = shutil.which(os.environ.get("HEPTA_TEST_CLANG", "clang"))
        if not compiler:
            raise AssertionError("real Clang required; no silent skip")
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
            capture_output=True, text=True, timeout=20, check=False,
        )
        self.assertEqual(
            result.returncode, 0,
            f"stage={stage} stdout={result.stdout}\nstderr={result.stderr}",
        )
        self.assertIn("PASS prestart receipt fault", result.stdout)

    def test_failed_release_receipt_before_event_append(self):
        self._probe("pre_event")

    def test_failed_release_receipt_after_event_append(self):
        self._probe("post_event")

if __name__ == "__main__":
    unittest.main()
