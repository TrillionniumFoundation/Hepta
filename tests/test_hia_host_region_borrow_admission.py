"""Real Linux memfd/Clang probes: failed lease token must not expose unowned writable pages.

A token-generation failure before a lease is registered cannot authorize any
page-access transition. Covers public host borrowing and internal native call
admission on the unmodified parent source for a reproducible RED baseline.
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

from hepta.hia_host_region import HostRegion, NativeRegionLibrary, TrustedRegionContract

path, digest, scenario = sys.argv[1:]
region = HostRegion(7, max_leases=2, max_native_calls=2)
library = NativeRegionLibrary(path, digest, TrustedRegionContract((("region_fill", "write"),), True))

with patch("hepta.hia_host_region.secrets.token_hex",
           side_effect=RuntimeError("lease identity generation refused")):
    try:
        if scenario == "external":
            region.borrow("write", generation=0)
        elif scenario == "native":
            region.call(library, "region_fill", generation=0, argument=13)
        else:
            raise AssertionError("unknown fault scenario")
    except RuntimeError as exc:
        assert str(exc) == "lease identity generation refused", repr(exc)
    else:
        raise AssertionError("injected lease identity generation did not fail")

state = region.snapshot()
assert state["state"] == "ready", state
assert state["read_leases"] == state["write_leases"] == state["native_jobs"] == 0, state
assert state["permission"] == "none", state
assert state["observed_mapping_permissions"] == "---s", state
assert library.snapshot()["active_calls"] == 0, library.snapshot()

if scenario == "external":
    with region.borrow("write", generation=0) as grant:
        grant.write(b"1234567")
assert region.call(library, "region_fill", generation=0, argument=13) == sum(range(13, 20))
assert region.snapshot()["state"] == "ready"
region.close()
library.close()
print("PASS no unowned writable mapping and exact C reentry", scenario)
'''


class BorrowAdmissionTokenFailureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
            raise AssertionError("actual Linux x86-64 required; no silent skip")
        compiler = shutil.which(os.environ.get("HEPTA_TEST_CLANG", "clang"))
        if not compiler:
            raise AssertionError("actual Clang required; no silent skip")
        cls.temp = tempfile.TemporaryDirectory()
        cls.path, cls.digest = build_fixture(
            Path(cls.temp.name), Path(compiler).resolve(), {}
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def _check(self, scenario):
        result = subprocess.run(
            [sys.executable, "-B", "-c", PROBE, str(self.path), self.digest, scenario],
            capture_output=True, text=True, timeout=15, check=False,
        )
        self.assertEqual(result.returncode, 0,
                         f"scenario={scenario} stdout={result.stdout} stderr={result.stderr}")
        self.assertIn("PASS no unowned writable mapping", result.stdout)

    def test_public_write_borrow_token_failure_keeps_pages_inaccessible(self):
        self._check("external")

    def test_native_call_lease_token_failure_keeps_pages_inaccessible(self):
        self._check("native")


if __name__ == "__main__":
    unittest.main()
