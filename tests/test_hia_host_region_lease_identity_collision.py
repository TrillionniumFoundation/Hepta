"""Fail-closed lease identity admission on real Linux memfd and Clang native C.

These controls deliberately force an entropy-source duplicate or malformed
result. A second lease must never overwrite the first owner's registered
capability or hide a native reader. They are adversarial fault injections, not
a claim that the platform secrets API normally generates duplicate tokens.
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
    HostRegion, HostRegionRejected, NativeRegionLibrary, TrustedRegionContract
)

path, digest, scenario = sys.argv[1:]
region = HostRegion(7, max_leases=3, max_native_calls=2)
library = NativeRegionLibrary(
    path, digest,
    TrustedRegionContract((("region_fill", "write"), ("region_sum", "read")), True)
)

def expect_rejection(operation):
    try:
        operation()
    except HostRegionRejected as error:
        assert "lease identity" in str(error), repr(error)
    else:
        raise AssertionError("a repeated or malformed lease identity was admitted")

if scenario in {"duplicate-public", "duplicate-native"}:
    anchor = region.borrow("read", generation=0)
    token = anchor._token
    with patch("hepta.hia_host_region.secrets.token_hex", return_value=token):
        if scenario == "duplicate-public":
            expect_rejection(lambda: region.borrow("read", generation=0))
        else:
            expect_rejection(lambda: region.call(
                library, "region_sum", generation=0, argument=0
            ))
    state = region.snapshot()
    assert state["state"] == "ready", state
    assert state["read_leases"] == 1 and state["write_leases"] == 0, state
    assert state["native_jobs"] == 0, state
    assert state["permission"] == "read", state
    assert state["observed_mapping_permissions"] == "r--s", state
    assert anchor.read() == bytes(7)
    assert library.snapshot()["active_calls"] == 0
    anchor.close()
elif scenario == "malformed":
    with patch("hepta.hia_host_region.secrets.token_hex", return_value=None):
        expect_rejection(lambda: region.borrow("read", generation=0))
    state = region.snapshot()
    assert state["state"] == "ready", state
    assert state["read_leases"] == state["write_leases"] == 0, state
    assert state["native_jobs"] == 0, state
    assert state["permission"] == "none", state
    assert state["observed_mapping_permissions"] == "---s", state
else:
    raise AssertionError("unknown lease identity fault scenario")

with region.borrow("write", generation=0) as grant:
    grant.write(b"1234567")
assert region.call(library, "region_fill", generation=0, argument=13) == sum(range(13, 20))
assert region.snapshot()["state"] == "ready"
assert region.snapshot()["observed_mapping_permissions"] == "---s"
region.close()
library.close()
print("PASS duplicate/malformed identity rejected, original grant preserved, real C reentry", scenario)
'''


class LeaseIdentityCollisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
            raise AssertionError("real Linux x86-64 host required; no silent skip")
        compiler = shutil.which(os.environ.get("HEPTA_TEST_CLANG", "clang"))
        if not compiler:
            raise AssertionError("real Clang compiler required; no silent skip")
        cls.temp = tempfile.TemporaryDirectory()
        cls.path, cls.digest = build_fixture(
            Path(cls.temp.name), Path(compiler).resolve(), {}
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def _probe(self, scenario):
        result = subprocess.run(
            [sys.executable, "-B", "-c", PROBE, str(self.path), self.digest, scenario],
            capture_output=True, text=True, timeout=20, check=False
        )
        self.assertEqual(
            result.returncode, 0,
            f"scenario={scenario} stdout={result.stdout}\nstderr={result.stderr}"
        )
        self.assertIn("PASS duplicate/malformed identity rejected", result.stdout)

    def test_second_public_read_cannot_reuse_live_owner_token(self):
        self._probe("duplicate-public")

    def test_native_reader_cannot_replace_live_public_grant(self):
        self._probe("duplicate-native")

    def test_malformed_entropy_result_denied_before_page_access(self):
        self._probe("malformed")


if __name__ == "__main__":
    unittest.main()
