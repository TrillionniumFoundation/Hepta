"""P7 fail-closed admission: failures before Thread construction must retire grants.

These are actual Linux memfd/Clang C-ABI probes, not a production recovery
certificate. A *started* worker whose start() later raises is separately tested
by test_hia_host_region and must remain permanently quarantined.
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
import secrets
import sys
from unittest.mock import patch

from hepta.hia_host_region import HostRegion, NativeRegionLibrary, TrustedRegionContract

path, digest, scenario = sys.argv[1:]
region = HostRegion(7, max_leases=2, max_native_calls=2)
library = NativeRegionLibrary(path, digest, TrustedRegionContract((("region_fill", "write"),), True))

if scenario == "constructor":
    # Thread object did not exist: no native work can have been scheduled.
    with patch("hepta.hia_host_region.threading.Thread",
               side_effect=RuntimeError("prestart constructor refused")):
        try:
            region.call(library, "region_fill", generation=0, argument=13)
        except RuntimeError as exc:
            assert str(exc) == "prestart constructor refused", repr(exc)
        else:
            raise AssertionError("injected native worker constructor did not fail")
elif scenario == "job-token":
    # RegionLease.__init__ receives token 1; job scheduling token 2 fails
    # before construction/start of any native worker.
    genuine = secrets.token_hex
    seen = []
    def token(n):
        seen.append(n)
        if len(seen) == 2:
            raise RuntimeError("prestart job token refused")
        return genuine(n)
    with patch("hepta.hia_host_region.secrets.token_hex", side_effect=token):
        try:
            region.call(library, "region_fill", generation=0, argument=13)
        except RuntimeError as exc:
            assert str(exc) == "prestart job token refused", repr(exc)
        else:
            raise AssertionError("injected job token generation did not fail")
    assert len(seen) == 2, seen
else:
    raise AssertionError("unknown scenario")

state = region.snapshot()
assert state["state"] == "ready", state
assert state["read_leases"] == state["write_leases"] == state["native_jobs"] == 0, state
assert state["observed_mapping_permissions"] == "---s", state
assert library.snapshot()["active_calls"] == 0, library.snapshot()
assert region.call(library, "region_fill", generation=0, argument=13) == sum(range(13, 20))
assert region.snapshot()["state"] == "ready"
region.close()
library.close()
print("PASS exact native C reuse after prestart failure", scenario)
'''


class PrestartAdmissionRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
            raise AssertionError("real native Linux x86-64 required; no silent skip")
        compiler = shutil.which(os.environ.get("HEPTA_TEST_CLANG", "clang"))
        if not compiler:
            raise AssertionError("real Clang binary required; no silent skip")
        cls.temp = tempfile.TemporaryDirectory()
        cls.library_path, cls.digest = build_fixture(
            Path(cls.temp.name), Path(compiler).resolve(), {}
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def _probe(self, scenario):
        outcome = subprocess.run(
            [sys.executable, "-B", "-c", PROBE, str(self.library_path),
             self.digest, scenario],
            capture_output=True, text=True, timeout=15, check=False
        )
        self.assertEqual(
            outcome.returncode, 0,
            f"scenario={scenario} stdout={outcome.stdout}\nstderr={outcome.stderr}"
        )
        self.assertIn("PASS exact native C reuse", outcome.stdout)

    def test_prestart_thread_constructor_failure_retires_unstarted_grant(self):
        self._probe("constructor")

    def test_prestart_job_token_failure_retires_unstarted_grant(self):
        self._probe("job-token")


if __name__ == "__main__":
    unittest.main()
