"""Linux memfd/Clang regression: post-grant bookkeeping failures are atomic.

The original #531 source mprotects the mapping, then registers a lease and
records a borrowed event without rollback on an exception. A failed registry
write or audit event must not strand an inaccessible capability and writable
kernel pages. Injection is limited to the Python bookkeeping boundary; page
permissions and the subsequent C call are observed on a real Linux host.
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
from hepta.hia_host_region import HostRegion, NativeRegionLibrary, TrustedRegionContract

path, digest, scenario = sys.argv[1:]
region = HostRegion(7, max_leases=3, max_native_calls=2)
library = NativeRegionLibrary(path, digest, TrustedRegionContract((("region_fill", "write"),), True))

class RefusingGrants(dict):
    def __setitem__(self, key, value):
        raise RuntimeError("owner grant registration refused")

def operation():
    if scenario.startswith("native"):
        region.call(library, "region_fill", generation=0, argument=13)
    else:
        region.borrow("write", generation=0)

if scenario == "read-peer-event":
    anchor = region.borrow("read", generation=0)
    with patch.object(region, "_event", side_effect=RuntimeError("borrow receipt refused")):
        try:
            region.borrow("read", generation=0)
        except RuntimeError as error:
            assert str(error) == "borrow receipt refused", repr(error)
        else:
            raise AssertionError("audit receipt fault was not injected")
    state = region.snapshot()
    assert state["state"] == "ready", state
    assert state["read_leases"] == 1 and state["write_leases"] == 0, state
    assert state["permission"] == "read" and state["observed_mapping_permissions"] == "r--s", state
    anchor.close()
elif scenario.endswith("-registry"):
    original = region._lease_grants
    region._lease_grants = RefusingGrants(original)
    try:
        operation()
    except RuntimeError as error:
        assert str(error) == "owner grant registration refused", repr(error)
    else:
        raise AssertionError("registry fault was not injected")
    finally:
        region._lease_grants = dict(region._lease_grants)
elif scenario.endswith("-event"):
    with patch.object(region, "_event", side_effect=RuntimeError("borrow receipt refused")):
        try:
            operation()
        except RuntimeError as error:
            assert str(error) == "borrow receipt refused", repr(error)
        else:
            raise AssertionError("audit receipt fault was not injected")
else:
    raise AssertionError("unknown post-grant fault scenario")

state = region.snapshot()
assert state["state"] == "ready", state
assert state["read_leases"] == state["write_leases"] == state["native_jobs"] == 0, state
assert state["permission"] == "none" and state["observed_mapping_permissions"] == "---s", state
assert library.snapshot()["active_calls"] == 0, library.snapshot()
with region.borrow("write", generation=0) as lease:
    lease.write(b"1234567")
assert region.call(library, "region_fill", generation=0, argument=13) == sum(range(13, 20))
region.close()
library.close()
print("PASS atomic admission, no unowned page and subsequent real C call", scenario)
'''


class NativePostGrantAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
            raise AssertionError("real Linux x86-64 host required, not a silent skip")
        compiler = shutil.which(os.environ.get("HEPTA_TEST_CLANG", "clang"))
        if compiler is None:
            raise AssertionError("real Clang compiler required, not a silent skip")
        cls.temp = tempfile.TemporaryDirectory()
        cls.library_path, cls.digest = build_fixture(
            Path(cls.temp.name), Path(compiler).resolve(), {}
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def _probe(self, scenario):
        result = subprocess.run(
            [sys.executable, "-B", "-c", PROBE, str(self.library_path),
             self.digest, scenario],
            capture_output=True, text=True, timeout=20, check=False,
        )
        self.assertEqual(result.returncode, 0,
                         f"scenario={scenario} stdout={result.stdout}\nstderr={result.stderr}")
        self.assertIn("PASS atomic admission", result.stdout)

    def test_external_registry_failure_reverts_page_permissions(self):
        self._probe("external-registry")

    def test_native_registry_failure_reverts_page_permissions(self):
        self._probe("native-registry")

    def test_external_event_failure_retires_unreturned_lease(self):
        self._probe("external-event")

    def test_native_event_failure_retires_unreturned_lease(self):
        self._probe("native-event")

    def test_shared_reader_event_failure_retains_only_original_read_grant(self):
        self._probe("read-peer-event")


if __name__ == "__main__":
    unittest.main()
