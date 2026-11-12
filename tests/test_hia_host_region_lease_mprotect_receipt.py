"""P7 losing the final page-revocation receipt on public lease close must fence the owner.

A genuine Linux memfd/Clang C worker completes first. The new faults are
controlled Python host observation failures before/after mprotect, not natural
kernel mprotect failures or power-loss recovery evidence.
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
region = HostRegion(7, max_leases=2, max_native_calls=2)
library = NativeRegionLibrary(
    path, digest, TrustedRegionContract((("region_fill", "write"),), True)
)

# An actual reviewed C worker has completed and released its code reference.
assert region.call(
    library, "region_fill", generation=0, argument=13
) == sum(range(13, 20))
assert library.snapshot()["active_calls"] == 0
lease = region.borrow("write", generation=0)
lease.write(b"abcdefg")
old_protect = region._protect
injected = []

def failed_revocation_receipt(permission):
    if permission == "none" and not injected:
        injected.append(permission)
        if stage == "post_revoke":
            # The actual kernel mprotect succeeds, but its host observation
            # raises after returning from the kernel transition.
            old_protect(permission)
        # pre_revoke simulates the observation failing before kernel call.
        raise OSError("controlled last-lease page revocation receipt loss")
    return old_protect(permission)

with patch.object(region, "_protect", side_effect=failed_revocation_receipt):
    try:
        lease.close()
    except BaseException as error:
        failure = error
    else:
        raise AssertionError("unreceipted last-lease revocation was accepted")

assert injected == ["none"], injected
assert isinstance(failure, HostRegionUncertain), (
    "unreceipted mprotect leaked raw error: " + repr(failure)
)
state = region.snapshot()
assert state["state"] == "permanent_deny", state
assert region._unprovable_quiescence is True, state
assert state["generation"] > 0, state
assert state["read_leases"] == state["write_leases"] == state["native_jobs"] == 0, state
assert state["observed_mapping_permissions"] == (
    "rw-s" if stage == "pre_revoke" else "---s"
), state
assert any(e["kind"] == "quarantined" for e in state["events"]), state
assert library.snapshot()["active_calls"] == 0

# Ambiguous physical page rights cannot be treated as a recovered/ready owner.
for operation in (
    lambda: region.borrow("read", generation=state["generation"]),
    lambda: region.call(library, "region_fill", generation=state["generation"], argument=13),
    lambda: region.recover(timeout=1),
    lambda: region.close(),
):
    try:
        operation()
    except HostRegionRejected:
        pass
    else:
        raise AssertionError("uncertain page revocation admitted reuse/recovery/unmapping")

library.close()
print("PASS final lease page revocation uncertainty denied actual native reuse", stage)
'''


class LeaseMprotectReceiptTests(unittest.TestCase):
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
        self.assertIn("PASS final lease page revocation", outcome.stdout)

    def test_last_lease_page_revocation_fails_before_kernel_call(self):
        self._probe("pre_revoke")

    def test_last_lease_page_revocation_fails_after_kernel_call(self):
        self._probe("post_revoke")


if __name__ == "__main__":
    unittest.main()
