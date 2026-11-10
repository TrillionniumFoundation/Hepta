"""P7: a failed host write receipt must not leave a partially changed memfd ready.

A genuine Clang C worker runs on the Linux mapping before each controlled
pre/partial/post write exception. This is process-local fault injection, not a
power-cut or proof of arbitrary mmap kernel fault recovery.
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
assert region.call(library, "region_fill", generation=0, argument=13) == sum(range(13, 20))
assert region.snapshot()["observed_mapping_permissions"] == "---s"

lease = region.borrow("write", generation=0)
raw = region._memory
old = bytes(raw[:7])
assert old == bytes(range(13, 20)), old

class FaultyWriteReceipt:
    def __init__(self, backing):
        self.backing = backing

    def __setitem__(self, key, value):
        assert key == slice(0, 7), key
        assert value == b"ABCDEFG", value
        if stage == "partial":
            # Real writes to the kernel-backed memfd precede a lost receipt.
            self.backing[0:3] = value[:3]
        elif stage == "after":
            self.backing[key] = value
        elif stage != "before":
            raise AssertionError("unknown stage")
        raise OSError("controlled host write receipt loss: " + stage)

with patch.object(region, "_memory", FaultyWriteReceipt(raw)):
    try:
        lease.write(b"ABCDEFG")
    except BaseException as error:
        failure = error
    else:
        raise AssertionError("write returned success despite lost receipt")

# The actual mapping was changed for partial/after, not a fake bytearray.
observed = bytes(raw[:7])
expected = {
    "before": old,
    "partial": b"ABC" + old[3:],
    "after": b"ABCDEFG",
}[stage]
assert observed == expected, (stage, observed, expected)
print("controlled_write_fault", stage, type(failure).__name__, observed.hex(), flush=True)
assert isinstance(failure, HostRegionUncertain), repr(failure)

state = region.snapshot()
assert state["state"] == "quarantined", state
assert state["generation"] > 0, state
assert state["write_leases"] == 1 and state["native_jobs"] == 0, state
assert state["observed_mapping_permissions"] == "rw-s", state
for blocked in (
    lease.read,
    lambda: lease.write(b"ABCDEFG"),
    lambda: region.borrow("read", generation=0),
    lambda: region.call(library, "region_fill", generation=0, argument=13),
    lambda: region.recover(timeout=0),
):
    try:
        blocked()
    except HostRegionRejected:
        pass
    else:
        raise AssertionError("unconfirmed host write permitted stale access")

lease.close()
assert region.snapshot()["observed_mapping_permissions"] == "---s"
receipt = region.recover(timeout=0)
assert receipt["state"] == "ready", receipt
generation = region.snapshot()["generation"]
with region.borrow("read", generation=generation) as copy_lease:
    assert copy_lease.read() == bytes(7), copy_lease.read()
assert region.call(library, "region_fill", generation=generation, argument=13) == sum(range(13, 20))
assert region.snapshot()["state"] == "ready"
region.close()
library.close()
print("PASS real memfd host write fault quarantined, zeroed and C worker reexecuted", stage)
'''


class HostWriteReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
            raise AssertionError("actual Linux x86-64 host required; no silent skip")
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

    def _probe(self, stage):
        result = subprocess.run(
            [sys.executable, "-B", "-c", PROBE, str(self.path), self.digest, stage],
            capture_output=True, text=True, timeout=25, check=False,
        )
        self.assertEqual(result.returncode, 0,
                         f"stage={stage} stdout={result.stdout}\nstderr={result.stderr}")
        self.assertIn("PASS real memfd host write fault", result.stdout)

    def test_write_receipt_lost_before_kernel_bytes_changed(self):
        self._probe("before")

    def test_write_receipt_lost_after_partial_kernel_bytes_changed(self):
        self._probe("partial")

    def test_write_receipt_lost_after_all_kernel_bytes_changed(self):
        self._probe("after")


if __name__ == "__main__":
    unittest.main()
