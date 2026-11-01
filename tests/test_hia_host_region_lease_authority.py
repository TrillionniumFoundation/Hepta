"""Adversarial lease capability metadata controls; Linux memfd, no native library.

An admitted Python lease is a mutable presentation object, not the authoritative
source of its access extent, mode, generation or internal ownership status.
These assertions must fail on the original #522 implementation, not be skipped.
"""
from __future__ import annotations

import platform
import unittest

from hepta.hia_host_region import HostRegion, HostRegionRejected


class OwnerLeaseAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
            raise AssertionError("real Linux x86-64 host required; do not silently skip")

    def test_mutable_write_lease_cannot_expand_owner_extent(self):
        region = HostRegion(16)
        try:
            with region.borrow("write", generation=0) as setup:
                setup.write(b"0123456789abcdef")
            lease = region.borrow("write", generation=0, offset=4, length=4)
            try:
                lease._offset, lease._length = 0, 16
                with self.assertRaisesRegex(HostRegionRejected, "lease"):
                    lease.write(b"Z" * 16)
                self.assertEqual(region.snapshot()["write_leases"], 1)
            finally:
                lease.close()
            with region.borrow("read", generation=0) as reader:
                self.assertEqual(reader.read(), b"0123456789abcdef")
        finally:
            region.close()

    def test_mutable_mode_does_not_spoof_registered_reader(self):
        region = HostRegion(16, max_leases=2)
        try:
            with region.borrow("write", generation=0) as writer:
                writer.write(b"0123456789abcdef")
            lease = region.borrow("read", generation=0, offset=2, length=3)
            try:
                lease._mode = "write"
                with self.assertRaisesRegex(HostRegionRejected, "lease"):
                    lease.read()
                status = region.snapshot()
                self.assertEqual((status["read_leases"], status["write_leases"]), (1, 0))
                with region.borrow("read", generation=0) as another:
                    self.assertEqual(another.read(), b"0123456789abcdef")
            finally:
                lease.close()
        finally:
            region.close()

    def test_mutable_generation_and_offset_do_not_rebind_scope(self):
        region = HostRegion(8)
        try:
            lease = region.borrow("read", generation=0, offset=0, length=4)
            try:
                lease._generation = 10
                with self.assertRaises(HostRegionRejected):
                    lease.read()
                lease._generation = 0
                lease._offset = 4
                with self.assertRaisesRegex(HostRegionRejected, "lease"):
                    lease.read()
            finally:
                lease.close()
        finally:
            region.close()

    def test_mutable_internal_flag_cannot_pin_external_lease(self):
        region = HostRegion(8)
        try:
            lease = region.borrow("read", generation=0)
            try:
                lease._internal = True
                try:
                    lease.close()
                except HostRegionRejected as exc:
                    self.fail("mutable lease flag denied ordinary release: " + str(exc))
                self.assertEqual(region.snapshot()["read_leases"], 0)
                self.assertEqual(region.snapshot()["observed_mapping_permissions"], "---s")
            finally:
                if not lease._closed:
                    lease._internal = False
                    lease.close()
        finally:
            region.close()


if __name__ == "__main__":
    unittest.main()
