"""Adversarial P7 cleanup tests: a mutable lease token must not pin an owner grant.

The original #528 Python handle is mutable.  Read/write must reject a changed
token, but release must locate the original owner-retained grant by object
identity, never by a caller-modifiable key.  Linux memfd tests only; this is not
power-loss or arbitrary foreign-pointer certification.
"""
from __future__ import annotations

import platform
import unittest

from hepta.hia_host_region import HostRegion, HostRegionRejected


class OwnerLeaseTokenRevocationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
            raise AssertionError("actual Linux x86-64 memfd required, not a skipped test")

    def test_altered_token_rejects_read_but_release_revokes_original_grant(self):
        region = HostRegion(16)
        lease = None
        try:
            lease = region.borrow("read", generation=0)
            token = lease._token
            lease._token = "0" * 32
            try:
                with self.assertRaises(HostRegionRejected):
                    lease.read()
                lease.close()
                self.assertEqual(region.snapshot()["read_leases"], 0)
                self.assertEqual(region.snapshot()["observed_mapping_permissions"], "---s")
            finally:
                lease._token = token
                if not lease._closed:
                    lease.close()
        finally:
            region.close()

    def test_swapped_registered_token_does_not_revoke_other_reader(self):
        region = HostRegion(8, max_leases=2)
        first = second = None
        try:
            first = region.borrow("read", generation=0)
            second = region.borrow("read", generation=0)
            original_token = first._token
            first._token = second._token
            try:
                with self.assertRaises(HostRegionRejected):
                    first.read()
                first.close()
                self.assertEqual(region.snapshot()["read_leases"], 1)
                self.assertEqual(second.read(), b"\0" * 8)
            finally:
                first._token = original_token
                if not first._closed:
                    first.close()
                if not second._closed:
                    second.close()
            self.assertEqual(region.snapshot()["read_leases"], 0)
        finally:
            region.close()

    def test_context_manager_exit_cleans_original_grant_after_key_tampering(self):
        region = HostRegion(8)
        lease = None
        try:
            lease = region.borrow("read", generation=0)
            original_token = lease._token
            try:
                with lease:
                    lease._token = "tampered"
                self.assertEqual(region.snapshot()["read_leases"], 0)
                self.assertEqual(region.snapshot()["observed_mapping_permissions"], "---s")
            finally:
                lease._token = original_token
                if not lease._closed:
                    lease.close()
        finally:
            region.close()


if __name__ == "__main__":
    unittest.main()
