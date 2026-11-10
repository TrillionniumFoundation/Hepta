"""Actual kernel permissions, native integration and conservative uncertainty."""
from __future__ import annotations

import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from hepta.hia_host_region import (HostRegion,HostRegionRejected,NativeRegionLibrary,
    TrustedRegionContract,RegionLease,retained_host_regions,MAX_REGIONS)


@unittest.skipUnless(sys.platform=="linux" and hasattr(os,"memfd_create"),"Linux memfd required")
class HostRegionKernelTests(unittest.TestCase):
    def test_bounds_rw_permissions_and_closed_identity(self):
        region=HostRegion(17,max_leases=2,max_native_calls=2)
        try:
            with self.assertRaises(HostRegionRejected): copy.copy(region)
            with self.assertRaises(HostRegionRejected): copy.deepcopy(region)
            self.assertEqual(region.snapshot()["observed_mapping_permissions"],"---s")
            with region.borrow("write",generation=0) as owner:
                owner.write(bytes(range(17)))
                self.assertEqual(region.snapshot()["observed_mapping_permissions"],"rw-s")
                with self.assertRaises(HostRegionRejected): region.borrow("read",generation=0)
            first=region.borrow("read",generation=0,offset=1,length=3)
            second=region.borrow("read",generation=0)
            self.assertEqual(first.read(),bytes([1,2,3]))
            self.assertEqual(region.snapshot()["observed_mapping_permissions"],"r--s")
            for action in (lambda:region.borrow("read",generation=0),lambda:first.write(b"abc"),lambda:copy.copy(first),region.close):
                with self.assertRaises(HostRegionRejected): action()
            fake=RegionLease(region,"read",0,17,0)
            with self.assertRaises(HostRegionRejected): fake.read()
            first.close();first.close();second.close()
            with self.assertRaises(HostRegionRejected): first.read()
            with self.assertRaises(HostRegionRejected): region.borrow("read",generation=0,offset=16,length=2)
            with self.assertRaises(HostRegionRejected): region.borrow("read",generation=True)
            self.assertEqual(region.snapshot()["observed_mapping_permissions"],"---s")
        finally: region.close()
        self.assertEqual(region.close(),{"mapping":"closed","fd":"closed"})

    def test_kernel_seals_deny_extent_changes_and_fd_writes(self):
        region=HostRegion(17)
        try:
            self.assertEqual(region.snapshot()["kernel_seals"]&0x17,0x17)
            for operation in (lambda:os.ftruncate(region._fd,0),lambda:os.ftruncate(region._fd,8192),lambda:os.pwrite(region._fd,b"x",0)):
                with self.assertRaises(OSError): operation()
        finally: region.close()

    def test_retention_budget_counts_unclosed_regions(self):
        regions=[]
        try:
            for _ in range(MAX_REGIONS): regions.append(HostRegion(1))
            with self.assertRaises(HostRegionRejected): HostRegion(1)
            self.assertEqual(len(retained_host_regions()["regions"]),MAX_REGIONS)
        finally:
            for region in regions: region.close()

    def test_unknown_pointer_retention_is_refused_before_native_loading(self):
        with self.assertRaisesRegex(HostRegionRejected,"no-escape"):
            NativeRegionLibrary("/path/that/must/not/be/opened","0"*64,
                                TrustedRegionContract((("entry","read"),),False))

    def test_uncertain_close_is_not_retried_after_numeric_fd_reuse(self):
        # Isolate intentional permanent ownership debt from this test process.
        script='''
import os
from unittest.mock import patch
from hepta.hia_host_region import HostRegion,HostRegionRejected,retained_host_regions
r=HostRegion(4096)
fd=r._fd
real=os.close
attempts=[]
def close(value):
    attempts.append(value)
    real(value)
    raise OSError("close completed but observer failed")
with patch("hepta.hia_host_region.os.close",side_effect=close):
    for _ in range(2):
        try:r.close()
        except HostRegionRejected:pass
        else:raise AssertionError("uncertain close was called successful")
assert attempts==[fd]
assert r.snapshot()["state"]=="permanent_deny"
assert len(retained_host_regions()["regions"])==1
print("uncertain close retained; numeric fd attempted once")
'''
        result=subprocess.run([sys.executable,"-c",script],capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr.decode())




if __name__=="__main__": unittest.main()
