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
from tests.hia_host_region_fixture import build_fixture,exercise,ENTRIES


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


@unittest.skipUnless(sys.platform=="linux" and shutil.which(os.environ.get("HEPTA_TEST_CLANG","clang")),"actual native Clang/Linux required")
class HostRegionNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory()
        cls.directory=Path(cls.temporary.name)
        cls.report={}
        cls.path,cls.digest=build_fixture(cls.directory,Path(shutil.which(os.environ.get("HEPTA_TEST_CLANG","clang"))).resolve(),cls.report)

    @classmethod
    def tearDownClass(cls): cls.temporary.cleanup()

    def test_real_hia_bridge_threads_quarantine_and_recovery(self):
        evidence=exercise(self.path,self.digest)
        self.assertGreaterEqual(evidence["native_concurrent_reader_peak"],2)
        self.assertEqual(len(evidence["denials"]),18)
        self.assertFalse(evidence["retained_after"]["regions"])

    def test_reviewed_code_uses_pinned_bytes_after_source_path_replaced(self):
        mutable=self.directory/"replaceable.so"
        mutable.write_bytes(self.path.read_bytes())
        library=NativeRegionLibrary(mutable,self.digest,TrustedRegionContract(ENTRIES,True))
        region=HostRegion(7)
        try:
            with self.assertRaises(HostRegionRejected): copy.copy(library)
            with self.assertRaises(HostRegionRejected): copy.deepcopy(library)
            mutable.write_bytes(b"replaced after sealed pin")
            self.assertEqual(region.call(library,"region_fill",generation=0,argument=13),sum(range(13,20)))
        finally:
            region.close();library.close()

    def test_digest_mismatch_cannot_reach_callable_library(self):
        before=len(retained_host_regions()["libraries"])
        with self.assertRaises(HostRegionRejected):
            NativeRegionLibrary(self.path,"0"*64,TrustedRegionContract(ENTRIES,True))
        self.assertEqual(len(retained_host_regions()["libraries"]),before)

    def test_uncertain_worker_launch_permanently_denies_reuse(self):
        script='''
import sys,threading
from unittest.mock import patch
from hepta.hia_host_region import HostRegion,NativeRegionLibrary,TrustedRegionContract,HostRegionRejected,HostRegionUncertain
r=HostRegion(4096)
l=NativeRegionLibrary(sys.argv[1],sys.argv[2],TrustedRegionContract((("region_delayed_sum","read"),),True))
real=threading.Thread.start
def start(thread):
    real(thread)
    raise RuntimeError("started but caller observation failed")
with patch("hepta.hia_host_region.threading.Thread.start",new=start):
    try:r.call(l,"region_delayed_sum",generation=0,argument=30)
    except HostRegionUncertain:pass
    else:raise AssertionError("uncertain start admitted")
for job in r._jobs.values():job["thread"].join(1)
assert r.snapshot()["state"]=="permanent_deny"
for operation in (lambda:r.recover(timeout=0),r.close,l.close):
    try:operation()
    except HostRegionRejected:pass
    else:raise AssertionError("unconfirmed ownership was reclaimed")
print("launch uncertainty retained even after observed return; permanent deny")
'''
        result=subprocess.run([sys.executable,"-c",script,str(self.path),self.digest],capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr.decode())


if __name__=="__main__": unittest.main()
