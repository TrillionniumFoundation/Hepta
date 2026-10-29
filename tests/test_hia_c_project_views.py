"""Original upstream bodies reach Core; cursor extrema and lifetimes stay checked."""
from __future__ import annotations

from collections import deque
import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_runtime import HIAProgramTrap
from hepta.hia_program_source import (HIAProgramSourceRejected, lower_c_project_views,
                                      lower_source)
from hepta.hia_program_llvm import build_program_native
from tools.qualify_hia_legacy_queue import populate_project, compile_database, ENTRY
from tools.qualify_hia_filecheck import update

CLANG = os.environ.get("CLANG") or shutil.which("clang")


@unittest.skipUnless(CLANG, "Clang required for actual captured upstream project")
class HIAProjectViewsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix="hia-project-views-")
        cls.work=Path(cls.temporary.name)
        cls.project=cls.work/"project"
        cls.contracts=populate_project(cls.project)
        cls.database=compile_database(cls.project,cls.work/"capture")
        with patch("hepta.backend.emit_rust",side_effect=AssertionError("Rust fallback forbidden")), \
             patch("hepta.backend.compile_rust",side_effect=AssertionError("Rust fallback forbidden")):
            cls.migrated=lower_c_project_views(cls.database,contracts=cls.contracts,clang=CLANG,
                client_source=(cls.project/"client.hepta").read_text(),retain_asts=True)
        cls.core=cls.migrated["program"]
        cls.native=cls.work/"core.so"
        build_program_native(cls.core.canonical_bytes,cls.native,clang=CLANG)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_real_body_inventory_and_original_ast_bytes_are_retained(self):
        self.assertEqual(len(self.migrated["functions"]),12)
        self.assertEqual(self.migrated["authored_client_function_bodies"],1)
        self.assertTrue(self.migrated["declaration_inventory_complete"])
        self.assertEqual(set(self.migrated["raw_asts"]),{0,1,2,3})
        for text in self.migrated["raw_asts"].values():
            self.assertEqual(json.loads(text)["kind"],"TranslationUnitDecl")
        names={f["name"] for f in self.core.as_dict()["functions"]}
        self.assertTrue({"c_memcmp","c_bcmp","c_ring_buffer_queue_arr","c_ring_buffer_dequeue_arr"}<=names)
        self.assertFalse(self.migrated["claims"]["rust_backend_required"])
        self.assertNotIn("i128",self.migrated["source"])

    def test_vm_native_queue_application_and_all_refusal_cleanups(self):
        fn=getattr(ctypes.CDLL(str(self.native)),ENTRY)
        fn.argtypes=[ctypes.c_size_t,ctypes.c_ulonglong,ctypes.c_uint,ctypes.c_uint]
        fn.restype=ctypes.c_ulonglong
        for count in range(12):
            args=[count,0xfedcba9876543210,0xffffffff,0xedb88320]
            expected=1<<32 if count>8 else update(args[2],args[1].to_bytes(8,"little")[:count],args[3])
            vm=execute_program(self.core,ENTRY,args)
            self.assertEqual((vm["result"],int(fn(*args))),(expected,expected))
            self.assertEqual(vm["resources"]["live_owners"],0)
            self.assertEqual(vm["resources"]["loans_started"],vm["resources"]["loans_ended"])
        for failure in (1,2,3):
            vm=execute_program(self.core,ENTRY,[8,123,1,0xedb88320],allocation_fail_at=failure)
            self.assertEqual(vm["result"],2<<32)
            self.assertEqual(vm["resources"]["allocations"],failure-1)
            self.assertEqual(vm["resources"]["frees"],failure-1)
            self.assertEqual(vm["resources"]["live_owners"],0)

    def test_unsigned_and_signed_cursor_extrema_match_unbounded_integer_spec(self):
        maximum=(1<<64)-1
        cases=[(offset,index,length) for offset in (0,1,4,maximum,1<<63)
               for index in (-1,-4,-(1<<63),0,1,4,(1<<63)-1,maximum)
               for length in (0,1,4,maximum)]
        lib=ctypes.CDLL(str(self.native))
        for signed in (False,True):
            name="c_view_index_signed" if signed else "c_view_index_unsigned"
            fn=getattr(lib,name)
            fn.argtypes=[ctypes.c_size_t,ctypes.c_int64 if signed else ctypes.c_uint64,ctypes.c_size_t]
            fn.restype=ctypes.c_size_t
            for offset,index,length in cases:
                allowed = (-(1<<63)<=index<(1<<63)) if signed else (0<=index<=maximum)
                if not allowed:
                    continue
                with self.subTest(signed=signed,offset=offset,index=index,length=length):
                    expected=offset+index
                    if 0<=expected<length:
                        self.assertEqual(execute_program(self.core,name,[offset,index,length])["result"],expected)
                        self.assertEqual(int(fn(offset,index,length)),expected)
                    else:
                        with self.assertRaises(HIAProgramTrap):execute_program(self.core,name,[offset,index,length])

    def test_native_invalid_cursor_aborts_before_any_pointer_access(self):
        script='''import ctypes,resource,sys
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
lib=ctypes.CDLL(sys.argv[1]);signed=sys.argv[2]=='signed'
fn=getattr(lib,'c_view_index_signed' if signed else 'c_view_index_unsigned')
fn.argtypes=[ctypes.c_size_t,ctypes.c_int64 if signed else ctypes.c_uint64,ctypes.c_size_t]
fn.restype=ctypes.c_size_t
fn(1,-9223372036854775808 if signed else 18446744073709551615,4)
'''
        for mode in ("signed","unsigned"):
            result=subprocess.run([os.sys.executable,"-c",script,str(self.native),mode],capture_output=True,timeout=10)
            self.assertEqual(result.returncode,-6,result.stderr)

    def test_ring_overwrite_paths_match_independent_queue_oracle(self):
        client='''
        fn ring_probe(capacity:usize,count:usize)->u64 effects{alloc,block,panic,write}{
            let mut data=buffer(capacity);let mut output=buffer(1);
            let mut ring=C_ring_buffer_t{f_buffer_mask:0,f_tail_index:0,f_head_index:0,};
            c_ring_buffer_init(mut ring,mut data,0,capacity);
            let mut i:usize=0;
            while i<count {c_ring_buffer_queue(mut ring,mut data,i as u8);i=i+1;}
            let mut result:u64=0;
            while c_ring_buffer_dequeue(mut ring,mut data,mut output,0)!=0 {
                result=wrapping_add(wrapping_mul(result,257),(output[0] as u64));
            }
            drop(move output);drop(move data);return result;
        }'''
        core=lower_source(self.migrated["source"]+client)
        for capacity in (1,2,4,8,16):
            for count in (0,1,7,19,33):
                expected=deque(maxlen=capacity-1)
                for i in range(count):expected.append(i&255)
                value=0
                for byte in expected:value=(value*257+byte)&((1<<64)-1)
                actual=execute_program(core,"ring_probe",[capacity,count])
                self.assertEqual(actual["result"],value)
                self.assertEqual(actual["resources"]["live_owners"],0)

    def test_source_body_changes_are_retranslated_and_missing_drop_refuses(self):
        with tempfile.TemporaryDirectory(prefix="hia-changed-view-") as temp:
            work=Path(temp);project=work/"project";shutil.copytree(self.project,project)
            path=project/"checksum.c"
            path.write_text(path.read_text().replace("state ^ (unsigned int)byte","state ^ ((unsigned int)byte + 1U)"))
            db=compile_database(project,work/"capture")
            changed=lower_c_project_views(db,contracts=self.contracts,clang=CLANG)
            actual=execute_program(changed["program"],"c_checksum_byte",[123,49,0xedb88320])["result"]
            self.assertEqual(actual,update(123,bytes([50]),0xedb88320))
            self.assertNotEqual(changed["program"].sha256,self.core.sha256)
        bad='fn bad()->u64 effects{alloc,block,panic}{let storage=buffer(4);return 1;}'
        with self.assertRaises(HIAProgramSourceRejected):
            lower_source(self.migrated["source"]+bad)

    def test_resource_capabilities_do_not_escape_public_c_abi(self):
        exports=set(self.core.as_dict()["exports"])
        self.assertIn(ENTRY,exports)
        self.assertNotIn("c_memcmp",exports)
        self.assertNotIn("c_ring_buffer_queue",exports)
        self.assertEqual(verify_program(self.core.canonical_bytes).sha256,self.core.sha256)


if __name__=="__main__":unittest.main()
