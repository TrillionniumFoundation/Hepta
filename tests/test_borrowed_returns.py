"""Single-origin returned borrows and disjoint struct-field access.

Returned references are always validated by rustc. The independent C path must
reject returned references, while its own place analysis handles named fields.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.backend import compile_rust, find_rustc
from hepta.c_backend import compile_c
from hepta.pipeline import analyze


PACKET = "struct Packet{data:Buffer<u8>,trailer:Buffer<u8>}"
VIEW = PACKET + "fn view(p:read Packet)->read Buffer<u8> effects {} {return read p.data;}"


def compiler():
    try:
        return find_rustc(os.environ.get("RUSTC"))
    except HeptaError:
        return None


RUSTC = compiler()


class BorrowedReturnChecks(unittest.TestCase):
    def reject(self, source, code):
        result = analyze(source, native=False)
        self.assertFalse(result.report["ok"], result.report)
        self.assertIn(code, [d["code"] for d in result.report["diagnostics"]], result.report)

    def test_local_and_owned_sources_cannot_escape(self):
        self.reject("fn bad(x:read u32)->read u32 effects {} {let local:u32=3;return read local;}", "E_BORROW_RETURN_SOURCE")
        self.reject("fn bad(x:take Buffer<u8>)->read Buffer<u8> effects {} {return read x;}", "E_BORROW_RETURN_SOURCE")
        self.reject("fn bad()->read u32 effects {} {let local:u32=3;return read local;}", "E_BORROW_RETURN_SOURCE")

    def test_ambiguous_multiple_borrowed_inputs_are_rejected(self):
        self.reject("fn bad(a:read u32,b:read u32)->read u32 effects {} {return read a;}", "E_BORROW_RETURN_SOURCE")

    def test_mutable_borrow_cannot_be_returned_from_read_input(self):
        self.reject("fn bad(a:read u32)->mut u32 effects {} {return mut a;}", "E_READ_ONLY")

    def test_return_requires_matching_explicit_mode(self):
        self.reject("fn bad(a:read u32)->read u32 effects {} {return a;}", "E_BORROW_MODE")
        self.reject("fn bad(a:mut u32)->mut u32 effects {} {return read a;}", "E_BORROW_MODE")

    def test_returned_borrow_cannot_become_an_owner(self):
        body = "fn main()->Unit effects {alloc,block,panic} {let p=Packet{data:buffer(3),trailer:buffer(2)};%s drop(move p);}"
        for attempted in ("let stolen=view(read p);release(move stolen);", "let stolen=move view(read p);release(move stolen);", "release(move view(read p));"):
            with self.subTest(attempted=attempted):
                self.reject(VIEW + body % attempted, "E_MOVE_BORROW")

    def test_read_result_does_not_grant_mutation(self):
        self.reject(VIEW + "fn main()->Unit effects {alloc,block,panic} {let mut p=Packet{data:buffer(3),trailer:buffer(2)};view(read p)[0]=1;drop(move p);}", "E_READ_ONLY")

    def test_borrowed_return_still_requires_consuming_other_resources(self):
        self.reject("fn bad(a:read u32,b:take Buffer<u8>)->read u32 effects {} {return read a;}", "E_LINEAR_UNCONSUMED")

    def test_no_first_class_reference_bindings_are_invented(self):
        self.reject("fn f(a:read u32)->Unit effects {} {let alias=read a;}", "E_BORROW_CONTEXT")
        self.reject("fn view(a:read [u8])->read [u8] effects {} {return read a;} fn f(a:read [u8])->Unit effects {} {let alias=view(read a);}", "E_UNSIZED")

    def test_runtime_capabilities_cannot_escape_as_borrows(self):
        self.reject("fn bad(c:read Cancellation)->read Cancellation effects {} {return read c;}", "E_CANCELLATION_TYPE")
        self.reject("fn bad(c:read Sender<u64>)->read Sender<u64> effects {} {return read c;}", "E_SENDER_TYPE")

    def test_borrowed_returns_cannot_cross_c_abi_or_c_backend(self):
        self.reject('export "C" fn get(x:read u32)->read u32 effects {} {return read x;}', "E_C_ABI")
        result = analyze("fn get(x:read u32)->read u32 effects {} {return read x;}", native=False, backend="c")
        self.assertFalse(result.report["ok"])
        self.assertIn("E_C_BACKEND_SUBSET", [d["code"] for d in result.report["diagnostics"]])


@unittest.skipUnless(RUSTC, "requires real pinned rustc")
class NativeBorrowedReturns(unittest.TestCase):
    def execute(self, source, backend="rust", no_std=False):
        a = analyze(source, rustc=RUSTC, backend=backend, crate_type="rlib" if no_std else "bin", no_std=no_std)
        self.assertTrue(a.report["ok"], a.report)
        with tempfile.TemporaryDirectory(prefix="hepta-borrow-return-") as td:
            out = Path(td) / ("unit.o" if no_std else "run")
            built = compile_c(a.c, crate_type="bin", output=out) if backend == "c" else compile_rust(a.rust, rustc=RUSTC, crate_type="obj" if no_std else "bin", output=out)
            self.assertTrue(built["ok"], built)
            if not no_std:
                p = subprocess.run([out], capture_output=True, timeout=10)
                self.assertEqual(p.returncode, 0, p.stderr)
        return a

    def test_read_mut_slice_returns_and_reborrow_chains(self):
        self.execute("""
        struct Packet{data:Buffer<u8>,trailer:Buffer<u8>}
        fn bytes(p:read Packet)->read [u8] effects {} {return read p.data;}
        fn view(p:read Packet)->read [u8] effects {} {return read bytes(read p);}
        fn writable(p:mut Packet)->mut [u8] effects {} {return mut p.data;}
        fn head(xs:mut [u8])->mut u8 effects {panic} {return mut xs[0];}
        fn set(x:mut u8,v:u8)->Unit effects {write} {x=v;}
        fn total(xs:read [u8])->u64 effects {panic} {
          let mut sum:u64=0;
          for i in 0..len(xs) {sum=wrapping_add(sum,xs[i] as u64);}
          return sum;
        }
        fn main()->Unit effects {alloc,block,panic,write} {
          let mut p=Packet{data:buffer(4),trailer:buffer(2)};
          writable(mut p)[1]=9;
          set(mut head(mut writable(mut p)),7);
          assert(len(view(read p))==4);
          assert(total(read view(read p))==16);
          assert(p.data[0]==7);assert(p.data[1]==9);
          drop(move p);
        }
        """)

    def test_returned_scalar_or_copy_struct_is_copied_when_used_as_value(self):
        self.execute("""
        struct Point{x:u64,y:u64}
        fn ref_point(p:read Point)->read Point effects {} {return read p;}
        fn ref_x(p:read Point)->read u64 effects {} {return read p.x;}
        fn ref_generic<T>(x:read T)->read T effects {} {return read x;}
        fn main()->Unit effects {panic} {
          let p=Point{x:13,y:21};let q=ref_point(read p);
          assert(q.x==13);assert(ref_x(read p)==13);assert(ref_generic::<u64>(read q.y)==21);
        }
        """)

    def test_no_std_read_return_is_a_real_object(self):
        self.execute("fn head(x:read [u8])->read u8 effects {panic} {return read x[0];} pub fn value(x:read [u8])->u8 effects {panic} {return head(read x);}", no_std=True)

    def test_native_checker_rejects_owner_move_with_outstanding_returned_borrow(self):
        source = VIEW + """
        fn observe(a:read Buffer<u8>,p:take Packet)->Unit effects {alloc,block} {drop(move p);}
        fn main()->Unit effects {alloc,block,panic} {
          let p=Packet{data:buffer(4),trailer:buffer(2)};
          observe(read view(read p),move p);
        }
        """
        a = analyze(source, rustc=RUSTC, crate_type="bin")
        self.assertFalse(a.report["ok"], a.report)
        self.assertIn("E0505", [d["code"] for d in a.report["diagnostics"]], a.report)

    def test_native_checker_rejects_overlapping_returned_mutable_borrows(self):
        source = """
        fn view(x:mut [u8])->mut u8 effects {panic} {return mut x[0];}
        fn both(x:mut u8,y:mut u8)->Unit effects {write} {x=y;}
        fn main()->Unit effects {write,panic} {
          let mut data:[u8;2]=[1,2];both(mut view(mut data),mut view(mut data));
        }
        """
        a = analyze(source, rustc=RUSTC, crate_type="bin")
        self.assertFalse(a.report["ok"], a.report)
        self.assertIn("E0499", [d["code"] for d in a.report["diagnostics"]], a.report)

    def test_disjoint_owned_struct_fields_are_borrowed_without_moving(self):
        self.execute("""
        struct Pair{left:Buffer<u8>,right:Buffer<u8>}
        fn copy_first(dst:mut [u8],src:read [u8])->Unit effects {panic,write} {dst[0]=src[0];}
        fn main()->Unit effects {alloc,block,panic,write} {
          let mut p=Pair{left:buffer(2),right:buffer(2)};
          p.right[0]=37;copy_first(mut p.left,read p.right);
          assert(p.left[0]==37);drop(move p);
        }
        """)

    def test_c_and_rust_agree_on_disjoint_nested_fields(self):
        source = """
        struct Pair{left:i32,right:i32}
        struct Nested{pair:Pair,other:i32}
        fn set(dst:mut i32,src:read i32)->Unit effects {write} {dst=src;}
        fn main()->Unit effects {write,panic} {
          let mut p=Nested{pair:Pair{left:1,right:44},other:7};
          set(mut p.pair.left,read p.pair.right);set(mut p.other,read p.pair.left);
          assert(p.pair.left==44);assert(p.other==44);
        }
        """
        self.execute(source)
        self.execute(source, backend="c")

    def test_c_rejects_same_field_ancestor_and_unproved_indices(self):
        cases = [
            "struct P{a:i32,b:i32} fn f(x:mut i32,y:read i32)->Unit effects {write} {x=y;} fn main()->Unit effects {write} {let mut p=P{a:1,b:2};f(mut p.a,read p.a);}",
            "struct P{a:i32,b:i32} fn f(x:mut P,y:read i32)->Unit effects {write} {x.a=y;} fn main()->Unit effects {write} {let mut p=P{a:1,b:2};f(mut p,read p.a);}",
            "fn f(x:mut i32,y:read i32)->Unit effects {write} {x=y;} fn main()->Unit effects {write,panic} {let mut p:[i32;2]=[1,2];f(mut p[0],read p[1]);}",
        ]
        for source in cases:
            with self.subTest(source=source):
                a=analyze(source,native=False,backend="c",crate_type="bin")
                self.assertFalse(a.report["ok"],a.report)
                self.assertIn("E_C_BORROW",[d["code"] for d in a.report["diagnostics"]])


if __name__ == "__main__":
    unittest.main()
