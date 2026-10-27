"""Reject invalid ownership ordering before C generation; run only valid neighbours."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from hepta.backend import compile_rust
from hepta.c_backend import compile_c
from hepta.pipeline import analyze, resource_ir_analysis

PREFIX = """module operand_order;
fn dispose(data:take Buffer<u8>)->u8 effects {alloc,block} {
    release(move data); return 7;
}
"""
REJECTED = {
    "rhs_consumes_index_owner": PREFIX + """
fn main()->Unit effects {alloc,block,panic} {
    let mut out=buffer(8); let index=buffer(1);
    out[index[0] as usize]=dispose(move index);
    release(move out);
}""",
    "rhs_consumes_index_field": PREFIX + """
struct Index { bytes:Buffer<u8>, tag:u64 }
fn main()->Unit effects {alloc,block,panic} {
    let mut out=buffer(8); let index=Index{bytes:buffer(1),tag:1};
    out[index.bytes[0] as usize]=dispose(move index.bytes);
    release(move out);
}""",
    "rhs_consumes_returned_target_argument": PREFIX + """
fn view(out:mut Buffer<u8>, index:read Buffer<u8>)->mut [u8] from out effects {} {
    return mut out;
}
fn main()->Unit effects {alloc,block,panic} {
    let mut out=buffer(8); let index=buffer(1);
    view(mut out,read index)[0]=dispose(move index);
    release(move out);
}""",
}
ACCEPTED = {
    "index_value_materialized_before_rhs": PREFIX + """
fn main()->Unit effects {alloc,block,panic} {
    let mut out=buffer(8); let index=buffer(1);
    let position=index[0] as usize;
    out[position]=dispose(move index);
    assert(out[0]==7); release(move out);
}""",
    "rhs_consumes_disjoint_owner": PREFIX + """
fn main()->Unit effects {alloc,block,panic} {
    let mut out=buffer(8); let index=buffer(1); let other=buffer(3);
    out[index[0] as usize]=dispose(move other);
    assert(out[0]==7); release(move index); release(move out);
}""",
    "rhs_reads_before_mutable_target": """module order_view;
fn view(out:mut Buffer<u8>)->mut [u8] effects {} {return mut out;}
fn main()->Unit effects {alloc,block,panic} {
    let mut out=buffer(8);
    view(mut out)[0]=(out[0]+7) as u8;
    assert(out[0]==7); release(move out);
}""",
    "restore_after_rhs_partial_extraction": PREFIX + """
struct Pair { left:Buffer<u8>, right:Buffer<u8> }
fn reuse(data:take Buffer<u8>)->Buffer<u8> effects {} {return move data;}
fn main()->Unit effects {alloc,block,panic} {
    let mut p=Pair{left:buffer(3),right:buffer(5)};
    let left=move p.left; p.left=reuse(move left);
    assert(len(p.left)==3);drop(move p);
}""",
}


class ResourceEvaluationOrderTests(unittest.TestCase):
    def test_rhs_precedes_index_and_returned_target_arguments(self):
        for name, source in REJECTED.items():
            with self.subTest(name=name):
                frontend = analyze(source, native=False, crate_type="bin")
                self.assertTrue(frontend.report["ok"], frontend.report)
                graph = resource_ir_analysis(frontend)
                self.assertFalse(graph["ok"], graph)
                self.assertIn("E_RIR_USE_AFTER_MOVE", str(graph.get("diagnostics")))
                emitted = analyze(source, native=False, backend="c", crate_type="bin")
                self.assertFalse(emitted.report["ok"])
                self.assertIsNone(emitted.c)
                self.assertEqual(emitted.report["diagnostics"][0]["code"], "E_C_RESOURCE_IR")
                rust = analyze(source, native=True, crate_type="bin")
                self.assertFalse(rust.report["ok"])
                self.assertTrue({"E0382", "E0505"}.intersection(d["code"] for d in rust.report["diagnostics"]))

    def test_valid_neighbours_execute_through_both_backends(self):
        with tempfile.TemporaryDirectory() as td:
            for name, source in ACCEPTED.items():
                for backend in ("rust", "c"):
                    with self.subTest(name=name, backend=backend):
                        analysis = analyze(source, native=True, backend=backend, crate_type="bin")
                        self.assertTrue(analysis.report["ok"], analysis.report)
                        verified = resource_ir_analysis(analysis)
                        self.assertTrue(verified["ok"], verified)
                        output = Path(td) / (name + "-" + backend)
                        built = (compile_rust(analysis.rust, crate_type="bin", output=output) if backend == "rust" else
                                 compile_c(analysis.c, crate_type="bin", output=output, sanitize=True))
                        self.assertTrue(built["ok"], built)
                        proc = subprocess.run([str(output)], capture_output=True, text=True, timeout=10)
                        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
