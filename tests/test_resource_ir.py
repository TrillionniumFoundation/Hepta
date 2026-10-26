"""Independent resource CFG checking, from real source and adversarial JSON."""
import copy
from pathlib import Path
import subprocess
import sys
import unittest

from hepta.checker import check
from hepta.modules import load_project
from hepta.parser import parse
from hepta.resource_ir import ResourceIRError, verify_resource_ir
from hepta.resource_lowering import lower_resource_ir


ROOT = Path(__file__).resolve().parents[1]
SIMPLE = "fn main()->Unit effects {alloc,block,panic} {let bytes=buffer(8);drop(move bytes);}"
FIELDS = """
struct Pair { left:Buffer<u8>, right:Buffer<u8> }
fn copy_first(dst:mut [u8],src:read [u8])->Unit effects {panic,write} {dst[0]=src[0];}
fn main()->Unit effects {alloc,block,panic,write} {
  let mut pair=Pair{left:buffer(2),right:buffer(2)};
  copy_first(mut pair.left,read pair.right); drop(move pair);
}
"""


def lower(source):
    program = parse(source)
    checked = check(program)
    if not checked.ok:
        raise AssertionError([d.to_dict() for d in checked.diagnostics])
    return lower_resource_ir(program, checked)


def function(document, name="main"):
    return next(fn for fn in document["functions"] if fn["name"] == name)


def operations(fn, name=None):
    return [(block, i, op) for block in fn["blocks"] for i, op in enumerate(block["ops"])
            if name is None or op["op"] == name]


class ResourceIRTests(unittest.TestCase):
    def reject(self, document, code):
        report = verify_resource_ir(document)
        self.assertFalse(report["ok"], report)
        self.assertEqual(report["diagnostics"][0]["code"], code, report)

    def test_verifier_imports_no_parser_or_checker(self):
        process = subprocess.run([sys.executable, "-c", "import sys; import hepta.resource_ir; assert 'hepta.parser' not in sys.modules; assert 'hepta.checker' not in sys.modules"],
                                 cwd=ROOT, text=True, capture_output=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)

    def test_real_owned_library_lowers_with_match_early_returns_and_loops(self):
        project = load_project(ROOT / "examples/owned/main.hepta")
        checked = check(project.program)
        self.assertTrue(checked.ok, checked.diagnostics)
        doc = lower_resource_ir(project.program, checked, project_sha256=project.identity)
        report = verify_resource_ir(doc)
        self.assertTrue(report["ok"], report)
        self.assertEqual(len(report["functions"]), 6)
        all_ops = {op["op"] for fn in doc["functions"] for _, _, op in operations(fn)}
        self.assertTrue({"acquire", "move", "pack", "unpack", "drop", "borrow", "end_borrow", "call", "use"} <= all_ops)
        self.assertGreater(sum(f["normal_exits"] for f in report["functions"]), 6)
        self.assertFalse(report["claims"]["source_to_ir_refinement_proved"])
        self.assertFalse(report["claims"]["native_codegen_uses_this_ir"])

    def test_returned_views_reborrow_chains_and_writes_lower(self):
        doc = lower("""
        struct Packet{data:Buffer<u8>,trailer:Buffer<u8>}
        fn bytes(p:read Packet)->read [u8] effects {} {return read p.data;}
        fn view(p:read Packet)->read [u8] effects {} {return read bytes(read p);}
        fn writable(p:mut Packet)->mut [u8] effects {} {return mut p.data;}
        fn head(xs:mut [u8])->mut u8 effects {panic} {return mut xs[0];}
        fn set(x:mut u8,v:u8)->Unit effects {write} {x=v;}
        fn main()->Unit effects {alloc,block,panic,write} {
          let mut p=Packet{data:buffer(4),trailer:buffer(2)};
          writable(mut p)[1]=9;set(mut head(mut writable(mut p)),7);
          assert(len(view(read p))==4);drop(move p);
        }
        """)
        self.assertTrue(verify_resource_ir(doc)["ok"])
        self.assertEqual(function(doc, "view")["returns"]["origin"], "p0")

    def test_copied_returned_scalars_do_not_escape_as_local_loans(self):
        doc = lower("""
        struct Point{x:u64,y:u64}
        fn point(p:read Point)->read Point effects {} {return read p;}
        fn field(p:read Point)->read u64 effects {} {return read p.x;}
        fn main()->Unit effects {panic} {
          let p=Point{x:13,y:21};let q=point(read p);assert(field(read q)==13);
        }
        """)
        self.assertTrue(verify_resource_ir(doc)["ok"])

    def test_removed_drop_is_a_real_exit_leak(self):
        doc = lower(SIMPLE)
        block, index, _ = operations(function(doc), "drop")[0]
        del block["ops"][index]
        self.reject(doc, "E_RIR_LEAK")

    def test_duplicate_move_is_rejected(self):
        doc = lower(SIMPLE)
        block, index, op = operations(function(doc), "move")[0]
        block["ops"].insert(index + 1, copy.deepcopy(op))
        self.reject(doc, "E_RIR_USE_AFTER_MOVE")

    def test_drop_with_live_loan_is_rejected(self):
        doc = lower(SIMPLE)
        block, index, op = operations(function(doc), "drop")[0]
        block["ops"].insert(index, {"op": "borrow", "id": "injected", "place": {"root": op["src"], "path": []}, "mode": "read", "type": "Buffer<u8>"})
        self.reject(doc, "E_RIR_LOAN_CONFLICT")

    def test_local_borrow_cannot_replace_declared_return_origin(self):
        doc = lower("fn head(xs:read [u8])->read u8 effects {panic} {return read xs[0];}")
        fn = function(doc, "head")
        fn["locals"].append({"id": "local", "type": "u8", "mutable": False})
        _, _, borrow = operations(fn, "borrow")[0]
        borrow["place"] = {"root": "local", "path": []}
        self.reject(doc, "E_RIR_RETURN")

    def test_undeclared_loan_cannot_survive_normal_return(self):
        doc = lower("fn main()->Unit effects {panic} {let x:[u8;2]=[1,2];assert(len(x)==2);}")
        block, index, _ = operations(function(doc), "end_borrow")[0]
        del block["ops"][index]
        self.reject(doc, "E_RIR_LOAN_ESCAPE")

    def test_external_calls_need_declared_unproved_obligations(self):
        doc = lower('extern "C" fn native(x:u64)->u64 effects {ffi,unsafe}; fn call(x:u64)->u64 effects {ffi,unsafe} {unsafe {return native(x);}}')
        report = verify_resource_ir(doc)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["status"], "resource_cfg_verified_with_external_assumptions")
        self.assertFalse(report["claims"]["external_contracts_proved"])
        missing_call = copy.deepcopy(doc)
        operations(function(missing_call, "call"), "foreign")[0][2]["obligation"] = None
        self.reject(missing_call, "E_RIR_EXTERNAL")
        doc["obligations"] = {}
        self.reject(doc, "E_RIR_EXTERNAL")

    def test_loop_backedge_cannot_change_live_owners(self):
        doc = lower("fn main()->Unit effects {alloc,block,panic} {let b=buffer(4);let mut i:usize=0;while i<2 {i=i+1;}drop(move b);}")
        fn = function(doc)
        owner = operations(fn, "move")[0][2]["dest"]
        header = next(block for block in fn["blocks"] if block["term"]["op"] == "branch")
        body = next(block for block in fn["blocks"] if block["id"] == header["term"]["then"])
        body["ops"].append({"op": "drop", "src": owner})
        self.reject(doc, "E_RIR_JOIN")

    def test_continuing_branch_requires_equal_owner_states(self):
        doc = lower("fn test(flag:bool)->Unit effects {alloc,block,panic} {let b=buffer(2);if flag {} else {} drop(move b);}")
        fn = function(doc, "test")
        owner = operations(fn, "move")[0][2]["dest"]
        branch = next(block for block in fn["blocks"] if block["term"]["op"] == "branch")
        arm = next(block for block in fn["blocks"] if block["id"] == branch["term"]["then"])
        arm["ops"].append({"op": "drop", "src": owner})
        self.reject(doc, "E_RIR_JOIN")

    def test_duplicate_owned_pack_field_is_rejected(self):
        doc = lower(FIELDS)
        pack = operations(function(doc), "pack")[0][2]
        pack["fields"][1] = pack["fields"][0]
        self.reject(doc, "E_RIR_USE_AFTER_MOVE")

    def test_enum_unpack_requires_actual_switch_fact(self):
        doc = lower("fn main()->Unit effects {alloc,block} {match try_buffer(4) {Result::Ok(b)=>{drop(move b);},Result::Err(code)=>{},}}")
        unpack = operations(function(doc), "unpack")[0][2]
        unpack["variant"] = "Err"
        self.reject(doc, "E_RIR_VARIANT")

    def test_overwritten_copy_enum_invalidates_earlier_switch_fact(self):
        doc = lower("enum Flag{A(u8),B(u16)} fn f()->Unit effects {} {let flag:Flag=Flag::A(1);match flag {Flag::A(x)=>{},Flag::B(y)=>{},}}")
        fn = function(doc, "f")
        fn["locals"].append({"id": "replacement", "type": "u16", "mutable": False})
        block, index, unpack = operations(fn, "unpack")[0]
        block["ops"].insert(index, {"op": "pack", "dest": unpack["src"], "variant": "B", "fields": ["replacement"]})
        self.reject(doc, "E_RIR_VARIANT")

    def test_known_disjoint_fields_pass_and_same_field_conflicts(self):
        doc = lower(FIELDS)
        self.assertTrue(verify_resource_ir(doc)["ok"])
        borrows = operations(function(doc), "borrow")
        self.assertEqual([b[2]["place"]["path"] for b in borrows], [["left"], ["right"]])
        borrows[1][2]["place"]["path"] = ["left"]
        self.reject(doc, "E_RIR_LOAN_CONFLICT")

    def test_ancestor_and_dynamic_indices_remain_conservative(self):
        doc = lower(FIELDS)
        first = operations(function(doc), "borrow")[0][2]
        first["place"]["path"] = []
        first["type"] = "Pair"
        self.reject(doc, "E_RIR_LOAN_CONFLICT")

    def test_one_mutable_loan_cannot_fill_mut_then_read_arguments(self):
        doc = lower(FIELDS)
        call = operations(function(doc), "call")[0][2]
        call["args"][1]["id"] = call["args"][0]["id"]
        self.reject(doc, "E_RIR_LOAN_CONFLICT")

    def test_one_shared_loan_can_fill_two_read_arguments(self):
        doc = lower("fn total(a:read [u8],b:read [u8])->u8 effects {panic} {return a[0]+b[0];} fn main()->Unit effects {panic} {let a:[u8;2]=[1,2];assert(total(read a,read a)==2);}")
        call = operations(function(doc), "call")[0][2]
        call["args"][1]["id"] = call["args"][0]["id"]
        self.assertTrue(verify_resource_ir(doc)["ok"])

    def test_dynamic_indices_remain_conservative(self):
        doc = lower("fn put(x:mut u8)->Unit effects {write} {x=1;} fn main()->Unit effects {write,panic} {let mut a:[u8;2]=[0,0];put(mut a[0]);put(mut a[1]);}")
        block, index, _ = operations(function(doc), "end_borrow")[0]
        del block["ops"][index]
        self.reject(doc, "E_RIR_LOAN_CONFLICT")

    def test_borrowed_call_does_not_allow_move_of_its_origin(self):
        source = """
        struct Packet{data:Buffer<u8>}
        fn view(p:read Packet)->read Buffer<u8> effects {} {return read p.data;}
        fn observe(a:read Buffer<u8>,p:take Packet)->Unit effects {alloc,block} {drop(move p);}
        fn main()->Unit effects {alloc,block,panic} {let p=Packet{data:buffer(4)};observe(read view(read p),move p);}
        """
        with self.assertRaises(ResourceIRError) as raised:
            lower(source)
        self.assertEqual(raised.exception.code, "E_RIR_LOAN_CONFLICT")

    def test_unknown_operations_and_spurious_proof_claims_fail_closed(self):
        doc = lower(SIMPLE)
        function(doc)["blocks"][0]["ops"].append({"op": "trust_me"})
        self.reject(doc, "E_RIR_OP")
        doc = lower(SIMPLE)
        doc["claims"]["source_to_ir_refinement_proved"] = True
        self.reject(doc, "E_RIR_CLAIM")

    def test_owned_classification_is_not_a_trusted_flag(self):
        doc = lower(SIMPLE)
        doc["types"]["Buffer<u8>"] = {"kind": "scalar", "name": "u8"}
        self.reject(doc, "E_RIR_TYPE")
        doc = lower(SIMPLE)
        doc["types"]["Buffer<u8>"] = {"kind": "struct", "name": "Buffer<u8>", "args": [], "fields": []}
        self.reject(doc, "E_RIR_TYPE")
        doc = lower(SIMPLE)
        doc["types"]["Buffer<u8>"]["owned"] = False
        self.reject(doc, "E_RIR_SCHEMA")

    def test_unreachable_unknown_terminators_and_missing_edges_fail_closed(self):
        doc = lower(SIMPLE)
        fn = function(doc)
        fn["blocks"].append({"id": "dead", "ops": [], "term": {"op": "trust_exit"}})
        self.reject(doc, "E_RIR_TERM")
        fn["blocks"][-1]["term"] = {"op": "jump", "target": "missing"}
        self.reject(doc, "E_RIR_CFG")

    def test_unreachable_known_operation_cannot_fake_resource_qualification(self):
        # Previously the data-only verifier checked only the *shape* of a
        # dead block. Its impossible drop was never semantically executed,
        # yet the entire graph obtained resource_cfg_verified.
        document = lower(SIMPLE)
        self.assertTrue(verify_resource_ir(document)["ok"])
        fn = function(document)
        fn["blocks"].append({
            "id": "forged_dead",
            "ops": [{"op": "drop", "src": "missing_owner"}],
            "term": {"op": "return", "value": None, "loan": None},
        })
        self.reject(document, "E_RIR_UNREACHABLE")

    def test_even_well_formed_unreachable_resource_blocks_are_not_certified(self):
        document = lower(SIMPLE)
        function(document)["blocks"].append({
            "id": "dead_but_well_formed", "ops": [],
            "term": {"op": "return", "value": None, "loan": None},
        })
        self.reject(document, "E_RIR_UNREACHABLE")

    def test_source_generated_diamond_and_while_remain_reachable(self):
        document = lower("""
        fn main()->Unit effects {alloc,block,panic} {
            let b = buffer(2);
            let mut i:usize = 0;
            if i == 0 { i = i + 1; } else { i = i + 2; }
            while i < 4 { i = i + 1; }
            drop(move b);
        }""")
        result = verify_resource_ir(document)
        self.assertTrue(result["ok"], result)
        for row in result["functions"]:
            self.assertEqual(row["reachable_blocks"], row["total_blocks"])

    def test_unmodelled_raw_pointers_are_rejected(self):
        program = parse('extern "C" fn raw_value(p:raw const u8)->u8 effects {ffi,unsafe};')
        checked = check(program)
        self.assertTrue(checked.ok)
        with self.assertRaises(ResourceIRError) as raised:
            lower_resource_ir(program, checked)
        self.assertEqual(raised.exception.code, "E_RIR_LOWER_UNSUPPORTED")


if __name__ == "__main__":
    unittest.main()
