"""Named field initialization, ownership and independent CFG rejection."""
import copy
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.backend import compile_rust, find_rustc
from hepta.checker import check
from hepta.parser import parse
from hepta.pipeline import analyze, interface_hash
from hepta.resource_ir import verify_resource_ir
from hepta.resource_lowering import lower_resource_ir
from hepta.semantic_ir import lower_checked_program

ROOT = Path(__file__).resolve().parents[1]
DECL = "struct Pair{left:Buffer<u8>,right:Buffer<u8>,tag:u64}"
INIT = "let mut p=Pair{left:buffer(3),right:buffer(5),tag:7};"
GOOD = DECL + "fn f()->Unit effects {alloc,block,panic} {" + INIT + "release(move p.left);p.left=buffer(9);drop(move p);}"


def lower(source):
    program = parse(source)
    checked = check(program)
    if not checked.ok:
        raise AssertionError([d.to_dict() for d in checked.diagnostics])
    return lower_resource_ir(program, checked)


def ops(document, name):
    return [(fn, block, index, op) for fn in document["functions"] for block in fn["blocks"]
            for index, op in enumerate(block["ops"]) if op["op"] == name]


class PartialPlaceChecks(unittest.TestCase):
    def reject(self, body, code, declarations=DECL):
        result = analyze(declarations + "fn f()->Unit effects {alloc,block,panic,write} {" + body + "}", native=False).report
        self.assertFalse(result["ok"], result)
        self.assertIn(code, [d["code"] for d in result["diagnostics"]], result)

    def accept(self, body, declarations=DECL):
        self.assertTrue(verify_resource_ir(lower(declarations + "fn f()->Unit effects {alloc,block,panic,write} {" + body + "}"))["ok"])

    def test_partial_move_preserves_copy_and_owned_siblings(self):
        self.accept(INIT + "release(move p.left);assert(p.tag==7);assert(len(p.right)==5);release(move p.right);")

    def test_nested_move_then_move_parent_after_restoration(self):
        self.accept("let mut p=Outer{pair:Pair{left:buffer(3),right:buffer(5),tag:7},last:buffer(2)};"
                    "release(move p.pair.left);p.pair.left=buffer(9);let q=move p.pair;drop(move q);release(move p.last);",
                    DECL + "struct Outer{pair:Pair,last:Buffer<u8>}")

    def test_same_fields_consumed_on_both_continuing_branches(self):
        self.accept(INIT + "if p.tag==7 {release(move p.left);}else{release(move p.left);}release(move p.right);")

    def test_loop_restores_the_same_place_state(self):
        self.accept(INIT + "for i in 0..3 {let b=move p.left;release(move b);p.left=buffer(3);}drop(move p);")

    def test_scope_forgets_only_consumed_owned_fields(self):
        self.accept("if true {" + INIT + "release(move p.left);release(move p.right);}else{}")

    def test_consuming_match_payload_partial_fields_leave_scope(self):
        self.accept("let value:Result<Pair,u8>=Result::Ok(Pair{left:buffer(3),right:buffer(5),tag:7});"
                    "match move value {Result::Ok(p)=>{release(move p.left);release(move p.right);},Result::Err(e)=>{}}")

    def test_partial_move_generic_abstract_body_without_instantiation(self):
        source = "struct Box<T>{value:T,tag:u64} fn extract<T:Owned>(b:take Box<T>)->T effects {} {return move b.value;}"
        report = verify_resource_ir(lower(source))
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["generic_functions_checked"], 1)

    def test_duplicate_field_move_rejected_before_rust(self):
        self.reject(INIT + "release(move p.left);release(move p.left);release(move p.right);", "E_USE_AFTER_MOVE")

    def test_named_field_resolution_does_not_erase_generic_arguments(self):
        self.reject(INIT + "assert(p::<u8>.tag==7);drop(move p);", "E_GENERIC_CONTEXT")

    def test_whole_move_with_missing_field_rejected(self):
        self.reject(INIT + "release(move p.left);drop(move p);", "E_USE_AFTER_MOVE")

    def test_whole_borrow_with_missing_field_rejected(self):
        self.reject(INIT + "release(move p.left);inspect(read p);release(move p.right);", "E_USE_AFTER_MOVE",
                    DECL + "fn inspect(p:read Pair)->Unit effects {} {}")

    def test_copy_sibling_after_whole_move_rejected(self):
        self.reject(INIT + "drop(move p);assert(p.tag==7);", "E_USE_AFTER_MOVE")

    def test_unconsumed_remaining_sibling_is_an_error(self):
        self.reject(INIT + "release(move p.left);", "E_LINEAR_UNCONSUMED")

    def test_different_partial_states_cannot_join(self):
        self.reject(INIT + "if true {release(move p.left);}else{release(move p.right);}drop(move p);", "E_LINEAR_BRANCH")

    def test_partial_move_in_loop_without_restoration_rejected(self):
        self.reject(INIT + "for i in 0..3 {release(move p.left);}release(move p.right);", "E_LINEAR_LOOP")

    def test_partial_move_in_short_circuit_rejected(self):
        self.reject(INIT + "let x=false&&consume(move p.left);drop(move p);", "E_LINEAR_SHORT_CIRCUIT",
                    DECL + "fn consume(b:take Buffer<u8>)->bool effects {alloc,block} {release(move b);return true;}")

    def test_live_field_cannot_be_overwritten(self):
        self.reject(INIT + "p.left=buffer(8);drop(move p);", "E_LINEAR_REASSIGN")

    def test_partial_parent_cannot_be_overwritten(self):
        self.reject("let mut p=Box{pair:Pair{left:buffer(3),right:buffer(5),tag:7}};release(move p.pair.left);"
                    "p.pair=Pair{left:buffer(2),right:buffer(4),tag:9};drop(move p);", "E_LINEAR_REASSIGN",
                    DECL + "struct Box{pair:Pair}")

    def test_restoration_cannot_revive_moved_parent(self):
        self.reject(INIT + "drop(move p);p.left=buffer(9);", "E_USE_AFTER_MOVE")

    def test_restoration_needs_mutable_binding(self):
        self.reject(INIT.replace("let mut", "let") + "release(move p.left);p.left=buffer(9);drop(move p);", "E_LINEAR_REASSIGN")

    def test_borrowed_field_cannot_be_moved(self):
        report = analyze(DECL + "fn f(p:mut Pair)->Unit effects {alloc,block} {release(move p.left);}", native=False).report
        self.assertIn("E_MOVE_BORROW", [d["code"] for d in report["diagnostics"]])


class PartialPlaceIR(unittest.TestCase):
    def reject(self, document, code):
        report = verify_resource_ir(document)
        self.assertFalse(report["ok"], report)
        self.assertEqual(report["diagnostics"][0]["code"], code, report)

    def test_partial_operations_require_v3_and_legacy_graphs_still_work(self):
        doc = lower(GOOD)
        self.assertEqual(doc["schema"], "hepta.resource-ir.v3")
        doc["schema"] = "hepta.resource-ir.v2"
        self.reject(doc, "E_RIR_SCHEMA")
        old = lower("fn f()->Unit effects {alloc,block,panic} {let b=buffer(3);drop(move b);}")
        for schema in ("hepta.resource-ir.v1", "hepta.resource-ir.v2"):
            old["schema"] = schema
            self.assertTrue(verify_resource_ir(old)["ok"])

    def test_duplicated_field_take_rejected(self):
        doc = lower(GOOD)
        _, block, index, op = ops(doc, "take_field")[0]
        block["ops"].insert(index + 1, copy.deepcopy(op))
        self.reject(doc, "E_RIR_USE_AFTER_MOVE")

    def test_take_during_ancestor_loan_rejected(self):
        doc = lower(GOOD)
        _, block, index, op = ops(doc, "take_field")[0]
        block["ops"].insert(index, {"op":"borrow", "id":"attack", "place":{"root":op["place"]["root"],"path":[]}, "type":"Pair", "mode":"read"})
        self.reject(doc, "E_RIR_LOAN_CONFLICT")

    def test_disjoint_field_loan_during_take_is_allowed(self):
        doc = lower(GOOD)
        _, block, index, op = ops(doc, "take_field")[0]
        block["ops"].insert(index, {"op":"borrow", "id":"disjoint", "place":{"root":op["place"]["root"],"path":["right"]}, "type":"Buffer<u8>", "mode":"read"})
        block["ops"].insert(index + 2, {"op":"end_borrow", "id":"disjoint"})
        self.assertTrue(verify_resource_ir(doc)["ok"])

    def test_forged_field_type_rejected(self):
        doc = lower(GOOD)
        fn, _, _, op = ops(doc, "take_field")[0]
        next(s for s in fn["locals"] if s["id"] == op["dest"])["type"] = "usize"
        self.reject(doc, "E_RIR_MOVE")

    def test_init_cannot_overwrite_sibling(self):
        doc = lower(GOOD)
        ops(doc, "init_field")[0][3]["place"]["path"] = ["right"]
        self.reject(doc, "E_RIR_DOUBLE_OWNER")

    def test_init_cannot_ignore_mutability(self):
        doc = lower(GOOD)
        fn, _, _, op = ops(doc, "init_field")[0]
        next(s for s in fn["locals"] if s["id"] == op["place"]["root"])["mutable"] = False
        self.reject(doc, "E_RIR_MUTABILITY")

    def test_forget_cannot_drop_remaining_owner(self):
        doc = lower(GOOD)
        _, block, index, op = ops(doc, "take_field")[0]
        block["ops"].insert(index + 1, {"op":"forget", "src":op["place"]["root"]})
        self.reject(doc, "E_RIR_LEAK")

    def test_removed_restoration_prevents_whole_move(self):
        doc = lower(GOOD)
        _, block, index, _ = ops(doc, "init_field")[0]
        del block["ops"][index]
        self.reject(doc, "E_RIR_USE_AFTER_MOVE")

    def test_moving_parent_during_child_loan_rejected(self):
        doc = lower(GOOD)
        _, block, index, op = ops(doc, "init_field")[0]
        block["ops"].insert(index + 1, {"op":"borrow", "id":"attack", "place":op["place"], "type":"Buffer<u8>", "mode":"read"})
        self.reject(doc, "E_RIR_LOAN_CONFLICT")


class DeclaredReturnOrigin(unittest.TestCase):
    def test_explicit_origin_preserved_in_hsir_interface_and_cfg(self):
        source = "fn pick(a:read u64,b:read u64)->read u64 from a effects {} {return read a;}"
        p = parse(source); checked = check(p)
        self.assertTrue(checked.ok, checked.diagnostics)
        self.assertEqual(lower_checked_program(p, checked)["functions"][0]["return_origin"], "a")
        self.assertEqual(lower(source)["functions"][0]["returns"]["origin"], "p0")
        other = parse(source.replace("from a", "from b").replace("return read a", "return read b"))
        self.assertNotEqual(interface_hash(p), interface_hash(other))

    def test_wrong_missing_or_value_origin_rejected(self):
        for signature, body in [
            ("->read u64", "return read a;"),
            ("->read u64 from missing", "return read a;"),
            ("->read u64 from a", "return read b;"),
            ("->u64 from a", "return a;"),
            ("->mut u64 from a", "return mut a;"),
        ]:
            with self.subTest(signature=signature, body=body):
                result = analyze("fn f(a:read u64,b:read u64)" + signature + " effects {} {" + body + "}", native=False).report
                self.assertFalse(result["ok"], result)

    def test_cannot_hide_wrong_origin_in_nested_call(self):
        source = "fn pick(a:read u64,b:read u64)->read u64 from b effects {} {return read b;}"
        source += "fn f(x:read u64,y:read u64)->read u64 from x effects {} {return read pick(read x,read y);}"
        result = analyze(source, native=False).report
        self.assertIn("E_BORROW_RETURN_SOURCE", [d["code"] for d in result["diagnostics"]])

    def test_independent_ir_rejects_origin_swap_and_legacy_profile(self):
        source = "fn pick(a:read u64,b:read u64)->read u64 from a effects {} {return read a;}"
        doc = lower(source)
        doc["functions"][0]["returns"]["origin"] = "p1"
        self.assertFalse(verify_resource_ir(doc)["ok"])
        doc = lower(source); doc["schema"] = "hepta.resource-ir.v2"
        self.assertFalse(verify_resource_ir(doc)["ok"])


class NativePlaces(unittest.TestCase):
    def test_qualification_has_real_cleanup_and_rejects_forged_evidence(self):
        from tools.qualify_places import qualify_places, validate_places_qualification
        with tempfile.TemporaryDirectory(prefix="hepta-places-evidence-") as td:
            root=Path(td)
            report=qualify_places(root/'native',rustc=find_rustc(os.environ.get('RUSTC')),retain_graph=root/'graph.json')
            self.assertTrue(report['ok'],report)
            validate_places_qualification(report)
            mutations=[
                lambda r:r.update(ok=False),
                lambda r:r['claims'].update(source_to_ir_refinement_proved=True),
                lambda r:r.update(allocation_scope='global process'),
                lambda r:r['projects'].pop(),
                lambda r:r['projects'].append(copy.deepcopy(r['projects'][0])),
                lambda r:r['projects'][0]['native_gate'].update(ok=False),
                lambda r:r['projects'][0]['native_gate'].update(compiler_sha256='0'*64),
                lambda r:r['projects'][0]['native_gate']['backend'].update(check_only=False),
                lambda r:r['projects'][0]['native_gate'].update(rust_sha256='0'*64),
                lambda r:r['projects'][0]['native_build'].update(check_only=True),
                lambda r:r['projects'][0]['native_build'].update(artifact_bytes=0),
                lambda r:r['projects'][0]['native_build'].update(artifact_bytes=True),
                lambda r:r['projects'][0]['native_build'].update(artifact_sha256='0'*64),
                lambda r:r['projects'][0]['native_build'].update(rust_sha256='0'*64),
                lambda r:r['projects'][0]['native_build'].update(target='invented-host'),
                lambda r:r['projects'][0]['execution'].update(exit_code=False),
                lambda r:r['projects'][0]['execution'].update(executable_sha256='0'*64),
                lambda r:r['projects'][0]['execution'].update(stderr='failed'),
                lambda r:r['projects'][0]['execution'].update(stdout='{}'),
                lambda r:r['projects'][0]['observations'].pop(),
                lambda r:r['projects'][0]['observations'][0].update(allocated=0),
                lambda r:r['projects'][1]['observations'][0].update(live_bytes=4093),
                lambda r:r['projects'][0]['resource_ir'].update(bytes=0),
                lambda r:r['projects'][0]['resource_ir'].update(sha256='0'*64),
                lambda r:r['projects'][0]['resource_ir'].update(canonical_sha256='0'*64),
                lambda r:r['projects'][0]['resource_verifier'].update(ok=False),
                lambda r:r['projects'][1]['resource_verifier'].update(ok=True),
                lambda r:r['adversarial_checks'].pop(),
                lambda r:r['adversarial_checks'][0].update(ok=False),
            ]
            for number,mutate in enumerate(mutations):
                with self.subTest(mutation=number):
                    changed=copy.deepcopy(report);mutate(changed)
                    with self.assertRaises(ValueError):validate_places_qualification(changed)

    def test_native_nested_fields_loops_and_selected_borrow_lifetimes(self):
        rustc = find_rustc(os.environ.get("RUSTC"))
        source = (ROOT / "examples/places/library.hepta").read_text()
        source += """
        fn mutable(a:mut u64,b:read u64)->mut u64 from a effects {} {return mut a;}
        fn set(value:mut u64,new_value:u64)->Unit effects {write} {value=new_value;}
        fn main()->Unit effects {alloc,block,panic,write} {
          assert(exercise(false,12281)==12281);assert(exercise(true,12281)==7);assert(cycles()==11);
          let mut value:u64=3;let other:u64=9;set(mut mutable(mut value,read other),17);assert(value==17);
        }"""
        result = analyze(source, rustc=rustc, crate_type="bin")
        self.assertTrue(result.report["ok"], result.report)
        self.assertTrue(verify_resource_ir(lower(source))["ok"])
        with tempfile.TemporaryDirectory(prefix="hepta-places-") as td:
            native = compile_rust(result.rust, rustc=rustc, crate_type="bin", output=Path(td) / "run")
            self.assertTrue(native["ok"], native)
            execution = subprocess.run([native["artifact"]], capture_output=True, text=True, timeout=15)
            self.assertEqual(execution.returncode, 0, execution.stderr)


if __name__ == "__main__":
    unittest.main()
