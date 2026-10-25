"""Source ownership, independent topology protocol and actual native trees."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

from hepta.concurrent_ir import verify_concurrent_ir
from hepta.pipeline import analyze, concurrent_ir_analysis
from tests.test_task_groups import RUSTC
from tools.validate_task_tree import CONTROLS, execute, run_qualification, validate_task_tree_report

ROOT = Path(__file__).resolve().parents[1]
EFFECTS = "alloc,block,panic,write,spawn"
TREE = "let mut root=task_group(1,8,1);let child=task_group(0,0,1);group_adopt(mut root,move child);"
JOIN = "group_tree_join(move root);"


def source(body):
    return f"fn main()->Unit effects {{{EFFECTS}}} {{" + body + "}"


def graph(text):
    checked = analyze(text, native=False)
    result = concurrent_ir_analysis(checked)
    if result["concurrent_ir"] is None:
        raise AssertionError(result)
    return result["concurrent_ir"]


class TreeSourceChecks(unittest.TestCase):
    def reject(self, text, code):
        report = analyze(source(text), native=False).report
        self.assertFalse(report["ok"], report)
        self.assertIn(code, {item["code"] for item in report["diagnostics"]}, report)

    def test_every_new_builtin_checks_arity(self):
        for call in ("group_adopt(mut root);", "group_tree_snapshot();", "group_tree_join();", "group_tree_cancel_and_join();"):
            with self.subTest(call=call):
                self.reject(TREE + call + JOIN, "E_ARITY")

    def test_child_owner_cannot_be_used_after_adoption(self):
        self.reject(TREE + "group_snapshot(read child);" + JOIN, "E_USE_AFTER_MOVE")

    def test_parent_join_obligation_survives_child_transfer(self):
        self.reject(TREE, "E_LINEAR_UNCONSUMED")

    def test_cancel_does_not_discharge_tree_join(self):
        self.reject(TREE + "group_cancel(mut root);", "E_LINEAR_UNCONSUMED")

    def test_tree_report_is_copy_and_cannot_be_constructed(self):
        self.reject(TREE + "let x=GroupTreeReport{};" + JOIN, "E_REPORT_CONSTRUCTION")
        result = analyze(source(TREE + "let r=group_tree_snapshot(read root);let s=r;assert(r.groups==s.groups);" + JOIN), native=False).report
        self.assertTrue(result["ok"], result)

    def test_adoption_and_snapshot_modes_are_explicit(self):
        self.reject(TREE.replace("mut root,move child", "read root,move child") + JOIN, "E_BORROW_MODE")
        self.reject(TREE.replace("move child", "child") + JOIN, "E_MOVE_REQUIRED")
        self.reject(TREE + "group_tree_snapshot(mut root);" + JOIN, "E_BORROW_MODE")

    def test_consuming_refusal_is_declared_blocking_and_has_finite_contract(self):
        checked = analyze(source(TREE + JOIN), native=False).report
        self.assertTrue(checked["ok"], checked)
        contract = next(x for x in checked["resource_contracts"] if x["kind"] == "structured_task_tree")
        self.assertEqual(contract["limits"], {"groups": 256, "depth": 16})
        self.assertEqual(contract["refusal"], "consumes_cancels_and_joins_child_subtree")
        self.assertEqual(contract["termination"], "cooperative_workers_only")
        self.assertIn("process_RSS", contract["excludes"])
        missing = analyze(source(TREE + JOIN).replace(EFFECTS, "alloc,panic,write"), native=False).report
        self.assertFalse(missing["ok"])
        self.assertIn("E_EFFECT", {x["code"] for x in missing["diagnostics"]})

    def test_adopted_child_cannot_escape_via_post_transfer_spawn(self):
        program = (ROOT / "examples/groups/tree_pipeline.hepta").read_text().replace(
            "let before = group_tree_snapshot(read root);", "group_spawn(mut leaf, emit, move buffer(4));")
        checked = analyze(program, native=False).report
        self.assertFalse(checked["ok"])
        self.assertIn("E_USE_AFTER_MOVE", {x["code"] for x in checked["diagnostics"]})

    def test_C_backend_explicitly_rejects_tree_profile(self):
        for name in ("tree_pipeline", "tree_cancellation"):
            result = analyze((ROOT / f"examples/groups/{name}.hepta").read_text(), native=False, backend="c")
            self.assertFalse(result.report["ok"], result.report)
            self.assertIsNone(result.c)
            self.assertTrue(any(x["code"].startswith("E_C_") for x in result.report["diagnostics"]))

    @unittest.skipUnless(RUSTC, "requires native Rust compiler")
    def test_native_borrow_gate_rejects_self_adoption(self):
        result = analyze(source("let mut root=task_group(0,0,1);group_adopt(mut root,move root);"),
                         native=True, rustc=RUSTC, crate_type="bin").report
        self.assertFalse(result["ok"])
        self.assertIn("E0505", {x["code"] for x in result["diagnostics"]})


class TreeIndependentIR(unittest.TestCase):
    def test_parent_child_transfer_is_explicit_and_independent(self):
        doc = graph(source(TREE + JOIN))
        operations = doc["functions"][0]["blocks"][0]["operations"]
        adopt = next(x for x in operations if x["op"] == "adopt")
        self.assertNotEqual(adopt["parent"], adopt["child"])
        self.assertEqual(adopt["refusal"], "cancel_and_join_child_subtree")
        result = verify_concurrent_ir(json.loads(json.dumps(doc)))
        self.assertTrue(result["ok"], result)
        self.assertEqual((result["group_adoptions"], result["tree_joins"]), (1, 1))
        self.assertFalse(result["claims"]["runtime_data_race_freedom_proved"])
        self.assertFalse(result["claims"]["source_to_ir_refinement_proved"])

    def test_parent_owner_move_preserves_join_obligation(self):
        doc = graph(source(TREE + "let moved=move root;group_tree_join(move moved);"))
        self.assertTrue(verify_concurrent_ir(doc)["ok"])

    def test_independent_topology_mutations_fail_closed(self):
        original = graph(source(TREE + JOIN))
        mutations = {
            "orphaned_parent": lambda ops, adopt: ops.pop(),
            "refusal_detaches": lambda ops, adopt: adopt.update(refusal="detach_child"),
            "self_adoption": lambda ops, adopt: adopt.update(parent=adopt["child"]),
            "unknown_parent": lambda ops, adopt: adopt.update(parent="missing"),
            "resurrected_child": lambda ops, adopt: ops.append({"op": "group", "src": adopt["child"], "mode": "group_snapshot"}),
            "double_adoption": lambda ops, adopt: ops.insert(ops.index(adopt) + 1, copy.deepcopy(adopt)),
            "hidden_child": lambda ops, adopt: adopt.update(hidden_child="unverified"),
            "lost_transfer": lambda ops, adopt: ops.remove(adopt),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                doc = copy.deepcopy(original)
                operations = doc["functions"][0]["blocks"][0]["operations"]
                adopt = next(x for x in operations if x["op"] == "adopt")
                mutate(operations, adopt)
                self.assertFalse(verify_concurrent_ir(doc)["ok"])

    def test_self_adoption_rejected_without_native_backend(self):
        doc = graph(source("let mut root=task_group(0,0,1);group_adopt(mut root,move root);"))
        self.assertFalse(verify_concurrent_ir(doc)["ok"])

    def test_loop_adoptions_keep_the_parent_join_obligation(self):
        doc = graph(source("let mut root=task_group(0,0,1);for i in 0..3 {"
                           "let child=task_group(0,0,1);group_adopt(mut root,move child);}" + JOIN))
        self.assertTrue(verify_concurrent_ir(doc)["ok"])


@unittest.skipUnless(RUSTC, "requires native Rust compiler")
class TreeNativeQualification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_qualification(rustc=RUSTC, repeats=1)

    def test_native_three_level_failure_refusal_budget_and_race_matrix(self):
        self.assertEqual(self.report["status"], "passed", self.report["errors"])
        validate_task_tree_report(self.report, minimum_repeats=1)
        self.assertEqual(self.report["native_controls"]["runs"][0]["metrics"], CONTROLS)
        with self.assertRaises(ValueError):
            validate_task_tree_report(self.report)

    def test_wrong_native_runtimes_really_fail_or_time_out(self):
        for case in self.report["negative_controls"]:
            self.assertGreater(case["build"]["artifact_bytes"], 0)
            execution = case["execution"]
            if case["expected"] == "timeout":
                self.assertEqual(execution["status"], "timeout")
                self.assertIsNone(execution["returncode"])
                self.assertGreaterEqual(execution["elapsed_ns"], 2_000_000_000)
            else:
                self.assertNotEqual(execution["returncode"], 0)
                self.assertTrue(base64.b64decode(execution["stderr_base64"]))

    def test_validator_rejects_source_execution_topology_and_claim_mutations(self):
        def corrupt_raw(r):
            run = r["native_controls"]["runs"][0]["execution"]
            run["stdout_base64"] = base64.b64encode(b"invented observation\n").decode()
            run["stdout_sha256"] = hashlib.sha256(b"invented observation\n").hexdigest()
        mutations = [
            lambda r: r.update(compiler_sha256="0"*64),
            lambda r: r["source_files"].update({"hepta/runtime_task_tree.py":"0"*64}),
            lambda r: r["profile"].update(tree_groups=257),
            lambda r: r["profile"].update(tree_depth=True),
            lambda r: r["claims"].update(runtime_race_freedom_proved=True),
            lambda r: r["claims"].update(C_backend_tree_support=0),
            lambda r: r.update(repeats=True),
            lambda r: r.update(repeats=0),
            lambda r: r.update(errors=["previous failure omitted"]),
            lambda r: r["denominators"].update(adoption_failure_races=129),
            lambda r: r["denominators"].update(native_runs=True),
            lambda r: r["host"].update(system="simulator"),
            lambda r: r["toolchain"].update(executable_sha256="0"*64),
            lambda r: r["toolchain"].update(path="/does-not-exist/untrusted-compiler"),
            lambda r: r["c_compiler"].update(sha256="0"*64),
            lambda r: r["linker"].update(sha256="0"*64),
            lambda r: r["injector"].update(artifact_bytes=0),
            lambda r: r["injector"].update(artifact_sha256="0"*64),
            lambda r: r["native_controls"]["build"].update(linked_object_sha256="0"*64),
            lambda r: r["native_controls"]["build"].update(source_sha256="0"*64),
            lambda r: r["native_controls"]["build"].update(artifact_sha256="0"*64),
            lambda r: r["native_controls"]["build"].update(artifact_bytes=0),
            lambda r: r["native_controls"]["build"].update(flags=[]),
            lambda r: r["native_controls"]["build"]["execution"].update(returncode=1),
            lambda r: r["native_controls"]["build"]["execution"].update(argv=["timer-only-fixture"]),
            lambda r: r["native_controls"]["runs"].clear(),
            lambda r: r["native_controls"]["runs"][0].update(trial=True),
            lambda r: r["native_controls"]["runs"][0]["metrics"].update(adoption_failure_races=10000),
            lambda r: r["native_controls"]["runs"][0]["metrics"].update(remaining_pool_reservations=True),
            lambda r: r["native_controls"]["runs"][0]["execution"].update(returncode=True),
            lambda r: r["native_controls"]["runs"][0]["execution"].update(elapsed_ns=0),
            lambda r: r["native_controls"]["runs"][0]["execution"].update(timeout_seconds=True),
            lambda r: r["native_controls"]["runs"][0]["execution"].update(executable_sha256="0"*64),
            lambda r: r["native_controls"]["runs"][0]["execution"].update(stdout_base64="invalid base64"),
            corrupt_raw,
            lambda r: r["source_cases"].pop(),
            lambda r: r["source_cases"].append(copy.deepcopy(r["source_cases"][0])),
            lambda r: r["source_cases"][0]["analysis"].update(ok=False),
            lambda r: r["source_cases"][0]["analysis"].update(checks={}),
            lambda r: r["source_cases"][0]["analysis"].update(rust_sha256="0"*64),
            lambda r: r["source_cases"][0]["analysis"].update(backend=None),
            lambda r: r["source_cases"][0]["analysis"]["claims"].update(whole_language_soundness_proved=True),
            lambda r: r["source_cases"][0].update(concurrent_ir=None),
            lambda r: r["source_cases"][0]["concurrent_ir"].update(source_sha256="0"*64),
            lambda r: r["source_cases"][0]["ir_replay"].update(argv=["missing"]),
            lambda r: r["source_cases"][0]["ir_replay"].update(stdout_base64=base64.b64encode(b"{}").decode()),
            lambda r: r["negative_controls"].pop(),
            lambda r: r["negative_controls"][0]["build"].update(artifact_bytes=0),
            lambda r: r["negative_controls"][0]["execution"].update(returncode=0),
            lambda r: r["negative_controls"][0].update(expected="success"),
            lambda r: r["negative_controls"][-1]["execution"].update(status="completed", returncode=1),
            lambda r: r["negative_controls"][-1]["execution"].update(elapsed_ns=1),
            lambda r: r["negative_controls"][-1]["execution"].update(timeout_seconds=100),
        ]
        for number, mutate in enumerate(mutations):
            with self.subTest(number=number):
                damaged = copy.deepcopy(self.report)
                mutate(damaged)
                with self.assertRaises(ValueError):
                    validate_task_tree_report(damaged, minimum_repeats=1)

    def test_malformed_reports_fail_closed(self):
        for value in (None, {}, [], {"schema":1}):
            with self.assertRaises(ValueError):
                validate_task_tree_report(value, minimum_repeats=1)


class TreeFailureRecording(unittest.TestCase):
    def test_actual_timeout_retains_partial_raw_output(self):
        result = execute([sys.executable, "-c", "import sys,time;sys.stdout.buffer.write(b'partial\\x00');sys.stdout.flush();time.sleep(30)"], timeout=1)
        self.assertEqual(result["status"], "timeout")
        self.assertIsNone(result["returncode"])
        self.assertEqual(base64.b64decode(result["stdout_base64"]), b"partial\x00")
        self.assertEqual(result["stdout_sha256"], hashlib.sha256(b"partial\x00").hexdigest())

    def test_failed_launch_is_retained(self):
        result = execute(["/does-not-exist/hepta-task-tree-qualification"])
        self.assertEqual(result["status"], "launch_failed")
        self.assertIsNone(result["returncode"])
        self.assertTrue(result["error"])


if __name__ == "__main__":
    unittest.main()
