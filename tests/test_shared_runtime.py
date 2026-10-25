"""Source contracts, real concurrent execution and shared reservation failures."""
import copy
from pathlib import Path
import subprocess
import tempfile
import unittest

from hepta.backend import GROUP_RUNTIME, TASK_RUNTIME, compile_rust
from hepta.pipeline import analyze
from tests.test_task_groups import RUSTC
from tools.validate_shared_runtime import run_qualification, validate_shared_runtime_report

EFFECTS = "alloc,block,panic,write,spawn"
GROUPS = "let mut a=task_group(2,8,1);let mut b=task_group(2,8,1);"
JOIN = "group_cancel_and_join(move a);group_cancel_and_join(move b);"


class SharedRuntimeChecks(unittest.TestCase):
    def source(self, body):
        return f"fn main()->Unit effects {{{EFFECTS}}} {{" + GROUPS + body + JOIN + "}"

    def reject(self, body, code):
        report = analyze(self.source(body), native=False).report
        self.assertFalse(report["ok"], report)
        self.assertIn(code, {item["code"] for item in report["diagnostics"]}, report)

    def test_all_operation_arities_are_checked(self):
        for body in ("group_select_receive(read a,read b);", "group_budget_configure(mut a,1);",
                     "group_budget_share(mut a);", "group_budget_snapshot(read a,1);"):
            with self.subTest(body=body):
                self.reject(body, "E_ARITY")

    def test_select_preference_and_duration_have_distinct_types(self):
        self.reject("let mut x:u64=0;group_select_receive(read a,read b,mut x,1,0);", "E_TYPE")
        self.reject("let mut x:u64=0;group_select_receive(read a,read b,mut x,false,true);", "E_TYPE")

    def test_select_output_must_be_mutable(self):
        self.reject("let x:u64=0;group_select_receive(read a,read b,mut x,false,0);", "E_IMMUTABLE")

    def test_select_does_not_discharge_either_owner(self):
        source = self.source("let mut x:u64=0;group_select_receive(read a,read b,mut x,false,0);")
        report = analyze(source.replace(JOIN, ""), native=False).report
        self.assertFalse(report["ok"])
        self.assertIn("E_LINEAR_UNCONSUMED", {item["code"] for item in report["diagnostics"]})

    def test_select_requires_declared_effects(self):
        report = analyze(self.source("let mut x:u64=0;group_select_receive(read a,read b,mut x,false,0);").replace(
            f"effects {{{EFFECTS}}}", "effects {}"), native=False).report
        self.assertFalse(report["ok"])
        self.assertIn("E_EFFECT", {item["code"] for item in report["diagnostics"]})

    def test_configure_requires_mutable_group_and_numeric_limits(self):
        self.reject("group_budget_configure(read a,1,1,1,65536,65536);", "E_BORROW_MODE")
        self.reject("group_budget_configure(mut a,true,1,1,65536,65536);", "E_TYPE")

    def test_share_keeps_each_group_owner_obligation(self):
        report = analyze(self.source("group_budget_share(mut b,read a);").replace("group_cancel_and_join(move b);", ""), native=False).report
        self.assertFalse(report["ok"])
        self.assertIn("E_LINEAR_UNCONSUMED", {item["code"] for item in report["diagnostics"]})

    def test_budget_report_cannot_be_forged(self):
        self.reject("let value=GroupBudgetReport{};", "E_REPORT_CONSTRUCTION")

    def test_budget_contract_reports_only_attached_reservations(self):
        report = analyze(self.source("group_budget_configure(mut a,2,8,4,131072,65536);"), native=False).report
        self.assertTrue(report["ok"], report)
        contract = next(item for item in report["resource_contracts"] if item["kind"] == "shared_task_budget")
        self.assertEqual(contract["scope"], "explicitly_attached_group_instances")
        self.assertEqual(contract["limits"], {"reserved_threads": 2, "reserved_input_bytes": 8,
                         "reserved_queue_slots": 4, "reserved_requested_stack_bytes": 131072,
                         "worker_stack_request": 65536})
        self.assertIn("FFI_allocations", contract["excludes"])
        self.assertIn("OS_stack_rounding_and_guard_pages", contract["excludes"])
        self.assertIn("process_RSS", contract["excludes"])
        self.assertIs(contract["configuration_can_be_refused"], True)


@unittest.skipUnless(RUSTC, "requires native Rust compiler")
class SharedRuntimeNativeTests(unittest.TestCase):
    def runtime(self, source):
        with tempfile.TemporaryDirectory(prefix="hepta-shared-runtime-test-") as directory:
            output = Path(directory) / "run"
            build = compile_rust("#![allow(unused,dead_code)]\n" + TASK_RUNTIME + GROUP_RUNTIME + source,
                                 rustc=RUSTC, crate_type="bin", output=output)
            self.assertTrue(build["ok"], build)
            return subprocess.run([output], capture_output=True, text=True, timeout=15)

    def test_aliasing_target_and_sponsor_fails_native_borrow_check(self):
        source = SharedRuntimeChecks().source("group_budget_share(mut a,read a);")
        report = analyze(source, native=True, rustc=RUSTC, crate_type="bin").report
        self.assertFalse(report["ok"], report)
        self.assertIn("E0502", {item["code"] for item in report["diagnostics"]}, report)

    def test_invalid_configuration_and_activity_do_not_attach(self):
        run = self.runtime(r'''
fn worker(data:Vec<u8>,_:&HeptaCancellation,_:&HeptaSender)->u64{drop(data);0}
fn main(){
    let mut a=__hepta_group_new(2,8,2);
    assert!(!__hepta_group_budget_snapshot(&a).h_attached);
    assert!(!__hepta_group_budget_configure(&mut a,2,8,1,131072,65536));
    assert!(!__hepta_group_budget_configure(&mut a,2,8,2,131072,65535));
    assert!(!__hepta_group_budget_configure(&mut a,2,8,2,usize::MAX,usize::MAX));
    assert!(!__hepta_group_budget_snapshot(&a).h_attached);
    assert!(__hepta_group_spawn(&mut a,worker,vec![0]));
    assert!(!__hepta_group_budget_configure(&mut a,2,8,2,131072,65536));
    let mut b=__hepta_group_new(0,0,1);
    assert!(__hepta_group_budget_configure(&mut b,2,8,3,131072,65536));
    assert!(!__hepta_group_budget_share(&mut a,&b));
    assert_eq!(__hepta_group_budget_snapshot(&b).h_reserved_queue_slots,1);
    __hepta_group_join(a,1);__hepta_group_join(b,0);
}''')
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_pool_can_outlive_its_sponsoring_group(self):
        run = self.runtime(r'''
fn worker(data:Vec<u8>,_:&HeptaCancellation,_:&HeptaSender)->u64{drop(data);7}
fn main(){
    let mut root=__hepta_group_new(0,0,1);let mut child=__hepta_group_new(1,1,1);
    assert!(__hepta_group_budget_configure(&mut root,1,1,2,65536,65536));
    assert!(__hepta_group_budget_share(&mut child,&root));
    __hepta_group_join(root,0);
    assert_eq!(__hepta_group_budget_snapshot(&child).h_attached_groups,1);
    assert!(__hepta_group_spawn(&mut child,worker,vec![0]));
    let pool=std::sync::Arc::clone(child.budget.as_ref().unwrap());
    assert_eq!(__hepta_group_join(child,1).h_sum,7);
    let usage=pool.state.lock().unwrap();
    assert_eq!((usage.h_reserved_threads,usage.h_reserved_input_bytes,usage.h_reserved_queue_slots,
                usage.h_reserved_requested_stack_bytes,usage.h_attached_groups),(0,0,0,0,0));
}''')
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_zero_thread_budget_refuses_and_drops_input(self):
        run = self.runtime(r'''
fn worker(data:Vec<u8>,_:&HeptaCancellation,_:&HeptaSender)->u64{drop(data);7}
fn main(){
    let mut a=__hepta_group_new(1,1,1);
    assert!(__hepta_group_budget_configure(&mut a,0,0,1,0,65536));
    assert!(!__hepta_group_spawn(&mut a,worker,vec![0]));
    let usage=__hepta_group_budget_snapshot(&a);
    assert_eq!(usage.h_reserved_threads,0);assert_eq!(usage.h_rejected_admissions,1);
    assert_eq!(__hepta_group_join(a,1).h_accepted_tasks,0);
}''')
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_sealed_target_cannot_be_attached(self):
        run = self.runtime(r'''
fn main(){
    let mut a=__hepta_group_new(0,0,1);let mut b=__hepta_group_new(0,0,1);
    assert!(__hepta_group_budget_configure(&mut a,0,0,2,0,65536));
    __hepta_group_seal(&mut b);
    assert!(!__hepta_group_budget_share(&mut b,&a));
    assert!(!__hepta_group_budget_configure(&mut b,0,0,1,0,65536));
    __hepta_group_join(a,0);__hepta_group_join(b,0);
}''')
        self.assertEqual(run.returncode, 0, run.stderr)


@unittest.skipUnless(RUSTC, "requires native Rust compiler")
class SharedRuntimeQualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_qualification(rustc=RUSTC, repeats=1)

    def test_native_source_interleavings_and_real_failure_qualification(self):
        validate_shared_runtime_report(self.report)
        native = self.report["native_controls"]["runs"][0]["metrics"]
        self.assertEqual(native["registration_send_races"], 128)
        self.assertEqual(native["concurrent_budget_races"], 64)
        self.assertEqual(native["actual_spawn_or_handle_refusals"], 2)
        self.assertEqual(native["remaining_pool_reservations"], 0)

    def test_report_rejects_source_build_execution_and_claim_inflation(self):
        mutations = [
            lambda r: r.update(compiler_sha256="0" * 64),
            lambda r: r["source_files"].update({"hepta/runtime_concurrency.py": "0" * 64}),
            lambda r: r["claims"].update(whole_process_resources_bounded=True),
            lambda r: r["claims"].update(structured_task_tree_qualified_by_this_report=True),
            lambda r: r.update(repeats=True),
            lambda r: r.update(source_cases=[None]),
            lambda r: r["source_cases"].pop(),
            lambda r: r["source_cases"].append(r["source_cases"][0]),
            lambda r: r["source_cases"][0]["analysis"].update(ok=False),
            lambda r: r["source_cases"][0]["analysis"].update(checks={}),
            lambda r: r["source_cases"][0]["analysis"].update(backend={}),
            lambda r: r["source_cases"][0]["build"].update(check_only=True),
            lambda r: r["source_cases"][0]["build"].update(artifact_sha256=""),
            lambda r: r["source_cases"][0]["build"].update(flags=[]),
            lambda r: r["source_cases"][0]["runs"][0].update(returncode=True),
            lambda r: r["source_cases"][0]["runs"][0].update(elapsed_ns=-1),
            lambda r: r["source_cases"][0]["runs"][0].update(stdout="success"),
            lambda r: r["native_controls"].update(c_build=None),
            lambda r: r["native_controls"]["c_build"].update(object_bytes=0),
            lambda r: r["native_controls"].update(linked_object_sha256="0" * 64),
            lambda r: r["native_controls"]["build"].update(link_args=[]),
            lambda r: r["native_controls"]["runs"][0]["metrics"].update(registration_send_races=10000),
            lambda r: r["native_controls"]["runs"][0]["metrics"].update(actual_spawn_or_handle_refusals=0),
            lambda r: r["native_controls"]["runs"][0]["metrics"].update(remaining_pool_reservations=True),
            lambda r: r["native_controls"]["runs"][0].update(trial=1),
            lambda r: r["native_controls"]["runs"].clear(),
        ]
        for number, mutate in enumerate(mutations):
            with self.subTest(mutation=number):
                changed = copy.deepcopy(self.report)
                mutate(changed)
                with self.assertRaises(ValueError):
                    validate_shared_runtime_report(changed)


if __name__ == "__main__":
    unittest.main()
