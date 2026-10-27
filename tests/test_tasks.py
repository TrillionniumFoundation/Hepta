"""Native and adversarial tests for structured Task/Cancellation ownership.

Cancellation is cooperative.  The runtime tests observe successful joins and
resource release; they deliberately do not infer latency or deadlock guarantees.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from hepta.backend import compile_rust
from hepta.pipeline import analyze


ROOT = Path(__file__).resolve().parents[1]
RUSTC = Path(os.environ.get("RUSTC", ROOT.parent / "toolchains" / "rust-1.90.0" / "bin" / "rustc"))
NATIVE_AVAILABLE = RUSTC.is_file() and os.access(RUSTC, os.X_OK)
TASK_EFFECTS = "alloc, block, spawn, panic"
WORKER = """fn worker(data: take Buffer<u8>, token: read Cancellation) -> u64
effects {alloc, block} {
    let count: usize = len(read data);
    release(move data);
    return count as u64;
}
"""


def with_parent(body: str, effects: str = TASK_EFFECTS) -> str:
    return WORKER + f"fn parent() -> Unit effects {{{effects}}} {{ {body} }}"


def diagnostics(report: dict) -> set[str]:
    return {d["code"] for d in report.get("diagnostics", [])}


class TaskRejectionTests(unittest.TestCase):
    def rejects(self, source: str, expected_code: str | None = None) -> dict:
        report = analyze(source, native=True, rustc=str(RUSTC)).report
        self.assertFalse(report["ok"], report)
        self.assertEqual(report["checks"]["rust_borrows_types"], "not_run", report)
        if expected_code:
            self.assertIn(expected_code, diagnostics(report), report)
        return report

    def test_unjoined_handle_is_rejected(self):
        self.rejects(with_parent("let data=buffer(4); let task=spawn(worker,move data);"),
                     "E_LINEAR_UNCONSUMED")

    def test_discarding_fresh_task_is_rejected(self):
        self.rejects(with_parent("spawn(worker,move buffer(4));"), "E_LINEAR_DISCARD")

    def test_join_on_only_one_branch_is_rejected(self):
        source = WORKER + f"""fn parent(choose: bool) -> Unit effects {{{TASK_EFFECTS}}} {{
            let task=spawn(worker,move buffer(4));
            if choose {{ join(move task); }}
        }}"""
        self.rejects(source, "E_LINEAR_BRANCH")

    def test_early_return_cannot_abandon_task(self):
        source = WORKER + f"""fn parent(choose: bool) -> Unit effects {{{TASK_EFFECTS}}} {{
            let task=spawn(worker,move buffer(4));
            if choose {{ return; }}
            join(move task);
        }}"""
        self.rejects(source, "E_LINEAR_UNCONSUMED")

    def test_join_cannot_be_deferred_to_loop_that_might_not_execute(self):
        self.rejects(with_parent("let task=spawn(worker,move buffer(4)); for i in 0..0 {join(move task);}"),
                     "E_LINEAR_LOOP")

    def test_task_cannot_escape_as_return(self):
        source = WORKER + f"fn parent() -> Task<u64> effects {{{TASK_EFFECTS}}} {{ return move spawn(worker,move buffer(4)); }}"
        self.rejects(source, "E_TASK_SCOPE")

    def test_task_cannot_escape_as_parameter_even_with_borrow_mode(self):
        for mode in ("take", "read", "mut"):
            with self.subTest(mode=mode):
                self.rejects(f"fn accept(task: {mode} Task<u64>) -> Unit effects {{}} {{}}",
                             "E_TASK_SCOPE")

    def test_task_cannot_be_hidden_in_aggregate_or_raw_pointer(self):
        sources = [
            "struct Hidden { task: Task<u64> }",
            "fn hidden(p: raw const Task<u64>) -> Unit effects {} {}",
            with_parent("let task=spawn(worker,move buffer(4)); let box=[move task];"),
        ]
        for source in sources:
            with self.subTest(source=source):
                self.rejects(source, "E_NESTED_LINEAR")

    def test_task_result_type_is_currently_u64_only(self):
        self.rejects(with_parent("let task:Task<i64>=spawn(worker,move buffer(4));join(move task);"),
                     "E_TASK_TYPE")

    def test_input_transfer_requires_move_and_cannot_move_a_borrow(self):
        self.rejects(with_parent("let data=buffer(4);let task=spawn(worker,data);join(move task);"),
                     "E_MOVE_REQUIRED")
        source = WORKER + f"fn parent(data: read Buffer<u8>) -> Unit effects {{{TASK_EFFECTS}}} {{ let task=spawn(worker,move data);join(move task); }}"
        self.rejects(source, "E_MOVE_BORROW")

    def test_input_cannot_be_used_again_after_transfer(self):
        self.rejects(with_parent("let data=buffer(4);let task=spawn(worker,move data);release(move data);join(move task);"),
                     "E_USE_AFTER_MOVE")

    def test_join_and_cancel_join_require_consuming_owner(self):
        for operation in ("join", "cancel_and_join"):
            with self.subTest(operation=operation):
                self.rejects(with_parent(f"let task=spawn(worker,move buffer(4));{operation}(task);"),
                             "E_MOVE_REQUIRED")

    def test_handle_cannot_be_joined_twice_or_implicitly_copied(self):
        self.rejects(with_parent("let task=spawn(worker,move buffer(4));join(move task);cancel_and_join(move task);"),
                     "E_USE_AFTER_MOVE")
        self.rejects(with_parent("let task=spawn(worker,move buffer(4));let alias=task;join(move task);join(move alias);"),
                     "E_MOVE_REQUIRED")

    def test_buffer_release_cannot_dispose_of_task(self):
        self.rejects(with_parent("let task=spawn(worker,move buffer(4));release(move task);"))

    def test_cancellation_cannot_be_forged(self):
        sources = [
            "struct Cancellation { flag: bool }",
            "fn fake() -> Unit effects {} { let token=Cancellation {}; }",
            "fn fake() -> Unit effects {} { let token:Cancellation=0; }",
            "fn fake() -> Cancellation effects {} { return 0; }",
        ]
        for source in sources:
            with self.subTest(source=source):
                self.rejects(source)

    def test_cancellation_cannot_be_owned_mutated_or_retained(self):
        sources = [
            "fn f(token: take Cancellation) -> Unit effects {} {}",
            "fn f(token: mut Cancellation) -> Unit effects {} {}",
            "fn f(token: read Cancellation) -> Unit effects {} {let held=token;}",
            "fn f(token: read Cancellation) -> Unit effects {} {let held=move token;}",
            "fn f(token: read Cancellation) -> Unit effects {} {let held=[token];}",
            "struct Hold { token: Cancellation }",
            "fn f(token: read Cancellation) -> Cancellation effects {} {return token;}",
        ]
        for source in sources:
            with self.subTest(source=source):
                self.rejects(source, "E_CANCELLATION_TYPE")

    def test_polling_requires_explicit_read_borrow(self):
        for arg in ("token", "mut token", "move token"):
            with self.subTest(arg=arg):
                self.rejects(f"fn f(token: read Cancellation) -> bool effects {{}} {{return cancelled({arg});}}",
                             "E_BORROW_MODE")

    def test_worker_must_be_local_named_function_with_exact_signature(self):
        self.rejects(with_parent("let task=spawn(missing,move buffer(4));join(move task);"),
                     "E_TASK_WORKER")
        source = "fn bad(data: take Buffer<u8>) -> u64 effects {alloc,block} {release(move data);return 0;}"
        source += f"fn parent() -> Unit effects {{{TASK_EFFECTS}}} {{let task=spawn(bad,move buffer(4));join(move task);}}"
        self.rejects(source, "E_TASK_WORKER")

    def test_worker_cannot_hide_nested_spawn_behind_helpers(self):
        source = WORKER.replace("fn worker", "fn leaf") + f"""
fn low() -> u64 effects {{{TASK_EFFECTS}}} {{let task=spawn(leaf,move buffer(1));return join(move task);}}
fn middle() -> u64 effects {{{TASK_EFFECTS}}} {{return low();}}
fn worker(data:take Buffer<u8>, token:read Cancellation) -> u64 effects {{{TASK_EFFECTS}}} {{
    release(move data);return middle();
}}
fn parent() -> Unit effects {{{TASK_EFFECTS}}} {{let task=spawn(worker,move buffer(4));join(move task);}}
"""
        report = self.rejects(source, "E_TASK_WORKER_EFFECT")
        self.assertIn("spawn", report["effects"]["worker"])

    def test_worker_cannot_hide_unsafe_behind_helpers(self):
        source = f"""
fn low() -> u64 effects {{unsafe}} {{unsafe {{return 7;}}}}
fn middle() -> u64 effects {{unsafe}} {{unsafe {{return low();}}}}
fn worker(data:take Buffer<u8>, token:read Cancellation) -> u64 effects {{alloc,block,unsafe}} {{
    release(move data);unsafe {{return middle();}}
}}
fn parent() -> Unit effects {{{TASK_EFFECTS},unsafe}} {{let task=spawn(worker,move buffer(4));join(move task);}}
"""
        report = self.rejects(source, "E_TASK_WORKER_EFFECT")
        self.assertIn("unsafe", report["effects"]["worker"])

    def test_worker_cannot_hide_foreign_call_behind_helpers(self):
        source = f"""
extern "C" fn c_get() -> u64 effects {{ffi}};
fn low() -> u64 effects {{unsafe,ffi}} {{unsafe {{return c_get();}}}}
fn middle() -> u64 effects {{unsafe,ffi}} {{unsafe {{return low();}}}}
fn worker(data:take Buffer<u8>, token:read Cancellation) -> u64 effects {{alloc,block,unsafe,ffi}} {{
    release(move data);unsafe {{return middle();}}
}}
fn parent() -> Unit effects {{{TASK_EFFECTS},unsafe,ffi}} {{let task=spawn(worker,move buffer(4));join(move task);}}
"""
        report = self.rejects(source, "E_TASK_WORKER_EFFECT")
        self.assertTrue({"ffi", "unsafe"}.issubset(report["effects"]["worker"]))

    def test_no_spawn_resource_contract_remains_enforced(self):
        source = WORKER + f"fn parent() -> Unit effects {{{TASK_EFFECTS}}} resources {{may_spawn=false;}} {{let task=spawn(worker,move buffer(4));join(move task);}}"
        self.rejects(source, "E_RESOURCE")


@unittest.skipUnless(NATIVE_AVAILABLE, "real pinned rustc required for task execution")
class NativeTaskTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="hepta-tasks-test-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def build(self, source: str, *, supplement: str = "") -> tuple[Path, dict]:
        # Supplemented sources are an independent Rust observation harness,
        # never arbitrary input admitted by the Hepta language.
        kind = "rlib" if supplement else "bin"
        checked = analyze(source, rustc=str(RUSTC), crate_type=kind)
        self.assertTrue(checked.report["ok"], checked.report)
        self.assertEqual(checked.report["checks"]["rust_borrows_types"], "rustc_checked")
        claims = checked.report.get("claims", {})
        for claim in ("bounded_cancellation_latency", "bounded_cancellation_latency_proved",
                      "deadlock_freedom", "deadlock_freedom_proved", "termination_proved"):
            self.assertFalse(claims.get(claim, False), (claim, claims))
        output = self.directory / "tasks"
        built = compile_rust(checked.rust + supplement, rustc=str(RUSTC), crate_type="bin", output=output)
        self.assertTrue(built["ok"], built)
        self.assertGreater(output.stat().st_size, 0)
        return output, checked.report

    def run_ok(self, binary: Path):
        process = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        return process

    def test_normal_join_returns_worker_result_with_transferred_buffer(self):
        source = f"""
fn worker(data:take Buffer<u8>, token:read Cancellation) -> u64 effects {{alloc,block,panic}} {{
    let mut total:u64=0;
    for i in 0..len(read data) {{ total=wrapping_add(total,data[i] as u64); }}
    assert(!cancelled(read token));
    release(move data);
    return total;
}}
fn main() -> i32 effects {{{TASK_EFFECTS}}} {{
    let mut data=buffer(64);
    for i in 0..len(read data) {{ data[i]=i as u8; }}
    let task:Task<u64>=spawn(worker,move data);
    assert(join(move task)==2016);
    return 0;
}}
"""
        binary, _ = self.build(source)
        self.run_ok(binary)

    def test_cancellation_signals_worker_and_waits_for_release_before_return(self):
        size = 65539
        source = f"""
fn stop(token:read Cancellation) -> bool effects {{}} {{return cancelled(read token);}}
fn worker(data:take Buffer<u8>, token:read Cancellation) -> u64 effects {{alloc,block,panic}} {{
    while !stop(read token) {{}}
    let answer=wrapping_add(data[0] as u64,data[{size - 1}] as u64);
    release(move data);
    return answer;
}}
fn main() -> i32 effects {{{TASK_EFFECTS}}} {{
    let mut data=buffer({size});data[0]=19;data[{size - 1}]=23;
    let task=spawn(worker,move data);
    assert(cancel_and_join(move task)==42);
    return 0;
}}
"""
        supplement = f'''
struct ObserveAllocator;
static INPUT_FREED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
unsafe impl std::alloc::GlobalAlloc for ObserveAllocator {{
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {{
        std::alloc::GlobalAlloc::alloc(&std::alloc::System, layout)
    }}
    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {{
        if layout.size() == {size} {{
            INPUT_FREED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }}
        std::alloc::GlobalAlloc::dealloc(&std::alloc::System, ptr, layout)
    }}
}}
#[global_allocator] static OBSERVE: ObserveAllocator = ObserveAllocator;
fn main() {{
    assert_eq!(h_main(), 0);
    assert_eq!(INPUT_FREED.load(std::sync::atomic::Ordering::SeqCst), 1);
}}
'''
        binary, _ = self.build(source, supplement=supplement)
        self.run_ok(binary)

    def test_moved_handle_alias_and_direct_fresh_join_execute(self):
        source = WORKER + f"""fn main() -> i32 effects {{{TASK_EFFECTS}}} {{
            let task=spawn(worker,move buffer(17));
            let alias=move task;
            assert(join(move alias)==17);
            assert(join(move spawn(worker,move buffer(3)))==3);
            return 0;
        }}"""
        binary, _ = self.build(source)
        self.run_ok(binary)

    def test_both_runtime_branches_join_the_handle(self):
        source = WORKER + f"""
fn choose(flag:bool) -> u64 effects {{{TASK_EFFECTS}}} {{
    let task=spawn(worker,move buffer(9));
    if flag {{return join(move task);}} else {{return cancel_and_join(move task);}}
}}
fn main() -> i32 effects {{{TASK_EFFECTS}}} {{assert(choose(true)==9);assert(choose(false)==9);return 0;}}
"""
        binary, _ = self.build(source)
        self.run_ok(binary)

    def test_noncooperating_worker_is_not_falsely_force_cancelled(self):
        source = f"""
fn worker(data:take Buffer<u8>, token:read Cancellation) -> u64 effects {{alloc,block}} {{
    while true {{}}
    release(move data);
    return 0;
}}
fn main() -> i32 effects {{{TASK_EFFECTS}}} {{
    let task=spawn(worker,move buffer(1));cancel_and_join(move task);return 0;
}}
"""
        binary, report = self.build(source)
        # This is a harness timeout demonstrating the absence of a force-cancel
        # guarantee, not a claimed upper bound for cooperative cancellation.
        with self.assertRaises(subprocess.TimeoutExpired):
            subprocess.run([str(binary)], capture_output=True, text=True, timeout=0.3)
        self.assertFalse(report["claims"].get("bounded_cancellation_latency_proved", False))
        self.assertFalse(report["claims"].get("deadlock_freedom_proved", False))

    def test_published_task_example_runs_with_real_runtime(self):
        source = (ROOT / "examples" / "tasks.hepta").read_text()
        binary, _ = self.build(source)
        self.run_ok(binary)


if __name__ == "__main__":
    unittest.main()
