"""Actual core execution, source replay, cleanup and native correspondence."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.executable_core import (ExecutableCoreRejected, build_executable_core_source,
    decode_executable_core, execute_executable_core, lower_executable_core,
    verify_executable_core)
from hepta.llvm_owned_backend import emit_owned_llvm
from hepta.pipeline import analyze

from hepta.executable_core_qualify import QUALIFICATION_SOURCE as SOURCE, qualify_executable_core



def make_core(source=SOURCE, path="<executable-core-test>"):
    result = analyze(source, path, native=False, crate_type="cdylib")
    if not result.report["ok"]:
        raise AssertionError(result.report)
    return lower_executable_core(result.program, result.checked), result


def reseal(document):
    document.pop("sha256", None)
    document["sha256"] = hashlib.sha256(json.dumps(document, sort_keys=True,
        separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
    return document


class ExecutableCoreTests(unittest.TestCase):
    def test_source_replay_decoded_core_and_existing_native_emitter_agree(self):
        core, original = make_core()
        decoded, checked = decode_executable_core(core, source=SOURCE)
        self.assertIsNot(decoded, original.program)
        self.assertEqual(emit_owned_llvm(original.program, original.checked).text,
                         emit_owned_llvm(decoded, checked).text)
        self.assertEqual(verify_executable_core(core, source=SOURCE)["status"],
                         "source_replayed_and_core_rechecked")
        self.assertFalse(core["claims"]["source_to_ir_refinement_proved"])
        self.assertIn('"op": "buffer.try_new"', json.dumps(core))
        self.assertIn('"op": "borrow.mut"', json.dumps(core))

    def test_owned_lifecycle_nested_read_borrows_and_loops_execute(self):
        core, _ = make_core()
        for size in (0, 1, 2, 17, 65):
            with self.subTest(size=size):
                report = execute_executable_core(core, "lifecycle", [size, 249, 0], source=SOURCE)
                self.assertEqual(report["result"], sum((249 + i) % 256 for i in range(size)))
                self.assertEqual(report["resources"]["allocations"], int(size > 0))
                self.assertEqual(report["resources"]["frees"], int(size > 0))
                self.assertEqual(report["resources"]["live_owners"], 0)
                begins = [e for e in report["events"] if e["event"] == "borrow"]
                ends = [e for e in report["events"] if e["event"] == "end_borrow"]
                self.assertEqual(len(begins), len(ends))
                self.assertEqual(len(begins), 2 + size)

    def test_error_return_and_injected_second_failure_release_first_owner(self):
        core, _ = make_core()
        early = execute_executable_core(core, "lifecycle", [11, 7, 1], source=SOURCE)
        self.assertEqual(early["result"], 777)
        self.assertEqual(early["resources"]["live_bytes"], 0)
        failed = execute_executable_core(core, "second_allocation", [7], source=SOURCE, allocation_fail_at=2)
        self.assertEqual(failed["result"], 101)
        self.assertEqual(failed["resources"], {"allocations": 1, "frees": 1,
            "live_owners": 0, "live_bytes": 0, "peak_live_bytes": 3, "allocation_refusals": 1})
        self.assertFalse(failed["claims"]["host_allocator_failure_observed"])

    def test_oversized_try_allocation_is_language_error_not_harness_limit(self):
        core, _ = make_core()
        result = execute_executable_core(core, "second_allocation", [(1 << 64) - 1], source=SOURCE)
        self.assertEqual(result["result"], 101)
        self.assertEqual(result["resources"]["live_owners"], 0)

    def test_result_construction_owned_return_and_negative_minimum_literal(self):
        source = '''
        fn make(n:usize)->Result<Buffer<u8>,u8> effects{alloc,block,panic} {
            if n==0 {return Result::Err(7);}
            let owner=buffer(n);return Result::Ok(move owner);
        }
        export "C" fn result_case(n:usize)->i64 effects{alloc,block,panic} {
            let result=make(n);
            match move result {
                Result::Err(code)=>{return code as i64;},
                Result::Ok(owner)=>{let size=len(owner);drop(move owner);return size as i64;},
            }
        }
        export "C" fn minimum()->i64 effects{panic} {return -9223372036854775808;}
        '''
        core, _ = make_core(source)
        for n, expected in [(0, 7), (3, 3)]:
            report = execute_executable_core(core, "result_case", [n], source=source)
            self.assertEqual(report["result"], expected)
            self.assertEqual(report["resources"]["live_owners"], 0)
        self.assertEqual(execute_executable_core(core, "minimum", [], source=source)["result"], -(1 << 63))

    def test_integer_signed_division_cast_and_short_circuit(self):
        core, _ = make_core()
        for a, b in [(-19, 4), (19, -4), (-19, -4), (0, 1), (123456, 17)]:
            q = abs(a) // abs(b) * (-1 if (a < 0) != (b < 0) else 1)
            result = execute_executable_core(core, "signed_math", [a, b], source=SOURCE)
            self.assertEqual(result["result"], q + a - q * b)
        for value in [-1000, -129, -128, 127, 128, 255, 256]:
            result = execute_executable_core(core, "cast_byte", [value], source=SOURCE)
            self.assertEqual(result["result"], (value + 128) % 256 - 128)
        self.assertTrue(execute_executable_core(core, "short_circuit", [0], source=SOURCE)["result"])
        self.assertEqual(execute_executable_core(core, "shift", [1 << 30, 1], source=SOURCE)["result"], -(1 << 31))

    def test_guard_traps_and_interpreter_limits_have_distinct_status(self):
        core, _ = make_core()
        for name, args in [("trap_index", []), ("trap_overflow", [255]),
                           ("signed_math", [1, 0]), ("signed_math", [-(1 << 31), -1]),
                           ("shift", [1, -1]), ("shift", [1, 32])]:
            with self.subTest(name=name, args=args):
                result = execute_executable_core(core, name, args, source=SOURCE)
                self.assertEqual(result["status"], "trapped")
        self.assertEqual(execute_executable_core(core, "lifecycle", [100, 0, 0], source=SOURCE,
                                                max_steps=30)["status"], "budget_exhausted")
        self.assertEqual(execute_executable_core(core, "lifecycle", [100, 0, 0], source=SOURCE,
                                                max_heap_bytes=50)["status"], "budget_exhausted")

    def test_rehashed_changed_values_types_effects_resources_and_claims_reject(self):
        core, _ = make_core()
        mutations = [
            lambda d: d["functions"][-1]["body"][0]["value"]["args"][1].update(value=2),
            lambda d: d["functions"][-1]["body"][0]["value"]["type"].update(name="u64"),
            lambda d: d["functions"][1].update(declared_effects=[]),
            lambda d: d.update(resource_ir_sha256="0" * 64),
            lambda d: d["claims"].update(whole_language_soundness_proved=True),
            lambda d: d["functions"][0].update(name="wrong_function")]
        for change in mutations:
            altered = copy.deepcopy(core)
            change(altered)
            with self.assertRaisesRegex(ExecutableCoreRejected, "E_CORE_ORIGIN"):
                verify_executable_core(reseal(altered), source=SOURCE)

    def test_ast_mutation_cannot_rebind_old_source(self):
        core, original = make_core()
        original.program.functions[-1].body[0].data["expr"].children[1].value = 2
        with self.assertRaisesRegex(ExecutableCoreRejected, "E_CORE_ORIGIN"):
            lower_executable_core(original.program)

    def test_frontend_accepted_alias_conflict_is_rejected_by_resource_gate(self):
        source = '''fn both(a:mut Buffer<u8>,b:mut Buffer<u8>)->Unit effects {} {}
        fn bad()->Unit effects{alloc,block,panic}{let mut b=buffer(1);both(mut b,mut b);drop(move b);}'''
        result = analyze(source, native=False)
        self.assertTrue(result.report["ok"])
        with self.assertRaisesRegex(ExecutableCoreRejected, "E_CORE_RESOURCE"):
            lower_executable_core(result.program, result.checked)

    def test_profile_rejects_adt_generics_stored_loans_tasks_and_foreign_code(self):
        sources = ['struct Pair {value:u32} fn f()->u32 effects {} {return 0;}',
            'fn identity<T>(value:T)->T effects {} {return value;}',
            "struct View<'a>{value:read 'a u64} fn f()->Unit effects {} {}",
            "fn borrow<'a>(b:read 'a [u8])->read 'a [u8] from b effects {} {return read b;}",
            'fn worker(data:take Buffer<u8>,cancel:read Cancellation)->u64 effects {alloc,block} {release(move data);return 0;} '
            'fn f()->Unit effects {alloc,block,spawn,panic} {let task=spawn(worker,move buffer(1));cancel_and_join(move task);}',
            'extern "C" fn foreign(value:u32)->u32 effects {ffi};']
        for source in sources:
            result = analyze(source, native=False)
            self.assertTrue(result.report["ok"], result.report)
            with self.assertRaises(ExecutableCoreRejected):
                lower_executable_core(result.program, result.checked)

    def test_deep_core_and_invalid_inputs_fail_closed(self):
        core, _ = make_core()
        malformed = copy.deepcopy(core)
        value = []
        malformed["extra"] = value
        for _ in range(110):
            child = []
            value.append(child)
            value = child
        with self.assertRaisesRegex(ExecutableCoreRejected, "E_CORE_LIMIT"):
            verify_executable_core(malformed, source=SOURCE)
        for args in ([True, 1, 0], [-1, 1, 0], [1, 256, 0]):
            with self.assertRaisesRegex(ExecutableCoreRejected, "E_CORE_ENTRY"):
                execute_executable_core(core, "lifecycle", args, source=SOURCE)
        with self.assertRaisesRegex(ExecutableCoreRejected, "E_CORE_ENTRY"):
            execute_executable_core(core, "transfer", [0], source=SOURCE)


RUSTC = os.environ.get("RUSTC") or shutil.which("rustc")
CLANG = os.environ.get("CLANG") or shutil.which("clang")
CC = os.environ.get("CC") or shutil.which("cc")


@unittest.skipUnless(RUSTC and CLANG and CC, "locked Rust, Clang 20+ and C compiler required")
class ExecutableCoreNativeTests(unittest.TestCase):
    def test_core_interpreter_original_rust_c_and_decoded_core_llvm_agree(self):
        receipt = qualify_executable_core(rustc=RUSTC, clang=CLANG, cc=CC)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["input_cases"], 56)
        self.assertEqual(receipt["native_result_executions"], 168)
        self.assertEqual(receipt["mocked_native_executions"], 0)
        self.assertEqual(receipt["skipped_native_executions"], 0)
        self.assertEqual(len(receipt["guard_observations"]), 2)
        self.assertEqual(receipt["allocator_observation"]["allocations"], 5)
        self.assertEqual(receipt["allocator_observation"]["frees"], 5)
        self.assertEqual(receipt["allocator_observation"]["live_allocations"], 0)
        self.assertEqual(receipt["allocator_observation"]["observed_allocator_refusals"], 1)
        self.assertFalse(receipt["claims"]["whole_language_soundness_proved"])
        self.assertFalse(receipt["claims"]["real_os_out_of_memory_observed"])
        self.assertEqual(reseal({**receipt})["sha256"], receipt["sha256"])

    def test_native_entry_refuses_existing_output_and_missing_locked_reference(self):
        with tempfile.TemporaryDirectory(prefix="hepta-core-reject-") as td:
            source, output = Path(td) / "input.hepta", Path(td) / "already.so"
            source.write_text(SOURCE)
            output.write_bytes(b"keep")
            with self.assertRaisesRegex(ExecutableCoreRejected, "E_CORE_OUTPUT"):
                build_executable_core_source(source, output, rustc=RUSTC, clang=CLANG)
            self.assertEqual(output.read_bytes(), b"keep")
            with self.assertRaisesRegex(ExecutableCoreRejected, "E_CORE_NATIVE_REFERENCE"):
                build_executable_core_source(source, Path(td) / "missing.so", rustc=str(Path(td) / "absent-rustc"), clang=CLANG)
            self.assertFalse((Path(td) / "missing.so").exists())
