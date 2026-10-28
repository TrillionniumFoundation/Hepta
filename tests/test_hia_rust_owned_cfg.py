"""Independent Rust byte-owner CFG/call execution vs Python and native LLVM.

Converged from PR322 onto the shared v1-v7 Machine; not a second VM.

Cargo/Clang absence is an explicit skip, never a qualified result. Counter and
trap comparisons use the canonical Python VM only as a separate oracle; the
Rust process receives Core bytes and never invokes Python or native code.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import (
    HIAProgramBudgetExceeded, HIAProgramTrap, execute_program,
)
from tests.test_hia_program import b, branch, c, f, i, jump, m, ret
from tests.test_hia_program import joined_loan_program, resource_program
from tests.test_hia_rust_calls_shadow import borrowed_call, call_owner

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "rust" / "hia-core-shadow" / "Cargo.toml"
CLANG = os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang")


def loan_loop():
    """A real owner and mutable reborrow cross a loop's phi arguments."""
    return m(f("fill", [("n", "usize")], ["usize"],
               ["alloc", "write", "read", "trap"], [
        b("entry", [("n", "usize")], [
            c("zero", "usize", 0), i("buffer.new", ["n"], [("owner", "buffer")]),
            i("borrow.mut", ["owner"], [("parent", "mutbuf")]),
            i("borrow.mut", ["parent"], [("view", "mutbuf")]),
        ], jump("loop", "owner", "parent", "view", "zero", "zero", "n")),
        b("loop", [("lo", "buffer"), ("lp", "mutbuf"), ("lv", "mutbuf"),
                    ("index", "usize"), ("sum", "usize"), ("limit", "usize")], [
            i("compare.lt", ["index", "limit"], [("more", "bool")]),
        ], branch("more", ("body", "lo", "lp", "lv", "index", "sum", "limit"),
                   ("done", "lo", "lp", "lv", "sum"))),
        b("body", [("bo", "buffer"), ("bp", "mutbuf"), ("bv", "mutbuf"),
                    ("bi", "usize"), ("bs", "usize"), ("bn", "usize")], [
            c("byte", "u8", 7), c("one", "usize", 1),
            i("buffer.store", ["bv", "bi", "byte"]),
            i("buffer.load", ["bv", "bi"], [("readback", "u8")]),
            i("int.cast", ["readback"], [("wide", "usize")], mode="checked"),
            i("int.add.checked", ["bs", "wide"], [("nextsum", "usize")]),
            i("int.add.checked", ["bi", "one"], [("next", "usize")]),
        ], jump("loop", "bo", "bp", "bv", "next", "nextsum", "bn")),
        b("done", [("do", "buffer"), ("dp", "mutbuf"), ("dv", "mutbuf"),
                    ("answer", "usize")], [
            i("loan.end", ["dv"]), i("loan.end", ["dp"]), i("owner.drop", ["do"]),
        ], ret("answer")),
    ]))


def readonly_alias_call():
    """Two shared formals may refer to the same mutable caller loan."""
    reader = f("reader", [("left", "readbuf"), ("right", "readbuf")],
               ["u8"], ["read", "trap"], [
        b("read_entry", [("left", "readbuf"), ("right", "readbuf")], [
            c("zero", "usize", 0),
            i("borrow.read", ["left"], [("child", "readbuf")]),
            i("buffer.load", ["child", "zero"], [("first", "u8")]),
            i("loan.end", ["child"]),
            i("buffer.load", ["right", "zero"], [("second", "u8")]),
            i("int.add.checked", ["first", "second"], [("total", "u8")]),
        ], ret("total")),
    ])
    outer = f("outer", [], ["u8"], ["alloc", "read", "write", "trap"], [
        b("outer_entry", [], [
            c("size", "usize", 1), c("index", "usize", 0), c("byte", "u8", 41),
            i("buffer.new", ["size"], [("owner", "buffer")]),
            i("borrow.mut", ["owner"], [("view", "mutbuf")]),
            i("buffer.store", ["view", "index", "byte"]),
            i("call", ["view", "view"], [("answer", "u8")], function="reader"),
            i("buffer.store", ["view", "index", "answer"]),
            i("loan.end", ["view"]), i("owner.drop", ["owner"]),
        ], ret("answer")),
    ])
    return m(reader, outer)


def active_child_alias_call(*, shared_actual=False, nested=False, cross_block=False):
    """A child of one readonly formal must not suspend its aliased sibling."""
    document = readonly_alias_call()
    reader, outer = document["functions"]
    operations = reader["blocks"][0]["ops"]
    operations[3], operations[4] = operations[4], operations[3]
    if cross_block:
        reader["blocks"][0]["ops"] = operations[:2]
        reader["blocks"][0]["term"] = jump("read_join", "left", "right", "child", "zero")
        reader["blocks"].append(b("read_join", [
            ("jleft", "readbuf"), ("jright", "readbuf"),
            ("jchild", "readbuf"), ("jzero", "usize"),
        ], [
            i("buffer.load", ["jchild", "jzero"], [("first", "u8")]),
            i("buffer.load", ["jright", "jzero"], [("second", "u8")]),
            i("loan.end", ["jchild"]),
            i("int.add.checked", ["first", "second"], [("total", "u8")]),
        ], ret("total")))
    outer_ops = outer["blocks"][0]["ops"]
    position = next(n for n, op in enumerate(outer_ops) if op["op"] == "call")
    call = outer_ops[position]
    if shared_actual:
        outer_ops.insert(position, i("borrow.read", ["view"], [("shared", "readbuf")]))
        call["args"] = ["shared", "shared"]
        outer_ops.insert(position + 2, i("loan.end", ["shared"]))
    if nested:
        document["functions"].append(f("relay", [("a", "readbuf"), ("z", "readbuf")],
            ["u8"], ["read", "trap"], [
                b("relay_entry", [("a", "readbuf"), ("z", "readbuf")], [
                    i("call", ["a", "z"], [("answer", "u8")], function="reader"),
                ], ret("answer")),
            ]))
        call["attrs"]["function"] = "relay"
    return document


def allocation_sequence():
    return m(f("allocate", [], ["bool", "bool", "bool"], ["alloc"], [
        b("entry", [], [
            c("zero", "usize", 0), c("one", "usize", 1),
            i("buffer.try_new", ["zero"], [("empty", "buffer"), ("zero_ok", "bool")]),
            i("owner.drop", ["empty"]),
            i("buffer.try_new", ["one"], [("first", "buffer"), ("first_ok", "bool")]),
            i("buffer.try_new", ["one"], [("second", "buffer"), ("second_ok", "bool")]),
            i("owner.drop", ["first"]), i("owner.drop", ["second"]),
        ], ret("zero_ok", "first_ok", "second_ok")),
    ]))


def owned_recursion():
    return m(f("recur", [], [], ["alloc", "trap"], [
        b("entry", [], [
            c("one", "usize", 1), i("buffer.new", ["one"], [("owner", "buffer")]),
            i("call", [], function="recur"), i("owner.drop", ["owner"]),
        ], ret()),
    ]))


@unittest.skipUnless(shutil.which("cargo"), "Cargo unavailable: NO Rust resource qualification")
class RustOwnedCfgParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        built = subprocess.run([
            "cargo", "build", "--locked", "--offline", "--manifest-path", str(MANIFEST),
        ], cwd=ROOT, capture_output=True, text=True, timeout=240)
        if built.returncode:
            raise AssertionError("Rust build failed:\n" + built.stderr[-6000:])
        metadata = subprocess.run([
            "cargo", "metadata", "--no-deps", "--format-version", "1",
            "--locked", "--offline", "--manifest-path", str(MANIFEST),
        ], cwd=ROOT, capture_output=True, text=True, check=True, timeout=30)
        cls.executable = Path(json.loads(metadata.stdout)["target_directory"]) / "debug" / "hia-core-shadow"
        cls.parity_observations = 0

    @classmethod
    def tearDownClass(cls):
        print(f"Rust CFG/call/Python full-ledger parity observations: {cls.parity_observations}")

    def rust_process(self, document, function, args, *, options=None, mode="--owned-run"):
        raw = document if isinstance(document, bytes) else json.dumps(document).encode()
        command = [str(self.executable), mode, function, json.dumps(args)]
        if mode == "--owned-run":
            options = {} if options is None else options
            failure = options.get("allocation_fail_at")
            command += [str(options.get("max_steps", 100_000)),
                        str(options.get("max_heap_bytes", 16 * 1024 * 1024)),
                        "none" if failure is None else str(failure)]
        return subprocess.run(command, input=raw, cwd=ROOT,
                              capture_output=True, timeout=30)

    def assert_parity(self, document, function, args, **options):
        core = verify_program(document)
        # The compared machines use exactly the same explicit budget; the
        # development oracle's default differs from Python's default steps.
        options = {"max_steps": 100_000, "max_heap_bytes": 16 * 1024 * 1024, **options}
        observed = self.rust_process(core.canonical_bytes, function, args, options=options)
        self.assertEqual(observed.returncode, 0, observed.stderr.decode(errors="replace"))
        rust = json.loads(observed.stdout)
        try:
            python = execute_program(core, function, args, max_call_depth=32, **options)
        except (HIAProgramTrap, HIAProgramBudgetExceeded) as stopped:
            python = stopped.report
        for field in ("status", "steps", "resources", "program_sha256"):
            self.assertEqual(rust[field], python[field], field)
        if rust["status"] == "returned":
            self.assertEqual(rust["values"], python["values"])
        else:
            self.assertEqual(rust["error"]["code"], python["error"]["code"])
        self.assertTrue(rust["claims"]["finite_byte_owner_execution"])
        self.assertTrue(rust["claims"]["byte_owner_cfg_and_calls"])
        self.assertEqual(rust["profile"], "cfg-call-byte-owner-bulk-v3")
        for claim in ("production_admission_authorized", "whole_language_soundness_proved",
                      "native_backend_refinement_proved", "general_resource_execution"):
            self.assertFalse(rust["claims"][claim])
        type(self).parity_observations += 1
        return rust

    def test_owner_arguments_are_consumed_through_nested_calls(self):
        relay = f("relay", [("input", "buffer")], ["buffer"], [], [
            b("relay_entry", [("input", "buffer")], [
                i("owner.move", ["input"], [("output", "buffer")]),
            ], ret("output")),
        ])
        sink = f("sink", [("input", "buffer")], ["usize"], ["alloc"], [
            b("sink_entry", [("input", "buffer")], [
                i("buffer.len", ["input"], [("length", "usize")]),
                i("owner.drop", ["input"]),
            ], ret("length")),
        ])
        entry = f("entry", [("size", "usize")], ["usize"], ["alloc", "trap"], [
            b("start", [("size", "usize")], [
                i("buffer.new", ["size"], [("owner", "buffer")]),
                i("call", ["owner"], [("returned", "buffer")], function="relay"),
                i("call", ["returned"], [("answer", "usize")], function="sink"),
            ], ret("answer")),
        ])
        document = m(relay, sink, entry)
        for size in (0, 4):
            result = self.assert_parity(document, "entry", [size])
            self.assertEqual(result["values"], [size])
            self.assertEqual(result["resources"]["owners_created"], 1)
            self.assertEqual(result["resources"]["owners_dropped"], 1)
            for limit in range(1, result["steps"]):
                self.assert_parity(document, "entry", [size], max_steps=limit)
        entry["blocks"][0]["ops"].append(i("owner.drop", ["owner"]))
        with self.assertRaises(HIAProgramRejected):
            verify_program(document)
        self.assertNotEqual(self.rust_process(document, "entry", [4]).returncode, 0)

    def test_mutable_callee_reborrow_returns_control_to_caller(self):
        document = resource_program()
        writer = f("write", [("input", "mutbuf"), ("byte", "u8")], [], ["write", "trap"], [
            b("write_entry", [("input", "mutbuf"), ("byte", "u8")], [
                i("borrow.mut", ["input"], [("child", "mutbuf")]),
                c("index", "usize", 0),
                i("buffer.store", ["child", "index", "byte"]),
                i("loan.end", ["child"]),
            ], ret()),
        ])
        document["functions"].append(writer)
        operations = document["functions"][0]["blocks"][0]["ops"]
        position = next(n for n, operation in enumerate(operations) if operation["op"] == "buffer.store")
        operations[position] = i("call", ["writer", "value"], function="write")
        for size in (0, 1, 4):
            self.assert_parity(document, "owned", [size, 97])

    def test_uncalled_chain_signature_is_outside_execution_profile(self):
        document = m(
            f("entry", [], [], [], [b("entry_block", [], [], ret())]),
            f("carry", [("value", "chain")], ["chain"], [], [
                b("carry_entry", [("value", "chain")], [], ret("value")),
            ]),
        )
        document["schema"] = "hepta.hia.program.v7"
        verify_program(document)
        result = self.rust_process(document, "entry", [])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"E_HIA_RUST_UNSUPPORTED", result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_existing_scalar_oracle_refuses_resource_program_new_oracle_executes_it(self):
        document = resource_program()
        old = self.rust_process(document, "owned", [7, 19], mode="--scalar-run")
        self.assertNotEqual(old.returncode, 0)
        current = self.assert_parity(document, "owned", [7, 19])
        self.assertEqual(current["values"], [19])
        self.assertEqual(current["resources"]["frees"], 1)

    def test_move_reborrow_phi_loop_and_aliased_readonly_call(self):
        for n in (0, 1, 3, 31):
            with self.subTest(loop=n):
                report = self.assert_parity(loan_loop(), "fill", [n])
                self.assertEqual(report["values"], [7 * n])
                self.assertEqual(report["resources"]["live_local_loans"], 0)
        for condition in (True, False):
            self.assert_parity(joined_loan_program(), "join", [condition])
        self.assert_parity(borrowed_call(), "outer", [])
        self.assertEqual(self.assert_parity(readonly_alias_call(), "outer", [])["values"], [82])

    def test_readonly_call_formals_have_distinct_child_suspension_identity(self):
        # Regression: both static verifiers accepted the same Core and Python
        # returned 82, but sharing one dynamic View id made the Rust oracle
        # incorrectly suspend `right` when `left` had a shared child.
        for shared in (False, True):
            for nested in (False, True):
                for cross_block in (False, True):
                    with self.subTest(shared=shared, nested=nested, cross_block=cross_block):
                        document = active_child_alias_call(shared_actual=shared,
                                                          nested=nested, cross_block=cross_block)
                        report = self.assert_parity(document, "outer", [])
                        self.assertEqual(report["values"], [82])
                        self.assertEqual(report["resources"]["loans_started"], 3 if shared else 2)
                        self.assertEqual(report["resources"]["live_local_loans"], 0)
                        self.assertEqual(report["resources"]["frees"], 1)
                        if not shared and not nested and not cross_block:
                            self.assertEqual(report["steps"], 20)
        # Call-formal witnesses must not inflate program loan counters when
        # the callee stops while its local child remains live.
        document = active_child_alias_call(nested=True)
        for limit in (10, 13, 16):
            self.assert_parity(document, "outer", [], max_steps=limit)
        block = document["functions"][0]["blocks"][0]
        block["ops"] = block["ops"][:3]
        block["term"] = {"op": "trap", "code": "user"}
        report = self.assert_parity(document, "outer", [])
        self.assertEqual(report["resources"]["live_local_loans"], 2)
        self.assertEqual(report["resources"]["loans_started"], 2)
        self.assertEqual(report["resources"]["loans_ended"], 0)

    def test_actual_parent_suspension_and_readonly_permissions_still_reject(self):
        bad_parent = active_child_alias_call()
        # The sibling is usable; the *actual parent formal* remains suspended.
        bad_parent["functions"][0]["blocks"][0]["ops"][3]["args"][0] = "left"
        bad_mutable = active_child_alias_call()
        borrow = bad_mutable["functions"][0]["blocks"][0]["ops"][1]
        borrow["op"] = "borrow.mut"
        borrow["out"][0]["type"] = "mutbuf"
        for document in (bad_parent, bad_mutable):
            with self.assertRaises(HIAProgramRejected):
                verify_program(document)
            refused = self.rust_process(document, "outer", [])
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(refused.stdout, b"")
            self.assertIn(b"E_HIA_LOAN", refused.stderr)

    def test_owned_call_returns_allocation_failure_and_empty_cleanup(self):
        for size, failure in ((0, None), (0, 1), (7, None), (7, 1), ((1 << 64) - 1, None)):
            with self.subTest(size=size, failure=failure):
                self.assert_parity(call_owner(), "use", [size], allocation_fail_at=failure)
        for failure, expected in ((None, [True, True, True]), (1, [True, False, True]),
                                  (2, [True, True, False]), (3, [True, True, True])):
            report = self.assert_parity(allocation_sequence(), "allocate", [], allocation_fail_at=failure)
            self.assertEqual(report["values"], expected)
            self.assertEqual(report["resources"]["allocation_attempts"], 2)

    def test_traps_and_budgets_preserve_stopped_resource_state(self):
        for size, options in (
            (0, {}), (1, {"allocation_fail_at": 1}), ((1 << 64) - 1, {}),
            (8, {"max_heap_bytes": 7}), (4, {"max_steps": 4}),
        ):
            with self.subTest(size=size, options=options):
                self.assert_parity(resource_program(), "owned", [size, 41], **options)
        for steps in (1, 5, 12, 30):
            self.assert_parity(loan_loop(), "fill", [8], max_steps=steps)
        stopped = self.assert_parity(owned_recursion(), "recur", [])
        self.assertEqual(stopped["error"]["code"], "calls")
        self.assertEqual(stopped["resources"]["live_owners"], 32)
        self.assertEqual(stopped["resources"]["frees"], 0)
        # An explicit trap retains live owners/loans as well; host cleanup is
        # not counted as if the aborted source program executed destructors.
        document = resource_program()
        block = document["functions"][0]["blocks"][0]
        block["ops"] = block["ops"][:2]
        block["term"] = {"op": "trap", "code": "user"}
        report = self.assert_parity(document, "owned", [7, 41])
        self.assertEqual(report["resources"]["live_owners"], 1)
        self.assertEqual(report["resources"]["live_local_loans"], 1)

    def test_scalar_boundaries_trap_while_resources_are_live(self):
        from tests.test_hia_rust_scalar_vm import arithmetic
        cases = (
            ("int.div.checked", "i64", [-(1 << 63), -1]),
            ("int.rem.checked", "i64", [-(1 << 63), -1]),
            ("int.rem.checked", "i64", [-7, 3]),
            ("int.div.checked", "u64", [(1 << 64) - 1, 0]),
            ("int.mul.wrap", "u64", [(1 << 64) - 1, (1 << 64) - 1]),
            ("int.shl.checked", "u64", [1, 64]),
        )
        for opcode, typ, args in cases:
            document = arithmetic(opcode, typ)
            fn = document["functions"][0]
            fn["effects"].append("alloc")
            ops = fn["blocks"][0]["ops"]
            ops[:0] = [c("size", "usize", 1),
                       i("buffer.new", ["size"], [("owner", "buffer")]),
                       i("borrow.read", ["owner"], [("view", "readbuf")])]
            ops.extend([i("loan.end", ["view"]), i("owner.drop", ["owner"])])
            with self.subTest(opcode=opcode, args=args):
                report = self.assert_parity(document, "calc", args)
                expected = 1 if report["status"] == "trapped" else 0
                self.assertEqual(report["resources"]["live_owners"], expected)
                self.assertEqual(report["resources"]["live_local_loans"], expected)

    def test_whole_module_safety_refusals_before_execution(self):
        invalid = []
        program = resource_program()
        program["functions"][0]["blocks"][0]["ops"].append(i("owner.drop", ["moved"]))
        invalid.append(program)
        program = loan_loop()
        program["functions"][0]["blocks"][2]["ops"][2]["args"][0] = "bp"
        invalid.append(program)  # write through a parent suspended by its child
        program = joined_loan_program()
        program["functions"][0]["blocks"][0]["term"]["else"]["args"] = ["z", "a", "view"]
        invalid.append(program)
        program = borrowed_call()
        program["functions"][0]["blocks"][0]["ops"].append(i("loan.end", ["view"]))
        invalid.append(program)  # callee cannot revoke its caller's loan
        program = resource_program()
        program["functions"].append(f("dead", [], [], [], [
            b("dead_entry", [], [i("foreign.unchecked")], ret()),
        ]))
        invalid.append(program)  # even an uncalled body must reject
        for document in invalid:
            with self.subTest(document=document), self.assertRaises(HIAProgramRejected):
                verify_program(document)
            result = self.rust_process(document, document["functions"][-1]["name"], [])
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")
            self.assertNotIn(b"E_HIA_INPUT", result.stderr)  # module validation came first

    def test_v1_to_v7_cfg_and_calls_preserve_exact_ledger_inventory(self):
        for version in range(1, 8):
            for document, function, arguments in (
                (loan_loop(), "fill", [3]),
                (active_child_alias_call(nested=True, cross_block=True), "outer", []),
                (call_owner(), "use", [4]),
            ):
                document["schema"] = f"hepta.hia.program.v{version}"
                with self.subTest(version=version, function=function):
                    self.assert_parity(document, function, arguments)

    def test_capability_entries_and_nonexported_helpers_refuse(self):
        document = call_owner()
        document["exports"] = ["use"]
        self.assert_parity(document, "use", [3])
        refused = self.rust_process(document, "maker", [3])
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn(b"E_HIA_INPUT", refused.stderr)
        document.pop("exports")
        refused = self.rust_process(document, "maker", [3])
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn(b"E_HIA_INPUT", refused.stderr)
        for version in (0, 8, 99):
            document["schema"] = f"hepta.hia.program.v{version}"
            self.assertNotEqual(self.rust_process(document, "use", [3]).returncode, 0)

    @unittest.skipUnless(shutil.which(CLANG), "Clang missing: NO native resource comparison")
    def test_three_way_real_native_resource_result_and_allocator_trace(self):
        from hepta.clang_capture import run_bounded
        from hepta.hia_program_llvm import compile_program_llvm, emit_program_llvm
        document = resource_program()
        document["functions"].append(call_owner()["functions"][0])
        document["functions"].append(f("try_length", [("n", "usize")], ["usize"], ["alloc"], [
            b("entry", [("n", "usize")], [
                i("call", ["n"], [("owner", "buffer"), ("ok", "bool")], function="maker"),
                i("buffer.len", ["owner"], [("length", "usize")]),
                i("owner.drop", ["owner"]),
            ], ret("length")),
        ]))
        document["functions"].extend(active_child_alias_call(
            shared_actual=True, nested=True, cross_block=True)["functions"])
        core = verify_program(document)
        ir = emit_program_llvm(core)
        driver = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void *__real_calloc(size_t, size_t);
void __real_free(void *);
uint8_t owned(size_t, uint8_t);
size_t try_length(size_t);
uint8_t outer(void);
static size_t calls, frees, live;
static int refuse;
void *__wrap_calloc(size_t n, size_t width) {
    calls++; if (refuse) return NULL;
    void *p = __real_calloc(n, width); if (p) live++; return p;
}
void __wrap_free(void *p) {
    if (p) { if (!live) abort(); live--; frees++; } __real_free(p);
}
int main(int argc, char **argv) {
    size_t n = (size_t)strtoull(argv[1], 0, 10);
    refuse = argc > 3;
    size_t answer = argc > 2 && !strcmp(argv[2], "alias") ? (size_t)outer() :
                    argc > 2 ? try_length(n) : (size_t)owned(n, 41);
    printf("%zu %zu %zu %zu\n", answer, calls, frees, live);
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix="hia-rust-owned-native-") as directory:
            directory = Path(directory)
            obj, source, binary = directory / "owned.o", directory / "driver.c", directory / "driver"
            compile_program_llvm(ir, program=core, output=obj, clang=CLANG, kind="object")
            source.write_text(driver)
            built = run_bounded([CLANG, "-O2", str(source), str(obj),
                                 "-Wl,--wrap=calloc", "-Wl,--wrap=free", "-o", str(binary)])
            self.assertEqual(built.returncode, 0, built.stderr)
            for size in (1, 7, 31):
                rust = self.assert_parity(document, "owned", [size, 41])
                native = run_bounded([str(binary), str(size)])
                self.assertEqual(native.returncode, 0, native.stderr)
                expected = [rust["values"][0], rust["resources"]["allocation_attempts"],
                            rust["resources"]["frees"], rust["resources"]["live_owners"]]
                self.assertEqual([int(value) for value in native.stdout.split()], expected)
            aliases = self.assert_parity(document, "outer", [])
            observed = run_bounded([str(binary), "0", "alias"])
            self.assertEqual(observed.returncode, 0, observed.stderr)
            self.assertEqual([int(value) for value in observed.stdout.split()],
                             [aliases["values"][0], aliases["resources"]["allocation_attempts"],
                              aliases["resources"]["frees"], aliases["resources"]["live_owners"]])
            trapped = self.assert_parity(document, "owned", [0, 41])
            self.assertEqual(trapped["error"]["code"], "bounds")
            self.assertEqual(run_bounded([str(binary), "0"]).returncode, -6)
            for size, fail in ((0, False), (7, False), (0, True), (7, True)):
                rust = self.assert_parity(document, "try_length", [size],
                                          allocation_fail_at=1 if fail else None)
                command = [str(binary), str(size), "try"] + (["fail"] if fail else [])
                native = run_bounded(command)
                self.assertEqual(native.returncode, 0, native.stderr)
                expected = [rust["values"][0], rust["resources"]["allocation_attempts"],
                            rust["resources"]["frees"], rust["resources"]["live_owners"]]
                self.assertEqual([int(value) for value in native.stdout.split()], expected)


if __name__ == "__main__":
    unittest.main()

