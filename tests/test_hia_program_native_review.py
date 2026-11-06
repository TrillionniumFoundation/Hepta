"""Independent adversarial review of direct HIA machine output.

Expected values and allocation ledgers come from the existing interpreter and
an older, separately implemented C observer. The assembly below belongs only
to the test caller: it deliberately supplies dirty high argument bits and
checks the system ABI around an object already emitted without an assembler.
"""
from __future__ import annotations

import json
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import VerifiedProgram, execute_program, verify_program
from hepta.hia_program_native import (
    HIAProgramNativeRejected, build_program_machine, emit_program_machine,
)
from hepta.hia_program_runtime import HIAProgramTrap
from tools.qualify_hia_program import block, constant, function, operation, ret


ROOT = Path(__file__).resolve().parents[1]
CC = shutil.which("cc")
NATIVE_HOST = platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}


def _document(functions, version=6):
    return {"schema": f"hepta.hia.program.v{version}", "module": "independent_native_review",
            "functions": functions}


def _empty_memory_program():
    ops = [constant("zero", "usize", 0), constant("byte", "u8", 85),
           operation("buffer.new", ["zero"], [("a", "buffer")]),
           operation("buffer.new", ["zero"], [("b", "buffer")]),
           operation("borrow.mut", ["a"], [("am", "mutbuf")]),
           operation("borrow.read", ["b"], [("br", "readbuf")]),
           operation("buffer.fill", ["am", "byte"]),
           operation("buffer.copy", ["am", "br", "zero"]),
           operation("buffer.move_within", ["am", "zero", "zero", "zero"]),
           operation("buffer.copy_range", ["am", "br", "zero", "zero", "zero"]),
           operation("buffer.fill_range", ["am", "zero", "zero", "byte"]),
           operation("loan.end", ["am"]), operation("loan.end", ["br"]),
           operation("owner.drop", ["a"]), operation("owner.drop", ["b"]),
           constant("answer", "u64", 73)]
    return _document([function("empty_memory", [], ["u64"], ["alloc", "read", "write", "trap"],
                               [block("entry", [], ops, ret("answer"))])])


def _bounds_program():
    functions = []
    params = [("offset", "usize"), ("count", "usize")]
    for kind in ("swap", "fill", "move", "copy"):
        ops = [constant("four", "usize", 4), constant("zero", "usize", 0),
               constant("before", "u8", 17), constant("after", "u8", 99),
               operation("buffer.new", ["four"], [("a", "buffer")]),
               operation("borrow.mut", ["a"], [("am", "mutbuf")]),
               operation("buffer.fill", ["am", "before"])]
        if kind == "copy":
            ops += [operation("buffer.new", ["four"], [("b", "buffer")]),
                    operation("borrow.mut", ["b"], [("bm", "mutbuf")]),
                    operation("buffer.fill", ["bm", "after"]),
                    operation("loan.end", ["bm"]),
                    operation("borrow.read", ["b"], [("br", "readbuf")]),
                    operation("buffer.copy_range", ["am", "br", "zero", "offset", "count"]),
                    operation("loan.end", ["br"]), operation("owner.drop", ["b"])]
        else:
            args = {"swap": ["am", "zero", "offset"],
                    "fill": ["am", "offset", "count", "after"],
                    "move": ["am", "zero", "offset", "count"]}[kind]
            opcode = {"swap": "buffer.swap", "fill": "buffer.fill_range", "move": "buffer.move_within"}[kind]
            ops.append(operation(opcode, args))
        ops += [operation("loan.end", ["am"]), operation("owner.drop", ["a"])]
        functions.append(function("bad_" + kind, params, [], ["alloc", "read", "write", "trap"],
                                  [block("entry", params, ops, ret())]))
    return _document(functions)


EMPTY_MEMORY_DRIVER = r"""
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
uint64_t empty_memory(void);
void *__wrap_malloc(size_t n) { (void)n; _Exit(91); }
void *__wrap_calloc(size_t n, size_t s) { (void)n; (void)s; _Exit(92); }
void __wrap_free(void *p) { (void)p; _Exit(93); }
void *__wrap_memset(void *p, int c, size_t n) { (void)p; (void)c; (void)n; _Exit(94); }
void *__wrap_memcpy(void *d, const void *s, size_t n) { (void)d; (void)s; (void)n; _Exit(95); }
void *__wrap_memmove(void *d, const void *s, size_t n) { (void)d; (void)s; (void)n; _Exit(96); }
int main(void) { return empty_memory() == 73 ? 0 : 97; }
"""


BOUNDS_OBSERVER = r"""
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
void bad_swap(uint64_t, uint64_t);
void bad_fill(uint64_t, uint64_t);
void bad_move(uint64_t, uint64_t);
void bad_copy(uint64_t, uint64_t);
static unsigned char allocations[2][4];
static unsigned allocated, filled, expected_allocations;
void *__wrap_calloc(size_t n, size_t s) {
    if (n != 1 || s != 4 || allocated >= 2) _Exit(80);
    return allocations[allocated++];
}
void *__wrap_memset(void *p, int c, size_t n) {
    if (filled >= allocated || p != allocations[filled] || n != 4 || c != (filled ? 99 : 17)) _Exit(81);
    unsigned char *q = p;
    for (size_t i = 0; i < n; i++) q[i] = (unsigned char)c;
    filled++;
    return p;
}
void __wrap_free(void *p) { (void)p; _Exit(82); }
void *__wrap_memcpy(void *d, const void *s, size_t n) { (void)d; (void)s; (void)n; _Exit(83); }
void *__wrap_memmove(void *d, const void *s, size_t n) { (void)d; (void)s; (void)n; _Exit(84); }
_Noreturn void __wrap_abort(void) {
    if (allocated != expected_allocations || filled != expected_allocations) _Exit(85);
    for (unsigned a = 0; a < allocated; a++)
        for (unsigned i = 0; i < 4; i++)
            if (allocations[a][i] != (a ? 99 : 17)) _Exit(86);
    _Exit(90); /* exact abort boundary observed, bytes untouched, no cleanup claimed */
}
int main(int argc, char **argv) {
    if (argc != 4) return 87;
    uint64_t offset = strtoull(argv[2], NULL, 10), count = strtoull(argv[3], NULL, 10);
    expected_allocations = !strcmp(argv[1], "bad_copy") ? 2 : 1;
    if (!strcmp(argv[1], "bad_copy")) bad_copy(offset, count);
    else if (!strcmp(argv[1], "bad_swap")) bad_swap(offset, count);
    else if (!strcmp(argv[1], "bad_fill")) bad_fill(offset, count);
    else if (!strcmp(argv[1], "bad_move")) bad_move(offset, count);
    else return 88;
    return 89; /* a required trap was not reached */
}
"""


def _abi_program():
    types = ("i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "bool", "u8")
    params = [("a" + str(i), typ) for i, typ in enumerate(types)]
    # Force an actually used >4-KiB native frame so the stack-probe prologue
    # must preserve the incoming argument registers before saving them.
    ops = [constant("padding" + str(i), "u64", i) for i in range(600)]
    ops.append(constant("sum0", "u64", 0))
    total = 0
    for i, typ in enumerate(types):
        if typ == "bool":
            continue
        ops += [operation("int.cast", ["a" + str(i)], [("wide" + str(i), "u64")], mode="wrap"),
                operation("int.add.wrap", ["sum" + str(total), "wide" + str(i)], [("sum" + str(total + 1), "u64")])]
        total += 1
    ops += [operation("int.add.wrap", ["sum" + str(total), "padding599"], [("with_padding", "u64")]),
            constant("bonus", "u64", 101),
            operation("int.add.wrap", ["with_padding", "bonus"], [("with_bonus", "u64")]),
            operation("select", ["a8", "with_bonus", "with_padding"], [("answer", "u64")])]
    return _document([function("narrow_mix", params, ["u64"], [], [block("entry", params, ops, ret("answer"))])], version=1)


ABI_WITNESS = r"""
.text
.globl abi_witness
.type abi_witness,@function
abi_witness:
    push %rbp
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15
    sub $8, %rsp
    movabs $0xa5a5a5a5a5a5a5a5, %rax
    push %rax
    movabs $0xababababababab01, %rax
    push %rax
    movabs $0xfedcba9876543210, %rax
    push %rax
    movabs $0x8123456789abcdef, %rax
    push %rax
    movabs $0x0123456789abcd80, %rdi
    movabs $0xabcdefabcdefabfa, %rsi
    movabs $0xabcdefabcdef8001, %rdx
    movabs $0xabcdefabcdeffeed, %rcx
    movabs $0x1234567880000001, %r8
    movabs $0xabcdef01deadbeef, %r9
    movabs $0x1111222233334444, %rbp
    movabs $0x5555666677778888, %rbx
    mov %rsp, %r12
    movabs $0x9999aaaabbbbcccc, %r13
    movabs $0xddddeeeeffff0000, %r14
    movabs $0x0123456789abcdef, %r15
    call narrow_mix
    cmp %r12, %rsp
    jne .Lbad_abi
    movabs $0x1111222233334444, %r11
    cmp %r11, %rbp
    jne .Lbad_abi
    movabs $0x5555666677778888, %r11
    cmp %r11, %rbx
    jne .Lbad_abi
    movabs $0x9999aaaabbbbcccc, %r11
    cmp %r11, %r13
    jne .Lbad_abi
    movabs $0xddddeeeeffff0000, %r11
    cmp %r11, %r14
    jne .Lbad_abi
    movabs $0x0123456789abcdef, %r11
    cmp %r11, %r15
    jne .Lbad_abi
    jmp .Lrestore_abi
.Lbad_abi:
    movabs $0xdeadbeefdeadbeef, %rax
.Lrestore_abi:
    add $40, %rsp
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    pop %rbp
    ret
.size abi_witness, .-abi_witness
.section .note.GNU-stack,"",@progbits
"""


class DirectNativeProfileReview(unittest.TestCase):
    def test_public_loader_hook_symbols_rejected_before_object_publication(self):
        # _init was concretely observed becoming DT_INIT under GNU ld before
        # this guard. The other names are reserved for runtime/CRT lifecycle;
        # none may gain effects merely through loading a generated library.
        hooks = ("_init", "_fini", "__gmon_start__", "_ITM_registerTMCloneTable",
                 "_ITM_deregisterTMCloneTable", "__cxa_finalize", "__dso_handle")
        with tempfile.TemporaryDirectory(prefix="hia-direct-hook-review-") as temporary:
            root = Path(temporary)
            for name in hooks:
                document = _document([function(name, [], [], [], [block("entry", [], [], ret())])], version=1)
                program = verify_program(document)
                output = root / (name + ".o")
                with self.subTest(symbol=name), patch("hepta.hia_program_native.run_bounded",
                                                      side_effect=AssertionError("no native tool may run")):
                    with self.assertRaisesRegex(HIAProgramNativeRejected, "E_HIA_PROGRAM_ABI"):
                        build_program_machine(program, output, kind="object")
                    self.assertFalse(output.exists())

    def test_nonexported_core_hook_name_stays_a_private_renamed_function(self):
        document = _document([
            function("_init", [], ["u64"], [], [
                block("entry", [], [constant("value", "u64", 7)], ret("value"))]),
            function("entrypoint", [], ["u64"], [], [
                block("entry", [], [operation("call", [], [("value", "u64")], function="_init")], ret("value"))]),
        ], version=1)
        document["exports"] = ["entrypoint"]
        program = verify_program(document)
        image = emit_program_machine(program)
        self.assertEqual(image.exports, ("entrypoint",))
        self.assertNotIn(b"_init\0", image.object_bytes)
        self.assertEqual(execute_program(program, "entrypoint", [])["result"], 7)

    def test_future_verifier_admission_cannot_silently_extend_machine_lowering(self):
        # Model a future independent verifier accepting new Core constructs.
        # The already reviewed machine profile must still reject them, rather
        # than silently miscompile through broad "int." or "bool." prefixes.
        future = []
        document = _document([function("entrypoint", [], ["u8"], [], [
            block("entry", [], [constant("answer", "u8", 7)], ret("answer"))])], version=9)
        future.append(("schema", document))
        for opcode, typ in (("bool.nand", "bool"), ("int.add.saturating", "u8")):
            params = [("a", typ), ("b", typ)]
            document = _document([function("entrypoint", params, [typ], [], [
                block("entry", params, [operation(opcode, ["a", "b"], [("answer", typ)])], ret("answer"))])])
            future.append((opcode, document))
        document = _document([function("entrypoint", [], ["u128"], [], [
            block("entry", [], [constant("answer", "u128", 7)], ret("answer"))])])
        future.append(("type", document))
        for label, document in future:
            document["exports"] = ["entrypoint"]
            proposed = VerifiedProgram(json.dumps(document, sort_keys=True, separators=(",", ":")).encode())
            with self.subTest(construct=label), patch("hepta.hia_program.verify_program", return_value=proposed):
                with self.assertRaisesRegex(HIAProgramNativeRejected, "E_HIA_PROGRAM_PROFILE"):
                    emit_program_machine(proposed)


@unittest.skipUnless(CC and NATIVE_HOST, "real Linux x86-64 linker/caller required")
class DirectNativeIndependentReview(unittest.TestCase):
    def run_command(self, argv, timeout=30):
        result = subprocess.run([str(value) for value in argv], cwd=ROOT, capture_output=True,
                                text=True, timeout=timeout)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def test_original_324_case_chain_allocator_and_failure_matrix(self):
        from tools.qualify_hia_recursive_chain import (
            EXAMPLES, case_plan, independent_spec, load_examples, vm_ledger,
        )
        programs = load_examples()
        plan = case_plan()
        self.assertEqual(len(plan), 324)
        with tempfile.TemporaryDirectory(prefix="hia-direct-chain-review-") as temporary:
            root = Path(temporary)
            objects = []
            for name, program in programs.items():
                output = root / (name + ".o")
                build_program_machine(program, output, kind="object")
                objects.append(output)
            binary = root / "chain-observer"
            self.run_command([CC, "-O2", "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free",
                              EXAMPLES / "allocator_driver.c", *objects, "-o", binary])
            for name, n, mode, fail in plan:
                with self.subTest(function=name, n=n, mode=mode, fail_at=fail):
                    program = programs["composite_v2" if name in {"chain_task", "chain_stored_loan"} else "core_v7"]
                    args = [] if name == "chain_empty_pop" else [n, mode] if name == "chain_task" else [n]
                    expected = independent_spec(name, n, mode, fail)
                    observed = json.loads(self.run_command([binary, name, n, mode, fail]).stdout)
                    reference = execute_program(program, name, args, allocation_fail_at=fail or None)
                    self.assertEqual(vm_ledger(reference), expected)
                    self.assertEqual(observed, expected)
                    for field in ("live_bytes", "live_owners", "live_chains", "live_chain_nodes", "live_local_loans"):
                        self.assertEqual(reference["resources"][field], 0, field)

    def test_zero_byte_memory_operations_call_neither_allocator_nor_libc_memory(self):
        document = _empty_memory_program()
        reference = execute_program(verify_program(document), "empty_memory", [])
        self.assertEqual(reference["result"], 73)
        self.assertEqual(reference["resources"]["allocation_attempts"], 0)
        self.assertEqual(reference["resources"]["frees"], 0)
        with tempfile.TemporaryDirectory(prefix="hia-direct-empty-review-") as temporary:
            root = Path(temporary); obj = root / "empty.o"; source = root / "observer.c"; binary = root / "observer"
            build_program_machine(document, obj, kind="object")
            source.write_text(EMPTY_MEMORY_DRIVER)
            flags = ["-Wl,--wrap=" + name for name in ("malloc", "calloc", "free", "memset", "memcpy", "memmove")]
            self.run_command([CC, "-O0", "-fno-builtin", source, obj, *flags, "-o", binary])
            self.run_command([binary])

    def test_invalid_complete_ranges_trap_before_any_partial_write(self):
        program = verify_program(_bounds_program())
        cases = [("bad_swap", 4, 0), ("bad_swap", (1 << 64) - 1, 0)]
        cases += [(name, offset, count) for name in ("bad_fill", "bad_move", "bad_copy")
                  for offset, count in ((3, 2), ((1 << 64) - 1, 0), (0, (1 << 64) - 1))]
        with tempfile.TemporaryDirectory(prefix="hia-direct-bounds-review-") as temporary:
            root = Path(temporary); obj = root / "ranges.o"; source = root / "observer.c"; binary = root / "observer"
            build_program_machine(program, obj, kind="object")
            source.write_text(BOUNDS_OBSERVER)
            flags = ["-Wl,--wrap=" + name for name in ("calloc", "free", "memset", "memcpy", "memmove", "abort")]
            self.run_command([CC, "-O0", "-fno-builtin", source, obj, *flags, "-o", binary])
            for name, offset, count in cases:
                with self.subTest(function=name, offset=offset, count=count):
                    with self.assertRaises(HIAProgramTrap) as caught:
                        execute_program(program, name, [offset, count])
                    self.assertEqual(caught.exception.code, "bounds")
                    child = subprocess.run([str(binary), name, str(offset), str(count)],
                                           capture_output=True, text=True, timeout=10)
                    self.assertEqual(child.returncode, 90, child.stdout + child.stderr)

    def test_dirty_high_bits_callee_saves_stack_arguments_and_page_probe(self):
        program = verify_program(_abi_program())
        values = [-128, 250, -32767, 0xfeed, -2147483647, 0xdeadbeef,
                  0x8123456789abcdef - (1 << 64), 0xfedcba9876543210, True, 0xa5]
        expected = execute_program(program, "narrow_mix", values)["result"]
        self.assertNotEqual(expected, 0xdeadbeefdeadbeef)
        with tempfile.TemporaryDirectory(prefix="hia-direct-abi-review-") as temporary:
            root = Path(temporary); obj = root / "core.o"; witness = root / "witness.S"; driver = root / "driver.c"
            binary = root / "abi-observer"
            receipt = build_program_machine(program, obj, kind="object")
            self.assertGreater(receipt["function_frames"]["narrow_mix"], 4096)
            witness.write_text(ABI_WITNESS)
            driver.write_text("#include <stdint.h>\n#include <stdio.h>\nuint64_t abi_witness(void);\n"
                              "int main(void){uint64_t x=abi_witness();printf(\"%llu\\n\",(unsigned long long)x);return 0;}\n")
            self.run_command([CC, "-O2", driver, witness, obj, "-o", binary])
            self.assertEqual(int(self.run_command([binary]).stdout), expected)


class SafetyContractDirectNativeBoundaryTests(unittest.TestCase):
    def test_direct_x86_machine_backend_is_explicitly_unproved(self):
        contract = json.loads((ROOT / "docs/HIA_SAFETY_CONTRACT.json").read_bytes())
        catalog = contract["registry"]["instruction_catalog"]
        self.assertIn("direct x86-64 machine backends", catalog["backend_scope"])
        self.assertIn("catalog inclusion grants no native entry ABI", catalog["backend_scope"])
        self.assertFalse(catalog["safety_certificate"])
        self.assertFalse(contract["unproved_claims"]["core_to_native_refinement_proved"])
        capability = next(row for row in contract["capabilities"] if row["id"] == "native_lowering")
        self.assertTrue(any("direct x86-64 machine-code lowering" in item for item in capability["exclusions"]))


if __name__ == "__main__":
    unittest.main()
