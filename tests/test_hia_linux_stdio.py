"""Public opt-in contracts. No test binds the reference provider to real fds."""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import HIAProgramRejected, VerifiedProgram, verify_program
from hepta.hia_program_runtime import execute_program, HIAProgramTrap, HIAProgramBudgetExceeded
from hepta.hia_linux_stdio import (
    PROFILE, READ, WRITE, IO_OPCODES, VerifiedLinuxStdioProgram,
    LinuxStdioProviderRejected, LinuxStdioRequest,
    LinuxStdioSignal,
)


def program(kind="read", offset=0, count=2, *, buffer=None):
    """Same signed-word storage fixture as the frozen private kernel controls."""
    serial = 3
    instructions = []
    def op(typ, operation, args=(), attrs=None):
        nonlocal serial
        name = "v" + str(serial)
        serial += 1
        suffix = " " + json.dumps(attrs, separators=(",", ":")) if attrs is not None else ""
        instructions.append("  " + name + ":" + typ + " = " + operation + "(" + ",".join(args) + ")" + suffix + "\n")
        return name
    at = op("usize", "const", attrs={"value": offset})
    size = op("usize", "const", attrs={"value": count})
    result = op("i64", READ if kind == "read" else WRITE,
                (buffer or ("v1" if kind == "read" else "v0"), at, size))
    word = op("u64", "int.cast", (result,), {"mode": "wrap"})
    for index in range(8):
        target = op("usize", "const", attrs={"value": index})
        value = word
        if index:
            shift = op("u64", "const", attrs={"value": index * 8})
            value = op("u64", "int.shr.checked", (word, shift))
        byte = op("u8", "int.cast", (value,), {"mode": "wrap"})
        instructions.append("  _ = buffer.store(v2," + target + "," + byte + ")\n")
    zero = op("u32", "const", attrs={"value": 0})
    instructions.append("  ret(" + zero + ")\n")
    return ("hia-asm.v1 hepta.hia.program.v8 selfhost_linux_stdio\n"
            "fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(read,write,trap,linux_io) entry(b0)\n"
            "block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)\n" + "".join(instructions) + "end\n").encode()


TRANSITIVE = b'''hia-asm.v1 hepta.hia.program.v8 selfhost_linux_stdio
fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(write,trap) entry(b0)
block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)
  v3:u32 = call(v1) {"function":"f1"}
  ret(v3)
end
fn f1(v0:mutbuf) -> (u32) effects(write,trap,linux_io) entry(b0)
block b0(v0:mutbuf)
  v1:usize = const() {"value":0}
  v2:usize = const() {"value":2}
  v3:i64 = linux.stdin.read(v0,v1,v2)
  v4:u32 = const() {"value":0}
  ret(v4)
end
'''


class LinuxStdioPublicSourceTests(unittest.TestCase):
    def checked(self, raw=None):
        return assemble_program(program() if raw is None else raw, profile=PROFILE)

    def run_vm(self, checked, provider, *, source=b"source", output=b"\xa5" * 32,
               workspace=b"\x5a" * 64, **limits):
        return execute_program(checked, "f0", (source, output, workspace),
            profile=PROFILE, linux_stdio_provider=provider, **limits)

    def test_public_roundtrip_checks_actual_io_opcodes_without_proxy_calls(self):
        checked = self.checked()
        self.assertIs(type(checked), VerifiedLinuxStdioProgram)
        self.assertNotIsInstance(checked, VerifiedProgram)
        self.assertEqual(len(checked.as_dict()["functions"]), 1)
        operations = [i["op"] for b in checked.as_dict()["functions"][0]["blocks"] for i in b["ops"]]
        self.assertIn(READ, operations)
        self.assertNotIn("call", operations)
        self.assertEqual(render_assembly(checked, profile=PROFILE).encode(), program())
        self.assertEqual(verify_program(checked, profile=PROFILE).canonical_bytes, checked.canonical_bytes)
        self.assertFalse(checked.report()["default_core_authority"])

    def test_default_assembly_core_vm_and_code_still_refuse_extended_input(self):
        checked = self.checked()
        from hepta.hia_program_native import emit_program_machine, compile_program_machine
        from hepta.hia_program_llvm import emit_program_llvm
        cases = [lambda: assemble_program(program()),
                 lambda: render_assembly(checked),
                 lambda: verify_program(checked),
                 lambda: verify_program(checked.as_dict()),
                 lambda: execute_program(checked, "f0", (b"", b"", b"")),
                 lambda: emit_program_machine(checked),
                 lambda: compile_program_machine(checked, program=checked, output="unreachable"),
                 lambda: emit_program_llvm(checked)]
        for call in cases:
            with self.subTest(call=cases.index(call)):
                with self.assertRaises((HIAProgramRejected, ValueError, TypeError)):
                    call()

    def test_explicit_profile_is_exact_and_never_guessed_from_module(self):
        for profile in [False, True, 1, "", "selfhost_linux_stdio", PROFILE + " "]:
            with self.subTest(profile=profile):
                with self.assertRaises(HIAProgramRejected):
                    assemble_program(program(), profile=profile)
        with self.assertRaises(HIAProgramRejected):
            assemble_program(program().replace(b"selfhost_linux_stdio", b"selfhost"), profile=PROFILE)

    def test_exact_types_effects_and_empty_attributes_are_mandatory(self):
        raw = program()
        invalid = [
            raw.replace(b",linux_io", b"", 1),
            raw.replace(b"read,write,trap,linux_io", b"read,trap,linux_io", 1),
            raw.replace(b",linux_io)", b",linux_io,linux_io)", 1),
            raw.replace(b",linux_io)", b",linux_arbitrary_io)", 1),
            raw.replace(b"linux.stdin.read(v1,", b"linux.stdin.read(v0,", 1),
            raw.replace(b"v5:i64", b"v5:u64", 1),
            raw.replace(b"v3:usize", b"v3:u64", 1),
            raw.replace(b"v4:usize", b"v4:u64", 1),
            raw.replace(b"linux.stdin.read(v1,v3,v4)", b"linux.stdin.read(v1,v3)", 1),
            raw.replace(b"linux.stdin.read(v1,v3,v4)", b'linux.stdin.read(v1,v3,v4) {"fd":9}', 1),
            raw.replace(b"linux.stdin.read", b"linux.stderr.write", 1),
        ]
        for index, source in enumerate(invalid):
            with self.subTest(index=index):
                with self.assertRaises(HIAProgramRejected):
                    self.checked(source)

    def test_parent_suspend_and_loan_end_use_the_real_capability_checker(self):
        raw = program()
        blocked = raw.replace(b"  v3:usize", b"  v900:mutbuf = borrow.mut(v1)\n  v3:usize", 1)
        blocked = blocked.replace(b"  ret(", b"  _ = loan.end(v900)\n  ret(", 1)
        with self.assertRaises(HIAProgramRejected) as caught:
            self.checked(blocked)
        self.assertEqual(caught.exception.code, "E_HIA_LOAN")
        resumed = raw.replace(b"  v3:usize", b"  v900:mutbuf = borrow.mut(v1)\n  _ = loan.end(v900)\n  v3:usize", 1)
        result = self.run_vm(self.checked(resumed), lambda request: (2, b"hi"))
        self.assertEqual(bytes.fromhex(result["output_hex"]), b"hi" + b"\xa5" * 30)
        self.assertEqual(result["resources"]["loans_started"], 1)
        self.assertEqual(result["resources"]["loans_ended"], 1)

    def test_callee_effect_propagation_and_unknown_host_target_are_closed(self):
        with self.assertRaises(HIAProgramRejected) as caught:
            self.checked(TRANSITIVE)
        self.assertEqual(caught.exception.code, "E_HIA_EFFECT")
        permitted = TRANSITIVE.replace(b"effects(write,trap)", b"effects(write,trap,linux_io)", 1)
        calls = []
        result = self.run_vm(self.checked(permitted), lambda request: (calls.append(request) or (2, b"ok")))
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["values"], [0])
        raw = program().replace(b"linux.stdin.read(v1,v3,v4)", b'call(v1,v3,v4) {"function":"syscall"}')
        with self.assertRaises(HIAProgramRejected):
            self.checked(raw)
        raw = program().replace(b"linux.stdin.read(v1,v3,v4)", b'call(v1,v3,v4) {"function":"linux.stdin.read"}')
        with self.assertRaises(HIAProgramRejected):
            self.checked(raw)

    def test_forged_or_modified_verified_bytes_are_rechecked(self):
        checked = self.checked()
        invalid = checked.canonical_bytes.replace(b',"linux_io"', b"", 1)
        self.assertNotEqual(invalid, checked.canonical_bytes)
        forged = VerifiedLinuxStdioProgram(invalid)
        with self.assertRaises(HIAProgramRejected):
            verify_program(forged, profile=PROFILE)
        bad = VerifiedLinuxStdioProgram(bytearray(checked.canonical_bytes))
        with self.assertRaises(HIAProgramRejected):
            verify_program(bad, profile=PROFILE)
        document = checked.as_dict()
        document["functions"][0]["effects"] = []
        self.assertEqual(verify_program(checked, profile=PROFILE).canonical_bytes, checked.canonical_bytes)

    def test_exact_negative_errno_short_read_and_zero_still_issue_one_effect(self):
        cases = [("read", 0, 4, -9, b""), ("read", 0, 4, -4, b""),
                 ("read", 0, 4, -4095, b""), ("read", 3, 8, 3, b"abc"),
                 ("read", 32, 0, 0, b""), ("read", 0, 0, -9, b""),
                 ("write", 0, 3, 2, b""), ("write", 0, 0, -9, b""),
                 ("write", 6, 0, 0, b""), ("write", 0, 3, -32, b"")]
        for kind, offset, count, expected, payload in cases:
            with self.subTest(kind=kind, offset=offset, count=count, expected=expected):
                seen = []
                def provider(request):
                    seen.append(request)
                    return expected, payload
                result = self.run_vm(self.checked(program(kind, offset, count)), provider)
                self.assertEqual(len(seen), 1)
                self.assertEqual(seen[0].fd, 0 if kind == "read" else 1)
                self.assertEqual(int.from_bytes(bytes.fromhex(result["workspace_hex"])[:8], "little", signed=True), expected)
                self.assertEqual(result["values"], [0])

    def test_bounds_proven_before_provider_including_overflow_and_zero_count(self):
        for kind, offset, count in [("read", 33, 0), ("read", 31, 2),
                ("read", (1 << 64) - 1, 1), ("write", 7, 0), ("write", 5, 2)]:
            with self.subTest(kind=kind, offset=offset, count=count):
                with self.assertRaises(HIAProgramTrap) as caught:
                    self.run_vm(self.checked(program(kind, offset, count)),
                                lambda request: self.fail("provider must not run"))
                self.assertEqual(caught.exception.code, "bounds")
                self.assertEqual(caught.exception.report["effects"], [])
                self.assertEqual(caught.exception.report["output_hex"], (b"\xa5" * 32).hex())

    def test_provider_domain_and_foreign_exception_identity_are_preserved(self):
        checked = self.checked()
        invalid = [(True, b"x"), (1, bytearray(b"x")), (1,), (3, b"abc"),
                   (-4096, b""), (-9, b"x"), (2, b"x"), (0, b"x")]
        for response in invalid:
            with self.subTest(response=repr(response)):
                calls = []
                with self.assertRaises(LinuxStdioProviderRejected):
                    self.run_vm(checked, lambda request: (calls.append(request) or response))
                self.assertEqual(len(calls), 1)
        original = RuntimeError("exact provider exception")
        def provider(request):
            raise original
        with self.assertRaises(RuntimeError) as caught:
            self.run_vm(checked, provider)
        self.assertIs(caught.exception, original)

    def test_request_carries_no_mutable_owner_or_implicit_real_fd_provider(self):
        seen = []
        def provider(request):
            self.assertIs(type(request), LinuxStdioRequest)
            self.assertIs(type(request.write_bytes), bytes)
            with self.assertRaises(FrozenInstanceError):
                request.fd = 2
            seen.append(request)
            return 2, b""
        result = self.run_vm(self.checked(program("write", 1, 2)), provider)
        self.assertEqual(seen[0].write_bytes, b"ou")
        self.assertFalse(result["actual_kernel_execution"])
        with self.assertRaises(HIAProgramRejected):
            execute_program(self.checked(), "f0", (b"", b"", b""), profile=PROFILE)

    def test_default_global_opcode_and_effect_tables_are_not_extended(self):
        from hepta.hia_opcodes import EFFECTS, OPCODES, opcode_catalog, opcode_spec, OpcodeRejected
        self.assertEqual(EFFECTS, frozenset({"alloc", "read", "write", "trap"}))
        self.assertTrue(set(IO_OPCODES).isdisjoint(OPCODES))
        names = {row["name"] for row in opcode_catalog()["instructions"]}
        self.assertTrue(set(IO_OPCODES).isdisjoint(names))
        for operation in IO_OPCODES:
            with self.assertRaises(OpcodeRejected):
                opcode_spec(operation)

    def test_public_byte_boundary_exact_types_and_original_extent_limits(self):
        checked = self.checked()
        for buffers in [(b"", bytearray(32), b""), (b"", b"", b"", b""),
                        (b"", bytes(1048577), b"")]:
            with self.subTest(length=len(buffers)):
                with self.assertRaises(HIAProgramRejected):
                    execute_program(checked, "f0", buffers, profile=PROFILE,
                                    linux_stdio_provider=lambda request: (0, b""))
        with self.assertRaises(HIAProgramRejected):
            execute_program(checked, "f0", (b"", b"", b""), profile=PROFILE,
                linux_stdio_provider=lambda request: (0, b""), bounded_resource_limits={})

    def test_exact_one_mib_read_and_write_buffers_are_preserved(self):
        payload = bytes(range(256)) * 4096
        checked = self.checked(program("read", 0, len(payload)))
        result = self.run_vm(checked, lambda request: (len(payload), payload),
                             source=b"input", output=bytes(len(payload)))
        self.assertEqual(result["output_hex"], payload.hex())
        written = []
        checked = self.checked(program("write", 0, len(payload)))
        result = self.run_vm(checked, lambda request: (written.append(request.write_bytes) or (len(payload), b"")),
                             source=payload)
        self.assertEqual(written, [payload])
        self.assertEqual(result["source_hex"], payload.hex())

    def test_step_stop_is_not_errno_and_runs_no_provider(self):
        with self.assertRaises(HIAProgramBudgetExceeded) as caught:
            self.run_vm(self.checked(), lambda request: self.fail("not reached"), max_steps=1)
        self.assertEqual(caught.exception.code, "steps")
        self.assertEqual(caught.exception.report["effects"], [])

    def test_public_builder_rejects_bad_profile_and_compiler_pin_before_execution(self):
        from tools.build_hia_linux_stdio_program import build_linux_stdio_program
        checked = self.checked()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seed = root / "compiler.bin"
            seed.write_bytes(b"not an admitted compiler")
            with mock.patch("tools.build_hia_linux_stdio_program.compile_stage", side_effect=AssertionError("no child")):
                for profile, digest in [("", "0" * 64), (PROFILE, "0" * 64), (PROFILE, True)]:
                    with self.subTest(profile=profile, digest=digest):
                        with self.assertRaises((HIAProgramRejected, ValueError)):
                            build_linux_stdio_program(checked, root / "out", profile=profile,
                                compiler=seed, compiler_sha256=digest)
                        self.assertFalse((root / "out").exists())

    def test_original_compiler_bounds_and_entry_schema_are_not_widened(self):
        from hepta.hia_linux_stdio import FUNCTION_LIMIT, BLOCK_LIMIT, INSTRUCTION_LIMIT
        from tools.hia_selfhost_limits import MAX_FUNCTIONS, MAX_BLOCKS, MAX_INSTRUCTIONS
        self.assertEqual((FUNCTION_LIMIT, BLOCK_LIMIT, INSTRUCTION_LIMIT),
                         (MAX_FUNCTIONS, MAX_BLOCKS, MAX_INSTRUCTIONS))
        self.assertEqual((FUNCTION_LIMIT, BLOCK_LIMIT, INSTRUCTION_LIMIT), (128, 1536, 8192))
        original = self.checked().as_dict()
        many = copy.deepcopy(original)
        many["functions"] = [copy.deepcopy(original["functions"][0]) for _ in range(129)]
        for index, function in enumerate(many["functions"]):
            function["name"] = "f" + str(index)
        with self.assertRaises(HIAProgramRejected) as caught:
            verify_program(many, profile=PROFILE)
        self.assertEqual(caught.exception.code, "E_HIA_LIMIT")
        instructions = copy.deepcopy(original)
        block = instructions["functions"][0]["blocks"][0]
        block["ops"] = [{"op": "const", "args": [], "attrs": {"value": 0},
                         "out": [{"name": "v" + str(3 + i), "type": "u32"}]}
                        for i in range(8193)]
        block["term"] = {"op": "ret", "values": ["v3"]}
        with self.assertRaises(HIAProgramRejected) as caught:
            verify_program(instructions, profile=PROFILE)
        self.assertEqual(caught.exception.code, "E_HIA_LIMIT")
        for edit in [lambda d: d.update(schema="hepta.hia.program.v7"),
                     lambda d: d["functions"][0].update(name="other")]:
            doc = copy.deepcopy(original)
            edit(doc)
            with self.assertRaises(HIAProgramRejected):
                verify_program(doc, profile=PROFILE)

    def test_reference_signal_is_explicit_exact_and_retains_full_state(self):
        import signal
        for number in [True, 0, 65, signal.SIGPIPE]:
            with self.subTest(number=number):
                with self.assertRaises(ValueError):
                    LinuxStdioSignal(number)
        original = LinuxStdioSignal(int(signal.SIGPIPE))
        def provider(request):
            raise original
        with self.assertRaises(LinuxStdioSignal) as caught:
            self.run_vm(self.checked(program("write", 0, 3)), provider)
        self.assertIs(caught.exception, original)
        self.assertEqual(original.report["signal"], 13)
        self.assertEqual(original.report["output_hex"], (b"\xa5" * 32).hex())
        self.assertEqual(original.report["workspace_hex"], (b"\x5a" * 64).hex())
        self.assertEqual(len(original.report["effects"]), 1)
        self.assertFalse(original.report["actual_kernel_execution"])


if __name__ == "__main__":
    unittest.main()
