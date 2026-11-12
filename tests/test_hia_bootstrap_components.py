"""HIA-authored byte lexer and finite assembly parser/emitter, actually native.

The independent Python scanner below is an oracle only.  Native invocations read
the supplied source bytes; no token or expected instruction bytes are sent in.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_native_byte_runner import invoke_byte_program

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "examples" / "hia_bootstrap" / "components.hepta"
INVALID, NO_SPACE = 0xffffffff, 0xfffffffe
NATIVE = platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"} and shutil.which("ld")


def constant_source(value, *, module="scalar_seed", function="answer", block="entry", variable="result"):
    return (f"hia-asm.v1 hepta.hia.program.v8 {module}\n"
            f"exports({function})\n"
            f"fn {function}() -> (u64) effects() entry({block})\n"
            f"block {block}()\n"
            f"  {variable}:u64 = const() {{\"value\":{value}}}\n"
            f"  ret({variable})\nend\n").encode("ascii")


def reference_tokens(source):
    """Independent bounded ASCII oracle, not called from any native component."""
    text = source.decode("ascii")
    pattern = re.compile(r'[ \t\r\n]+|[A-Za-z_][A-Za-z_0-9.]*|[0-9]+|[(){}\[\],:=\->]')
    result, position = [], 0
    while position < len(text):
        if text[position] == '"':
            start = position
            position += 1
            # A quoted token has one forward cursor. Every escape consumes
            # exactly two bytes, so incomplete escape-heavy inputs stay linear.
            while position < len(text):
                char = text[position]
                if char == '"':
                    position += 1
                    break
                if char == '\\':
                    position += 1
                    if position == len(text) or text[position] not in '"\\/bfnrt':
                        raise ValueError("not in the ASCII bootstrap lexer")
                elif not 0x20 <= ord(char) <= 0x7e:
                    raise ValueError("not in the ASCII bootstrap lexer")
                position += 1
            else:
                raise ValueError("not in the ASCII bootstrap lexer")
            result.append((3, start, position))
            continue
        match = pattern.match(text, position)
        if match is None:
            raise ValueError("not in the ASCII bootstrap lexer")
        token = match[0]
        if not token.isspace():
            kind = 2 if token[0].isdigit() else 1 if token[0].isalpha() or token[0] == "_" else ord(token) + 128
            result.append((kind, position, match.end()))
        position = match.end()
    return result


def execute_text(text):
    """Wrap HIA-emitted bytes without translating their instructions; run child."""
    from hepta.hia_machine_elf import write_elf_object
    with tempfile.TemporaryDirectory(prefix="hia-component-text-") as directory:
        obj, library = Path(directory) / "generated.o", Path(directory) / "generated.so"
        obj.write_bytes(write_elf_object(text, [{"name": "generated", "offset": 0, "size": len(text), "global": True}], []))
        subprocess.run(["ld", "-shared", "-z", "noexecstack", "--no-undefined", "-o", str(library), str(obj)],
                       check=True, capture_output=True, timeout=10)
        script = "import ctypes,sys; x=ctypes.CDLL(sys.argv[1]).generated; x.argtypes=[]; x.restype=ctypes.c_uint64; print(x())"
        result = subprocess.run([sys.executable, "-B", "-c", script, str(library)], capture_output=True, text=True, timeout=3)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        return int(result.stdout.strip())


class BootstrapSourceTests(unittest.TestCase):
    def test_ascii_reference_lexer_handles_long_escaped_strings(self):
        for escaped in (br'\\/', br'\"'):
            source = b'"' + escaped * 16384 + b'"'
            self.assertEqual(reference_tokens(source), [(3, 0, len(source))])
            for incomplete in (source[:-1], source[:-1] + b'\\'):
                with self.assertRaisesRegex(ValueError, "not in the ASCII bootstrap lexer"):
                    reference_tokens(incomplete)

    def test_checked_in_hia_is_the_complete_authoring_output(self):
        from tools.generate_hia_bootstrap_components import component_document
        source = SOURCE.read_bytes()
        program = assemble_program(source)
        self.assertEqual(render_assembly(program).encode(), source)
        self.assertEqual(render_assembly(component_document()).encode(), source)
        self.assertEqual(len(program.as_dict()["functions"]), 30)
        self.assertGreater(len(source), 60000)


@unittest.skipUnless(NATIVE, "Linux x86-64 and GNU ld required")
class BootstrapNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_bytes()
        cls.program = assemble_program(cls.source)

    def invoke(self, name, source, capacity):
        result = invoke_byte_program(self.program, name, [source, bytearray([0xa5]) * capacity])
        self.assertEqual(result["status"], "returned", result)
        self.assertEqual(result["abi_status"], 0)
        self.assertEqual(result["arguments"][0], source)
        return result

    def test_native_lexer_reads_its_entire_actual_hia_source(self):
        result = self.invoke("lex_assembly", self.source, 1 << 20)
        expected = reference_tokens(self.source)
        self.assertEqual(result["core_status"], len(expected))
        observed = list(struct.iter_unpack("<III", result["arguments"][1][:12 * len(expected)]))
        self.assertEqual(observed, expected)
        self.assertEqual(result["arguments"][1][12 * len(expected):], bytes([0xa5]) * ((1 << 20) - 12 * len(expected)))

    def test_lexer_punctuation_strings_escapes_and_invalid_source(self):
        for source in (b'', b'alpha_2 int.add.wrap 0123 -17 (){}[],:=->\n',
                       br'"mode" "a\"b" "back\\slash" "\n\r\t\/"'):
            expected = reference_tokens(source)
            result = self.invoke("lex_assembly", source, max(1, len(expected) * 12))
            self.assertEqual(result["core_status"], len(expected))
            self.assertEqual(list(struct.iter_unpack("<III", result["arguments"][1][:12 * len(expected)])), expected)
        for source in (b'"unterminated', b'"bad\\q"', b'"raw\nline"', b'\xff', b'\0', b'# comment', br'"\u0041"'):
            result = self.invoke("lex_assembly", source, 128)
            self.assertEqual(result["core_status"], INVALID, source)
            self.assertEqual(result["arguments"][1], bytes([0xa5]) * 128)

    def test_lexer_capacity_rejection_has_no_partial_output(self):
        source = b"alpha beta"
        result = self.invoke("lex_assembly", source, 23)
        self.assertEqual(result["core_status"], NO_SPACE)
        self.assertEqual(result["arguments"][1], bytes([0xa5]) * 23)

    def test_real_hia_parser_emits_and_executes_changed_u64_programs(self):
        previous = None
        for value in (0, 1, 127, 128, 0xffffffff, 0x100000000, 0x8000000000000000, 0xffffffffffffffff):
            source = constant_source(value)
            assemble_program(source)  # independent existing-language admission
            result = self.invoke("compile_constant", source, 32)
            self.assertEqual(result["core_status"], 11)
            code = result["arguments"][1][:11]
            self.assertEqual(code, b"\x48\xb8" + value.to_bytes(8, "little") + b"\xc3")
            self.assertEqual(execute_text(code), value)
            self.assertEqual(result["arguments"][1][11:], bytes([0xa5]) * 21)
            if previous is not None:
                self.assertNotEqual(code, previous)
            previous = code

    def test_parser_uses_real_identifier_bindings(self):
        source = constant_source(98765, module="other_module", function="f_14", block="begin_2", variable="v3")
        result = self.invoke("compile_constant", source, 11)
        self.assertEqual(result["core_status"], 11)
        self.assertEqual(execute_text(result["arguments"][1]), 98765)
        for mutated in (source.replace(b"ret(v3)", b"ret(other)"), source.replace(b"entry(begin_2)", b"entry(other)"),
                        source.replace(b"exports(f_14)", b"exports(other)")):
            result = self.invoke("compile_constant", mutated, 16)
            self.assertEqual(result["core_status"], INVALID)
            self.assertEqual(result["arguments"][1], bytes([0xa5]) * 16)

    def test_parser_rejects_semantic_and_line_grammar_counterexamples_without_writes(self):
        source = constant_source(123)
        invalid = [constant_source(-1), constant_source(1 << 64), constant_source("01"),
                   source.replace(b"u64", b"u32"), source.replace(b"const()", b"int.add.wrap()"),
                   source.replace(b"hia-asm", b"hia - asm"), source.replace(b"->", b"- >"),
                   source.replace(b"exports(", b"exports ("), source.replace(b"ret(", b"ret ("),
                   source.replace(b"const() {", b"const(){"), source.replace(b"\nblock", b" block"),
                   source.replace(b"\n", b"\r\n"), constant_source(2, module="a" * 129),
                   source + b"fn unexpected() -> (u64) effects() entry(entry)\n"]
        for mutated in invalid:
            result = self.invoke("compile_constant", mutated, 16)
            self.assertEqual(result["core_status"], INVALID, mutated)
            self.assertEqual(result["arguments"][1], bytes([0xa5]) * 16)

    def test_compiler_capacity_failure_and_own_source_unsupported_are_explicit(self):
        result = self.invoke("compile_constant", constant_source(42), 10)
        self.assertEqual(result["core_status"], NO_SPACE)
        self.assertEqual(result["arguments"][1], bytes([0xa5]) * 10)
        result = self.invoke("compile_constant", self.source, 32)
        self.assertEqual(result["core_status"], INVALID)
        self.assertEqual(result["arguments"][1], bytes([0xa5]) * 32)
        # A lexer reading itself is a useful component check, not B1/B2/B3.
        self.assertFalse(result["build_receipt"]["claims"]["self_hosted"])


if __name__ == "__main__":
    unittest.main()
