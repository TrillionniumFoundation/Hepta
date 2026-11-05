"""Real native enum facts and independent C ABI consumers, not a guessed layout."""
from __future__ import annotations

import json
import os
from pathlib import Path
import random
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.backend import compile_rust, emit_rust, find_rustc
from hepta.c_backend import compile_c, emit_c
from hepta.c_import import import_header
from hepta.checker import check
from hepta.modules import load_project
from hepta.parser import parse
from hepta.pipeline import analyze_project


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("gcc"), "native GCC enum probes required")
class CEnumImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-enum-tests-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.header = self.directory / "enums.h"

    def imported(self, source, **kwargs):
        self.header.write_text(source, encoding="utf-8")
        return import_header(self.header, **kwargs)

    def command(self, args, **kwargs):
        result = subprocess.run(args, capture_output=True, text=True, timeout=60, **kwargs)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def wrapper(self, flags):
        wrapper = self.directory / "enum-gcc"
        wrapper.write_text("#!/bin/sh\nexec " + shlex.quote(shutil.which("gcc")) +
                           " " + " ".join(shlex.quote(flag) for flag in flags) + ' "$@"\n')
        wrapper.chmod(0o755)
        return str(wrapper)

    def test_named_typedef_and_anonymous_enum_facts(self):
        result = self.imported("""
        #include <limits.h>
        #define STEP 4
        enum Signed { LOW = -7, NEXT, HIGH = 31, SAME = HIGH, };
        typedef enum Signed SignedAlias;
        typedef enum Positive { ZERO, MASK = (1u << STEP) - 1 } Positive;
        typedef enum { FIRST = 0x20, SECOND, THIRD = SECOND + 3 } Anonymous;
        typedef const enum Signed *SignedPointer;
        typedef struct State { enum Signed code; Positive mask; Anonymous count; } State;
        SignedAlias advance(SignedAlias value, SignedPointer previous);
        """)
        facts = result.manifest
        self.assertEqual(set(facts["enums"]), {"enum Signed", "enum Positive", "Anonymous"})
        expected = {"LOW": -7, "NEXT": -6, "HIGH": 31, "SAME": 31,
                    "ZERO": 0, "MASK": 15, "FIRST": 32, "SECOND": 33, "THIRD": 36}
        self.assertEqual({name: facts["constants"][name]["value"] for name in expected}, expected)
        for name in expected:
            self.assertEqual(facts["constants"][name]["c_type"], "int")
            self.assertEqual(facts["constants"][name]["hepta_type"], facts["primitive_types"]["int"]["hepta"])
        signed = facts["enums"]["enum Signed"]["hepta_type"]
        self.assertTrue(signed.startswith("i"))
        self.assertEqual(facts["typedefs"]["SignedAlias"], signed)
        self.assertEqual(facts["typedefs"]["SignedPointer"], "raw const " + signed)
        self.assertTrue(check(parse(result.source)).ok)

    def test_compiler_controls_short_enum_storage(self):
        result = self.imported("""
        typedef enum Signed { NEGATIVE = -2, POSITIVE = 3 } Signed;
        typedef enum Small { OFF, ON } Small;
        typedef enum Medium { MEDIUM_ZERO, MEDIUM_MAX = 300 } Medium;
        typedef enum Wide { WIDE_ZERO, WIDE_MAX = 70000 } Wide;
        """, cc=self.wrapper(["-fshort-enums"]))
        facts = result.manifest["enums"]
        self.assertEqual([facts["enum " + name]["hepta_type"] for name in
                          ["Signed", "Small", "Medium", "Wide"]], ["i8", "u8", "u16", "u32"])
        # An enumerator remains int even when its enum occupies one byte.
        self.assertEqual(result.manifest["constants"]["NEGATIVE"]["hepta_type"], "i32")
        self.assertEqual(result.manifest["constants"]["ON"]["hepta_type"], "i32")

    def test_implicit_values_and_expression_corpus_match_python(self):
        rng = random.Random(20261105)
        expected, declarations = {}, []
        for index in range(40):
            first = rng.randrange(-3000, 3000)
            shift = rng.randrange(1, 10)
            value = rng.randrange(1, 100)
            prefix = f"E{index}_"
            declarations.append(f"enum Case{index} {{ {prefix}A = {first}, {prefix}B, "
                                f"{prefix}C = ({value} << {shift}) | 3, "
                                f"{prefix}D = ({prefix}C ^ 7) & 32767 }};")
            expected.update({prefix + "A": first, prefix + "B": first + 1,
                             prefix + "C": (value << shift) | 3,
                             prefix + "D": (((value << shift) | 3) ^ 7) & 32767})
        result = self.imported("\n".join(declarations))
        self.assertEqual({k: v["value"] for k, v in result.manifest["constants"].items()}, expected)
        assertions = "\n".join(f"assert(cconst_{name}() == {value});" for name, value in expected.items())
        program = parse(result.source + "\nfn main() -> Unit effects { panic } {" + assertions + "}")
        checked = check(program)
        self.assertTrue(checked.ok, checked.diagnostics)
        for optimize in [False, True]:
            report = compile_c(emit_c(program, checked), optimize=optimize, sanitize=True,
                               output=self.directory / "constants")
            self.assertTrue(report["ok"], report["diagnostics"])
            self.command([report["artifact"]])

    def abi_fixture(self, *, short=False):
        cc = self.wrapper(["-fshort-enums"]) if short else shutil.which("gcc")
        result = self.imported("""
        typedef enum Signed { NEGATIVE = -2, POSITIVE = 3 } Signed;
        typedef enum Small { OFF, ON } Small;
        typedef struct State { Signed signed_value; Small small_value; int count; } State;
        Signed next_signed(Signed value);
        Small toggle(Small value);
        State transform(State value);
        void update(Signed *value);
        """, cc=cc, contracts={name: {"ffi", "unsafe", "write"} for name in
                               ["next_signed", "toggle", "transform", "update"]})
        signed = result.manifest["enums"]["enum Signed"]["hepta_type"]
        small = result.manifest["enums"]["enum Small"]["hepta_type"]
        source = result.source + f"""
        export "C" fn hepta_roundtrip(value: State) -> State effects {{ ffi, unsafe, write }} {{
            unsafe {{ return transform(value); }}
        }}
        fn main() -> Unit effects {{ ffi, unsafe, write, panic }} {{
            let negative: {signed} = -2;
            let on: {small} = 1;
            let state = State {{ signed_value: negative, small_value: on, count: 40 }};
            let mut changed: [{signed}; 1] = [negative];
            unsafe {{
                assert(next_signed(negative) == 3);
                assert(toggle(on) == 0);
                let output = transform(state);
                assert(output.signed_value == 3); assert(output.small_value == 0);
                assert(output.count == 42);
                update(ptr_mut(mut changed));
            }}
            assert(changed[0] == 3);
        }}
        """
        implementation = self.directory / "implementation.c"
        implementation.write_text('''#include "enums.h"
        Signed next_signed(Signed value) { return value == NEGATIVE ? POSITIVE : NEGATIVE; }
        Small toggle(Small value) { return value == ON ? OFF : ON; }
        State transform(State value) {
            value.signed_value = next_signed(value.signed_value);
            value.small_value = toggle(value.small_value); value.count += 2; return value;
        }
        void update(Signed *value) { *value = next_signed(*value); }
        ''')
        return result, parse(source), cc, implementation

    def execute_abi(self, *, short=False, backend="c"):
        result, program, cc, implementation = self.abi_fixture(short=short)
        checked = check(program)
        self.assertTrue(checked.ok, [d.to_dict() for d in checked.diagnostics])
        harness = self.directory / "harness.c"
        harness.write_text('''#include "enums.h"
        extern State hepta_roundtrip(State value);
        int main(void) {
            State input = { NEGATIVE, ON, 40 };
            State output = hepta_roundtrip(input);
            return !(output.signed_value == POSITIVE && output.small_value == OFF && output.count == 42);
        }''')
        for optimize in [False, True]:
            obj = self.directory / "implementation.o"
            self.command([cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O3" if optimize else "-O0",
                          "-fsanitize=undefined", "-fno-sanitize-recover=all", "-c", str(implementation), "-o", str(obj)])
            if backend == "c":
                report = compile_c(emit_c(program, checked), cc=cc, optimize=optimize, sanitize=True,
                                   output=self.directory / "consumer", link_args=[str(obj)])
                library = compile_c(emit_c(program, checked, crate_type="staticlib"), cc=cc,
                                    crate_type="staticlib", optimize=optimize, sanitize=True,
                                    output=self.directory / "hepta.a")
            else:
                rustc = find_rustc(os.environ.get("RUSTC"))
                report = compile_rust(emit_rust(program, checked, crate_type="bin"), rustc=rustc,
                                      crate_type="bin", optimize=optimize, output=self.directory / "consumer",
                                      link_args=[str(obj), "-lubsan"])
                library = compile_rust(emit_rust(program, checked, crate_type="staticlib"), rustc=rustc,
                                       crate_type="staticlib", optimize=optimize, output=self.directory / "hepta.a")
            self.assertTrue(report["ok"], report["diagnostics"])
            self.command([report["artifact"]])
            self.assertTrue(library["ok"], library["diagnostics"])
            native = self.directory / "caller"
            self.command([cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined",
                          "-fno-sanitize-recover=all", str(harness), library["artifact"], str(obj),
                          "-lm", "-ldl", "-lpthread", "-o", str(native)])
            self.command([str(native)])

    def test_native_c_bidirectional_functions_records_and_pointers(self):
        self.execute_abi()

    def test_native_c_bidirectional_short_enum_abi(self):
        self.execute_abi(short=True)

    def test_native_rust_bidirectional_enum_abi(self):
        if not (os.environ.get("RUSTC") or shutil.which("rustc")):
            if os.environ.get("HEPTA_REQUIRE_RUST") == "1":
                self.fail("Rust is required by this qualification lane")
            self.skipTest("Rust compiler unavailable; C native evidence is separate")
        self.execute_abi(backend="rust")
        self.execute_abi(short=True, backend="rust")

    def test_enum_constants_can_size_array_fields(self):
        result = self.imported("enum Size { COUNT = 3 }; typedef struct Packet { int data[COUNT]; } Packet;")
        self.assertIn("data: [i32; 3]", result.source)
        self.assertEqual(result.manifest["layouts"]["Packet"]["fields"]["data"]["size"], 12)
        rust = emit_rust(parse(result.source), check(parse(result.source)), crate_type="rlib")
        self.assertIn("[i32; 3]", rust)
        # This existing C-backend record restriction is not silently broadened.
        with self.assertRaises(HeptaError) as error:
            emit_c(parse(result.source), check(parse(result.source)), crate_type="obj")
        self.assertEqual(error.exception.diagnostic.code, "E_C_BACKEND_SUBSET")

    def test_public_cli_import_and_module_execution(self):
        self.header.write_text("enum Mode { START = -3, FINISH = 9 };", encoding="utf-8")
        binding = self.directory / "api.hepta"
        imported = self.command([sys.executable, "-m", "hepta", "import-c", str(self.header),
                                 "--module", "api", "-o", str(binding)], cwd=ROOT)
        self.assertTrue(json.loads(imported.stdout)["ok"])
        entry = self.directory / "main.hepta"
        entry.write_text("import api; fn main() -> Unit effects { panic } { "
                         "assert(api::cconst_START() == -3); assert(api::cconst_FINISH() == 9); }")
        project = load_project(entry)
        self.assertEqual(len(project.c_imports), 1)
        for backend in ["rust", "c"]:
            analyzed = analyze_project(entry, backend=backend, native=False, crate_type="bin")
            self.assertTrue(analyzed.report["ok"], analyzed.report)
        run = self.command([sys.executable, "-m", "hepta", "run", str(entry),
                            "--backend", "c", "--json"], cwd=ROOT)
        self.assertEqual(json.loads(run.stdout)["returncode"], 0)

    def test_unsupported_enum_forms_reject_without_partial_binding(self):
        cases = [
            "enum Empty {};", "enum Opaque;", "enum { ANONYMOUS };",
            "enum Named { A } variable;", "typedef enum Named { A } One, Two;",
            "enum Bad { A = 1.5 };", "enum Bad { A = 'a' };",
            "enum Bad { A = (1 ? 2 : 3) };", "enum Bad { A = };",
            "enum Bad { A,, B };", "enum Bad { A = 2147483648 };",
            "enum Bad { A );", "enum Bad { A ];",
            "enum Bad { A = -2147483649 };", "enum Bad { A, A };",
            "enum One { A }; enum Two { A };", "enum Same { A }; enum Same { B };",
            "#define A 1\nenum Bad { A, B };", "enum Bad { A = missing };",
            "typedef struct Bad { enum Nested { A } value; } Bad;",
            "enum Bad : unsigned { A };", "enum Bad { A } __attribute__((packed));",
            "enum Missing value(void);", "typedef enum Missing Missing;",
        ]
        for source in cases:
            with self.subTest(source=source):
                with self.assertRaises(HeptaError) as error:
                    self.imported(source)
                self.assertTrue(error.exception.diagnostic.code.startswith("E_C_IMPORT_"))

    def test_non_enum_headers_retain_empty_enum_metadata(self):
        result = self.imported("#define COUNT 3\ntypedef unsigned long Counter; int add(int value);")
        self.assertEqual(result.manifest["enums"], {})
        self.assertEqual(result.manifest["constants"]["COUNT"]["value"], 3)
        self.assertEqual(result.manifest["functions"][0]["name"], "add")


if __name__ == "__main__":
    unittest.main()
