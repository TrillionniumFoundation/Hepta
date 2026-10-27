#!/usr/bin/env python3
"""Seeded differential C ABI matrix for Hepta's explicitly supported subset.

This is finite generated testing, not exhaustive ABI verification. C type
expectations use independent typedef composition rather than backend.c_decl.
Padding bytes are never compared: every scalar leaf is initialized and checked.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import datetime as dt
import json
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.validate import ROOT, RUST_FLAGS, Runner, compiler_identity, digest, rustc_path

SCALARS = {"u8": "uint8_t", "i8": "int8_t", "u16": "uint16_t", "i16": "int16_t",
           "u32": "uint32_t", "i32": "int32_t", "u64": "uint64_t", "i64": "int64_t",
           "usize": "size_t", "isize": "intptr_t", "f32": "float", "f64": "double"}


@dataclass(frozen=True)
class Shape:
    kind: str
    name: str = ""
    element: Shape | None = None
    length: int = 0

    def hepta(self) -> str:
        if self.kind == "array":
            return f"[{self.element.hepta()}; {self.length}]"
        if self.kind in {"const", "mut"}:
            return f"raw {self.kind} {self.element.hepta()}"
        return self.name


class Matrix:
    def __init__(self, seed: int, count: int, values: int = 3):
        self.seed, self.count, self.values = seed, count, values
        self.rng = random.Random(seed)
        self.fields: dict[str, list[tuple[str, Shape]]] = {}
        self.aliases: dict[Shape, str] = {}
        self.typedefs: list[str] = []
        self.structs: list[Shape] = []
        primitives = [Shape("scalar", name) for name in SCALARS]
        for index in range(count):
            fields = []
            for field in range(self.rng.randint(1, 5)):
                choices = primitives + [s for s in self.structs if self.leaves(s) <= 12]
                value = self.rng.choice(choices)
                if self.rng.random() < 0.32:
                    value = Shape("array", element=value, length=self.rng.randint(1, 4))
                if value.kind == "array" and self.rng.random() < 0.2:
                    value = Shape("array", element=value, length=2)
                fields.append((f"field{field}", value))
            shape = Shape("struct", f"Matrix{index:02d}")
            self.fields[shape.name] = fields
            self.structs.append(shape)
        u32, u16, unit = Shape("scalar", "u32"), Shape("scalar", "u16"), Shape("void", "Unit")
        self.pointers = [
            Shape("const", element=u32), Shape("mut", element=u32),
            Shape("const", element=Shape("mut", element=u32)),
            Shape("mut", element=Shape("const", element=u32)),
            Shape("const", element=Shape("const", element=u16)),
            Shape("mut", element=Shape("array", element=u32, length=3)),
            Shape("const", element=Shape("array", element=u32, length=3)),
            Shape("const", element=Shape("array", element=Shape("mut", element=u32), length=2)),
            Shape("mut", element=Shape("array", element=Shape("const", element=u32), length=2)),
            Shape("mut", element=Shape("const", element=Shape("array", element=u16, length=2))),
            Shape("const", element=unit), Shape("mut", element=Shape("const", element=unit)),
        ]
        # The final aggregate also exercises declarators in field position.
        # Pointer fields use null values; standalone pointer cases below use
        # live non-null objects and test the same nested pointer signatures.
        self.fields[self.structs[-1].name] = [(f"pointer{i}", t) for i, t in enumerate(self.pointers)] + [
            ("pointer_array", Shape("array", element=self.pointers[0], length=3)),
            ("array_pointer_array", Shape("array", element=self.pointers[6], length=2)),
        ]
        self.cases = [(f"scalar{index}", value) for index, value in enumerate(primitives)]
        self.cases += [(f"record{index}", value) for index, value in enumerate(self.structs)]
        self.cases += [(f"pointer{index}", value) for index, value in enumerate(self.pointers)]

    def leaves(self, shape: Shape) -> int:
        if shape.kind == "struct":
            return sum(self.leaves(value) for _, value in self.fields[shape.name])
        if shape.kind == "array":
            return shape.length * self.leaves(shape.element)
        return 1

    def alias(self, shape: Shape) -> str:
        if shape in self.aliases:
            return self.aliases[shape]
        # Compose C expectations with typedefs, not the production declarator algorithm.
        child = self.alias(shape.element) if shape.element else None
        alias = f"ExpectedType{len(self.aliases)}"
        self.aliases[shape] = alias
        if shape.kind == "scalar":
            declaration = f"typedef {SCALARS[shape.name]} {alias};"
        elif shape.kind == "void":
            declaration = f"typedef void {alias};"
        elif shape.kind == "struct":
            declaration = f"typedef hepta_{shape.name} {alias};"
        elif shape.kind == "array":
            declaration = f"typedef {child} {alias}[{shape.length}];"
        else:
            declaration = f"typedef {'const ' if shape.kind == 'const' else ''}{child} *{alias};"
        self.typedefs.append(declaration)
        return alias

    def scalar_literal(self, shape: Shape) -> str:
        if shape.name in {"f32", "f64"}:
            return str(self.rng.randint(-4096, 4096) / 4.0)
        bits = int(shape.name[1:]) if shape.name[1:].isdigit() else 32
        if shape.name.startswith("u"):
            return f"UINT64_C({self.rng.randrange(1 << bits)})"
        number = self.rng.randrange(-(1 << (bits - 1)), 1 << (bits - 1))
        return f"(-INT64_C({-number}))" if number < 0 else f"INT64_C({number})"

    def initialize(self, shape: Shape, path: str) -> list[str]:
        if shape.kind == "struct":
            return [line for field, child in self.fields[shape.name]
                    for line in self.initialize(child, path + "." + field)]
        if shape.kind == "array":
            return [line for index in range(shape.length)
                    for line in self.initialize(shape.element, f"{path}[{index}]")]
        if shape.kind in {"const", "mut"}:
            return [f"{path} = ({self.alias(shape)})0;"]
        return [f"{path} = ({self.alias(shape)})({self.scalar_literal(shape)});"]

    def compare(self, shape: Shape, left: str, right: str) -> list[str]:
        if shape.kind == "struct":
            return [line for field, child in self.fields[shape.name]
                    for line in self.compare(child, left + "." + field, right + "." + field)]
        if shape.kind == "array":
            return [line for index in range(shape.length)
                    for line in self.compare(shape.element, f"{left}[{index}]", f"{right}[{index}]")]
        return [f"assert({left} == {right});"]

    def generate(self) -> tuple[str, str, str, dict]:
        hepta = ["module abi_matrix;"]
        declaration_order = list(self.structs)
        self.rng.shuffle(declaration_order)
        for shape in declaration_order:
            hepta.append(f"repr(C) struct {shape.name} {{ " + ", ".join(
                field + ": " + value.hepta() for field, value in self.fields[shape.name]) + " }")
        c, checks, probes, layout = [], [], [], []
        call_count = 0
        for label, shape in self.cases:
            typ = shape.hepta()
            hepta += [f'extern "C" fn abi_c_{label}(value: {typ}) -> {typ} effects {{ ffi, unsafe }};',
                      f'export "C" fn abi_h_{label}(value: {typ}) -> {typ} effects {{ ffi, unsafe }} '
                      f'{{ unsafe {{ return abi_c_{label}(value); }} }}']
            alias = self.alias(shape)
            c += [f"{alias} abi_c_{label}({alias} value) {{ ++abi_calls; return value; }}",
                  f"typedef {alias} (*ExpectedSignature_{label})({alias});",
                  f'_Static_assert(_Generic(&abi_h_{label}, ExpectedSignature_{label}: 1, default: 0), "signature {label}");']
            for trial in range(self.values):
                identifier = f"v_{label}_{trial}"
                checks.append("{")
                if shape.kind in {"const", "mut"}:
                    child = shape.element
                    if child.kind == "void":
                        checks.append(f"uint8_t object_{identifier} = 0;")
                    else:
                        checks.append(f"{self.alias(child)} object_{identifier} = {{0}};")
                    checks.append(f"{alias} {identifier} = ({alias})&object_{identifier};")
                else:
                    checks.append(f"{alias} {identifier} = {{0}};")
                    checks.extend(self.initialize(shape, identifier))
                checks.append(f"{alias} out_{identifier} = abi_h_{label}({identifier});")
                checks.extend(self.compare(shape, identifier, f"out_{identifier}"))
                checks.append("}")
                call_count += 1
        for shape in self.structs:
            typ = "hepta_" + shape.name
            for label, rust_expr, c_expr in [
                ("size", f"core::mem::size_of::<H_{shape.name}>()", f"sizeof({typ})"),
                ("align", f"core::mem::align_of::<H_{shape.name}>()", f"_Alignof({typ})"),
            ] + [(field, f"core::mem::offset_of!(H_{shape.name}, h_{field})", f"offsetof({typ}, {field})")
                 for field, _ in self.fields[shape.name]]:
                symbol = f"abi_probe_{shape.name}_{label}"
                probes.append(f'#[unsafe(no_mangle)] pub extern "C" fn {symbol}() -> usize {{ {rust_expr} }}')
                layout += [f"extern size_t {symbol}(void);", f"/* expression: {c_expr} */"]
                checks.append(f"#ifdef ABI_LAYOUT\nassert({symbol}() == {c_expr});\n#endif")
            for field, child in self.fields[shape.name]:
                # The address is only inspected, never evaluated. A pointer to
                # the complete field type preserves array bounds and nested
                # pointer qualifiers that a value expression would decay/drop.
                # This is C11, including MSVC /std:c11, without GNU typeof.
                c.append(f'_Static_assert(_Generic(&(({typ}*)0)->{field}, {self.alias(child)} *: 1, default: 0), "field type {shape.name}.{field}");')
        # Ten integer + ten FP arguments exhaust both register banks on the host,
        # followed by an aggregate passed and returned through both languages.
        spill_shape = self.structs[0]
        spill_type = self.alias(spill_shape)
        hparams, cparams, cargs, spill_checks = [], [], [], []
        for index in range(20):
            htype, ctype = ("u64", "uint64_t") if index % 2 == 0 else ("f64", "double")
            hparams.append(f"arg{index}: {htype}")
            cparams.append(f"{ctype} arg{index}")
            cargs.append(f"({ctype}){37 * (index + 1)}")
            spill_checks.append(f"assert(arg{index} == ({ctype}){37 * (index + 1)});")
        hparams.append("record: " + spill_shape.name)
        cparams.append(spill_type + " record")
        hepta += [f'extern "C" fn abi_c_spill({", ".join(hparams)}) -> {spill_shape.name} effects {{ ffi, unsafe }};',
                  f'export "C" fn abi_h_spill({", ".join(hparams)}) -> {spill_shape.name} effects {{ ffi, unsafe }} '
                  '{ unsafe { return abi_c_spill(' + ", ".join([f"arg{i}" for i in range(20)] + ["record"]) + "); } }"]
        c.append(f"{spill_type} abi_c_spill({', '.join(cparams)}) {{ " + " ".join(spill_checks) + " ++abi_calls; return record; }")
        checks += ["{", f"{spill_type} spill = {{0}};", *self.initialize(spill_shape, "spill"),
                   f"{spill_type} spill_out = abi_h_spill({', '.join(cargs)}, spill);",
                   *self.compare(spill_shape, "spill", "spill_out"), "}"]
        call_count += 1
        body = ["#include \"matrix.h\"", "#include <assert.h>", "#include <stdio.h>",
                *self.typedefs, "static size_t abi_calls = 0;", *c,
                "#ifdef ABI_LAYOUT", *layout, "#endif", "int main(void) {", *checks,
                f"assert(abi_calls == {call_count});",
                'printf("{\\"status\\":\\"passed\\",\\"foreign_calls\\":%zu}\\n", abi_calls);',
                "return 0;", "}"]
        manifest = {"seed": self.seed, "aggregate_shapes": self.count,
                    "scalar_types": len(SCALARS), "pointer_shapes": len(self.pointers),
                    "pointer_types": [p.hepta() for p in self.pointers],
                    "values_per_shape": self.values, "expected_foreign_calls_per_run": call_count,
                    "register_spill_integer_arguments": 10, "register_spill_float_arguments": 10,
                    "aggregate_fields": {s.name: {f: t.hepta() for f, t in self.fields[s.name]} for s in self.structs}}
        return "\n".join(hepta) + "\n", "\n".join(body) + "\n", "\n".join(probes) + "\n", manifest


def run_matrix(runner: Runner, directory: Path, seed=20261024, cases=36, values=3) -> dict:
    source, harness, probes, manifest = Matrix(seed, cases, values).generate()
    hp, cp, emitted = directory / "matrix.hepta", directory / "matrix.c", directory / "matrix.rs"
    hp.write_text(source)
    cp.write_text(harness)
    runner.hepta("header", hp, "--output", directory / "matrix.h")
    runner.hepta("emit", hp, "--output", emitted)
    library = directory / "libmatrix.a"
    runner.hepta("build", hp, "--crate-type", "staticlib", "--output", library)
    cc = shutil.which("gcc") or "cc"
    executions = []
    for optimization in ("-O0", "-O2"):
        executable = directory / ("matrix" + optimization)
        runner.run([cc, "-std=c11", optimization, "-Wall", "-Wextra", "-Werror", "-pedantic-errors",
                    cp, library, "-ldl", "-lpthread", "-lm", "-lrt", "-lutil", "-o", executable])
        executions.append({"c_optimization": optimization, "layout_probe": False,
                           "result": json.loads(runner.run([executable]).stdout)})
    augmented = directory / "matrix_layout.rs"
    augmented.write_text(emitted.read_text() + "\n" + probes)
    probe_library = directory / "libmatrix_layout.a"
    runner.run([runner.rustc, augmented, *RUST_FLAGS, "--crate-type", "staticlib", "-o", probe_library])
    executable = directory / "matrix-layout"
    runner.run([cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-pedantic-errors", "-DABI_LAYOUT",
                cp, probe_library, "-ldl", "-lpthread", "-lm", "-lrt", "-lutil", "-o", executable])
    executions.append({"c_optimization": "-O2", "layout_probe": True,
                       "result": json.loads(runner.run([executable]).stdout)})
    return {"status": "passed", "manifest": manifest, "executions": executions,
            "source_sha256": digest(hp), "harness_sha256": digest(cp),
            "header_sha256": digest(directory / "matrix.h"), "rust_sha256": digest(emitted),
            "scope": "Host-only finite seeded ordinary C scalar/nested aggregate/array/pointer ABI tests. No bitfields, packed, varargs, exceptions or device execution."}


AUDIT_CASES = {
    "typedef_global": ('export "C" fn uint32_t() -> u32 effects {} { return 1; }', True),
    "generated_typedef": ('repr(C) struct Packet { value: u32 } export "C" fn hepta_Packet() -> u32 effects {} { return 1; }', True),
    "typedef_parameter": ('export "C" fn example(uint32_t: u32, other: u32) -> u32 effects {} { return other; }', False),
    "standard_macro_symbol": ('export "C" fn SIZE_MAX() -> u32 effects {} { return 1; }', True),
    "standard_macro_field": ('repr(C) struct Packet { SIZE_MAX: u32 }', False),
    "empty_c_struct": ('repr(C) struct Empty {}', True),
    "empty_c_array": ('repr(C) struct Empty { value: [u32; 0] }', True),
    "array_parameter": ('export "C" fn bad(value: [u32; 2]) -> u32 effects {} { return 1; }', True),
    "array_return": ('export "C" fn bad() -> [u32; 2] effects {} { return [1, 2]; }', True),
    "forward_pointer_to_record_array": ('repr(C) struct Container { next: raw const [Leaf; 2] } repr(C) struct Leaf { value: u32 } export "C" fn echo(value: Container) -> Container effects {} { return value; }', False),
    "recursive_pointer": ('repr(C) struct Node { value: u32, next: raw mut Node }', False),
    "recursive_array_pointee": ('repr(C) struct Node { next: raw const [Node; 2] }', True),
}


def audit_boundaries(runner: Runner, directory: Path) -> dict:
    results = {}
    for name, (source, must_reject) in AUDIT_CASES.items():
        hp, header = directory / (name + ".hepta"), directory / (name + ".h")
        hp.write_text(source)
        proc = subprocess.run([sys.executable, "-m", "hepta", "header", str(hp), "--output", str(header)],
                              cwd=ROOT, env=runner.env, text=True, capture_output=True, timeout=120)
        if proc.returncode:
            report = json.loads(proc.stdout)
            codes = [d.get("code") for d in report.get("diagnostics", [])]
            if not codes or any(code not in {"E_C_IDENTIFIER", "E_C_ABI", "E_C_TYPE", "E_C_RECURSIVE_LAYOUT"} for code in codes):
                raise RuntimeError(f"Unexpected rejection phase for {name}: {report}")
            results[name] = {"status": "rejected", "diagnostic_codes": codes}
        elif must_reject:
            raise RuntimeError(f"Unsupported ABI source was accepted: {name}")
        else:
            cp = directory / (name + ".c")
            cp.write_text('#include "' + header.name + '"\n')
            runner.run(["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic-errors", "-fsyntax-only", cp])
            results[name] = {"status": "accepted_and_c_header_compiled"}
    return {"status": "passed", "cases": results}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20261024)
    parser.add_argument("--cases", type=int, default=36)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/abi-matrix.json")
    parser.add_argument("--keep-dir", type=Path, help="retain reproducible generated fixtures")
    args = parser.parse_args(argv)
    if not 1 <= args.cases <= 100:
        parser.error("--cases must be between 1 and 100")
    rustc = rustc_path()
    if not rustc:
        parser.error("rustc is required")
    runner = Runner(rustc)
    report = {"schema": "hepta.abi-matrix.v1", "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "compiler_sources": compiler_identity(), "generator_sha256": digest(Path(__file__)),
              "status": "running"}
    temporary = tempfile.TemporaryDirectory(prefix="hepta-abi-matrix-") if not args.keep_dir else None
    directory = args.keep_dir.resolve() if args.keep_dir else Path(temporary.name)
    directory.mkdir(parents=True, exist_ok=True)
    try:
        report["rustc"] = runner.run([rustc, "--version", "--verbose"]).stdout
        report["c_compiler"] = runner.run([shutil.which("gcc") or "cc", "--version"]).stdout
        report["matrix"] = run_matrix(runner, directory, args.seed, args.cases)
        report["boundary_audit"] = audit_boundaries(runner, directory)
        report["status"] = "passed"
    except (RuntimeError, OSError, subprocess.SubprocessError, ValueError) as error:
        report["status"] = "failed"
        report["error"] = str(error)
    if compiler_identity() != report["compiler_sources"]:
        report["status"] = "failed"
        report["error"] = "Compiler sources changed during ABI validation; rerun a stable snapshot."
    report["commands"] = runner.commands
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    if temporary:
        temporary.cleanup()
    print(json.dumps({"status": report["status"], "report": str(args.output.resolve()), "error": report.get("error")}, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
