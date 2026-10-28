"""Source calling conventions survive scalarization at the native boundary.

The negative link controls use the actual DSO, not only an emitter string.
An ordinary scalar source helper remains a convenience native entrypoint;
nominal values, borrowed parameters and generated generic instances do not.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.checker import check
from hepta.hia_program import verify_program, execute_program
from hepta.hia_program_llvm import emit_program_llvm, compile_program_llvm
from hepta.hia_program_source import lower_source, source_report
from hepta.hia_source_bridge import lower_checked_owned_hia
from hepta.parser import parse


SOURCE = '''module source_exports;
struct Packet{word:u64}
fn inspect_packet(packet:Packet)->u64 effects{}{return packet.word;}
fn make_packet(x:u64)->Packet effects{}{return Packet{word:x};}
fn inspect_read(x:read u64)->u64 effects{}{return x;}
fn replace_scalar(x:mut u64,y:u64)->Unit effects{write}{x=y;}
fn identity<T:Copy>(x:T)->T effects{}{return x;}
fn scalar_helper(x:u64)->u64 effects{}{return x;}
export "C" fn public_identity(x:u64)->u64 effects{write}{
    let packet=make_packet(x);
    let first=inspect_packet(packet);
    let scalar=inspect_read(read first);
    let mut result:u64=0;
    replace_scalar(mut result,scalar);
    return identity::<u64>(result);
}'''
ENTRIES = frozenset({"scalar_helper", "public_identity"})
INTERNAL = frozenset({"inspect_packet", "make_packet", "inspect_read", "replace_scalar"})
CLANG = os.environ.get("CLANG") or shutil.which("clang")
NM = shutil.which("llvm-nm") or shutil.which("nm")


class SourceExportBoundaryTests(unittest.TestCase):
    def test_original_signatures_survive_canonical_wire_round_trip(self):
        core = lower_source(SOURCE)
        self.assertEqual(core.as_dict()["schema"], "hepta.hia.program.v1")
        self.assertEqual(core.as_dict()["exports"], sorted(ENTRIES))
        for checked in (core, verify_program(core.canonical_bytes), verify_program(core.as_dict())):
            self.assertEqual(checked.scalar_entrypoints, ENTRIES)
            self.assertEqual(set(emit_program_llvm(checked).exports), ENTRIES)
            for value in (0, 1, 17, 2**63, 2**64 - 1):
                self.assertEqual(execute_program(checked, "public_identity", [value])["result"], value)

    def test_erased_aggregate_and_borrow_modes_are_not_scalar_exports(self):
        core = lower_source(SOURCE)
        functions = {fn["name"]: fn for fn in core.as_dict()["functions"]}
        for name in INTERNAL:
            self.assertIn(name, functions)
            self.assertNotIn(name, core.scalar_entrypoints)
            # All four old spellings actually flatten to scalar signatures.
            self.assertTrue(all(p["type"] == "u64" for p in functions[name]["params"]))
            self.assertEqual(functions[name]["returns"], ["u64"])

    def test_concrete_generic_scalar_instance_remains_internal(self):
        report = source_report(SOURCE)
        generated = {row["instance"] for row in report["specializations"] if row["kind"] == "fn"}
        self.assertEqual(len(generated), 1)
        core = lower_source(SOURCE)
        self.assertTrue(generated <= {fn["name"] for fn in core.as_dict()["functions"]})
        self.assertTrue(generated.isdisjoint(core.scalar_entrypoints))

    def test_ordinary_scalar_and_unit_convenience_entries_are_retained(self):
        core = lower_source('fn scalar(x:u64)->u64 effects{}{return x;} fn noop()->Unit effects{}{}')
        self.assertEqual(core.scalar_entrypoints, frozenset({"scalar", "noop"}))
        self.assertEqual(set(emit_program_llvm(core).exports), {"scalar", "noop"})

    def test_all_aggregate_module_has_explicit_empty_native_exports(self):
        core = lower_source('struct Packet{word:u64} fn transform(p:Packet)->Packet effects{}{return p;}')
        self.assertEqual(core.as_dict()["exports"], [])
        self.assertEqual(verify_program(core.canonical_bytes).scalar_entrypoints, frozenset())

    def test_existing_source_bound_owner_bridge_keeps_v1_exports(self):
        source = '''struct Packet{word:u64}
        fn inspect_packet(packet:Packet)->u64 effects{}{return packet.word;}
        export "C" fn entry(x:u64)->u64 effects{alloc,block,panic}{
            let owner=buffer(3);drop(move owner);
            let packet=Packet{word:x};return inspect_packet(packet);
        }'''
        program = parse(source)
        lowered = lower_checked_owned_hia(program, check(program), project_sha256="d" * 64)
        self.assertEqual(lowered.program.as_dict()["schema"], "hepta.hia.program.v1")
        self.assertEqual(lowered.program.scalar_entrypoints, frozenset({"entry"}))
        self.assertEqual(emit_program_llvm(lowered.program).exports, ("entry",))
        actual = execute_program(lowered.program, "entry", [19])
        self.assertEqual(actual["result"], 19)
        self.assertEqual(actual["resources"]["allocations"], 1)
        self.assertEqual(actual["resources"]["frees"], 1)


@unittest.skipUnless(CLANG and NM, "actual Clang 20+ and native symbol inspection required")
class SourceNativeExportBoundaryTests(unittest.TestCase):
    def test_actual_dso_symbols_c_calls_and_internal_link_refusals(self):
        core = lower_source(SOURCE)
        with tempfile.TemporaryDirectory(prefix="hia-source-exports-") as temporary:
            root = Path(temporary)
            library = root / "source.so"
            receipt = compile_program_llvm(emit_program_llvm(core), program=core,
                                           output=library, clang=CLANG)
            self.assertEqual(set(receipt["exports"]), ENTRIES)
            symbols = subprocess.run([NM, "-D", "--defined-only", str(library)],
                capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(symbols.returncode, 0, symbols.stderr)
            self.assertEqual({line.split()[-1] for line in symbols.stdout.splitlines()}, ENTRIES)
            c = root / "caller.c"
            c.write_text('''#include <stdint.h>
#include <stdio.h>
uint64_t public_identity(uint64_t); uint64_t scalar_helper(uint64_t);
int main(void){
    const uint64_t inputs[]={0,1,17,UINT64_C(0x8000000000000000),UINT64_MAX};
    for(unsigned i=0;i<5;i++){
        if(public_identity(inputs[i])!=inputs[i] || scalar_helper(inputs[i])!=inputs[i])return 2;
    }
    puts("10 scalar C calls matched");return 0;
}
''', encoding="utf-8")
            binary = root / "caller"
            built = subprocess.run([CLANG, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                str(c), str(library), "-Wl,-rpath," + str(root), "-o", str(binary)],
                capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(built.returncode, 0, built.stderr)
            ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual((ran.returncode, ran.stdout, ran.stderr), (0, "10 scalar C calls matched\n", ""))
            loaded = ctypes.CDLL(str(library))
            generated = {row["instance"] for row in source_report(SOURCE)["specializations"] if row["kind"] == "fn"}
            for name in sorted(INTERNAL | generated):
                with self.subTest(internal=name):
                    with self.assertRaises(AttributeError):
                        getattr(loaded, name)
                    missing = root / (name + ".c")
                    missing.write_text('#include <stdint.h>\nuint64_t ' + name +
                        '(uint64_t);\nint main(void){return ' + name + '(7)!=7;}\n')
                    attempted = subprocess.run([CLANG, str(missing), str(library), "-o", str(root / name)],
                        capture_output=True, text=True, timeout=30, check=False)
                    self.assertNotEqual(attempted.returncode, 0)
                    self.assertIn(name, attempted.stderr)
                    self.assertFalse((root / name).exists())


if __name__ == "__main__":
    unittest.main()
