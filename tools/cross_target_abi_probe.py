#!/usr/bin/env python3
"""Clang-target C ABI layout compilation probes (NOT cross-target execution).

This never asserts Hepta ABI equivalence. It proves specified target data models
and a finite C producer/callback shape compile with Clang, plus a deliberately
false layout assertion fails for each target. No headers or build scripts run.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

TARGET_MACHINE = {
    'x86_64-unknown-linux-gnu': 'elf_x86_64',
    'aarch64-unknown-linux-gnu': 'elf_aarch64',
    'x86_64-pc-windows-msvc': 'coff_x86_64',
}
SOURCE = '''typedef unsigned int u32;
typedef unsigned long long u64;
typedef struct Record { u32 tag; u64 count; u32 flags; } Record;
typedef struct Nested { Record value; double score; } Nested;
_Static_assert(sizeof(int) == 4, "C int width mismatch");
_Static_assert(sizeof(u64) == 8, "u64 width mismatch");
_Static_assert(sizeof(Record) == 24, "Record size mismatch");
_Static_assert(_Alignof(Record) == 8, "Record alignment mismatch");
_Static_assert(__builtin_offsetof(Record, count) == 8, "Record count offset mismatch");
_Static_assert(__builtin_offsetof(Record, flags) == 16, "Record flags offset mismatch");
_Static_assert(sizeof(Nested) == 32, "Nested size mismatch");
_Static_assert(__builtin_offsetof(Nested, score) == 24, "Nested score offset mismatch");
Record make_record(u32 tag, u64 count, u32 flags) {
    Record result = { tag, count, flags };
    return result;
}
u64 consume_record(Record r) { return r.count + r.tag + r.flags; }
int callback_roundtrip(int (*callback)(Record), Record r) { return callback(r); }
'''
SYMBOLS = ('make_record', 'consume_record', 'callback_roundtrip')


def _hex(file: Path) -> str:
    return sha256(file.read_bytes()).hexdigest()


def _run(args: list[str], *, timeout: int = 25) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True,
                          timeout=timeout, check=False)


def _object_matches(binary: bytes, expected: str) -> bool:
    if expected.startswith('elf_'):
        if len(binary) < 20 or binary[:5] != b'\x7fELF\x02' or binary[5] != 1:
            return False
        machine = int.from_bytes(binary[18:20], 'little')
        return machine == {'elf_x86_64': 62, 'elf_aarch64': 183}[expected]
    return len(binary) >= 20 and binary[:2] == b'\x64\x86'


def run_probe(clang: str = 'clang') -> dict:
    executable = shutil.which(clang)
    if not executable:
        raise RuntimeError('E_ABI_TARGET_CLANG: Clang compiler unavailable')
    compiler = Path(executable).resolve()
    identity = _run([str(compiler), '--version'])
    if identity.returncode or not identity.stdout:
        raise RuntimeError('E_ABI_TARGET_CLANG: compiler identity query failed')
    cases = []
    with tempfile.TemporaryDirectory(prefix='hepta-cross-abi-') as temp:
        folder = Path(temp)
        source = folder / 'abi.c'
        source.write_text(SOURCE, encoding='utf-8')
        negative = folder / 'incorrect.c'
        negative.write_text(SOURCE.replace(
            '__builtin_offsetof(Record, count) == 8',
            '__builtin_offsetof(Record, count) == 4'), encoding='utf-8')
        for target, machine in TARGET_MACHINE.items():
            obj = folder / ('native-' + target + '.o')
            ir = folder / ('ir-' + target + '.ll')
            args = [str(compiler), '--target=' + target, '-std=c11',
                    '-O2', '-Wall', '-Wextra', '-Werror']
            native = _run([*args, '-c', str(source), '-o', str(obj)])
            llvm = _run([*args, '-S', '-emit-llvm', str(source), '-o', str(ir)])
            wrong = _run([*args, '-c', str(negative), '-o', str(folder / ('wrong-' + target + '.o'))])
            content = ir.read_text() if ir.exists() else ''
            symbols = all(('@' + name + '(') in content for name in SYMBOLS)
            correct = bool(native.returncode == 0 and llvm.returncode == 0
                           and obj.is_file() and ir.is_file()
                           and _object_matches(obj.read_bytes(), machine) and symbols)
            rejects_wrong = wrong.returncode != 0 and 'static assertion failed' in wrong.stderr.lower()
            cases.append({'target': target, 'machine_format': machine,
                          'status': 'passed' if correct and rejects_wrong else 'failed',
                          'native_object_sha256': _hex(obj) if correct else None,
                          'native_bytes': obj.stat().st_size if correct else None,
                          'llvm_ir_sha256': _hex(ir) if correct else None,
                          'layout_static_asserts_compiled': correct,
                          'expected_exported_symbols_present_in_ir': symbols,
                          'deliberate_layout_fault_rejected': rejects_wrong,
                          'negative_exit_code': wrong.returncode,
                          'diagnostics': {
                              'object': native.stderr[:800] if native.returncode else '',
                              'ir': llvm.stderr[:800] if llvm.returncode else '',
                              'negative': wrong.stderr[:800] if not rejects_wrong else ''},
                          'executed_on_target': False,
                          'independent_foreign_compiler_verified': False})
    ok = all(x['status'] == 'passed' for x in cases)
    return {
        'schema': 'hepta.abi-cross-target-c.v1', 'created_utc': datetime.now(timezone.utc).isoformat(),
        'status': 'passed' if ok else 'failed',
        'scope': 'Clang-only cross-target C object/layout compile and negative controls',
        'compiler': {'version': identity.stdout.splitlines()[0],
                     'path': str(compiler), 'sha256': _hex(compiler)},
        'source_sha256': sha256(SOURCE.encode('utf-8')).hexdigest(),
        'cases': cases,
        'claims': {'cross_target_execution_verified': False,
                   'independent_cross_compiler_interop_verified': False,
                   'hepta_abi_equivalence_verified': False,
                   'whole_p2_gate_closed': False,
                   'whole_project_blockers_closed': False},
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--clang', default='clang')
    parser.add_argument('--output', required=True)
    options = parser.parse_args(argv)
    report = run_probe(clang=options.clang)
    destination = Path(options.output).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=destination.parent,
                                     prefix='.hepta-cross-abi-', delete=False) as out:
        staged = Path(out.name)
        json.dump(report, out, indent=2, sort_keys=True)
        out.write('\n')
        out.flush()
    staged.replace(destination)
    print(json.dumps({'status': report['status'], 'output': str(destination),
                      'targets': {r['target']: r['status'] for r in report['cases']}}))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
