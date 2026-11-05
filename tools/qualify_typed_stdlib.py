#!/usr/bin/env python3
"""Run the complete inherited and typed-consumer inventory on exact source."""
from pathlib import Path
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools')]
backend=os.environ.get('HEPTA_TYPED_STDLIB_BACKEND','c')
if backend not in ('c','rust'):raise SystemExit('Select c or rust')
for key in ('HEPTA_BYTES_BACKEND','HEPTA_ORDERING_BACKEND','HEPTA_UTF8_BACKEND','HEPTA_BASE64_BACKEND'):
    if key in os.environ and os.environ[key]!=backend:raise SystemExit('Conflicting backend '+key)
    os.environ[key]=backend
import validate_c_store_adt_composition as inherited
import validate_c_numeric_adt_composition as tracking
from verify_typed_stdlib_sources import verify
LIBRARIES=['test_stdlib_bytes','test_stdlib_ordering','test_stdlib_utf8','test_stdlib_base64']
MODULES=inherited.MODULES+LIBRARIES+['test_typed_stdlib']

def identity():
    return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(ROOT.rglob('*')) if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc' and '.git' not in p.parts}

def main():
    if not __debug__:raise SystemExit('Assertions must remain enabled')
    os.chdir(ROOT)
    os.environ['PYTHONDONTWRITEBYTECODE']='1';os.environ['PYTHONPATH']=str(ROOT)
    provenance=verify()
    source=inherited.verify()
    if inherited.RUST_REQUIRED or backend=='rust':
        from hepta.backend import find_rustc,toolchain_info
        toolchain_info(find_rustc())
        selected=shutil.which(os.environ.get('RUSTC','rustc'))
        rustc=shutil.which('rustc')
        if not selected or not rustc or Path(selected).resolve()!=Path(rustc).resolve():raise SystemExit('Selected Rust must be actual pinned compiler on PATH')
        if not subprocess.check_output([selected,'--version'],text=True).startswith('rustc 1.90.0 '):raise SystemExit('Expected pinned Rust 1.90.0')
    suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(n) for n in MODULES)
    planned=[t.id() for t in tracking.flatten(suite)]
    inventory='typed_stdlib_rust_inventory.json' if inherited.RUST_REQUIRED else 'typed_stdlib_inventory.json'
    expected=json.loads((ROOT/'tools'/inventory).read_bytes())
    count=415 if inherited.RUST_REQUIRED else 407
    if planned!=expected or len(planned)!=count or len(set(planned))!=count:raise SystemExit('Frozen method inventory mismatch')
    before=identity()
    print('TYPED_STDLIB_IDENTITY '+json.dumps({'python':sys.version,'host':platform.platform(),'backend':backend,'source_sha256':before,'provenance':provenance,'inherited':source},sort_keys=True),flush=True)
    result=unittest.TextTestRunner(verbosity=2,resultclass=tracking.TrackedResult).run(suite)
    good=(result.wasSuccessful() and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses and planned==result.started==result.finished==result.passed and before==identity())
    print('TYPED_STDLIB_METHODS '+json.dumps({'planned':planned,'started':result.started,'finished':result.finished,'passed':result.passed,'tests_run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skips':len(result.skipped),'complete_pass':good},sort_keys=True),flush=True)
    if not good:raise SystemExit('Strict method/source gate failed')
    for script in ['tools/qualify_c_float_int_oracle.py','tools/qualify_c_numeric_adt_oracle.py','tools/qualify_c_array_adt_oracle.py','tools/qualify_c_store_adt_oracle.py',
                   'tests/stdlib_bytes_boundary_oracle.py','tests/stdlib_ordering_oracle.py','tools/stdlib_utf8_oracle.py','tools/stdlib_base64_oracle.py','tools/typed_stdlib_oracle.py']:
        subprocess.run([sys.executable,'-B',script],check=True)
    if before!=identity():raise SystemExit('Source changed during oracles')
    print('TYPED_STDLIB_PASS '+json.dumps({'methods':count,'oracle_scripts':9,'backend':backend,'source_unchanged':True,'whole_project_blockers_closed':False}),flush=True)

if __name__=='__main__':main()
