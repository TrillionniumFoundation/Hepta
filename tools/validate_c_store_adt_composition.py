#!/usr/bin/env python3
"""Freeze inherited and joint native method identities, source and provenance."""
from pathlib import Path
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import unittest
import validate_c_array_adt_composition as arrays
import validate_c_numeric_adt_composition as inherited
from verify_store_adt_sources import verify

ROOT=Path(__file__).resolve().parents[1]
ORIGIN_PREFIX='tests.raw_store_order_origin.RawStoreOrderTests.'
ORIGIN=[ORIGIN_PREFIX+name for name in [
    'test_trace_harness_distinguishes_call_order_without_invalid_memory',
    'test_nested_store_c_uses_separate_operand_temporaries',
    'test_c_stores_remain_inside_short_circuit_branches',
    'test_c_hepta_operand_panics_stop_later_operands',
    'test_c_plain_index_is_snapshotted_before_value_mutates_it',
]]
RUST_ONLY=[ORIGIN_PREFIX+name for name in [
    'test_rust_store_preserves_call_order','test_nested_store_rust_uses_separate_operand_temporaries',
    'test_rust_stores_remain_inside_short_circuit_branches',
    'test_rust_hepta_operand_panics_stop_later_operands','test_rust_plain_index_is_snapshotted_before_value_mutates_it',
]]
INAPPLICABLE=[ORIGIN_PREFIX+name for name in [
    'test_c_store_and_volatile_store_preserve_call_order',
    'test_rust_volatile_store_preserves_call_order',
    'test_unrelated_unsafe_and_index_rejections_remain',
]]
RUST_REQUIRED=os.environ.get('HEPTA_ENUM_REQUIRE_RUST')=='1'
MODULES=arrays.MODULES+['test_c_store_adt_composition']+ORIGIN+(RUST_ONLY if RUST_REQUIRED else [])


def main():
    provenance=verify()
    if RUST_REQUIRED:
        rustc=shutil.which('rustc');selected=shutil.which(os.environ.get('RUSTC','rustc'))
        if not rustc or not selected or Path(rustc).resolve()!=Path(selected).resolve():
            raise SystemExit('Native Rust must exist and RUSTC must select the rustc on PATH')
        version=subprocess.run([rustc,'--version'],capture_output=True,text=True,timeout=10)
        if version.returncode or not version.stdout.startswith('rustc 1.90.0 '):
            raise SystemExit('Native Rust must match pinned version 1.90.0')
    suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(name) for name in MODULES)
    planned=[test.id() for test in inherited.flatten(suite)]
    inventory='tools/c_store_adt_rust_test_ids.json' if RUST_REQUIRED else 'tools/c_store_adt_test_ids.json'
    expected=json.loads((ROOT/inventory).read_text())
    if planned!=expected or len(planned)!=len(set(planned)):
        raise SystemExit('Test inventory differs from frozen unique method IDs')
    # All materialized source/test/example/qualification inputs in this bounded
    # compiler export are bound; this is not a whole repository release gate.
    inputs=[]
    for directory in ['hepta','tests','examples','tools','docs','.github/workflows']:
        inputs.extend(path for path in (ROOT/directory).rglob('*') if path.is_file() and '__pycache__' not in path.parts and path.suffix!='.pyc')
    inputs.append(ROOT/'toolchain-lock.json')
    hashes={str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(inputs)}
    print(json.dumps({'python':sys.version,'host':platform.platform(),'source_transplants':provenance,
        'inventory_mode':'native-c-and-rust' if RUST_REQUIRED else 'native-c-only',
        'unexecuted_rust_methods':[] if RUST_REQUIRED else [*inherited.RUST_ONLY,arrays.ORIGIN_RUST,*RUST_ONLY],
        'inapplicable_origin_methods':{'ids':INAPPLICABLE,'reason':'All three origin methods include volatile operations not supported by this destination. New joint controls execute ordinary-store success/failure and the relevant existing frontend refusals.'},
        'source_sha256':hashes,'planned':planned}),flush=True)
    result=unittest.TextTestRunner(verbosity=2,resultclass=inherited.TrackedResult).run(suite)
    ok=(result.wasSuccessful() and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses
        and planned==result.started==result.finished==result.passed
        and all(hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==value for name,value in hashes.items()))
    print(json.dumps({'tests_run':result.testsRun,'started':result.started,'finished':result.finished,'passed':result.passed,'complete_pass':ok}),flush=True)
    return 0 if ok else 1


if __name__=='__main__':raise SystemExit(main())
