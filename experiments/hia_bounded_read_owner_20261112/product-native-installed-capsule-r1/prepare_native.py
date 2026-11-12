"""Fresh current-source B0/B1/B2 and source-owned ABI admission, not cold."""
from __future__ import annotations
import argparse
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import traceback

sys.path.insert(0, str(Path(__file__).absolute().parent))
from source_common import _create_directory, create, measurements, pin, read, require, snapshot, wire
from native_support import (ABI, CANDIDATE, CANDIDATE_TREE, GENERATED, LIMITS,
    NATIVE_LIMITS, QUALIFY_SHA, source_manifest, generated_rows, observe_compiler_bundle)
from git_binding import source_git


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--source-manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source, output = args.source_root, args.output
    require(all(p.is_absolute() and '..' not in p.parts for p in (source, output))
            and source != output and source not in output.parents, 'separate source and evidence required')
    _create_directory(output)
    report = {'schema': 'hepta.hia.bounded-read-product-fresh-compiler.v1', 'status': 'HOLD',
        'candidate_commit': CANDIDATE, 'candidate_tree': CANDIDATE_TREE,
        'scope': 'FRESH_B0_B1_B2_DEVELOPMENT_NOT_COLD', 'errors': [],
        'source_mutation_authorized': False, 'host_successor_compiler_calls': [],
        'compile_wall_seconds': 20, 'native_limits': NATIVE_LIMITS, 'original_authoring_limits': LIMITS,
        'old_compiler_reused': False, 'B3_or_mutation_qualification_claimed': False,
        'whole_native_delivery_qualified': False}
    rows = before = git_before = compiler_bundle = linker_record = None
    try:
        require(sys.version_info[:3] == (3, 14, 4) and sys.flags.isolated and sys.flags.no_site
                and sys.dont_write_bytecode and os.getcwd() == str(source), 'original isolated Python target differs')
        require(not any(name.startswith(('HEPTA_HIA_', 'LD_')) or name in ('PYTHONPATH','PYTHONHOME')
                        for name in os.environ), 'ambient runtime selector/loader refused')
        rows, manifest_raw, manifest_record = source_manifest(args.source_manifest)
        before = snapshot(source, rows)
        report['source_before'] = create(output / 'source-before.json', wire(before))
        report['source_manifest'] = manifest_record
        git_before = source_git(source, rows)
        report['source_git_before'] = git_before
        linker = Path(shutil.which('ld')).resolve(strict=True)
        _, linker_record = read(linker, 64 << 20, system_binary=True)
        observed = subprocess.run([str(linker), '--version'], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=5)
        report['linker'] = {'resolved': str(linker), 'binary_before': linker_record,
            'version_stdout': create(output / 'linker-version.stdout.log', observed.stdout),
            'version_stderr': create(output / 'linker-version.stderr.log', observed.stderr)}
        sys.path.insert(0, str(source))
        from tools.generate_hia_bounded_read import document, generated_files
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        value = document()
        generated = generated_files()
        require(set(generated) == {GENERATED, ABI}, 'complete checked-in generated resource pair differs')
        for name, raw in generated.items():
            require(read(source / name, 1 << 20)[0] == raw, 'actual source generator differs: '+name)
        assembly = generated[GENERATED]
        require(render_assembly(value).encode() == assembly and assemble_program(assembly).as_dict() == value,
                'actual public Core source roundtrip differs')
        require(generated_files() == generated and wire(document()) == wire(value), 'source generation not deterministic')
        generated_rows(rows, assembly)
        measures, functions = measurements(value, assembly)
        require(measures['functions'] == 14 and all(measures[name] <= limit for name,limit in LIMITS.items()),
                'original native compiler source cap differs')
        report['core_document'] = create(output / 'bounded-read.hia.json', wire(value))
        report['assembly'] = create(output / 'bounded-read.hiaasm', assembly)
        report['entry_abi'] = create(output / 'source-entry-abi.json', generated[ABI])
        report.update(measurements=measures, functions=functions, core_roundtrip=True, deterministic_source=True)
        from tools.hia_selfhost_contract import support_contract
        support_raw = wire(support_contract())
        require(support_raw == read(source/'docs/HIA_SELFHOST_CORE_SUPPORT.json', 8<<20)[0],
                'current source support contract is stale')
        from tests.test_hia_selfhost_language_coverage import coverage_manifest
        coverage_raw = wire(coverage_manifest())
        require(coverage_raw == read(source/'docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json', 8<<20)[0],
                'current source coverage contract is stale')
        report['current_contracts'] = {'support': pin(support_raw), 'coverage': pin(coverage_raw),
                                     'generated_in_memory_without_source_write': True}
        require(read(source/'tools/qualify_hia_selfhost.py', 1<<20)[1]['sha256'] == QUALIFY_SHA,
                'original native compile supervisor source differs')
        from tools import qualify_hia_selfhost as qualify
        require(qualify.ROOT == source and qualify.CAPACITY == 1<<20
                and qualify.NATIVE_OBSERVER is None and qualify.NATIVE_LINKED_OBSERVER is None,
                'original native compiler route changed')
        selfhost, selfhost_record = read(source/'examples/hia_bootstrap/selfhost.hiaasm', 1<<20)
        seed, seed_receipt = qualify.build_seed(output)
        report['fresh_seed'] = {'receipt': seed_receipt, 'image': read(seed, 16<<20)[1], 'selfhost': selfhost_record}
        def forbidden(*unused, **ignored):
            report['host_successor_compiler_calls'].append('build_seed')
            raise AssertionError('host successor compiler forbidden')
        qualify.build_seed = forbidden
        first, first_receipt = qualify.compile_stage(output,'B1',seed,selfhost,image_format='seed-shared')
        second, second_receipt = qualify.compile_stage(output,'B2',first,selfhost)
        require(read(first,1<<20)[0] == read(second,1<<20)[0], 'actual B1/B2 bytes differ')
        compiler_bundle = observe_compiler_bundle(source, output)
        report['compiler_bundle_before'] = compiler_bundle
        report['compiler_path'] = str(second)
        report['B1_receipt'] = first_receipt
        report['B2_receipt'] = second_receipt
        report['status'] = 'FRESH_COMPILER_PENDING_FINAL_SOURCE'
    except BaseException as error:
        report['errors'].append({'phase':'prepare','type':type(error).__name__,'traceback':traceback.format_exc()})
    finally:
        try:
            if rows is not None and before is not None:
                after = snapshot(source, rows)
                report['source_after'] = create(output/'source-after.json', wire(after))
                require(before == after, 'complete source changed during fresh preparation')
                report['source_preserved'] = True
                require(source_manifest(args.source_manifest)[2] == report['source_manifest'], 'source plan changed')
            if git_before is not None:
                report['source_git_after'] = source_git(source, rows)
                require(report['source_git_after'] == git_before, 'exact source Git identity changed')
            if compiler_bundle is not None:
                report['compiler_bundle_after'] = observe_compiler_bundle(source, output)
                require(report['compiler_bundle_after'] == compiler_bundle, 'actual compiler original bundle changed')
            if linker_record is not None:
                report['linker']['binary_after'] = read(linker,64<<20,system_binary=True)[1]
                require(report['linker']['binary_after'] == linker_record, 'actual linker changed')
            if report['status'] == 'FRESH_COMPILER_PENDING_FINAL_SOURCE':
                require(report.get('source_preserved') is True and not report['errors']
                        and not report['host_successor_compiler_calls'], 'fresh preparation conjunction incomplete')
                report['status'] = 'FRESH_B0_B1_B2_DEVELOPMENT_READY'
        except BaseException as error:
            report['status'] = 'HOLD'
            report['errors'].append({'phase':'final','type':type(error).__name__,'traceback':traceback.format_exc()})
        create(output/'report.json', wire(report))
    print(json.dumps({'status':report['status'],'cold_qualification':False}),flush=True)
    return 0 if report['status'] == 'FRESH_B0_B1_B2_DEVELOPMENT_READY' else 1


if __name__ == '__main__':
    raise SystemExit(main())
