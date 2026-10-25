"""Execute actual C++ owner migration through the independent LLVM backend.

This closes the connection between two capabilities: the Hepta input is the
fresh translator output, not a separately authored look-alike fixture. The
native executable links the LLVM object and a C observation driver only.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.cpp_owned_migrate import migrate_cpp_owned
from hepta.llvm_owned_backend import emit_owned_llvm, TARGET
from hepta.llvm_owned_pipeline import build_llvm_owned_source
from hepta.pipeline import analyze_project, compiler_hash
from tools.evidence_checks import native_build, normalized_errors, require, strict_equal
from tools.validate_cpp_owned import EXAMPLE, INPUTS, WRAP_FLAGS, cases, _case_sources, _observation_oracle

SCHEMA = 'hepta.cpp-owned-to-llvm-qualification.v1'
CLAIMS = {'actual_cpp_implementation_migrated': True, 'actual_migrated_source_compiled_by_llvm': True,
          'original_cpp_linked': False, 'rust_codegen_used_for_machine_code': False,
          'c_codegen_used_for_machine_code': False, 'fallback_used': False,
          'general_cpp_raii_migration': False, 'source_equivalence_proved': False,
          'whole_language_soundness_proved': False, 'performance_qualified_by_this_gate': False}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def identity(path):
    path = Path(path).resolve()
    return {'path': str(path), 'sha256': digest(path), 'bytes': path.stat().st_size}


def inputs():
    return {name: digest(ROOT / name) for name in (*INPUTS, 'tools/qualify_cpp_owned_llvm.py')}


def command(argv, report, field):
    row = {'argv': [str(x) for x in argv]}
    report[field] = row
    try:
        process = subprocess.run(row['argv'], cwd=ROOT, capture_output=True, timeout=120)
        row['exit_code'] = process.returncode
        for name, value in (('stdout', process.stdout), ('stderr', process.stderr)):
            row[name] = value.decode('utf-8', errors='replace')
            row[name + '_sha256'] = hashlib.sha256(value).hexdigest()
        require(process.returncode == 0, 'Native command failed: ' + json.dumps(row))
        return row
    except subprocess.TimeoutExpired as exc:
        import base64
        row.update(exit_code=None, timed_out=True)
        for name, value in (('stdout', exc.stdout or b''), ('stderr', exc.stderr or b'')):
            if isinstance(value, str): value = value.encode()
            row[name] = value.decode('utf-8', errors='replace')
            row[name + '_sha256'] = hashlib.sha256(value).hexdigest()
            row[name + '_bytes_base64'] = base64.b64encode(value).decode()
        raise


def qualify_cpp_owned_llvm(workdir, *, clang='clang', clangxx='clang++', rustc=None, cc='gcc'):
    work = Path(workdir).resolve()
    if Path(workdir).is_symlink() or work.exists():
        raise ValueError('A new LLVM migration work directory is required')
    work.mkdir(parents=True)
    report = {'schema': SCHEMA, 'ok': False, 'status': 'failed', 'workdir': str(work),
              'compiler_sha256': compiler_hash(), 'inputs': inputs(), 'claims': CLAIMS,
              'foreign_cpp_link_inputs': [], 'diagnostics': []}
    try:
        migrated, entry = work / 'migrated.hepta', work / 'consumer.hepta'
        report['migration'] = migrate_cpp_owned(EXAMPLE / 'owned_bytes.cpp', migrated, clangxx=clangxx)
        require(report['migration']['ok'] is True, 'Actual C++ owner migration rejected')
        entry.write_bytes((EXAMPLE / 'consumer.hepta').read_bytes())
        report['sources'] = {'migrated': identity(migrated), 'consumer': identity(entry)}
        obj = work / 'owned.o'
        report['build'] = build_llvm_owned_source(entry, obj, rustc=rustc, clang=clang, kind='object')
        require(report['build']['ok'] is True, 'Actual migrated source LLVM compilation rejected: ' + json.dumps(report['build']))
        report['llvm_object'] = identity(obj)
        vectors = cases()
        header, _ = _case_sources(vectors)
        (work / 'cases.h').write_text(header)
        report['case_header'] = identity(work / 'cases.h')
        report['case_families'] = dict(Counter(row['family'] for row in vectors))
        compiler = shutil.which(cc)
        require(compiler is not None, 'Native C observation driver compiler missing')
        report['cc'] = {'driver': compiler, **identity(compiler)}
        executable = work / 'owned-llvm'
        argv = [compiler, '-std=c11', '-O2', '-fno-lto', *WRAP_FLAGS, '-I' + str(work),
                str(EXAMPLE / 'harness.c'), str(obj), '-o', str(executable)]
        command(argv, report, 'link_process')
        report['executable'] = identity(executable)
        execution = command([executable], report, 'execution_process')
        report['observed'] = json.loads(execution['stdout'])
        require(strict_equal(report['observed'], _observation_oracle(vectors)), 'LLVM migrated lifecycle differs from independent oracle')
        report['inputs_unchanged'] = report['inputs'] == inputs() and report['compiler_sha256'] == compiler_hash()
        report.update(ok=True, status='passed')
        validate_report(report)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        report.update(ok=False, status='failed')
        report['diagnostics'].append({'message': str(exc)})
    return report


@normalized_errors
def validate_report(report):
    require(set(report) == {'schema', 'ok', 'status', 'workdir', 'compiler_sha256', 'inputs', 'claims',
            'foreign_cpp_link_inputs', 'diagnostics', 'migration', 'sources', 'build', 'llvm_object',
            'case_header', 'case_families', 'cc', 'link_process', 'executable', 'execution_process',
            'observed', 'inputs_unchanged'}, 'Closed vertical qualification schema required')
    require(report.get('schema') == SCHEMA and report.get('ok') is True and report.get('status') == 'passed'
            and report.get('diagnostics') == [], 'Completed C++ to LLVM vertical required')
    require(strict_equal(report.get('claims'), CLAIMS) and report.get('foreign_cpp_link_inputs') == [], 'Unsupported claims or foreign C++ link')
    require(report['compiler_sha256'] == compiler_hash() and report['inputs'] == inputs()
            and report.get('inputs_unchanged') is True, 'Current source/compiler identity differs')
    work = Path(report['workdir'])
    for label, name in (('llvm_object', 'owned.o'), ('case_header', 'cases.h'), ('executable', 'owned-llvm')):
        require(report[label] == identity(work / name), 'Retained native artifact differs: ' + label)
    require(report['sources']['migrated'] == identity(work / 'migrated.hepta')
            and report['sources']['consumer'] == identity(work / 'consumer.hepta'), 'Actual source artifacts differ')
    require(report['sources']['migrated']['sha256'] == digest(EXAMPLE / 'expected.hepta')
            and report['sources']['consumer']['sha256'] == digest(EXAMPLE / 'consumer.hepta'), 'Unexpected translated implementation/caller')
    migration = report['migration']
    require(migration['ok'] is True and migration['protocol_verified'] is True
            and migration['selected_resource_raii_translated'] is True
            and migration['source_sha256'] == digest(EXAMPLE / 'owned_bytes.cpp')
            and migration['output_sha256'] == report['sources']['migrated']['sha256']
            and migration['hepta_compiler_sha256'] == compiler_hash()
            and migration['source_declarations'] == 2 and migration['converted_source_declarations'] == 2
            and migration['unconverted_members'] == [] and len(migration['declaration_inventory']) == 15
            and migration['complete_ast_sha256'] == migration['protocol_ast_sha256']
            and migration['foreign_cpp_implementation_retained'] is False
            and type(migration['foreign_cpp_calls']) is int and migration['foreign_cpp_calls'] == 0,
            'Migration was not the complete selected implementation')
    build = report['build']
    require(build['ok'] is True and build['status'] == 'native_compiled_not_executed' and build['kind'] == 'object'
            and build['source'] == str(work / 'consumer.hepta') and build['output'] == str(work / 'owned.o'), 'Wrong source-facing LLVM build')
    for flag in ('actual_source_replayed', 'independent_resource_cfg_verified', 'native_rust_reference_required', 'native_artifact_compiled'):
        require(build['claims'][flag] is True, 'Missing native/resource source gate: ' + flag)
    for flag in ('rust_codegen_used', 'c_codegen_used', 'fallback_used', 'backend_refinement_proved', 'whole_language_memory_safety_proved'):
        require(build['claims'][flag] is False, 'Unexpected native backend claim: ' + flag)
    check = analyze_project(work / 'consumer.hepta', native=False, crate_type='rlib')
    require(check.report['ok'] is True, 'Current migrated frontend no longer checks')
    ir = emit_owned_llvm(check.program, check.checked, project_sha256=check.project.identity)
    reference = build['reference_validation']
    require(reference['ok'] is True and reference['compiler_sha256'] == compiler_hash()
            and reference['diagnostics'] == [] and reference['assumptions'] == [], 'Fresh safe native reference missing')
    native_build(reference['backend'], 'rust', check_only=True, crate_type='rlib',
                 source_sha256=hashlib.sha256(check.rust.encode()).hexdigest())
    binding, native = build['source_binding'], build['native_backend']
    require(binding['sources'] == check.project.sources and binding['project_sha256'] == check.project.identity
            and binding['compiler_sha256'] == compiler_hash() and binding['semantic_sha256'] == ir.semantic_sha256
            and binding['resource_ir_sha256'] == ir.resource_ir_sha256
            and binding['resource_verification_sha256'] == ir.resource_verification_sha256
            and binding['llvm_ir_sha256'] == ir.sha256, 'LLVM origin differs from fresh actual migrated source')
    require(native['ok'] is True and native['target'] == TARGET and native['kind'] == 'object'
            and native['output'] == report['llvm_object']['path'] and native['artifact_sha256'] == report['llvm_object']['sha256']
            and native['artifact_bytes'] == report['llvm_object']['bytes'] and native['llvm_ir_sha256'] == ir.sha256
            and build['reference_validation']['checks']['rust_borrows_types'] == 'rustc_checked', 'Native LLVM artifact/reference missing')
    vectors = cases()
    header, _ = _case_sources(vectors)
    require(report['case_header']['sha256'] == hashlib.sha256(header.encode()).hexdigest()
            and strict_equal(report['case_families'], dict(Counter(r['family'] for r in vectors))), 'Shared native cases differ')
    expected_argv = [report['cc']['driver'], '-std=c11', '-O2', '-fno-lto', *WRAP_FLAGS, '-I' + str(work),
                     str(EXAMPLE / 'harness.c'), str(work / 'owned.o'), '-o', str(work / 'owned-llvm')]
    require({k: report['cc'][k] for k in ('path', 'sha256', 'bytes')} == identity(report['cc']['driver']), 'Native C driver identity changed')
    for label, argv in (('link_process', expected_argv), ('execution_process', [str(work / 'owned-llvm')])):
        process = report[label]
        require(type(process['exit_code']) is int and process['exit_code'] == 0 and process['argv'] == argv, 'Actual exact native command missing')
        for name in ('stdout', 'stderr'):
            require(process[name + '_sha256'] == hashlib.sha256(process[name].encode()).hexdigest(), 'Native process stream differs')
    require(strict_equal(report['observed'], json.loads(report['execution_process']['stdout']))
            and strict_equal(report['observed'], _observation_oracle(vectors)), 'Actual LLVM behavior/allocation observations differ')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workdir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--clang', default='clang')
    parser.add_argument('--clangxx', default='clang++')
    parser.add_argument('--rustc', default=os.environ.get('RUSTC'))
    parser.add_argument('--cc', default=os.environ.get('CC', 'gcc'))
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.is_symlink():
        parser.error('New output required')
    report = qualify_cpp_owned_llvm(args.workdir, clang=args.clang, clangxx=args.clangxx, rustc=args.rustc, cc=args.cc)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'ok': report['ok'], 'status': report['status'], 'output': str(args.output)}))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
