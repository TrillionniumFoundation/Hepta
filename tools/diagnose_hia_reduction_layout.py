#!/usr/bin/env python3
"""Compile-only shrink-wrap ablation; no timing or production admission."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from hepta import hia_program_llvm as native
from hepta.hia_program_source import lower_source
from hepta.hia_reduction import propose_reduction_pipeline, reduction_program, verify_reduction_pipeline

ARMS = {'default': [], 'shrink_wrap_off': ['-mllvm', '-enable-shrink-wrap=false'],
        'shrink_wrap_on': ['-mllvm', '-enable-shrink-wrap=true']}
PROFILES = {'shrink-wrap': ARMS,
            'common-sink': {'default': [], 'common_sink_off': ['-mllvm', '-simplifycfg-sink-common=false']}}
TRACE_FLAGS = ['-mllvm', '-print-before=shrink-wrap', '-mllvm', '-print-after=shrink-wrap']


def digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')


def source_state():
    def git(*args):
        return subprocess.check_output(['git', '-C', str(ROOT), *args], text=True)
    return {'head': git('rev-parse', 'HEAD').strip(), 'tree': git('rev-parse', 'HEAD^{tree}').strip(),
            'status': git('status', '--porcelain', '--untracked-files=all')}


def bindings():
    # Bind Python dependencies, fixtures and this workflow, not just the runner.
    paths = list((ROOT / 'hepta').glob('*.py'))
    paths += [Path(__file__), ROOT / '.github/workflows/hia-reduction-layout-diagnostic.yml']
    paths += [ROOT / 'benchmarks/hia_reduction_release' / (w + '.hepta') for w in ('linear', 'affine')]
    return {str(p.relative_to(ROOT)): digest(p) for p in sorted(paths)}


def command(compiler, ir, output, arm, *, trace=False, profile='shrink-wrap'):
    if profile not in PROFILES or arm not in PROFILES[profile]:
        raise ValueError('unregistered layout arm')
    return [str(compiler), '--target=' + native.TARGET, '-x', 'ir', '-O3', '-fPIC', '-c',
            *PROFILES[profile][arm], *(TRACE_FLAGS if trace else []), str(ir), '-o', str(output)]


def equivalence(objects, sections, trace_object, *, profile='shrink-wrap'):
    if profile not in PROFILES or set(objects) != set(PROFILES[profile]) or set(sections) != set(PROFILES[profile]):
        raise ValueError('complete registered compiler arms required')
    return {'object_equal_to_default': {k: v == objects['default'] for k, v in objects.items()},
            'text_equal_to_default': {k: v == sections['default'] for k, v in sections.items()},
            'trace_object_equal_to_default': trace_object == objects['default'],
            'timing_performed': False, 'performance_qualified': False,
            'next_step': 'No speedup inferred. Identical objects rule out this flag as an optimization on this compiler/source. Different objects require separate preregistered correctness and complete original wall-time gates before any performance claim.'}


def run(output, clang, *, profile='shrink-wrap'):
    if profile not in PROFILES:
        raise ValueError('unregistered compiler experiment profile')
    arms = PROFILES[profile]
    output = Path(output).resolve()
    if output == ROOT or ROOT in output.parents:
        raise ValueError('evidence output must be outside the source checkout')
    output.mkdir(parents=True, exist_ok=False)
    before = source_state()
    if before['status']:
        raise ValueError('clean exact source checkout required')
    compiler = Path(shutil.which(clang) or clang).resolve()
    tool_paths = {'clang': compiler}
    for name in ('objdump', 'objcopy', 'nm'):
        found = shutil.which(name)
        if not found:
            raise ValueError('required existing tool unavailable: ' + name)
        tool_paths[name] = Path(found).resolve()
    tools = {name: {'path': str(path), 'sha256': digest(path)} for name, path in tool_paths.items()}
    bound = bindings()
    registration = {'schema': 'hepta.hia.reduction-layout-diagnostic.v1', 'source': before,
        'source_sha256': bound, 'tools': tools, 'workloads': ['linear', 'affine'], 'profile': profile, 'arms': arms,
        'target': native.TARGET, 'common_flags': ['-x', 'ir', '-O3', '-fPIC', '-c'],
        'trace_flags': TRACE_FLAGS, 'trace_arms': ['default'] if profile == 'shrink-wrap' else list(arms), 'maximum_compilations': 8, 'command_timeout_seconds': 60,
        'scope': 'compile-only ablation, no Rust comparison or target-library execution',
        'authority': 'DENY_ALL', 'production_activation_allowed': False, 'performance_qualified': False}
    save(output / 'REGISTRATION.json', registration)
    result = {'schema': registration['schema'], 'status': 'running', 'commands': [], 'workloads': {},
        'registration_sha256': digest(output / 'REGISTRATION.json'), 'authority': 'DENY_ALL',
        'production_activation_allowed': False, 'performance_qualified': False, 'timing_performed': False}
    started = time.monotonic_ns()

    def execute(argv):
        try:
            completed = native._run_logged(argv, command_log=result['commands'], timeout=60,
                stdout_limit=16000000, stderr_limit=16000000, cwd=str(output))
            if completed.returncode:
                raise ValueError('diagnostic command failed: ' + str(argv))
            return completed
        finally:
            save(output / 'RESULT.json', result)

    try:
        version = execute([str(compiler), '--version']).stdout
        result['compiler_version'] = version
        if re.search(r'clang version 20\.', version) is None:
            raise ValueError('existing Clang major 20 required for this experiment')
        for name in ('objdump', 'objcopy', 'nm'):
            result[name + '_version'] = execute([str(tool_paths[name]), '--version']).stdout
        for workload in registration['workloads']:
            directory = output / workload
            directory.mkdir()
            original = lower_source((ROOT / 'benchmarks/hia_reduction_release' / (workload + '.hepta')).read_text())
            proposal = propose_reduction_pipeline(original, include_induction=True)
            proof = verify_reduction_pipeline(original, proposal)
            save(directory / 'PROPOSAL.json', proposal)
            save(directory / 'PROOF.json', proof)
            if proof['status'] != 'verified':
                raise ValueError('fresh production reduction proof refused')
            reduced = reduction_program(original, proposal)
            (directory / 'original.core.json').write_bytes(original.canonical_bytes)
            (directory / 'reduced.core.json').write_bytes(reduced.canonical_bytes)
            ir = native.emit_program_llvm(reduced)
            ir_path = directory / 'canonical.ll'
            ir_path.write_text(ir.text)
            record = {'core_sha256': reduced.sha256, 'llvm_sha256': ir.sha256,
                      'exports': list(ir.exports), 'objects': {}, 'text_sections': {}}
            result['workloads'][workload] = record
            for arm in arms:
                obj = directory / (arm + '.o')
                execute(command(compiler, ir_path, obj, arm, profile=profile))
                record['objects'][arm] = digest(obj)
                text_section = directory / (arm + '.text.bin')
                execute([str(tool_paths['objcopy']), '--only-section=.text', '-O', 'binary', str(obj), str(text_section)])
                record['text_sections'][arm] = digest(text_section)
                assembly = execute([str(tool_paths['objdump']), '-dr', str(obj)])
                (directory / (arm + '.asm')).write_text(assembly.stdout)
                symbols = execute([str(tool_paths['nm']), '-S', str(obj)])
                (directory / (arm + '.symbols')).write_text(symbols.stdout)
            record['trace_objects'] = {}
            for trace_arm in registration['trace_arms']:
                trace_obj = directory / (trace_arm + '.trace.o')
                trace = execute(command(compiler, ir_path, trace_obj, trace_arm, trace=True, profile=profile))
                trace_name = 'shrink-wrap.mir.txt' if profile == 'shrink-wrap' else trace_arm + '.shrink-wrap.mir.txt'
                (directory / trace_name).write_text(trace.stderr)
                record['trace_objects'][trace_arm] = digest(trace_obj)
                if record['trace_objects'][trace_arm] != record['objects'][trace_arm]:
                    raise ValueError('trace instrumentation changed object bytes')
            record['trace_object_sha256'] = record['trace_objects']['default']
            record['equivalence'] = equivalence(record['objects'], record['text_sections'],
                                                record['trace_object_sha256'], profile=profile)
            if digest(ir_path) != ir.sha256:
                raise ValueError('shared canonical LLVM changed')
        result['status'] = 'completed'
    except BaseException as error:
        result.update(status='failed', error={'type': type(error).__name__, 'message': str(error)})
        raise
    finally:
        result['wall_ns'] = time.monotonic_ns() - started
        try:
            result['source_after'] = source_state()
            result['source_unchanged'] = result['source_after'] == before and bindings() == bound
            result['tools_unchanged'] = all(digest(tool_paths[n]) == t['sha256'] for n, t in tools.items())
            result['artifact_sha256'] = {str(p.relative_to(output)): digest(p)
                for p in sorted(output.rglob('*')) if p.is_file() and p.name != 'RESULT.json'}
            if not result['source_unchanged'] or not result['tools_unchanged']:
                result['status'] = 'failed'
        except BaseException as error:
            result.update(status='failed', final_identity_error=str(error))
        save(output / 'RESULT.json', result)
    if result['status'] != 'completed':
        raise ValueError('diagnostic final identity failed')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--clang', default='/usr/bin/clang-20')
    parser.add_argument('--profile', choices=tuple(PROFILES), default='shrink-wrap')
    args = parser.parse_args()
    print(json.dumps({'status': run(args.output, args.clang, profile=args.profile)['status'], 'performance_qualified': False}))
