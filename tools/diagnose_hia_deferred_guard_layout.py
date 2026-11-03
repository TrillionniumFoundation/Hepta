#!/usr/bin/env python3
"""Bounded compile-only experiment. Never native admission or execution."""
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
from hepta.hia_program import _decode, verify_program
from hepta.hia_program_source import lower_source
from hepta.hia_optimization import _digest
from hepta.hia_reduction import propose_reduction_pipeline, _freeze_pipeline, _verify_frozen, reduction_checker_identity
from tools.experimental_deferred_guard_proposer import propose_deferred_guard
from tools.stage_deferred_guard_evidence import snapshot_tree, allowed_artifact_paths, safe_read_file
from tools.check_deferred_guard_candidate import check_deferred_guard, deferred_guard_checker_identity

WORKLOADS = ('linear', 'affine')
ARMS = ('reference', 'deferred')
TRACE_FLAGS = ['-mllvm', '-print-before=shrink-wrap', '-mllvm', '-print-after=shrink-wrap']
MAX_COMMANDS = 24
MAX_COMPILATIONS = 8
DENY = {'authority': 'DENY_ALL', 'native_admission': False, 'production_admission': False,
        'performance_qualified': False, 'timing_performed': False, 'quota_equivalence': False}


def digest(path):
    return sha256(safe_read_file(path)).hexdigest()


def bounded_artifact_digest(path):
    data = safe_read_file(path, remaining=native.MAX_ARTIFACT_BYTES)
    if not data:
        raise ValueError('native artifact must be nonempty')
    return sha256(data).hexdigest()


def save(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')
    os.replace(temporary, path)


def source_state():
    def git(*args):
        return subprocess.check_output(['git', '-C', str(ROOT), *args], text=True)
    return {'head': git('rev-parse', 'HEAD').strip(), 'tree': git('rev-parse', 'HEAD^{tree}').strip(),
            'status': git('status', '--porcelain', '--untracked-files=all')}


def bindings():
    paths = list((ROOT / 'hepta').glob('*.py'))
    paths += [ROOT / 'tools' / name for name in ('diagnose_hia_deferred_guard_layout.py',
              'experimental_deferred_guard_proposer.py', 'check_deferred_guard_candidate.py',
              'research_deferred_guard_model.py', 'stage_deferred_guard_evidence.py')]
    paths += list((ROOT / 'tests').glob('test_deferred_guard*.py'))
    paths += [ROOT / '.github/workflows/hia-deferred-guard-layout-diagnostic.yml']
    paths += [ROOT / 'benchmarks/hia_reduction_release' / (w + '.hepta') for w in WORKLOADS]
    return {str(p.relative_to(ROOT)): digest(p) for p in sorted(paths)}


def command(compiler, ir, output, *, trace=False):
    return [str(compiler), '--target=' + native.TARGET, '-x', 'ir', '-O3', '-fPIC', '-c',
            *(TRACE_FLAGS if trace else []), str(ir), '-o', str(output)]


def prepare(output):
    """Freeze/check both workloads and emit only their exact checked Core; no subprocess."""
    output = Path(output)
    identity = deferred_guard_checker_identity()
    prepared = {}
    for workload in WORKLOADS:
        directory = output / workload
        directory.mkdir()
        base = lower_source((ROOT / 'benchmarks/hia_reduction_release' / (workload + '.hepta')).read_text())
        reduction = propose_reduction_pipeline(base, include_induction=True)
        wire, _ = _decode(propose_deferred_guard(base, reduction))
        # Detach the checker's input as well; it must not mutate the frozen tree
        # subsequently used to build either compilation arm.
        checked_wire, _ = _decode(wire)
        check = check_deferred_guard(base, checked_wire)
        save(directory / 'PROPOSAL.json', wire)
        save(directory / 'CHECK.json', check)
        if check['status'] != 'checked' or check['checker_sha256'] != identity:
            raise ValueError('fresh independent deferred check refused or identity changed')
        candidate = verify_program(wire['candidate_core'])
        original, narrowed, fast, frozen = _freeze_pipeline(base, wire['reduction'])
        reference_proof, reference = _verify_frozen(original, narrowed, fast, frozen, check['policy'])
        save(directory / 'REFERENCE_PROOF.json', reference_proof)
        if reference_proof['status'] != 'verified' or reference is None:
            raise ValueError('fresh reference proof refused')
        if (check['base_sha256'], check['candidate_sha256'], check['reference_sha256']) != (
                base.sha256, candidate.sha256, reference.sha256):
            raise ValueError('fresh checked source/candidate/reference mismatch')
        expected_reference = {'base_sha256': original.sha256, 'narrowed_sha256': narrowed.sha256,
            'candidate_sha256': reference.sha256, 'proposal_sha256': _digest(frozen),
            'checker_sha256': reduction_checker_identity()}
        if any(reference_proof[k] != value or check['reduction_verification'][k] != value
               for k, value in expected_reference.items()):
            raise ValueError('fresh reference proof identity mismatch')
        for stage in ('narrowing', 'guarded_reduction'):
            stage_proof = reference_proof['proofs'][stage]
            if (stage_proof['policy'] != check['policy']
                    or stage_proof['policy_sha256'] != _digest(check['policy'])
                    or stage_proof['checker_sha256'] != check['reduction_verification']['proofs'][stage]['checker_sha256']):
                raise ValueError('fresh reference proof policy/checker mismatch')
        if check['proposal_sha256'] != _digest(wire):
            raise ValueError('frozen proposal changed after checking')
        prepared[workload] = {}
        for arm, core in (('reference', reference), ('deferred', candidate)):
            (directory / (arm + '.core.json')).write_bytes(core.canonical_bytes)
            emitter_identity = native._implementation_hash()
            ir = native.emit_program_llvm(core)
            if (ir.core_sha256 != core.sha256 or sha256(ir.text.encode()).hexdigest() != ir.sha256
                    or ir.target != native.TARGET or ir.input_sha256 != core.input_sha256
                    or ir.exports != tuple(sorted(core.scalar_entrypoints))
                    or ir.implementation_sha256 != emitter_identity
                    or native._implementation_hash() != emitter_identity):
                raise ValueError('emitted LLVM identity mismatch')
            (directory / (arm + '.ll')).write_text(ir.text)
            save(directory / (arm + '.llvm.json'), {'core_sha256': ir.core_sha256,
                 'llvm_sha256': ir.sha256, 'exports': list(ir.exports), 'target': ir.target,
                 'implementation_sha256': ir.implementation_sha256, 'input_sha256': ir.input_sha256,
                 'checker_sha256': identity, **DENY})
            prepared[workload][arm] = ir
    if deferred_guard_checker_identity() != identity:
        raise ValueError('checker changed during preparation')
    return prepared


class Executor:
    """Enforce both budgets at the subprocess boundary, not merely in metadata."""
    def __init__(self, output, result):
        self.output, self.result = output, result
        self.commands = self.compilations = 0

    def execute(self, argv):
        compile_command = '-c' in argv
        if self.commands >= MAX_COMMANDS or (compile_command and self.compilations >= MAX_COMPILATIONS):
            raise ValueError('diagnostic command budget exceeded')
        self.commands += 1
        self.compilations += int(compile_command)
        self.result.update(command_count=self.commands, compilation_count=self.compilations)
        try:
            completed = native._run_logged(argv, command_log=self.result['commands'], timeout=60,
                stdout_limit=16000000, stderr_limit=16000000, cwd=str(self.output))
            if completed.returncode:
                raise ValueError('diagnostic command failed: ' + str(argv))
            # Production bounded capture normally raises on incomplete streams.
            # Retain a fail-closed check should its behavior ever change.
            for row in self.result['commands'][-1:]:
                if row.get('stdout_complete') is False or row.get('stderr_complete') is False:
                    raise ValueError('diagnostic command output incomplete')
            return completed
        finally:
            save(self.output / 'RESULT.json', self.result)


def run(output, clang):
    output = Path(output).resolve()
    if output == ROOT or ROOT in output.parents:
        raise ValueError('evidence output must be outside the source checkout')
    output.mkdir(parents=True, exist_ok=False)
    result = {'schema': 'hepta.hia.deferred-guard-layout-diagnostic.v1', 'status': 'running',
              'commands': [], 'workloads': {}, 'command_count': 0, 'compilation_count': 0, **DENY}
    save(output / 'RESULT.json', result)
    started = time.monotonic_ns()
    before = bound = tools = identity = None
    tool_paths = {}
    try:
        before, bound = source_state(), bindings()
        if before['status']:
            raise ValueError('clean exact source checkout required')
        identity = deferred_guard_checker_identity()
        prepared = prepare(output)
        if deferred_guard_checker_identity() != identity or source_state() != before or bindings() != bound:
            raise ValueError('source/checker changed before compilation')
        compiler = Path(shutil.which(clang) or clang).resolve()
        tool_paths['clang'] = compiler
        for name in ('objdump', 'objcopy', 'nm'):
            found = shutil.which(name)
            if not found:
                raise ValueError('required existing tool unavailable: ' + name)
            tool_paths[name] = Path(found).resolve()
        tools = {name: {'path': str(path), 'sha256': digest(path)} for name, path in tool_paths.items()}
        registration = {'schema': result['schema'], 'source': before, 'source_sha256': bound,
            'checker_sha256': identity, 'tools': tools, 'workloads': list(WORKLOADS), 'arms': list(ARMS),
            'target': native.TARGET, 'common_flags': ['-x', 'ir', '-O3', '-fPIC', '-c'],
            'trace_flags': TRACE_FLAGS, 'maximum_compilations': MAX_COMPILATIONS,
            'maximum_commands': MAX_COMMANDS, 'command_timeout_seconds': 60,
            'runner_timeout_seconds': 300, 'scope': 'compile-only, no linking or target execution',
            'inputs': {w: {'guards': json.loads((output / w / 'PROPOSAL.json').read_text())['reduction']['guarded']['guards'],
                          'proposal_sha256': digest(output / w / 'PROPOSAL.json'),
                          'check_sha256': digest(output / w / 'CHECK.json'),
                          'arms': {a: {'core_sha256': prepared[w][a].core_sha256,
                                       'llvm_sha256': prepared[w][a].sha256} for a in ARMS}} for w in WORKLOADS},
            **DENY}
        prepared_hashes = {name: sha256(data).hexdigest()
                           for name, data in snapshot_tree(output, allowed_artifact_paths()).items() if name != 'RESULT.json'}
        registration['prepared_artifact_sha256'] = prepared_hashes
        save(output / 'REGISTRATION.json', registration)
        result['registration_sha256'] = digest(output / 'REGISTRATION.json')
        executor = Executor(output, result)
        execute = executor.execute
        version = execute([str(compiler), '--version']).stdout
        result['compiler_version'] = version
        if re.search(r'clang version 20\.', version) is None:
            raise ValueError('Clang major 20 required for this experiment')
        for name in ('objdump', 'objcopy', 'nm'):
            result[name + '_version'] = execute([str(tool_paths[name]), '--version']).stdout
        for workload in WORKLOADS:
            directory = output / workload
            record = {'objects': {}, 'text_sections': {}, 'trace_objects': {}}
            result['workloads'][workload] = record
            for arm in ARMS:
                ir_path, obj = directory / (arm + '.ll'), directory / (arm + '.o')
                if digest(ir_path) != prepared[workload][arm].sha256:
                    raise ValueError('frozen LLVM changed before compilation')
                execute(command(compiler, ir_path, obj))
                record['objects'][arm] = bounded_artifact_digest(obj)
                section = directory / (arm + '.text.bin')
                execute([str(tool_paths['objcopy']), '--only-section=.text', '-O', 'binary', str(obj), str(section)])
                record['text_sections'][arm] = bounded_artifact_digest(section)
                assembly = execute([str(tool_paths['objdump']), '-dr', str(obj)])
                (directory / (arm + '.asm')).write_text(assembly.stdout)
                symbols = execute([str(tool_paths['nm']), '-S', str(obj)])
                (directory / (arm + '.symbols')).write_text(symbols.stdout)
            for arm in ARMS:
                obj = directory / (arm + '.trace.o')
                trace = execute(command(compiler, directory / (arm + '.ll'), obj, trace=True))
                (directory / (arm + '.shrink-wrap.mir.txt')).write_text(trace.stderr)
                record['trace_objects'][arm] = bounded_artifact_digest(obj)
                if record['trace_objects'][arm] != record['objects'][arm]:
                    raise ValueError('trace instrumentation changed object bytes: ' + arm)
            record['observation'] = {'object_equal': record['objects']['reference'] == record['objects']['deferred'],
                'text_equal': record['text_sections']['reference'] == record['text_sections']['deferred'],
                'interpretation': 'Layout observation only; equal or different bytes imply no speedup or admission.', **DENY}
        if (executor.commands, executor.compilations) != (24, 8):
            raise ValueError('incomplete registered command inventory')
        result['status'] = 'completed'
    except BaseException as error:
        result.update(status='failed', error={'type': type(error).__name__, 'message': str(error)})
        raise
    finally:
        result['runner_wall_ns'] = time.monotonic_ns() - started
        try:
            if before is not None and bound is not None:
                result['source_after'] = source_state()
                result['source_unchanged'] = result['source_after'] == before and bindings() == bound
                if not result['source_unchanged']:
                    result['status'] = 'failed'
            if identity is not None:
                result['checker_unchanged'] = deferred_guard_checker_identity() == identity
                if not result['checker_unchanged']:
                    result['status'] = 'failed'
            if tools is not None:
                result['tools_unchanged'] = all(digest(tool_paths[n]) == t['sha256'] for n, t in tools.items())
                if not result['tools_unchanged']:
                    result['status'] = 'failed'
            recorded_binary_hashes = {}
            for workload, record in result['workloads'].items():
                for field, suffix in (('objects', '.o'), ('text_sections', '.text.bin'), ('trace_objects', '.trace.o')):
                    for arm, value in record[field].items():
                        recorded_binary_hashes[str(Path(workload) / (arm + suffix))] = value
            result['recorded_binaries_unchanged'] = all(bounded_artifact_digest(output / p) == h
                for p, h in recorded_binary_hashes.items())
            if not result['recorded_binaries_unchanged']:
                result['status'] = 'failed'
            if 'prepared_hashes' in locals():
                result['prepared_artifacts_unchanged'] = all(digest(output / p) == h for p, h in prepared_hashes.items())
                result['registration_unchanged'] = digest(output / 'REGISTRATION.json') == result['registration_sha256']
                if not result['prepared_artifacts_unchanged'] or not result['registration_unchanged']:
                    result['status'] = 'failed'
            if 'prepared' in locals():
                result['llvm_unchanged'] = all(digest(output / w / (a + '.ll')) == prepared[w][a].sha256
                    for w in WORKLOADS for a in ARMS)
                if not result['llvm_unchanged']:
                    result['status'] = 'failed'
        except BaseException as error:
            result.update(status='failed', final_identity_error=str(error))
        try:
            result['artifact_sha256'] = {name: sha256(data).hexdigest()
                for name, data in snapshot_tree(output, allowed_artifact_paths()).items() if name != 'RESULT.json'}
            expected = {**locals().get('prepared_hashes', {}), **locals().get('recorded_binary_hashes', {})}
            if 'registration_sha256' in result:
                expected['REGISTRATION.json'] = result['registration_sha256']
            result['inventory_matches_recorded'] = all(result['artifact_sha256'].get(p) == h for p, h in expected.items())
            if not result['inventory_matches_recorded']:
                result['status'] = 'failed'
        except BaseException as error:
            result.update(status='failed', artifact_inventory_error=type(error).__name__ + ': unsafe or incomplete evidence tree')
        save(output / 'RESULT.json', result)
    if result['status'] != 'completed':
        raise ValueError('diagnostic final identity failed')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--clang', default='/usr/bin/clang-20')
    args = parser.parse_args()
    print(json.dumps({'status': run(args.output, args.clang)['status'], **DENY}))
