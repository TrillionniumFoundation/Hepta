"""One reviewed R9 generation/check and the retained one-owner size/pack prefix."""
from pathlib import Path
import argparse
import json
import os
import runpy
import stat
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
import prefix_support as S


def generation_child(stage):
    out = S.EXEC / 'generation' / stage
    result = {'schema': 'hia.R9.original-generation-stage.v1', 'stage': stage,
        'status': 'FAIL', 'generator_main_attempted': 0,
        'frozen_source_runtime_equal': False, 'generated_source': None,
        'finalization_errors': [], 'compile_calls': 0, 'VM_calls': 0, 'ELF_calls': 0}
    before = controls_before = None
    original_argv, original_path = sys.argv[:], sys.path[:]
    old_umask = None
    started = time.monotonic_ns()
    try:
        S.dump(out / 'RUNTIME-BEFORE.json', S.runtime_guard())
        controls_before = S.controls_guard()
        S.dump(out / 'CONTROLS-BEFORE.json', controls_before)
        before = S.snapshot(out / 'SOURCE-RUNTIME-BEFORE.json', {'source', 'runtime'})
        asset = S.EXEC / 'generated/file_render_checker_word64.hepta'
        S.mkdir(asset.parent)
        generated_before = None
        if stage == 'generate':
            S.require(not asset.exists() and not asset.is_symlink(), 'unique generated asset already exists')
        else:
            previous = json.loads(S.read(S.EXEC / 'generation/generate/RESULT.json')[0])
            S.require(previous['status'] == 'PASS_ORIGINAL_R9_GENERATOR_STAGE'
                and previous['generator_main_attempted'] == 1, 'first generation did not complete')
            generated_before = S.identity(asset)
            S.require(generated_before == previous['generated_source'], 'asset changed before original check')
        code, _ = S.fixed(S.PLAN['projected_generator'])
        original, _ = S.fixed(S.PLAN['candidate_generator'])
        restored = code
        for edit in reversed(S.PLAN['generator_projection']):
            after, prior = edit['after'].encode(), edit['before'].encode()
            S.require(restored.count(after) == 1, 'generator inverse is not unique')
            restored = restored.replace(after, prior, 1)
        S.require(restored == original, 'generator complete source inverse differs')
        filename = S.PLAN['projected_generator']['path']
        command = [filename, '--report', str(out / 'report.json')]
        if stage == 'check':
            command.append('--check')
        S.dump(out / 'ORIGINAL-MAIN-ARGV.json', {'argv': command,
            'captured_code': S.pin(code), 'whole_module_inverse_equal': True,
            'all_original_function_bodies_unchanged': True})
        sys.argv = command
        old_umask = os.umask(0o022)
        namespace = {'__name__': '__main__', '__file__': filename,
            '__package__': None, '__cached__': None}
        result['generator_main_attempted'] = 1
        exec(compile(code, filename, 'exec'), namespace)
        raw, mode, _ = S.read(asset)
        report = json.loads(S.read(out / 'report.json')[0])
        generated = report['generated']
        S.require(set(generated) == {'functions', 'blocks', 'ops', 'word64_projection'}
            and {k: generated[k] for k in ('functions', 'blocks', 'ops')}
                == {'functions': 107, 'blocks': 1456, 'ops': 6347}, 'actual generated counts differ')
        proof = generated['word64_projection']
        S.require(proof['whole_inverse_equal'] is True
            and proof['complete_original_Core_verifier_returned'] is True
            and len(proof['removed_identity_casts']) == 317, 'actual generated inverse/verifier proof differs')
        S.require(mode == 0o644 and 0 < len(raw) <= 1048576
            and report['source_bytes'] == len(raw)
            and report['source_sha256'] == S.pin(raw)['sha256'], 'actual generated source binding differs')
        result['generated_source'] = S.identity(asset)
        if generated_before is not None:
            S.require(result['generated_source'] == generated_before, 'original check changed generated asset')
        result['report'] = S.identity(out / 'report.json')
        result['status'] = 'PASS_ORIGINAL_R9_GENERATOR_STAGE'
    except BaseException as error:
        result.update(error_type=type(error).__name__, error=str(error), traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        if old_umask is not None:
            os.umask(old_umask)
        sys.argv, sys.path[:] = original_argv, original_path
        for label, action in (
            ('SOURCE-RUNTIME', lambda: S.snapshot(out / 'SOURCE-RUNTIME-AFTER.json', {'source', 'runtime'})),
            ('CONTROLS', S.controls_guard), ('RUNTIME', S.runtime_guard)):
            try:
                observed = action()
                if label == 'SOURCE-RUNTIME':
                    S.require(before is not None and observed == before, 'complete frozen source/runtime changed')
                    result['frozen_source_runtime_equal'] = True
                else:
                    S.dump(out / (label + '-AFTER.json'), observed)
                    if label == 'CONTROLS':
                        S.require(controls_before is not None and observed == controls_before, 'author controls changed')
            except BaseException as error:
                result['status'] = 'FAIL'
                result['finalization_errors'].append({'name': label, 'type': type(error).__name__,
                    'error': str(error), 'traceback': traceback.format_exc()})
        asset = S.EXEC / 'generated/file_render_checker_word64.hepta'
        if result['generated_source'] is None and asset.exists():
            try:
                result['partial_generated_source'] = S.identity(asset)
            except BaseException as error:
                result['partial_generated_source_error'] = {'type': type(error).__name__, 'error': str(error)}
        result['elapsed_ns'] = time.monotonic_ns() - started
        S.dump(out / 'RESULT.json', result)
    return 0 if result['status'] == 'PASS_ORIGINAL_R9_GENERATOR_STAGE' else 1


def original_size_driver(bound):
    runner, _ = S.fixed(bound['runner'])
    plan_raw, _ = S.fixed(bound['plan'])
    S.require(runner == S.read(S.AUTHOR / 'size-runner.py')[0], 'actual retained size runner differs')
    original_argv, original_path = sys.argv[:], sys.path[:]
    try:
        sys.argv = [bound['runner']['path'], '--plan-sha256', S.pin(plan_raw)['sha256']]
        try:
            runpy.run_path(bound['runner']['path'], run_name='__main__')
        except SystemExit as stopped:
            S.require(type(stopped.code) is int, 'retained driver returned a noninteger exit')
            return stopped.code
        raise ValueError('retained driver did not execute its original main exit')
    finally:
        sys.argv, sys.path[:] = original_argv, original_path


def driver():
    S.runtime_guard()
    S.require(not S.EXEC.exists() and not S.EXEC.is_symlink(), 'unique prefix output already exists; no retry')
    parent = S.EXEC.parent.lstat()
    expected_parent = S.PLAN['output_parent']
    S.require(stat.S_ISDIR(parent.st_mode) and parent.st_dev == expected_parent['device']
        and parent.st_ino == expected_parent['inode']
        and stat.S_IMODE(parent.st_mode) == expected_parent['mode'], 'fixed output filesystem parent differs')
    disk = os.statvfs(S.EXEC.parent)
    free = disk.f_bavail * disk.f_frsize
    S.require(free >= S.PLAN['minimum_free_bytes'] == 3221225472, 'original 3 GiB entry floor unavailable')
    S.mkdir(S.EXEC)
    S.dump(S.EXEC / 'ENTRY.json', {'free_bytes': free, 'required_free_bytes': 3221225472,
        'execution_root': str(S.EXEC), 'new_independent_scope': True, 'old_outputs_moved_or_deleted': False})
    S.write(S.EXEC / 'PREFIX-PLAN.json', S.PLAN_RAW)
    result = {'schema': 'hia.R9.private-generation-size-pack-prefix-result.v1', 'status': 'FAIL',
        'stages': [], 'not_started': ['generate', 'check', 'size-pack'],
        'generation_owner_launches': 0, 'size_driver_attempts': 0,
        'compile_calls_attempted': 0, 'pack_calls_attempted': 0,
        'semantic_Native_cases': 0, 'VM_calls': 0, 'aggregate_cases': 0, 'ELF_exec_calls': 0,
        'ordinary_SOURCE_rebound': False, 'public_R5_profile_changed': False,
        'matching_current_cold': False, 'whole_native': False, 'automatic_retry': False,
        'finalization_errors': [], 'parent_preflight_and_finalization_outside_owned_product_deadlines': True}
    before = controls_before = binding = None
    started = time.monotonic_ns()
    try:
        controls_before = S.controls_guard()
        S.dump(S.EXEC / 'CONTROLS-BEFORE.json', controls_before)
        before = S.snapshot(S.EXEC / 'FULL-FRESH-BEFORE.json')
        original_capsule = S.capsule()
        S.dump(S.EXEC / 'ORIGINAL-CAPSULE-READBACK.json', {'complete_members': len(original_capsule),
            'all_complete_bytes_modes_verified': True, 'capsule': S.PLAN['size_author_capsule']})
        sys.path.insert(0, str(S.SOURCE))
        from tools.hia_selfhost_process_owner import run_owned
        for stage in ('generate', 'check'):
            out = S.EXEC / 'generation' / stage
            S.mkdir(out)
            command = [sys.executable, '-I', '-S', '-B', str(S.AUTHOR / 'run_prefix.py'),
                '--plan-sha256', S.PLAN['authorization_pin'], '--stage', stage]
            launch = {'command': command, 'cwd': str(S.SOURCE), 'env': S.PLAN['environment'],
                'supervisor_env': S.PLAN['environment'], 'qualification_seconds': 180,
                'cleanup_seconds': 3, 'automatic_retry': False}
            S.dump(out / 'LAUNCH.json', launch)
            row = {'stage': stage, 'status': 'STARTED', 'command': command}
            result['stages'].append(row)
            result['not_started'].remove(stage)
            result['generation_owner_launches'] += 1
            owner = run_owned(command, cwd=S.SOURCE, env=S.PLAN['environment'],
                supervisor_env=S.PLAN['environment'], stdout_path=out / 'stdout.bin',
                stderr_path=out / 'stderr.bin', receipt_path=out / 'OWNER.json',
                qualification_seconds=180, cleanup_seconds=3)
            S.dump(out / 'OWNER-RETURNED.json', owner)
            row.update(status='FAIL', owner=owner)
            S.owner_record(out / 'OWNER.json', owner)
            S.complete_owner(owner)
            actual = json.loads(S.read(out / 'RESULT.json')[0])
            row['result'] = S.identity(out / 'RESULT.json')
            S.require(actual['status'] == 'PASS_ORIGINAL_R9_GENERATOR_STAGE'
                and actual['generator_main_attempted'] == 1 and actual['finalization_errors'] == []
                and actual['frozen_source_runtime_equal'] is True, 'original generator stage failed')
            row['status'] = 'PASS'
            S.dump(S.EXEC / ('PROGRESS-' + stage + '.json'), result)
        binding = S.generation_admission()
        S.dump(S.EXEC / 'GENERATED-BINDING.json', binding)
        from bind_size_context import bind
        bound = bind(binding)
        S.dump(S.EXEC / 'SIZE-CONTEXT.json', bound)
        row = {'stage': 'size-pack', 'status': 'STARTED', 'binding': bound}
        result['stages'].append(row)
        result['not_started'].remove('size-pack')
        result['size_driver_attempts'] = 1
        result['compile_calls_attempted'] = result['pack_calls_attempted'] = None
        code = original_size_driver(bound)
        row['driver_returncode'] = code
        raw, _, _ = S.read(S.EXEC / 'size-pack/OUTER.json')
        actual = json.loads(raw)
        row.update(status='FAIL', result=S.identity(S.EXEC / 'size-pack/OUTER.json'))
        result['compile_calls_attempted'] = actual['compile_calls_attempted']
        result['pack_calls_attempted'] = actual['pack_calls_attempted']
        S.require(code == 0 and actual['status'] == 'PASS_EXPLICIT_U32_SIZE_AND_PRIVATE_PACK_ONLY'
            and actual['finalization_errors'] == []
            and actual['compile_calls_attempted'] == actual['pack_calls_attempted'] == 1,
            'original size/conditional pack did not pass')
        S.complete_owner(actual['owner'])
        row['status'] = 'PASS'
        child = actual['actual_child_result']
        result.update(status='PASS_PRIVATE_R9_GENERATION_AND_SIZE_PACK_ONLY',
            actual_generated_source=binding['files']['source'], actual_image=child['image'],
            actual_ELF=child['ELF'], actual_size=child['size'],
            original_R8_output_basenames_retained_in_new_R9_scope=True)
    except BaseException as error:
        result.update(error_type=type(error).__name__, error=str(error), traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        if binding is not None:
            try:
                S.dump(S.EXEC / 'GENERATED-BINDING-AFTER.json', S.generation_binding_guard(binding))
            except BaseException as error:
                result['status'] = 'FAIL'
                result['finalization_errors'].append({'name': 'GENERATED-BINDING', 'type': type(error).__name__,
                    'error': str(error), 'traceback': traceback.format_exc()})
        for label, action in (('FULL-FRESH', lambda: S.snapshot(S.EXEC / 'FULL-FRESH-AFTER.json')),
                ('CONTROLS', S.controls_guard), ('RUNTIME', S.runtime_guard)):
            try:
                observed = action()
                if label == 'FULL-FRESH':
                    S.require(before is not None and observed == before, 'complete original fresh domain changed')
                else:
                    S.dump(S.EXEC / (label + '-AFTER.json'), observed)
                    if label == 'CONTROLS':
                        S.require(controls_before is not None and observed == controls_before, 'fixed author controls changed')
            except BaseException as error:
                result['status'] = 'FAIL'
                result['finalization_errors'].append({'name': label, 'type': type(error).__name__,
                    'error': str(error), 'traceback': traceback.format_exc()})
        result['elapsed_ns'] = time.monotonic_ns() - started
        S.dump(S.EXEC / 'RESULT.json', result)
        try:
            files = {}
            for path in sorted(S.EXEC.rglob('*')):
                st = path.lstat()
                if stat.S_ISREG(st.st_mode):
                    files[path.relative_to(S.EXEC).as_posix()] = S.identity(path)
                else:
                    S.require(stat.S_ISDIR(st.st_mode), 'nonordinary actual evidence path')
            S.dump(S.EXEC / 'RAW-INVENTORY.json', {'files': files, 'count': len(files),
                'logical_bytes': sum(row['identity']['bytes'] for row in files.values()),
                'excludes_this_inventory_itself': True, 'all_partial_and_failed_outputs_retained': True})
        except BaseException as error:
            S.dump(S.EXEC / 'RAW-INVENTORY-ERROR.json', {'type': type(error).__name__,
                'error': str(error), 'traceback': traceback.format_exc()})
            return 1
        print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result['status'] == 'PASS_PRIVATE_R9_GENERATION_AND_SIZE_PACK_ONLY' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan-sha256', required=True)
    parser.add_argument('--stage', choices=('generate', 'check'))
    args = parser.parse_args()
    unsigned = dict(S.PLAN)
    authorization = unsigned.pop('authorization_pin')
    S.require(args.plan_sha256 == authorization == S.pin(S.encode(unsigned))['sha256'],
        'exact reviewed prefix authorization hash differs')
    raise SystemExit(generation_child(args.stage) if args.stage else driver())
