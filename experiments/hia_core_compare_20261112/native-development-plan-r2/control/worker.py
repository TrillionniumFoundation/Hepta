"""One original compiler invocation and one finite native child, under 180/3.

This is isolated development with a reused, explicitly pinned B3. It neither
claims matching-source cold qualification nor calls any original Core caller.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback

CONTROL = Path(__file__).resolve().parent
ROOT = CONTROL.parent
sys.path.insert(0, str(CONTROL))
from common import create, frozen, pin, read_file, require, save, physical_files
from trace import audit_trace


def main():
    started = time.monotonic()
    request_raw, _ = read_file(Path(sys.argv[1]), 262144)
    require(sha256(request_raw).hexdigest() == sys.argv[2], 'worker request identity differs')
    request = json.loads(request_raw)
    policy_raw, _ = read_file(ROOT / request['policy_path'], 262144)
    require(sha256(policy_raw).hexdigest() == request['policy_sha256'], 'worker policy differs')
    policy = json.loads(policy_raw)
    output = Path(request['operation_root'])
    report = {'schema': 'hepta.hia.core-compare-finite-development.v1', 'status': 'HOLD',
              'scope': 'REUSED_B3_FINITE_LOCAL_NATIVE_DEVELOPMENT_ONLY',
              'source_evidence_commit': policy['source_evidence_commit'],
              'source_before_after_preserved': False, 'expected_ids': policy['expected_ids'],
              'compile_attempts': 0, 'native_child_attempts': 0,
              'original18_executed': False, 'original116_executed': False,
              'native_Core39_executed': False, 'installed_wheel_executed': False,
              'matching_source_cold': False, 'default_activated': False,
              'CPython_object_runtime_closed': False, 'runtime': sys.version}
    before = frozen(ROOT, policy)
    save(output / 'inputs-before.json', before)
    stage = output / 'stage'
    try:
        require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
                'worker is not the frozen isolated runtime')
        require(list(sys.version_info[:3]) == policy['python_version'], 'worker runtime version differs')
        stage.mkdir(mode=0o700)
        stage_paths = []
        for relative in policy['stage_files']:
            source = ROOT / 'product' / relative
            raw, _ = read_file(source, 1 << 20)
            target = stage / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            create(target, raw)
            stage_paths.append(target)
        save(output / 'stage-before.json', [pin(path) for path in stage_paths])
        build = output / 'build'
        build.mkdir(mode=0o700)
        sys.path.insert(0, str(ROOT / 'compiler-source'))
        from tools import qualify_hia_selfhost as compiler
        require(compiler.CAPACITY == 1 << 20
                and compiler.NATIVE_OBSERVER is None and compiler.NATIVE_LINKED_OBSERVER is None,
                'original compilation path or capacities differ')
        require(Path(compiler.__file__).resolve() == ROOT / 'compiler-source/tools/qualify_hia_selfhost.py'
                and compiler.CHILD == ROOT / 'compiler-source/tools/hia_selfhost_child.py',
                'compiler helper is not the exact copied original')
        source_raw, _ = read_file(stage / 'examples/hia_bootstrap/core_compare.hiaasm', 1 << 20)
        require(sha256(source_raw).hexdigest() == policy['numeric_source_sha256'], 'numeric HIA bytes differ')
        report['compile_attempts'] += 1
        image_path, receipt = compiler.compile_stage(build, 'core-compare',
            Path(policy['compiler']['path']), source_raw)
        image_raw, image_pin = read_file(image_path, 1 << 20)
        full_output, _ = read_file(build / 'core-compare.output.bin', 1 << 20)
        receipt_raw, receipt_pin = read_file(build / 'core-compare.receipt.json', 65536)
        compile_request_raw, compile_request_pin = read_file(build / 'core-compare.request.json', 65536)
        compile_request = json.loads(compile_request_raw)
        stdout_raw, _ = read_file(build / 'core-compare.stdout.log', 65536)
        child_receipt = json.loads(stdout_raw)
        require(receipt == json.loads(receipt_raw), 'compile receipt object differs from original bytes')
        require(all(receipt.get(key) == value for key, value in child_receipt.items()),
                'original compiler child stdout does not project into the receipt')
        require(receipt['status'] == 'returned' and receipt['abi_status'] == 0
                and receipt['source_unchanged'] is True and receipt['forbidden_compiler_modules_loaded'] == []
                and receipt['artifact_sha256'] == policy['compiler']['sha256']
                and receipt['image_sha256'] == policy['compiler']['sha256']
                and receipt['source_sha256'] == receipt['input_sha256'] == policy['numeric_source_sha256']
                and receipt['produced_sha256'] == image_pin['sha256']
                and receipt['core_u32'] == receipt['produced_bytes'] == len(image_raw)
                and len(full_output) == 1 << 20 and full_output[:len(image_raw)] == image_raw
                and sha256(full_output).hexdigest() == receipt['output_sha256'],
                'actual compiled image or complete compiler output differs')
        require(receipt['limits'] == {'cpu_seconds': 10, 'address_bytes': 256 << 20,
                    'core_dumpable': False, 'stack_bytes': 8 << 20,
                    'output_capacity': 1 << 20, 'workspace_bytes': 1 << 20},
                'original compiler child limits changed')
        require(compile_request['capacity'] == compile_request['workspace_size'] == 1 << 20
                and compile_request['workspace_fill'] == 0 and compile_request['format'] == 'flat-x86-64'
                and compile_request['image'] == policy['compiler']['path']
                and compile_request['image_sha256'] == policy['compiler']['sha256']
                and compile_request['source_sha256'] == policy['numeric_source_sha256'],
                'original compiler request differs')
        compile_files = [pin(build / ('core-compare.' + suffix)) for suffix in (
            'input.bin', 'output.bin', 'request.json', 'stdout.log', 'stderr.log', 'receipt.json', 'image.bin')]
        require(compile_files[0]['sha256'] == policy['numeric_source_sha256']
                and compile_files[4]['size'] == 0, 'compiler input or stderr differs')
        report['compilation'] = {'receipt': receipt, 'files': compile_files,
                                 'original_wall_seconds': 20, 'original_cpu_seconds': 10}
        manifest = {'schema': 'hepta.hia.core-compare-native.v1',
                    'source_sha256': policy['numeric_source_sha256'],
                    'abi_sha256': pin(stage / 'hepta/hia_core_compare_abi.json')['sha256'],
                    'bridge_sha256': pin(stage / 'hepta/hia_core_compare_native.py')['sha256'],
                    'selection_sha256': pin(stage / 'hepta/hia_core_compare_selection.py')['sha256'],
                    'image_path': image_path.name, 'image_sha256': image_pin['sha256'],
                    'compiler_sha256': policy['compiler']['sha256']}
        manifest_path = build / 'manifest.json'
        save(manifest_path, manifest)
        actual_paths = stage_paths + [image_path, manifest_path]
        actual_paths += [ROOT / name for name in policy['native_child_control_paths']]
        actual_paths += [Path(policy['compiler']['path']), Path(policy['python']['path'])]
        actual_paths = sorted(set(actual_paths), key=str)
        child_request = {'schema': 'hepta.hia.numeric-native-finite-child.v1',
            'evidence': str(output / 'native'), 'stage': str(stage), 'manifest': str(manifest_path),
            'vm_reference': str(ROOT / 'reference/actual-VM-cases.json'),
            'vm_reference_size': (ROOT / 'reference/actual-VM-cases.json').stat().st_size,
            'retained_primitive': str(ROOT / 'reference/retained-lowering.py.txt'),
            'expected_ids': policy['expected_ids'], 'python_version': policy['python_version'],
            'image_sha256': image_pin['sha256'], 'compiler_sha256': policy['compiler']['sha256'],
            'input_pins': [pin(path) for path in actual_paths]}
        child_request_path = output / 'native-request.json'
        save(child_request_path, child_request)
        command = [policy['python']['path'], '-I', '-S', '-B', str(CONTROL / 'native_cases.py'),
                   str(child_request_path)]
        save(output / 'native-intent.json', {'command': command, 'cwd': str(output),
             'owner_budget_includes_compilation_and_all_cases': [180, 3],
             'separate_wall_extension': False, 'compile_attempts': 1, 'native_child_attempts': 1,
             'native_child_rlimits': {'cpu_seconds': 180, 'address_bytes': 256 << 20,
                 'stack_bytes': 8 << 20, 'file_bytes': 16 << 20, 'file_descriptors': 32},
             'same_actual_image_sha256': image_pin['sha256']})
        child_started = time.monotonic()
        report['native_child_attempts'] += 1
        with (output / 'native.stdout.log').open('xb') as stdout, (output / 'native.stderr.log').open('xb') as stderr:
            process = subprocess.run(command, cwd=output, stdin=subprocess.DEVNULL,
                                     stdout=stdout, stderr=stderr, close_fds=True)
        save(output / 'native-execution.json', {'command': command, 'returncode': process.returncode,
             'seconds': time.monotonic() - child_started, 'stdout': pin(output / 'native.stdout.log'),
             'stderr': pin(output / 'native.stderr.log')})
        require(process.returncode == 0, 'finite native child did not return successfully')
        result_raw, result_pin = read_file(output / 'native/report.json', 1 << 20)
        result = json.loads(result_raw)
        require(result['status'] == 'FINITE_NATIVE_CASES_PASS'
                and result['expected_ids'] == result['loaded_ids'] == result['executed_ids'] == policy['expected_ids']
                and result['tests_run'] == 8 and result['source_preserved'] is True
                and result['native_image_sha256'] == image_pin['sha256']
                and result['compiler_sha256'] == policy['compiler']['sha256']
                and result['request_sha256'] == sha256(child_request_path.read_bytes()).hexdigest()
                and result['native_buffer_sizes'] == [256, 128, 512]
                and result['native_window_limbs'] == 32
                and not any(result.get(name) for name in ('error', 'preservation_error', 'errors', 'failures',
                    'skipped', 'expectedFailures', 'unexpectedSuccesses', 'loader_errors',
                    'forbidden_imports', 'subprocess_attempts')), 'finite native result is incomplete')
        numeric_raw, numeric_pin = read_file(output / 'native/NUMERIC-CASES.json', 1 << 20)
        numeric = json.loads(numeric_raw)
        require(numeric['actual_pair_count'] == len(numeric['cases']) == 173
                and numeric['matched_VM_pair_count'] == 172
                and numeric['actual_image_sha256'] == image_pin['sha256'], 'actual numeric pair count differs')
        audit = audit_trace(output / 'native/trace', image_pin['sha256'], policy['numeric_source_sha256'],
                            ROOT / 'reference/actual-VM-cases.json')
        require(audit['entry_count'] == policy['expected_trace_counts']['entries']
                and audit['actual_window_requests'] == policy['expected_trace_counts']['window_requests']
                and audit['status_counts'] == policy['expected_trace_counts']['statuses']
                and audit['case_count'] == policy['expected_trace_counts']['trace_cases'],
                'actual complete trace counts differ from the frozen finite protocol population')
        save(output / 'FULL-TRACE-AUDIT.json', audit)
        after_build = [pin(Path(item['path'])) for item in compile_files]
        require(after_build == compile_files, 'complete original compiler artifacts changed during native cases')
        report.update(native_report=result_pin, numeric_cases=numeric_pin, actual_trace=audit,
                      actual_image_sha256=image_pin['sha256'], actual_native_test_count=8,
                      original_VM_matrix_pairs=172, complete_large_pair_count=1)
        report['status'] = 'FINITE_NATIVE_DEVELOPMENT_PASS'
    except BaseException:
        report['status'] = 'HOLD'
        report['error'] = traceback.format_exc()
    finally:
        try:
            after = frozen(ROOT, policy)
            save(output / 'inputs-after.json', after)
            report['source_before_after_preserved'] = before == after
            if before != after:
                report['status'] = 'HOLD'
            if stage.exists():
                actual_stage, actual_directories = physical_files(stage)
                expected_directories = sorted({parent.as_posix() for name in policy['stage_files']
                    for parent in Path(name).parents if parent != Path('.')})
                require(actual_stage == sorted(policy['stage_files']) and actual_directories == expected_directories,
                        'minimal source fixture physical membership changed')
                stage_after = [pin(stage / name) for name in policy['stage_files']]
                save(output / 'stage-after.json', stage_after)
                stage_before_raw, _ = read_file(output / 'stage-before.json', 65536)
                require(stage_after == json.loads(stage_before_raw), 'minimal source fixture changed')
        except BaseException:
            report['status'] = 'HOLD'
            report['preservation_error'] = traceback.format_exc()
        report['seconds'] = time.monotonic() - started
        save(output / 'worker-report.json', report)
    print(json.dumps({'status': report['status'], 'compile_attempts': report['compile_attempts'],
                      'native_child_attempts': report['native_child_attempts'], 'seconds': report['seconds']}))
    return 0 if report['status'] == 'FINITE_NATIVE_DEVELOPMENT_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
