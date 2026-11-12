"""Own one source-only generation step under the unchanged external guardian.

This file is a static draft. It performs no native compilation and does not
execute the original eight read_bounded callers or the new foreign controls.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import traceback

sys.path.insert(0, str(Path(__file__).absolute().parent))
from source_common import create, pin, read, require, wire
from workflow_process import run_workflow_step

CANDIDATE = '436398aca7297059eeaca45e5fd8af1e028bf0e6'
TREE = '8df3f6a460d757f522224a337630b8a8480cad59'
MANIFEST_SHA = '2e130e0a77516bbf1a5b0ffa772ed849b4e29d45102195c271c5713dac42484c'


def observed_inputs(expected):
    result = {}
    require(type(expected) is dict and expected, 'fixed input map absent')
    for name, wanted in expected.items():
        require(type(name) is str and Path(name).is_absolute(),
                'fixed input path is not absolute')
        raw, info = read(Path(name), max(1, wanted['bytes']),
                         system_binary=bool(wanted.get('system_binary', False)))
        require(info['bytes'] == wanted['bytes']
                and info['sha256'] == wanted['sha256'],
                'fixed driver input differs: ' + name)
        result[name] = info
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--context-sha256', required=True)
    args = parser.parse_args()
    raw_context, context_record = read(args.context, 256 << 10)
    require(sha256(raw_context).hexdigest() == args.context_sha256,
            'driver context bytes differ')
    context = json.loads(raw_context)
    root = Path(context['root'])
    require(args.context == root / 'context.json'
            and Path.cwd() == root
            and Path(__file__).absolute() == root / 'control' / 'driver.py',
            'driver root/cwd/script binding differs')
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
            'driver must be fresh -I -S -B')
    require(context['schema'] == 'hia.bounded-read-source-actions-context.v1'
            and context['candidate_commit'] == CANDIDATE
            and context['candidate_tree'] == TREE
            and context['candidate_members'] == 4025
            and context['controller_seconds'] == 180
            and context['cleanup_seconds'] == 3
            and context['source_step_seconds'] == 60
            and context['source_manifest_sha256'] == MANIFEST_SHA
            and context['native_execution_requested'] is False
            and context['product_tests_requested'] is False
            and context['cold_qualification_requested'] is False,
            'driver context scope differs')
    expected_command = [
        context['python']['resolved'], '-I', '-S', '-B',
        str(root / 'control' / 'source_worker.py'),
        '--source-root', context['source'],
        '--source-manifest', str(root / 'control' / 'source-manifest.json'),
        '--output-dir', str(root / 'generated'),
    ]
    require(context['source_command'] == expected_command,
            'source command must be the fixed source-only worker')
    allowed_environment = {
        'PATH': context['execution_PATH'],
        'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
        'PYTHONDONTWRITEBYTECODE': '1',
    }
    require(type(allowed_environment['PATH']) is str,
            'controlled tool PATH absent')
    report = {
        'schema': 'hia.bounded-read-source-actions-driver.v1',
        'status': 'HOLD', 'context_original': context_record,
        'candidate_commit': CANDIDATE, 'candidate_tree': TREE,
        'command': expected_command, 'source_step_seconds': 60,
        'outer_owner_seconds': 180, 'cleanup_seconds': 3,
        'native_compilation_executed': False,
        'native_execution_executed': False, 'product_tests_executed': False,
        'cold_qualified': False, 'whole_native_delivery_qualified': False,
        'original_product_deadlines_changed': False,
    }
    before = None
    try:
        before = observed_inputs(context['fixed_inputs'])
        report['inputs_before'] = before
        outcome = run_workflow_step(expected_command, cwd=root,
            env=allowed_environment,
            stdout_path=root / 'logs' / 'source.stdout.log',
            stderr_path=root / 'logs' / 'source.stderr.log',
            receipt_path=root / 'logs' / 'source.process.json',
            seconds=60)
        step_raw, step_info = read(root / 'logs' / 'source.process.json', 1 << 20)
        step = json.loads(step_raw)
        report['workflow_step'] = step_info
        require(step == outcome and step['schema'] == 'hepta.hia.external-workflow-process.v1'
                and step['command'] == expected_command and step['cwd'] == str(root)
                and step['workflow_seconds'] == 60
                and step['status'] == 'WORKFLOW_STEP_COMPLETED'
                and step['returncode'] == 0 and step['timed_out'] is False
                and step['cleanup']['complete'] is True
                and not step['cleanup']['signalled']
                and not step['cleanup']['errors'],
                'source step did not complete naturally')
        for leaf in ('source.stdout.log', 'source.stderr.log'):
            log_raw, log_info = read(root / 'logs' / leaf, 8 << 20)
            require(step['logs'][str(root / 'logs' / leaf)] == log_info['sha256'],
                    'step original log SHA differs')
            report.setdefault('source_logs', {})[leaf] = log_info
        worker_raw, worker_info = read(root / 'generated' / 'report.json', 4 << 20)
        worker = json.loads(worker_raw)
        report['worker_report'] = worker_info
        require(worker['schema'] == 'hepta.hia.bounded-read-source-authoring.v2'
                and worker['status'] == 'SOURCE_AUTHORING_PASS_NOT_NATIVE_QUALIFIED'
                and worker['canonical_candidate_commit'] == CANDIDATE
                and worker['canonical_candidate_tree'] == TREE
                and worker['complete_source_members'] == 4025
                and worker['baseline_members'] == 4023
                and worker['source_stable'] is True
                and worker['manifest_stable'] is True
                and worker['core_roundtrip'] is True
                and worker['deterministic_source'] is True
                and worker['measurements']['functions'] == 12
                and worker['syntax_checked'] == [
                    'hepta/hia_bounded_read_native.py',
                    'tools/generate_hia_bounded_read.py'],
                'actual worker source-only result differs')
        for name in ('native_compilation_executed', 'native_execution_executed',
                     'old_or_new_lifecycle_controls_executed',
                     'original_eight_test_methods_executed',
                     'formal_git_consumer_or_clone_qualification',
                     'cold_qualified', 'default_activation',
                     'whole_native_delivery_qualified'):
            require(worker[name] is False, 'worker scope promotion: ' + name)
        for name, filename in (
            ('source_before', 'source-before.json'),
            ('source_after', 'source-after.json'),
            ('core_document', 'bounded-read.hia.json'),
            ('assembly', 'bounded-read.hiaasm'),
        ):
            body, observed = read(root / 'generated' / filename, 16 << 20)
            require(worker[name] == observed,
                    'actual source output or identity differs: ' + filename)
            report.setdefault('outputs', {})[filename] = observed
        before_raw, _ = read(root / 'generated' / 'source-before.json', 16 << 20)
        after_raw, _ = read(root / 'generated' / 'source-after.json', 16 << 20)
        require(before_raw == after_raw, 'complete source original snapshots differ')
        report['status'] = 'SOURCE_DRIVER_PENDING_FINAL_INPUT_CHECK'
    except BaseException as error:
        report['status'] = 'HOLD'
        report['error'] = {'type': type(error).__name__,
                           'traceback': traceback.format_exc()}
    finally:
        try:
            after = observed_inputs(context['fixed_inputs'])
            report['inputs_after'] = after
            current_context, current_record = read(args.context, 256 << 10)
            report['inputs_stable'] = (
                before is not None and before == after
                and current_context == raw_context
                and current_record == context_record)
            require(report['inputs_stable'], 'driver inputs changed')
            if report['status'] == 'SOURCE_DRIVER_PENDING_FINAL_INPUT_CHECK':
                report['status'] = 'SOURCE_DRIVER_PASS_PENDING_OUTER_GUARDIAN'
        except BaseException as error:
            report['status'] = 'HOLD'
            report['final_check_error'] = {
                'type': type(error).__name__, 'traceback': traceback.format_exc()}
        create(root / 'driver-report.json', wire(report))
        print(json.dumps({'status': report['status'],
                          'scope': 'NEW_COMPONENT_SOURCE_AUTHORING_ONLY',
                          'worker_report': report.get('worker_report'),
                          'inputs_stable': report.get('inputs_stable'),
                          'error': report.get('error'),
                          'final_check_error': report.get('final_check_error')}),
              flush=True)
    return 0 if report['status'] == 'SOURCE_DRIVER_PASS_PENDING_OUTER_GUARDIAN' else 1


if __name__ == '__main__':
    raise SystemExit(main())
