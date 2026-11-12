"""Admit the completed R6 tree and observe retained budget failures unchanged."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sys
import traceback
import zipfile
import run_evaluation_development as original

SOURCE_TREE = '76f273c30134b34157b12113e4f0449498b08fe0'
IMAGE_SHA = '7d07a7271f15d547d3823c1fc7da3041f54756ae92529aa97a6fe7c369ab103d'
METHODS = {
    'expired': 'test_expired_evaluation_is_rejected_before_any_reference_or_native_runner',
    'timeout': 'test_native_timeout_is_incomplete_terminated_and_not_adoptable',
    'loop': 'test_reference_loop_cannot_restart_or_overrun_frozen_context_deadline',
}


def prepare(source, joint, output):
    if not original.prepare(source, joint, output):
        return False
    actual = original.read(output / 'AUTHORED-SOURCE.json')
    original.require(len(actual) == 3257 and original.tree_id(actual) == SOURCE_TREE,
                     'restored complete R6 generated input differs')
    original.write(output / 'GENERATED-SOURCE.json', actual)
    original.write(output / 'RESTORED-R6.json', {
        'status': 'EXACT_PRIOR_R6_SOURCE_RESTORED_NOT_QUALIFIED', 'source_files': 3257,
        'source_tree': SOURCE_TREE, 'prior_run': 43302988100,
        'prior_complete_raw_index': '2c8204d56acb3e807af298b69e2e3d1795623a45',
        'generators_reexecuted': 0, 'original_six_failures_preserved': True,
        'current_cold': False, 'whole_native': False})
    return True


def build(source, output):
    if not original.build(source, output):
        return False
    manifest = original.read(output / 'candidate/development-manifest.json')
    image = output / 'candidate' / manifest['image_path']
    original.require(manifest['image_sha256'] == IMAGE_SHA and original.sha(image.read_bytes()) == IMAGE_SHA,
                     'new development build differs from prior exact R6 image')
    return True


def case(source, output, name):
    original.current_source(source, output)
    environment = original.env()
    # The child admits the same installed clang-20 through _prerequisites.
    # Empty initial HEPTA environment is its unchanged explicit fixture rule.
    for key in tuple(environment):
        if key.startswith('HEPTA_'):
            del environment[key]
    receipt = original.command(source, output, 'profile-' + name,
        [sys.executable, '-I', '-B', str(original.INPUTS / 'run_profile_case.py'),
         '--source', str(source), '--compiler', str(output / 'retained-development-compiler.bin'),
         '--evaluation-manifest', str(output / 'candidate/development-manifest.json'),
         '--output', str(output / ('profile-' + name)), '--group', 'namespace', '--method', METHODS[name]],
        environment, seconds=1800)
    original.current_source(source, output)
    path = output / ('profile-' + name) / 'REPORT.json'
    report = original.read(path) if path.is_file() else None
    return (receipt['status'] == 'WORKFLOW_STEP_COMPLETED' and report is not None
            and report['status'] == 'OBSERVATION_COMPLETE' and report['tests_run'] == 1
            and report['source_unchanged'] and report['input_bytes_unchanged'])


def finish(source, output):
    report = {'schema': 'hia.evaluation.r6.phase-diagnostic-complete.v1', 'status': 'HOLD',
              'scope': 'INSTRUMENTED_DEVELOPMENT_DIAGNOSTIC_NOT_QUALIFICATION',
              'runtime': original.runtime(), 'original_test_limits_changed': False,
              'old_six_failures_reclassified': False, 'current_cold': False,
              'whole_native': False, 'default_changed': False}
    try:
        after = original.snapshot(source)
        original.write(output / 'SOURCE-AFTER.json', after)
        before = original.read(output / 'GENERATED-SOURCE.json')
        report.update(source_files=len(after), source_tree=original.tree_id(after), source_unchanged=before == after,
                      immutable_harness_inputs_unchanged=original.check_inputs() == original.read(output / 'HARNESS-INPUTS.json'),
                      retained_compiler_unchanged=original.sha((output / 'retained-development-compiler.bin').read_bytes()) == original.COMPILER_SHA)
        report['cases'] = {}
        for name in METHODS:
            path = output / ('profile-' + name) / 'REPORT.json'
            costs = output / ('profile-' + name) / 'COST-REPORT.json'
            report['cases'][name] = {'original_case': original.read(path) if path.is_file() else None,
                                      'costs': original.read(costs) if costs.is_file() else None}
        completed = all(item['original_case'] is not None and item['original_case']['status'] == 'OBSERVATION_COMPLETE'
                        and item['original_case']['tests_run'] == 1 and item['costs'] is not None
                        and item['costs']['observer_exit_error'] is None for item in report['cases'].values())
        report['all_original_outcomes'] = {name: item['original_case'].get('outcome') if item['original_case'] else 'NOT_EXECUTED'
                                           for name, item in report['cases'].items()}
        report['status'] = 'OBSERVATIONS_COMPLETE' if completed and report['source_unchanged'] and report['retained_compiler_unchanged'] else 'HOLD'
    except BaseException:
        report['traceback'] = traceback.format_exc()
    original.write(output / 'REPORT.json', report)
    manifest = {p.relative_to(output).as_posix(): dict(mode=oct(p.stat().st_mode & 0o7777), **original.identity(p.read_bytes()))
                for p in sorted(output.rglob('*')) if p.is_file()}
    original.write(output / 'EVIDENCE-MANIFEST.json', manifest)
    with zipfile.ZipFile(output / 'RAW-EVIDENCE.zip', 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for relative in list(manifest) + ['EVIDENCE-MANIFEST.json']:
            archive.write(output / relative, relative)
    print(json.dumps({'status': report['status'], 'outcomes': report.get('all_original_outcomes'),
                      'source_unchanged': report.get('source_unchanged')}), flush=True)
    return report['status'] == 'OBSERVATIONS_COMPLETE'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--stage', choices=('prepare', 'build', *METHODS, 'finish'), required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--joint', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source, joint, output = args.source.resolve(), args.joint.resolve(), args.output.resolve()
    os.environ['P1_JOINT_HARNESS'] = str(joint)
    original.runtime()
    ok = False
    error = None
    try:
        if args.stage == 'prepare':
            ok = prepare(source, joint, output)
        elif args.stage == 'build':
            ok = build(source, output)
        elif args.stage == 'finish':
            return 0 if finish(source, output) else 1
        else:
            ok = case(source, output, args.stage)
    except BaseException:
        error = traceback.format_exc()
        print(error, flush=True)
    if output.is_dir():
        original.write(output / ('STAGE-' + args.stage + '.json'), {
            'stage': args.stage, 'status': 'OBSERVATION_STAGE_COMPLETED' if ok else 'HOLD',
            'traceback': error, 'performance_qualification': False})
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
