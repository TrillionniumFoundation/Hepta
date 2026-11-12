"""Independent actual CPython 3.14.4 baseline observations and shared R4 gates.

The authentic product HEAD stays 4b19 throughout. Joint R2 and R4 are finite,
byte-bound overlays in this separate checkout. Baseline differences remain
observations of the original implementation, never relabelled qualifications.
"""
from __future__ import annotations

import argparse
import base64
import importlib
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import traceback
import zlib

import original_run_development as original
from workflow_process import run_workflow_step

INPUTS = Path(__file__).resolve().parent
HEAD, TREE = original.HEAD, original.TREE
COMPILER_SHA = original.COMPILER_SHA
BASELINE_TREE = 'a9a2b5ec40d176a7684a03ca2859190abd982db0'
FINAL_TREE = '3e67be1f7a92ce418c0625b13ef8e948f143b7c0'
BASELINE_WRAPPER_SHA = '60f22da0a04c781b92c870dc59251999db356efd5ca11c4a5168585ec7a32b0a'
FINAL_WRAPPER_SHA = '16d857875f16acf7624332310098de2b9a35b0f401b397b1bebfd02cee04d146'
LABELS = original.LABELS
STAGES = ('baseline', 'observe-baseline', 'prepare', 'panel60', 'complete124', 'plan44', 'finish')
sha, blob, describe, write = original.sha, original.blob, original.describe, original.write


def input_identity():
    paths = sorted(p for p in INPUTS.iterdir() if p.is_file())
    return {p.name: describe(p) for p in paths}


def check_frozen_inputs():
    expected = json.loads((INPUTS / 'FROZEN-INPUTS.json').read_bytes())
    actual = input_identity()
    actual.pop('FROZEN-INPUTS.json')
    reduced = {name: {'bytes': row['bytes'], 'sha256': row['sha256'],
                     'blob': row['git_blob_sha1']} for name, row in actual.items()}
    if reduced != expected:
        raise AssertionError('frozen harness inputs differ')
    if sha((INPUTS / 'workflow_process.py').read_bytes()) != original.SUPERVISOR_SHA:
        raise AssertionError('original process supervisor changed')
    if sha((INPUTS / 'original_run_development.py').read_bytes()) != 'fde3fb85f10423c5120d8b96084133b006f08dfded9f3243d0af1ae7a469171e':
        raise AssertionError('retained original harness helpers changed')
    return input_identity()


def decode_packet(name, expected_sha, expected_bytes):
    raw = (INPUTS / name).read_bytes()
    if len(raw) != expected_bytes or sha(raw) != expected_sha:
        raise AssertionError('frozen packet wrapper differs: ' + name)
    wrapper = json.loads(raw)
    compressed = base64.b64decode(wrapper['data'], validate=True)
    if len(compressed) != wrapper['compressed_bytes'] or sha(compressed) != wrapper['compressed_sha256']:
        raise AssertionError('packet compressed bytes differ: ' + name)
    plain = zlib.decompress(compressed)
    if len(plain) != wrapper['bytes'] or sha(plain) != wrapper['sha256']:
        raise AssertionError('packet raw bytes differ: ' + name)
    return json.loads(plain)


def reduced_snapshot(rows):
    return {name: {'bytes': row['bytes'], 'sha256': row['sha256'],
                   'blob': row['git_blob_sha1'], 'mode': row['git_mode']}
            for name, row in rows.items()}


def validate_record(data, record):
    return (type(record['bytes']) is int and len(data) == record['bytes']
            and sha(data) == record['sha256'] and blob(data) == record['blob']
            and record['mode'] in ('100644', '100755'))


def apply_packet(source, packet, before, expected_count, expected_tree):
    paths = set()
    before_records = reduced_snapshot(before)
    for row in packet['files']:
        name = row['path']
        if (type(name) is not str or name in paths or '\\' in name
                or name.startswith('/') or any(x in ('', '.', '..') for x in name.split('/'))):
            raise AssertionError('unsafe or duplicate overlay path')
        paths.add(name)
        target = source / name
        if row['before'] != before_records.get(name):
            raise AssertionError('overlay before identity differs: ' + name)
        if row['before'] is None:
            if target.exists():
                raise AssertionError('new overlay path already exists: ' + name)
        elif not validate_record(target.read_bytes(), row['before']):
            raise AssertionError('actual input bytes differ before overlay: ' + name)
        data = row['content'].encode('utf-8')
        if not validate_record(data, row):
            raise AssertionError('overlay content identity differs: ' + name)
    for row in packet['files']:
        target = source / row['path']
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(row['content'].encode('utf-8'))
        target.chmod(0o755 if row['mode'] == '100755' else 0o644)
    after = original.snapshot(source, set(before) | paths)
    after_records = reduced_snapshot(after)
    if (len(after) != expected_count or after_records != packet['final_files']
            or original.tree_id(after) != expected_tree
            or not original.source_matches(source, after)):
        raise AssertionError('complete finite overlay identity differs')
    changed = {name for name in after if after_records[name] != before_records.get(name)}
    if changed != paths:
        raise AssertionError('unexpected or redundant overlay paths')
    return after


def admit_actual_product(source):
    if (original.git(source, 'rev-parse', 'HEAD').decode().strip() != HEAD
            or original.git(source, 'rev-parse', 'HEAD^{tree}').decode().strip() != TREE
            or original.git(source, 'status', '--porcelain=v1', '--untracked-files=all')):
        raise AssertionError('authentic published product checkout differs')
    entries = {}
    for line in original.git(source, 'ls-tree', '-rz', '--full-tree', 'HEAD').split(b'\0'):
        if not line:
            continue
        metadata, path = line.split(b'\t', 1)
        mode, kind, identity = metadata.decode().split()
        if kind != 'blob' or mode not in ('100644', '100755'):
            raise AssertionError('unexpected authentic Git source member')
        entries[path.decode()] = (mode, identity)
    if len(entries) != 3153:
        raise AssertionError('original 3153-file inventory differs')
    before = original.snapshot(source, entries)
    if any((before[name]['git_mode'], before[name]['git_blob_sha1']) != row
           for name, row in entries.items()) or original.tree_id(before) != TREE:
        raise AssertionError('authentic checkout bytes, modes or complete tree differ')
    return before


def admit_compiler(out):
    wrapper = json.loads((INPUTS / 'retained-compiler.json').read_bytes())
    compressed = base64.b64decode(wrapper['data'], validate=True)
    if len(compressed) != wrapper['compressed_bytes'] or sha(compressed) != wrapper['compressed_sha256']:
        raise AssertionError('retained compiler compressed identity differs')
    raw = zlib.decompress(compressed)
    if len(raw) != 669494 or sha(raw) != COMPILER_SHA or wrapper['sha256'] != COMPILER_SHA:
        raise AssertionError('retained original compiler bytes differ')
    target = out / 'retained-development-compiler.bin'
    target.write_bytes(raw)
    target.chmod(0o444)
    return target


def configure_source(source):
    env, removed = original.clean_environment()
    os.environ.clear()
    os.environ.update(env)
    os.chdir(source)
    sys.path.insert(0, str(source))
    return removed


def compile_images(source, out, destination, labels):
    from tools.qualify_hia_selfhost import compile_stage
    destination.mkdir(mode=0o700)
    compiler = out / 'retained-development-compiler.bin'
    held = compiler.read_bytes()
    compiled = []
    for label in labels:
        module = importlib.import_module('hepta.hia_' + label + '_native')
        source_path = source / ('examples/hia_bootstrap/' + label + '.hiaasm')
        if module.SOURCE.resolve() != source_path:
            raise AssertionError('source resource does not resolve to admitted checkout')
        raw = source_path.read_bytes()
        folder = destination / label
        folder.mkdir(mode=0o700)
        image, receipt = compile_stage(folder, label, compiler, raw)
        manifest = {'schema': module.SCHEMA, 'source_sha256': sha(raw),
                    'image_path': image.name, 'image_sha256': sha(image.read_bytes()),
                    'compiler_sha256': COMPILER_SHA}
        write(folder / 'manifest.json', manifest)
        if source_path.read_bytes() != raw or compiler.read_bytes() != held:
            raise AssertionError('actual compile inputs changed')
        compiled.append({'label': label, 'manifest': manifest, 'receipt': receipt})
        print('ACTUAL_DEVELOPMENT_COMPILE', destination.name, label, manifest['image_sha256'], flush=True)
    return compiled


def stage_report(out, name, body):
    report = {'scope': 'INDEPENDENT_CPYTHON3144_SHARED_R4_DEVELOPMENT',
              'current_cold': False, 'whole_native': False, 'status': 'FAIL_OR_INCOMPLETE'}
    try:
        body(report)
    except BaseException:
        report['exception'] = traceback.format_exc()
    finally:
        write(out / (name + '.json'), report)
        print(json.dumps({'stage': name, 'status': report['status']}, sort_keys=True), flush=True)
    return 0 if report['status'] in ('BASELINE_READY_NOT_QUALIFICATION', 'ORIGINAL_OBSERVATIONS_COMPLETE',
                                     'DEVELOPMENT_INPUTS_READY_NOT_COLD') else 1


def prepare_baseline(source, out):
    out.mkdir(mode=0o700)
    def body(report):
        if (sys.implementation.name != 'cpython' or sys.version_info[:3] != (3, 14, 4)
                or sys.platform != 'linux' or platform.machine() != 'x86_64'):
            raise AssertionError('actual CPython 3.14.4 Linux x86-64 is required')
        write(out / 'HARNESS-BEFORE.json', check_frozen_inputs())
        before = admit_actual_product(source)
        write(out / 'AUTHENTIC-SOURCE.json', before)
        packet = decode_packet('baseline-joint-r2.json', BASELINE_WRAPPER_SHA, 1122923)
        if (packet['base_commit'] != HEAD or packet['base_tree'] != TREE
                or len(packet['files']) != 51):
            raise AssertionError('exact original joint R2 packet identity differs')
        baseline = apply_packet(source, packet, before, 3181, BASELINE_TREE)
        write(out / 'BASELINE-SOURCE.json', baseline)
        write(out / 'TOOLS-BEFORE.json', original.tool_inputs())
        admit_compiler(out)
        report['removed_environment'] = configure_source(source)
        report['compiled'] = compile_images(source, out, out / 'baseline-images', ('core_lowering',))
        if not original.source_matches(source, baseline):
            raise AssertionError('original baseline source changed during compilation')
        report.update(status='BASELINE_READY_NOT_QUALIFICATION', source_files=3181,
                      candidate_tree=BASELINE_TREE, authentic_head=HEAD,
                      baseline_equivalence_not_asserted=True)
    return stage_report(out, 'BASELINE-PREPARE', body)


def observe_baseline(source, out):
    def body(report):
        if json.loads((out / 'BASELINE-PREPARE.json').read_bytes())['status'] != 'BASELINE_READY_NOT_QUALIFICATION':
            raise AssertionError('baseline preparation incomplete')
        baseline = json.loads((out / 'BASELINE-SOURCE.json').read_bytes())
        if not original.source_matches(source, baseline):
            raise AssertionError('original baseline source changed')
        check_frozen_inputs()
        folder = out / 'baseline-observations'
        folder.mkdir(mode=0o700)
        env, removed = original.clean_environment()
        commands = {
          'core-label': [sys.executable, '-B', str(INPUTS / 'probe_original_core_call.py'), str(source),
                         str(out / 'baseline-images/core_lowering/manifest.json'), str(folder / 'core-label')],
          'mechanism120': [sys.executable, '-B', str(INPUTS / 'probe_shared_mechanism.py'),
                           '--source', str(source), '--compiler', str(out / 'retained-development-compiler.bin'),
                           '--output', str(folder / 'mechanism120')],
        }
        results = {}
        for name, command in commands.items():
            process = run_workflow_step(command, cwd=source, env=env,
                       stdout_path=folder / (name + '.stdout.log'), stderr_path=folder / (name + '.stderr.log'),
                       receipt_path=folder / (name + '.PROCESS.json'), seconds=1800)
            path = folder / name / 'REPORT.json'
            actual = json.loads(path.read_bytes()) if path.exists() else {}
            results[name] = {'process': process, 'report': describe(path) if path.exists() else None,
                             'original_status': actual.get('status'),
                             'matched': actual.get('matches', actual.get('matched')),
                             'count': actual.get('count', actual.get('total')),
                             'native_entries': actual.get('native_entries', actual.get('entries'))}
        write(folder / 'SOURCE-AFTER.json', original.snapshot(source, baseline))
        valid = (original.source_matches(source, baseline)
                 and results['core-label']['count'] == 4 and results['mechanism120']['count'] == 120
                 and results['core-label']['original_status'] in ('PASS', 'DIFFERENCE_OBSERVED')
                 and results['mechanism120']['original_status'] in ('PASS', 'ORIGINAL_EQUIVALENCE_FAIL')
                 and all(r['process']['status'] == 'WORKFLOW_STEP_COMPLETED'
                         and r['native_entries'] > 0 for r in results.values()))
        report.update(results=results, removed_environment=removed,
                      original_source_unchanged=original.source_matches(source, baseline),
                      equivalence_failures_preserved_not_qualification=True)
        if not valid:
            raise AssertionError('original observation did not complete faithfully')
        report['status'] = 'ORIGINAL_OBSERVATIONS_COMPLETE'
    return stage_report(out, 'BASELINE-OBSERVATIONS', body)


def development_inputs(out):
    paths = [out / 'retained-development-compiler.bin', out / 'composition-manifests-r1.json',
             out / 'run_panel60.py']
    for label in LABELS:
        path = out / 'development-r1' / label / 'manifest.json'
        manifest = json.loads(path.read_bytes())
        paths.extend((path, path.parent / manifest['image_path']))
    return [describe(path) for path in paths]


def prepare_fixed(source, out):
    def body(report):
        if json.loads((out / 'BASELINE-PREPARE.json').read_bytes())['status'] != 'BASELINE_READY_NOT_QUALIFICATION':
            raise AssertionError('baseline source was not admitted')
        baseline = json.loads((out / 'BASELINE-SOURCE.json').read_bytes())
        if not original.source_matches(source, baseline):
            raise AssertionError('baseline source changed before finite R4 transition')
        check_frozen_inputs()
        write(out / 'BASELINE-FINAL-SOURCE.json', original.snapshot(source, baseline))
        packet = decode_packet('final-r4.json', FINAL_WRAPPER_SHA, 750700)
        if (packet['origin_base_commit'] != HEAD or packet['origin_base_tree'] != TREE
                or packet['input_tree'] != BASELINE_TREE or len(packet['files']) != 13):
            raise AssertionError('frozen R4 finite delta identity differs')
        after = apply_packet(source, packet, baseline, 3184, FINAL_TREE)
        write(out / 'CANDIDATE-SOURCE.json', after)
        report['removed_environment'] = configure_source(source)
        report['compiled'] = compile_images(source, out, out / 'development-r1', LABELS)
        shutil.copyfile(INPUTS / 'run_panel60.py', out / 'run_panel60.py')
        write(out / 'composition-manifests-r1.json',
              {name: str(out / 'development-r1' / name / 'manifest.json') for name in LABELS[:-1]})
        write(out / 'DEVELOPMENT-INPUTS.json', development_inputs(out))
        if not original.source_matches(source, after):
            raise AssertionError('R4 source changed during actual compilation')
        report.update(status='DEVELOPMENT_INPUTS_READY_NOT_COLD', source_files=3184,
                      candidate_tree=FINAL_TREE, authentic_head=HEAD)
    return stage_report(out, 'PREPARE', body)


def run_stage(source, out, stage):
    if json.loads((out / 'PREPARE.json').read_bytes())['status'] != 'DEVELOPMENT_INPUTS_READY_NOT_COLD':
        raise AssertionError('R4 development preparation incomplete')
    expected = json.loads((out / 'CANDIDATE-SOURCE.json').read_bytes())
    held = json.loads((out / 'DEVELOPMENT-INPUTS.json').read_bytes())
    if not original.source_matches(source, expected) or development_inputs(out) != held:
        raise AssertionError('frozen source or actual executable input changed before stage')
    check_frozen_inputs()
    folder = out / stage
    folder.mkdir(mode=0o700)
    env, removed = original.clean_environment()
    if stage == 'panel60':
        command = [sys.executable, '-B', str(out / 'run_panel60.py'), str(source)]
    elif stage == 'complete124':
        command = [sys.executable, '-B', 'tools/qualify_hia_core_lowering_callers.py',
                   '--development-manifest', str(out / 'development-r1/core_lowering/manifest.json'),
                   '--composition-manifests', str(out / 'composition-manifests-r1.json'),
                   '--evidence', str(folder / 'evidence')]
    elif stage == 'plan44':
        command = [sys.executable, '-B', 'tools/qualify_hia_machine_plan_native_callers.py',
                   '--manifest', str(out / 'development-r1/machine_plan/manifest.json'),
                   '--development', '--output', str(folder / 'REPORT.json'),
                   '--evidence-dir', str(folder / 'evidence')]
    else:
        raise AssertionError('unknown fixed-source gate')
    write(folder / 'INTENT.json', {'command': command, 'cwd': str(source), 'outer_seconds': 1800,
          'removed_environment': removed, 'original_inner_limits_unchanged': True, 'current_cold': False})
    process = run_workflow_step(command, cwd=source, env=env,
              stdout_path=folder / 'stdout.log', stderr_path=folder / 'stderr.log',
              receipt_path=folder / 'PROCESS.json', seconds=1800)
    unchanged = original.source_matches(source, expected)
    inputs_unchanged = development_inputs(out) == held
    write(folder / 'SOURCE-CUSTODY.json', {'all_source_files': len(expected),
          'all_source_bytes_and_modes_unchanged': unchanged,
          'all_actual_development_inputs_unchanged': inputs_unchanged})
    print(json.dumps({'stage': stage, 'process': process, 'source_unchanged': unchanged,
                      'development_inputs_unchanged': inputs_unchanged}, sort_keys=True), flush=True)
    return 0 if unchanged and inputs_unchanged and process['status'] == 'WORKFLOW_STEP_COMPLETED' else 1


def finish(source, out):
    out.mkdir(mode=0o700, exist_ok=True)
    report = {'scope': 'INDEPENDENT_CPYTHON3144_SHARED_R4_DEVELOPMENT', 'status': 'FAIL_OR_INCOMPLETE',
              'current_cold': False, 'whole_native': False, 'default_changed': False,
              'legacy_deleted': False, 'stages': {}, 'actual_reports': {}}
    try:
        expected = json.loads((out / 'CANDIDATE-SOURCE.json').read_bytes())
        write(out / 'SOURCE-AFTER.json', original.snapshot(source, expected))
        report['source_unchanged'] = original.source_matches(source, expected)
        inputs = development_inputs(out)
        write(out / 'DEVELOPMENT-INPUTS-AFTER.json', inputs)
        report['actual_inputs_unchanged'] = inputs == json.loads((out / 'DEVELOPMENT-INPUTS.json').read_bytes())
        tools = original.tool_inputs()
        write(out / 'TOOLS-AFTER.json', tools)
        report['tools_unchanged'] = tools == json.loads((out / 'TOOLS-BEFORE.json').read_bytes())
        harness = check_frozen_inputs()
        write(out / 'HARNESS-AFTER.json', harness)
        report['harness_unchanged'] = harness == json.loads((out / 'HARNESS-BEFORE.json').read_bytes())
        report['authentic_checkout_head'] = original.git(source, 'rev-parse', 'HEAD').decode().strip()
        report['candidate_content_tree'] = original.tree_id(expected)
        baseline = json.loads((out / 'BASELINE-OBSERVATIONS.json').read_bytes())
        report['original_baseline_observations'] = baseline
        for name in ('panel60', 'complete124', 'plan44'):
            path = out / name / 'PROCESS.json'
            report['stages'][name] = json.loads(path.read_bytes()) if path.exists() else {'status': 'NOT_COMPLETED'}
        for name, relative, expected_tests in (
          ('panel60', 'component-checker-r4/REPORT.json', 60),
          ('complete124', 'complete124/evidence/REPORT.json', 124),
          ('plan44', 'plan44/REPORT.json', 44)):
            path = out / relative
            actual = json.loads(path.read_bytes()) if path.exists() else {}
            count = actual.get('tests_run')
            if name == 'complete124' and actual:
                groups = actual['groups']
                if ([g['tests_run'] for g in groups] != [23, 51, 50]
                        or any(not g['strict_pass'] or g['loaded_ids'] != g['executed_ids']
                               or len(set(g['loaded_ids'])) != g['tests_run'] for g in groups)
                        or actual['retained_owner_entries']
                        or not actual['retained_callers_explicitly_select_all_six_owners']):
                    raise AssertionError('all original 23/51/50 caller denominators must execute without fallback')
                count = sum(g['tests_run'] for g in groups)
            report['actual_reports'][name] = {'identity': describe(path) if path.exists() else None,
                     'status': actual.get('status'), 'expected_tests': expected_tests,
                     'actual_tests': count}
            if actual.get('status') != 'PASS' or count != expected_tests:
                raise AssertionError('complete original gate did not pass: ' + name)
        passed = (report['source_unchanged'] and report['actual_inputs_unchanged'] and report['tools_unchanged']
                  and report['harness_unchanged'] and report['authentic_checkout_head'] == HEAD
                  and report['candidate_content_tree'] == FINAL_TREE
                  and baseline['status'] == 'ORIGINAL_OBSERVATIONS_COMPLETE'
                  and all(row['status'] == 'WORKFLOW_STEP_COMPLETED' for row in report['stages'].values()))
        report['status'] = 'ALL_DECLARED_DEVELOPMENT_GATES_PASS' if passed else 'FAIL_OR_INCOMPLETE'
    except BaseException:
        report['exception'] = traceback.format_exc()
    finally:
        report['workflow_steps'] = json.loads(os.environ.get('HIA_STEP_OUTCOMES', '{}'))
        write(out / 'RESULT.json', report)
        members = []
        for path in sorted(out.rglob('*')):
            if path.is_file():
                row = describe(path)
                row['path'] = path.relative_to(out).as_posix()
                members.append(row)
        write(out / 'EVIDENCE-MANIFEST.json', {'files': members, 'complete_raw_preserved': True,
              'self_excluded': True, 'authentic_base': HEAD, 'authentic_tree': TREE,
              'current_cold': False, 'baseline_equivalence_failures_not_relabelled': True})
        print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if report['status'] == 'ALL_DECLARED_DEVELOPMENT_GATES_PASS' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--stage', choices=STAGES, required=True)
    args = parser.parse_args()
    source, out = args.source.resolve(strict=True), args.out.resolve()
    if args.stage == 'baseline':
        return prepare_baseline(source, out)
    if args.stage == 'observe-baseline':
        return observe_baseline(source, out)
    if args.stage == 'prepare':
        return prepare_fixed(source, out)
    if args.stage == 'finish':
        return finish(source, out)
    return run_stage(source, out, args.stage)


if __name__ == '__main__':
    raise SystemExit(main())
