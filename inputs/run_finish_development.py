"""New explicit finish R5 controls in two separately admitted source scopes.

The product Git HEAD remains authentic 4b. Core/Plan uses its original R4
overlay; Byte uses its own original CoreR3+Byte18 overlay. Only the three
reviewed finish function bodies change. No claim of a qualified union,
current-source cold, defaults, deletion or whole-native completion is made.
"""
from __future__ import annotations
import argparse
import ast
import base64
import importlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import traceback
import zlib

import original_run_development as original
import core_r4_driver as core
import byte_r4_driver as byte
from workflow_process import run_workflow_step

INPUTS = Path(__file__).resolve().parent
HEAD, TREE = original.HEAD, original.TREE
sha, blob, describe, write = original.sha, original.blob, original.describe, original.write
CORE_GATES = ('panel60', 'complete124', 'plan44')
BYTE_GATES = ('byte-generated', 'byte25', 'byte4', 'byte29')
ORIGINAL_TREES = {'core': '3e67be1f7a92ce418c0625b13ef8e948f143b7c0', 'byte': 'd1ff194d49229056c9722d39bff2a1acd6b4657b'}
FIXED_TREES = {'core': '1fe9c231a9c394264a5231a81e8648279ed18688', 'byte': '291a2cc8351257c56d6ca75ccd282242ef0985fe'}
STAGES = ('prepare', 'build-original', 'observe-original', 'apply-fix',
          'build-fixed', 'observe-fixed') + CORE_GATES + BYTE_GATES + ('finish',)


def read(path):
    return json.loads(Path(path).read_bytes())


def check_inputs():
    expected = read(INPUTS / 'FROZEN-INPUTS.json')
    actual = {}
    for path in sorted(INPUTS.iterdir()):
        if path.is_file() and path.name != 'FROZEN-INPUTS.json':
            raw = path.read_bytes()
            actual[path.name] = {'bytes': len(raw), 'sha256': sha(raw), 'blob': blob(raw)}
    if actual != expected:
        raise AssertionError('complete immutable harness input set/bytes differ')
    if sha((INPUTS / 'workflow_process.py').read_bytes()) != original.SUPERVISOR_SHA:
        raise AssertionError('original process supervisor differs')
    return actual


def runtime():
    if (sys.implementation.name != 'cpython' or sys.version_info[:3] != (3, 14, 4)
            or sys.platform != 'linux' or platform.machine() != 'x86_64'):
        raise AssertionError('actual CPython3.14.4 Linux x86-64 is required')
    versions = {name: importlib.metadata.version(name)
                for name in ('setuptools', 'wheel', 'jsonschema', 'z3-solver')}
    if versions != {'setuptools': '78.1.1', 'wheel': '0.46.3',
                     'jsonschema': '4.26.0', 'z3-solver': '4.15.4.0'}:
        raise AssertionError('original explicit development package versions differ')
    return {'python': sys.version, 'implementation': sys.implementation.name,
            'platform': platform.platform(), 'versions': versions}


def expected_source(out, fixed):
    return read(out / ('FIXED-SOURCE.json' if fixed else 'ORIGINAL-SOURCE.json'))


def assert_source(source, out, fixed):
    expected = expected_source(out, fixed)
    if not original.source_matches(source, expected):
        raise AssertionError('all source bytes/modes/membership or authentic HEAD changed')
    return expected


def prepare(scope, source, out):
    out.mkdir(mode=0o700)
    report = {'status': 'HOLD', 'scope': scope, 'runtime': runtime(),
              'current_cold': False, 'whole_native': False}
    try:
        write(out / 'HARNESS-BEFORE.json', check_inputs())
        write(out / 'TOOLS-BEFORE.json', original.tool_inputs())
        before = core.admit_actual_product(source)
        write(out / 'AUTHENTIC-4B-SOURCE.json', before)
        if scope == 'core':
            joint = core.decode_packet('baseline-joint-r2.json', core.BASELINE_WRAPPER_SHA, 1122923)
            current = core.apply_packet(source, joint, before, 3181, core.BASELINE_TREE)
            packet = core.decode_packet('final-r4.json', core.FINAL_WRAPPER_SHA, 750700)
            current = core.apply_packet(source, packet, current, 3184, core.FINAL_TREE)
            report['prior_source_scope'] = 'CoreR4 exact original3184; six owner composition'
        else:
            packet = core.decode_packet('core-r3-source.json',
                'cadfcce4f8b3b3acabaab12f2bdeb091f44c001b384967b7cb960b346f8abd15', 369257)
            prior = read(INPUTS / 'byte-source.json')
            if len(packet['files']) != 27 or len(prior['files']) != 18:
                raise AssertionError('complete original CoreR3/Byte18 overlays differ')
            reduced = core.reduced_snapshot(before)
            byte.apply(source, reduced, packet['files'], core=True)
            byte.apply(source, reduced, prior['files'])
            byte.snapshot(source, reduced)
            current = original.snapshot(source, reduced)
            if len(current) != 3179:
                raise AssertionError('original Byte3179 inventory differs')
            report['prior_source_scope'] = 'Byte final18 + original CoreR3; not a CoreR4 union'
        if original.tree_id(current) != ORIGINAL_TREES[scope]:
            raise AssertionError('complete original overlay tree differs')
        write(out / 'ORIGINAL-SOURCE.json', current)
        if not original.source_matches(source, current):
            raise AssertionError('original overlay custody differs')
        compiler = core.admit_compiler(out)
        report.update(status='SOURCE_AND_COMPILER_READY_NOT_QUALIFICATION',
                      authentic_head=HEAD, authentic_tree=TREE, source_files=len(current),
                      actual_overlay_tree=original.tree_id(current),
                      compiler=describe(compiler), delta_packet=describe(INPUTS / 'finish-source.json'))
    except BaseException:
        report['exception'] = traceback.format_exc()
    finally:
        write(out / 'PREPARE.json', report)
        print(json.dumps({'stage': 'prepare', 'scope': scope, 'status': report['status']}), flush=True)
    return int(report['status'] != 'SOURCE_AND_COMPILER_READY_NOT_QUALIFICATION')


def manifests(out, scope, fixed):
    if scope == 'core':
        folder = out / ('development-r1' if fixed else 'original-images')
        return {'core': str(folder / 'core_lowering/manifest.json'),
                'plan': str(folder / 'machine_plan/manifest.json')}
    folder = out / ('byte-fixed-image' if fixed else 'byte-original-image')
    return {'byte': str(folder / 'development-manifest.json')}


def image_inputs(out, scope, fixed):
    paths = [out / 'retained-development-compiler.bin',
             out / ('FIXED-MANIFESTS.json' if fixed else 'ORIGINAL-MANIFESTS.json')]
    mapping = manifests(out, scope, fixed)
    if scope == 'core' and fixed:
        mapping = {name: str(out / 'development-r1' / name / 'manifest.json')
                   for name in original.LABELS}
        paths.extend((out / 'composition-manifests-r1.json', out / 'run_panel60.py'))
    for value in mapping.values():
        path = Path(value)
        spec = read(path)
        paths.extend((path, (path.parent / spec['image_path']).resolve(strict=True)))
    return [describe(path) for path in paths]


def build(scope, source, out, fixed):
    assert_source(source, out, fixed)
    check_inputs()
    removed = core.configure_source(source)
    report = {'status': 'HOLD', 'fixed': fixed, 'scope': scope, 'current_cold': False,
              'whole_native': False, 'removed_environment': removed}
    try:
        if scope == 'core':
            folder = out / ('development-r1' if fixed else 'original-images')
            labels = original.LABELS if fixed else ('core_lowering', 'machine_plan')
            report['compiles'] = core.compile_images(source, out, folder, labels)
            if fixed:
                shutil.copyfile(INPUTS / 'run_panel60.py', out / 'run_panel60.py')
                write(out / 'composition-manifests-r1.json',
                      {name: str(out / 'development-r1' / name / 'manifest.json')
                       for name in original.LABELS[:-1]})
        else:
            from tools.build_hia_native_byte_abi import build_development
            folder = out / ('byte-fixed-image' if fixed else 'byte-original-image')
            manifest = build_development(folder, out / 'retained-development-compiler.bin')
            if Path(manifest).resolve() != Path(manifests(out, scope, fixed)['byte']).resolve():
                raise AssertionError('original Byte builder manifest path differs')
            report['build_manifest'] = read(manifest)
        write(out / ('FIXED-MANIFESTS.json' if fixed else 'ORIGINAL-MANIFESTS.json'),
              manifests(out, scope, fixed))
        inputs = image_inputs(out, scope, fixed)
        write(out / ('FIXED-INPUTS.json' if fixed else 'ORIGINAL-INPUTS.json'), inputs)
        assert_source(source, out, fixed)
        report['status'] = 'DEVELOPMENT_IMAGES_READY_NOT_COLD'
    except BaseException:
        report['exception'] = traceback.format_exc()
    finally:
        write(out / ('BUILD-FIXED.json' if fixed else 'BUILD-ORIGINAL.json'), report)
        print(json.dumps({'stage': 'build-fixed' if fixed else 'build-original',
                          'status': report['status'], 'scope': scope}), flush=True)
    return int(report['status'] != 'DEVELOPMENT_IMAGES_READY_NOT_COLD')


def apply_fix(scope, source, out):
    before = assert_source(source, out, False)
    check_inputs()
    patch = read(INPUTS / 'finish-source.json')
    changes, changed = [], set()
    for item in patch['changes']:
        name = item['path']
        if scope == 'core' and name == 'hepta/hia_native_byte_abi_native.py':
            continue
        path = source / name
        raw = path.read_bytes()
        old = item['exact_replacement']['before'].encode()
        new = item['exact_replacement']['after'].encode()
        if raw.count(old) != 1:
            raise AssertionError('exact reviewed finish function not present once: ' + name)
        if scope == 'core' or name == 'hepta/hia_native_byte_abi_native.py':
            record = item['before']
            if (len(raw) != record['bytes'] or sha(raw) != record['sha256']
                    or blob(raw) != record['git_blob_sha1']):
                raise AssertionError('exact promised complete before bytes differ: ' + name)
        after = raw.replace(old, new, 1)
        if scope == 'core' or name == 'hepta/hia_native_byte_abi_native.py':
            record = item['after']
            if (len(after) != record['bytes'] or sha(after) != record['sha256']
                    or blob(after) != record['git_blob_sha1']):
                raise AssertionError('exact promised complete after bytes differ: ' + name)
        old_tree, new_tree = ast.parse(raw), ast.parse(after)
        old_functions = [node for node in ast.walk(old_tree)
                         if isinstance(node, ast.FunctionDef) and node.name == 'finish']
        new_functions = [node for node in ast.walk(new_tree)
                         if isinstance(node, ast.FunctionDef) and node.name == 'finish']
        if len(old_functions) != 1 or len(new_functions) != 1:
            raise AssertionError('finish AST target is not unique')
        old_functions[0].body = new_functions[0].body
        if ast.dump(old_tree) != ast.dump(new_tree):
            raise AssertionError('unrelated AST changed')
        changes.append({'path': name, 'before': {'bytes': len(raw), 'sha256': sha(raw), 'blob': blob(raw)},
                        'after': {'bytes': len(after), 'sha256': sha(after), 'blob': blob(after)},
                        'only_finish_body_changed': True,
                        'entire_file_matches_canonical_CoreR4': scope == 'core'})
        changed.add(name)
        path.write_bytes(after)
    after = original.snapshot(source, before)
    actual = {name for name in before if before[name] != after[name]}
    if actual != changed or len(changed) != (2 if scope == 'core' else 3):
        raise AssertionError('finite finish-only modified path set differs')
    if not original.source_matches(source, after):
        raise AssertionError('candidate source membership changed')
    if original.tree_id(after) != FIXED_TREES[scope]:
        raise AssertionError('complete fixed candidate tree differs')
    write(out / 'FIXED-SOURCE.json', after)
    write(out / 'FINITE-DELTA.json', {'scope': scope, 'changes': changes,
          'authentic_head': HEAD, 'authentic_tree': TREE,
          'candidate_tree_by_git_encoding': original.tree_id(after),
          'candidate_is_not_a_Git_commit': True, 'status': 'FINITE_DELTA_APPLIED_NOT_QUALIFIED'})
    return 0


def invoke(scope, source, out, stage):
    fixed = stage != 'observe-original'
    expected = assert_source(source, out, fixed)
    check_inputs()
    inputs = image_inputs(out, scope, fixed)
    if inputs != read(out / ('FIXED-INPUTS.json' if fixed else 'ORIGINAL-INPUTS.json')):
        raise AssertionError('actual images/manifest/compiler input changed')
    folder = out / stage
    folder.mkdir(mode=0o700)
    env, removed = original.clean_environment()
    env['PYTHONPATH'] = str(source)
    env['HEPTA_HIA_TEST_PACKAGING_PYTHON'] = sys.executable
    if stage.startswith('observe-'):
        command = [sys.executable, '-B', str(INPUTS / 'probe_finish.py'),
                   '--phase', 'fixed' if fixed else 'original',
                   '--manifests', str(out / ('FIXED-MANIFESTS.json' if fixed else 'ORIGINAL-MANIFESTS.json')),
                   '--output', str(folder / 'REPORT.json')]
    elif stage == 'panel60':
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
    elif stage in BYTE_GATES:
        env['HEPTA_HIA_NATIVE_BYTE_ABI_DEVELOPMENT_COMPILER'] = str(out / 'retained-development-compiler.bin')
        env['HEPTA_HIA_NATIVE_BYTE_ABI_EVIDENCE'] = str(folder / 'component')
        if stage == 'byte-generated':
            command = [sys.executable, '-B', 'tools/generate_hia_native_byte_abi.py', '--check']
        elif stage in ('byte25', 'byte4'):
            command = [sys.executable, '-B', str(INPUTS / ('run_byte25.py' if stage == 'byte25' else 'run_byte4.py')),
                       '--source', str(source), '--output', str(folder / 'REPORT.json')]
        else:
            command = [sys.executable, '-B', 'tools/qualify_hia_native_byte_abi.py',
                       '--output', str(folder / 'evidence'),
                       '--development-manifest', manifests(out, scope, True)['byte']]
    else:
        raise AssertionError('unknown original gate')
    seconds = 120 if stage == 'byte-generated' else 1800
    write(folder / 'INTENT.json', {'command': command, 'cwd': str(source), 'outer_seconds': seconds,
          'removed_environment': removed, 'original_inner_limits_unchanged': True,
          'current_cold': False, 'source_files': len(expected)})
    process = run_workflow_step(command, cwd=source, env=env,
          stdout_path=folder / 'stdout.log', stderr_path=folder / 'stderr.log',
          receipt_path=folder / 'PROCESS.json', seconds=seconds)
    custody = {'all_source_files': len(expected),
               'source_unchanged': original.source_matches(source, expected),
               'native_inputs_unchanged': image_inputs(out, scope, fixed) == inputs}
    write(folder / 'SOURCE-CUSTODY.json', custody)
    print(json.dumps({'stage': stage, 'scope': scope, 'process': process, 'custody': custody}), flush=True)
    return int(process['status'] != 'WORKFLOW_STEP_COMPLETED'
               or not custody['source_unchanged'] or not custody['native_inputs_unchanged'])


def emit_small_reports(out):
    files = {}
    for path in sorted(out.rglob('*')):
        if (not path.is_file() or path.suffix not in ('.json', '.log')
                or path.stat().st_size > (4 << 20)):
            continue
        raw = path.read_bytes()
        try:
            text = raw.decode('utf-8')
        except UnicodeDecodeError:
            continue
        files[path.relative_to(out).as_posix()] = {'bytes': len(raw), 'sha256': sha(raw), 'content': text}
    data = (json.dumps({'scope': 'LOSSLESS_TEXT_REPORT_SUBSET_FULL_RAW_IN_ACTIONS_ARTIFACT',
                       'files': files}, sort_keys=True, separators=(',', ':')) + '\n').encode()
    compressed = zlib.compress(data, 6)
    (out / 'TEXT-REPORTS.json.zlib').write_bytes(compressed)
    encoded = base64.b64encode(compressed).decode()
    chunks = [encoded[i:i+16000] for i in range(0, len(encoded), 16000)]
    for i, chunk in enumerate(chunks):
        print('HIA_FINISH_R5_TEXT ' + json.dumps({'index': i, 'count': len(chunks),
              'chunk_sha256': sha(chunk.encode()), 'raw_bytes': len(data), 'raw_sha256': sha(data),
              'compressed_bytes': len(compressed), 'compressed_sha256': sha(compressed), 'data': chunk}), flush=True)


def finish(scope, source, out):
    report = {'scope': scope, 'status': 'HOLD', 'current_cold': False,
              'whole_native': False, 'default_changed': False, 'old_owners_removed': False}
    try:
        stages = ('observe-original', 'observe-fixed') + (CORE_GATES if scope == 'core' else BYTE_GATES)
        report['stages'] = {}
        for stage in stages:
            process = read(out / stage / 'PROCESS.json')
            custody = read(out / stage / 'SOURCE-CUSTODY.json')
            report['stages'][stage] = {'process': process, 'custody': custody}
            if (process['status'] != 'WORKFLOW_STEP_COMPLETED'
                    or not custody['source_unchanged'] or not custody['native_inputs_unchanged']):
                raise AssertionError('actual original gate/observation failed: ' + stage)
        before = read(out / 'observe-original/REPORT.json')
        after = read(out / 'observe-fixed/REPORT.json')
        report['original_observation'], report['new_observation'] = before, after
        if before['status'] != 'ORIGINAL_BEHAVIOR_OBSERVED' or after['status'] != 'PASS':
            raise AssertionError('both actual original and new finish observations are required')
        for observed in (before, after):
            if (observed['tests_run'] != 5 or any(observed[k] for k in
                    ('failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes'))):
                raise AssertionError('complete finish fixture conjunction differs')
        if scope == 'core':
            panel = read(out / 'component-checker-r4/REPORT.json')
            core_report = read(out / 'complete124/evidence/REPORT.json')
            plan = read(out / 'plan44/REPORT.json')
            report['original_reports'] = {'panel60': panel, 'complete124': core_report, 'plan44': plan}
            if panel['status'] != 'PASS' or panel['tests_run'] != 60 or not panel['inputs_unchanged']:
                raise AssertionError('original panel60 did not pass completely')
            if (core_report['status'] != 'PASS'
                    or [g['tests_run'] for g in core_report['groups']] != [23, 51, 50]
                    or any(not g['strict_pass'] or g['loaded_ids'] != g['executed_ids']
                           or len(set(g['loaded_ids'])) != g['tests_run'] for g in core_report['groups'])
                    or core_report['retained_owner_entries']
                    or not core_report['retained_callers_explicitly_select_all_six_owners']):
                raise AssertionError('complete original124 conjunction differs')
            if plan['status'] != 'PASS' or plan['tests_run'] != 44:
                raise AssertionError('complete original44 conjunction differs')
        else:
            report['original_reports'] = {name: read(out / name / 'REPORT.json')
                                          for name in ('byte25', 'byte4')}
            report['original_reports']['byte29'] = read(out / 'byte29/evidence/report.json')
            if (report['original_reports']['byte25']['status'] != 'PASS'
                    or report['original_reports']['byte25']['tests_run'] != 25
                    or report['original_reports']['byte4']['status'] != 'PASS'
                    or report['original_reports']['byte4']['testsRun'] != 4
                    or report['original_reports']['byte29']['status'] != 'SELECTED_NATIVE_BYTE_ABI_CALLERS_PASS'):
                raise AssertionError('complete original Byte25/4/29 conjunction differs')
        expected = assert_source(source, out, True)
        write(out / 'SOURCE-AFTER.json', original.snapshot(source, expected))
        tool_after = original.tool_inputs()
        write(out / 'TOOLS-AFTER.json', tool_after)
        if tool_after != read(out / 'TOOLS-BEFORE.json'):
            raise AssertionError('actual toolchain/package input changed')
        if check_inputs() != read(out / 'HARNESS-BEFORE.json'):
            raise AssertionError('harness changed')
        if image_inputs(out, scope, True) != read(out / 'FIXED-INPUTS.json'):
            raise AssertionError('actual image inputs changed')
        report.update(status='PASS', source_files=len(expected),
                      source_unchanged=True, actual_inputs_unchanged=True,
                      authentic_head=HEAD, actual_overlay_tree=original.tree_id(expected),
                      independent_prior_scope=read(out / 'PREPARE.json')['prior_source_scope'])
    except BaseException:
        report['exception'] = traceback.format_exc()
    finally:
        try:
            if (out / 'FIXED-SOURCE.json').exists():
                expected = expected_source(out, True)
                after_all = original.snapshot(source, expected)
                path = out / 'SOURCE-AFTER.json'
                if not path.exists():
                    write(path, after_all)
                report['final_source_custody'] = original.source_matches(source, expected)
                if not report['final_source_custody']:
                    report['status'] = 'HOLD'
        except BaseException:
            report['final_custody_exception'] = traceback.format_exc()
            report['status'] = 'HOLD'
        write(out / 'REPORT.json', report)
        members = []
        for path in sorted(out.rglob('*')):
            if path.is_file():
                row = describe(path)
                row['path'] = path.relative_to(out).as_posix()
                members.append(row)
        write(out / 'EVIDENCE-MANIFEST.json', {'files': members, 'self_excluded': True,
              'complete_actual_raw_in_artifact': True, 'base_commit': HEAD,
              'source_reconstruction': 'authentic Git4b + immutable prior packets + finite finish delta',
              'current_cold': False})
        emit_small_reports(out)
        print(json.dumps({'status': report['status'], 'scope': scope,
                          'current_cold': False, 'whole_native': False}), flush=True)
    return int(report['status'] != 'PASS')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scope', choices=('core', 'byte'), required=True)
    parser.add_argument('--stage', choices=STAGES, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source, out = args.source.resolve(), args.output.resolve()
    try:
        if args.stage == 'prepare':
            return prepare(args.scope, source, out)
        if args.stage == 'build-original':
            return build(args.scope, source, out, False)
        if args.stage == 'apply-fix':
            return apply_fix(args.scope, source, out)
        if args.stage == 'build-fixed':
            return build(args.scope, source, out, True)
        if args.stage == 'finish':
            return finish(args.scope, source, out)
        return invoke(args.scope, source, out, args.stage)
    except BaseException:
        out.mkdir(mode=0o700, exist_ok=True)
        error = {'stage': args.stage, 'scope': args.scope, 'status': 'HOLD',
                 'exception': traceback.format_exc(), 'current_cold': False}
        write(out / (args.stage + '-EXCEPTION.json'), error)
        print(json.dumps(error), flush=True)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
