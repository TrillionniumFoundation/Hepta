"""Require exact whole Source success, then the unchanged 43 + 10 + 9 controls.

This is a development image repair gate, not matching-source cold qualification.
The original Source runner and Native workflow fragment are unchanged; the fixed materializer adds only the reviewed fourth evidence location.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import time
import traceback


def encode(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode()


def pin(raw):
    return {'bytes': len(raw), 'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'sha256': hashlib.sha256(raw).hexdigest()}


def check(value, message):
    if not value:
        raise AssertionError(message)


def matches(raw, expected):
    actual = pin(raw)
    return all(actual[key] == expected[key] for key in ('bytes', 'git_blob', 'sha256'))


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(value)


def git(source, *args):
    result = subprocess.run(['git', '-C', str(source), *args], capture_output=True, check=False)
    check(result.returncode == 0, 'read-only Git failed: ' + result.stderr.decode('utf-8', 'replace'))
    return result.stdout


def read_sources(source, expected_tree):
    check(git(source, 'write-tree').decode().strip() == expected_tree, 'source index tree differs')
    git(source, 'diff', '--exit-code', expected_tree, '--')
    rows = {}
    for field in git(source, 'ls-files', '--stage', '-z').split(b'\0'):
        if not field:
            continue
        meta, encoded_name = field.split(b'\t', 1)
        mode, blob, stage = meta.decode().split()
        name = encoded_name.decode('utf-8')
        check(stage == '0' and mode in ('100644', '100755'), 'unmerged or nonregular source')
        check(name not in rows and not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/')), 'unsafe source path')
        path = source / name
        check(not path.is_symlink() and path.is_file(), 'source file is not regular')
        raw = path.read_bytes()
        check(pin(raw)['git_blob'] == blob, 'source bytes differ: ' + name)
        actual_mode = stat.S_IMODE(path.stat().st_mode)
        check(actual_mode == (0o755 if mode == '100755' else 0o644), 'source mode differs: ' + name)
        rows[name] = dict(pin(raw), mode=actual_mode, git_mode=mode)
    check(len(rows) == 3175, 'full generated source file count differs')
    for directory, dirs, files in os.walk(source, followlinks=False):
        directory = Path(directory)
        if directory == source:
            dirs[:] = [n for n in dirs if n != '.git']
        for name in dirs:
            check(not (directory / name).is_symlink(), 'source directory symlink')
        for name in files:
            path = directory / name
            relative = path.relative_to(source).as_posix()
            check(stat.S_ISREG(path.lstat().st_mode), 'unexpected nonregular worktree entry')
            if '__pycache__' in path.relative_to(source).parts and path.suffix == '.pyc':
                continue
            check(relative in rows, 'unexpected worktree file: ' + relative)
    return dict(sorted(rows.items()))


def source_authority(materialization_root, source, fixed, ids, out):
    result_path = materialization_root / 'evidence/raw/RESULT.json'
    report_path = materialization_root / 'evidence/raw/checks/SOURCE-TESTS.json'
    result_raw, report_raw = result_path.read_bytes(), report_path.read_bytes()
    result, report = json.loads(result_raw), json.loads(report_raw)
    check(result['status'] == 'SOURCE_PASS' and not result['failures'], 'whole Source did not pass')
    check(type(result['product_tests_executed']) is int and result['product_tests_executed'] == 1411, 'whole Source denominator differs')
    check(report == result['source_tests'], 'source report differs from materializer result')
    expected = ids['r19_expected_ordered_ids']
    check(type(report['tests_run']) is int and report['tests_run'] == report['expected'] == len(expected) == 1411, 'source test count differs')
    check(report['status'] == 'PASS' and report['complete'] is True, 'incomplete Source result')
    check(report['ordered_ids'] == report['actual_started_ids'] == report['actual_stopped_ids'] == expected, 'Source ordered IDs differ')
    for key in ('errors', 'failures', 'skipped', 'expected_failures', 'unexpected_successes', 'duplicate_ids',
                'missing_a733_ids', 'missing_main_ids', 'missing_frozen_a733_ids', 'missing_frozen_main_ids'):
        check(not report[key], 'Source anomalies: ' + key)
    check(all(not value for value in report['loader_errors'].values()), 'Source loader errors')
    check(report['selectors'] == ids['selectors'], 'Source selectors differ')
    prior = ids['required_r11_ordered_projection']
    check(len(prior) == len(set(prior)) == 1329 and [n for n in expected if n in set(prior)] == prior,
          'original1329 Source projection changed')
    for key, count in (('r18_expected_ordered_ids', 1374), ('r17_expected_ordered_ids', 1363),
                       ('r16_expected_ordered_ids', 1357), ('r15_expected_ordered_ids', 1356), ('r14_expected_ordered_ids', 1353),
                       ('r13_expected_ordered_ids', 1352), ('r12_expected_ordered_ids', 1342),
                       ('original_r10_r2_ordered_ids', 1319)):
        retained = ids[key]
        check(len(retained) == len(set(retained)) == count and
              [name for name in expected if name in set(retained)] == retained,
              'fixed earlier Source ordered projection changed: ' + key)
    manifest_raw = (materialization_root / 'evidence/raw/harness/INPUTS.json').read_bytes()
    check(matches(manifest_raw, fixed['materialization_plan']), 'executed materialization inputs differ')
    driver_raw = (materialization_root / 'evidence/raw/harness/DRIVER.py').read_bytes()
    check(matches(driver_raw, fixed['materialization_driver']), 'executed materialization driver differs')
    tree = result['generation']['tree']
    rows = read_sources(source, tree)
    for name, expected_pin in fixed['repaired_source_files'].items():
        check(matches((source / name).read_bytes(), expected_pin), 'repaired generated or author source differs: ' + name)
    for row in fixed['original_test_files']:
        check(matches((source / row['path']).read_bytes(), row), 'original test bytes differ: ' + row['path'])
    put(out / 'FULL-SOURCE-RESULT.json', result_raw)
    put(out / 'FULL-SOURCE-TESTS.json', report_raw)
    put(out / 'FIXED-SOURCE-MANIFEST.json', encode(rows))
    return {'source_tree': tree, 'source_files': len(rows), 'result': pin(result_raw), 'source_tests': pin(report_raw),
            'repository_HEAD': git(source, 'rev-parse', 'HEAD').decode().strip(),
            'identity_note': 'The harness Actions head and repository historical HEAD are not the generated source tree.',
            'required_original_projection': 1329, 'tests_run': 1411}, rows


def clean_environment(source, out):
    keys = ('PATH', 'HOME', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ', 'TMPDIR', 'RUNNER_TEMP', 'LD_LIBRARY_PATH', 'SYSTEMROOT')
    env = {key: os.environ[key] for key in keys if key in os.environ}
    env.update(PYTHONDONTWRITEBYTECODE='1', HIA_PARSER_CONTROL_SOURCE=str(source), HIA_PARSER_CONTROL_ROOT=str(out))
    return env


def run_group(harness, out, environment, name, script, *args):
    folder = out / 'outer' / name
    folder.mkdir(parents=True, exist_ok=False)
    command = [sys.executable, '-I', '-B', str(harness / 'tools/supervise.py'), name + '-owner', script, name, *args]
    started = time.monotonic_ns()
    with (folder / 'stdout.log').open('xb') as stdout, (folder / 'stderr.log').open('xb') as stderr:
        child = subprocess.run(command, cwd=out, env=environment, stdout=stdout, stderr=stderr, check=False)
    command_result = {'argv': command, 'returncode': child.returncode, 'wall_ns': time.monotonic_ns() - started,
                      'owner_limits': {'qualification_seconds': 180, 'cleanup_seconds': 3}}
    put(folder / 'COMMAND.json', encode(command_result))
    owner_path = out / 'evidence' / (name + '-owner') / 'owner.json'
    report_path = out / 'evidence' / name / 'REPORT.json'
    record = {'command': command_result, 'status': 'FAIL'}
    if owner_path.is_file():
        owner_raw = owner_path.read_bytes()
        owner = json.loads(owner_raw)
        record['owner'] = owner
        record['owner_pin'] = pin(owner_raw)
        record['owner_admitted'] = owner.get('status') == 'OWNED_PROCESS_COMPLETED' and type(owner.get('returncode')) is int and owner['returncode'] == 0 and owner.get('qualification_seconds') == 180 and owner.get('cleanup_seconds') == 3 and owner.get('cleanup', {}).get('complete') is True and owner.get('cleanup', {}).get('observed_echild') is True
    if report_path.is_file():
        report_raw = report_path.read_bytes()
        record['report'] = json.loads(report_raw)
        record['report_pin'] = pin(report_raw)
    if child.returncode == 0 and record.get('owner_admitted') and record.get('report', {}).get('status') == 'PASS' and record['report'].get('source_unchanged') is True:
        record['status'] = 'PASS'
    return record


def admit_tests(record, group, ids, executable):
    check(record['status'] == 'PASS', 'test owner failed: ' + group)
    report = record['report']
    expected = ids['bounded_groups'][group]
    check(report['group'] == group and type(report['tests_run']) is int and type(report['loaded']) is int,
          'wrong test group/count type')
    check(report['tests_run'] == report['loaded'] == len(expected), 'test count differs')
    check(report['loaded_ids'] == report['started_ids'] == report['stopped_ids'] == expected, 'fixed test ordered IDs differ')
    check(not any(report[key] for key in ('loader_errors', 'errors', 'failures', 'skipped', 'expected_failures', 'unexpected_successes')), 'test result anomaly')
    if group == 'original43':
        check(report['declared_packaging_interpreter'] == executable, 'packaging used another Python')
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--materialization-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    harness = Path(__file__).resolve().parents[1]
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    (out / 'evidence').mkdir()
    report = {'schema': 'hepta.r19-formal-parser-bounded.v1', 'status': 'FAIL',
        'scope': 'ACTUAL314_SOURCE_SUCCESS_REQUIRED_DEVELOPMENT_IMAGE_CONTROLS_NOT_COLD',
        'python': sys.version, 'executable': str(Path(sys.executable).resolve()),
        'full_Source_pass_inherited': False, 'required_tests': 62, 'groups': {}, 'failures': [],
        'current_source_cold_qualification': False, 'whole_native': False, 'product_refs_changed': False}
    before = None
    source = args.materialization_root / 'repository'
    try:
        check(sys.version_info[:3] == (3, 14, 4), 'wrong actual interpreter')
        check(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'wrong native platform')
        report['packaging_versions'] = {name: importlib.metadata.version(name) for name in ('pip', 'setuptools', 'wheel')}
        check(report['packaging_versions']['setuptools'] == '78.1.1' and report['packaging_versions']['wheel'] == '0.46.3', 'fixed packaging dependencies differ')
        fixed_raw = (harness / 'inputs/PARSER-CONTROLS.json').read_bytes()
        check(pin(fixed_raw)['git_blob'] == os.environ['EXPECTED_PARSER_CONTROLS_BLOB'], 'bounded control manifest differs')
        fixed = json.loads(fixed_raw)
        expected_raw = (harness / 'inputs/FORMAL-EXPECTED-IDS.json').read_bytes()
        check(matches(expected_raw, fixed['expected_ids']), 'expected IDs input differs')
        ids = json.loads(expected_raw)
        check(sum(map(len, ids['bounded_groups'].values())) == 62, 'fixed group total differs')
        for name, expected_pin in fixed['harness_files'].items():
            check(matches((harness / name).read_bytes(), expected_pin), 'bounded harness file differs: ' + name)
        put(out / 'PARSER-CONTROLS.json', fixed_raw)
        put(out / 'FORMAL-EXPECTED-IDS.json', expected_raw)
        for name in fixed['harness_files']:
            put(out / 'harness' / name, (harness / name).read_bytes())
        authority, before = source_authority(args.materialization_root, source, fixed, ids, out)
        report['source_authority'] = authority
        compiler = bytearray()
        for item in fixed['compiler']['parts']:
            encoded = (harness / item['path']).read_bytes()
            check(matches(encoded, item['encoded']), 'compiler encoded part differs')
            decoded = base64.b64decode(encoded, validate=True)
            check(matches(decoded, item['decoded']), 'compiler decoded part differs')
            compiler.extend(decoded)
        check(matches(compiler, fixed['compiler']), 'full development compiler differs')
        put(out / 'inputs/B3.image.bin', bytes(compiler))
        report['compiler_scope'] = fixed['compiler']['scope']
        environment = clean_environment(source, out)
        report['groups']['source'] = run_group(harness, out, environment, 'source10', 'run_group.py', 'source')
        report['groups']['build'] = run_group(harness, out, environment, 'build', 'run_build.py')
        if report['groups']['build']['status'] == 'PASS':
            manifest = out / 'evidence/build/build/manifest.json'
            check(manifest.is_file(), 'actual build has no fixture manifest')
            report['groups']['fresh5'] = run_group(harness, out, environment, 'fresh5', 'probe_fresh_selected.py', str(manifest))
            report['groups']['original43'] = run_group(harness, out, environment, 'original43', 'run_group.py', 'original43', str(manifest))
            report['groups']['native'] = run_group(harness, out, environment, 'native9', 'run_group.py', 'native', str(manifest))
        else:
            for name in ('fresh5', 'original43', 'native'):
                report['groups'][name] = {'status': 'NOT_EXECUTED_NO_SUCCESSFUL_BUILD'}
        admissions = {}
        for group in ('source', 'original43', 'native'):
            try:
                admissions[group] = admit_tests(report['groups'][group], group, ids, report['executable'])
            except BaseException:
                admissions[group] = False
                report['failures'].append({'group': group, 'traceback': traceback.format_exc()})
        report['fixed_test_admissions'] = admissions
        check(all(admissions.values()), 'one or more required original groups failed')
        check(all(row['status'] == 'PASS' for row in report['groups'].values()), 'build or fresh subprocess group failed')
        fresh = report['groups']['fresh5']['report']['records']
        check(len(fresh) == 5 and all(type(row['returncode']) is int and row['returncode'] == 2 for row in fresh), 'fresh rejection controls differ')
        report['tests_run'] = sum(report['groups'][name]['report']['tests_run'] for name in ('source', 'original43', 'native'))
        check(report['tests_run'] == 62, 'required62 incomplete')
        report['status'] = 'PASS'
    except BaseException:
        report['failures'].append({'stage': 'bounded-formal', 'traceback': traceback.format_exc()})
    finally:
        if before is not None:
            try:
                after = read_sources(source, report['source_authority']['source_tree'])
                put(out / 'FINAL-SOURCE-MANIFEST.json', encode(after))
                report['source_unchanged'] = before == after
                check(before == after, 'bounded controls changed source')
            except BaseException:
                report['status'] = 'FAIL'
                report['failures'].append({'stage': 'source-after', 'traceback': traceback.format_exc()})
        report['finished_ns'] = time.time_ns()
        put(out / 'RESULT.json', encode(report))
    print(json.dumps({key: report.get(key) for key in ('status', 'tests_run', 'source_unchanged', 'scope', 'failures')}, sort_keys=True))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
