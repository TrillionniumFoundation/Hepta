#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Run the source-bound final runtime gates on the authorized ai395 checkout."""

import datetime
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

TASK = pathlib.Path('/home/qq/hepta-hia-agent-native-20261106-f4e250f91ef4')
REPO = TASK / 'runtime'
EVIDENCE = TASK / 'evidence'
COMMIT = 'd95866c9e244e03a182740d420f94294ee43cdcd'
CARGO = '/home/qq/.cargo/bin/cargo'
MANIFEST = TASK / 'runtime-staged-source-r4b.json'
SUMMARY = EVIDENCE / 'runtime-final-gates.json'


def sha256(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def output(argv):
    return subprocess.check_output(argv, cwd=REPO, text=True).strip()


def verify_source(manifest_digest, qualified):
    assert sha256(MANIFEST) == manifest_digest, 'staged manifest changed'
    assert output(['/usr/bin/git', 'rev-parse', 'HEAD']) == COMMIT, 'HEAD changed'
    for name, pin in qualified.items():
        assert name.startswith('runtime/') and '..' not in pathlib.PurePosixPath(name).parts
        assert sha256(TASK / name) == pin, ('qualified source changed', name)
    subprocess.run(['/usr/bin/git', 'diff', '--exit-code', COMMIT], cwd=REPO, check=True)
    assert not output(['/usr/bin/git', 'status', '--porcelain=v1']), 'working tree changed'


def save(report):
    pending = SUMMARY.with_suffix('.json.pending')
    pending.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    pending.replace(SUMMARY)


def tail(path, maximum=10000):
    with path.open('rb') as stream:
        stream.seek(max(0, path.stat().st_size - maximum))
        return stream.read().decode('utf-8', 'replace')


def main():
    os.umask(0o022)
    os.environ['PATH'] = str(TASK / 'tools/bin') + ':/home/qq/.cargo/bin:' + os.environ.get('PATH', '')
    manifest_digest = sha256(MANIFEST)
    assert manifest_digest == 'd9b1ae288681315585143534c12838ca839feb67731285dad2621ef06dfd94a8', 'unexpected staged manifest'
    qualified = json.loads(MANIFEST.read_text())['files']
    assert len(qualified) == 16
    required_env = {
        'CARGO_BUILD_JOBS': '4',
        'CARGO_PROFILE_DEV_DEBUG': '0',
        'CARGO_PROFILE_TEST_DEBUG': '0',
    }
    assert all(os.environ.get(name) == value for name, value in required_env.items())
    assert os.environ['PATH'].split(':')[:2] == [str(TASK / 'tools/bin'), '/home/qq/.cargo/bin']
    verify_source(manifest_digest, qualified)
    failed_log = EVIDENCE / 'runtime-nextest-all-features.log'
    failed_log_pin = sha256(failed_log)
    report = {
        'schema': 'hia-runtime-final-gates-v1',
        'source_commit': COMMIT,
        'qualified_file_count': len(qualified),
        'qualified_files': qualified,
        'staged_manifest_sha256': manifest_digest,
        'source_report_path': str(EVIDENCE / 'runtime-final-source.json'),
        'source_report_sha256': sha256(EVIDENCE / 'runtime-final-source.json'),
        'started_at_utc': utc(),
        'cohort_closure': {'confirmed_by': 'root', 'last_server_pid': 1903240,
                           'last_server_exit_code': 0,
                           'last_server_exit_at_utc': '2026-11-07T00:16:02.287309Z',
                           'terminal_job_id': '1a1b35c3499-fc05-8263'},
        'environment': required_env | {'PATH': os.environ['PATH'], 'umask': '022'},
        'cargo_version': output([CARGO, '+1.95.0', '--version']),
        'rustc_version': output(['/home/qq/.cargo/bin/rustc', '+1.95.0', '--version']),
        'nextest_version': output([CARGO, '+1.95.0', 'nextest', '--version']),
        'preserved_prior_failed_log': {'path': str(failed_log), 'sha256': failed_log_pin},
        'state': 'running',
        'steps': [],
    }
    save(report)
    steps = [
        ('nextest_all_features', 'runtime-nextest-all-features-final.log', [
            CARGO, '+1.95.0', 'nextest', 'run', '--locked', '--all-targets', '--all-features',
            '--test-threads', '1', '--retries', '0', '--no-fail-fast']),
        ('nextest_no_default_features', 'runtime-nextest-no-default-final.log', [
            CARGO, '+1.95.0', 'nextest', 'run', '--locked', '--all-targets', '--no-default-features',
            '--test-threads', '1', '--retries', '0', '--no-fail-fast']),
        ('build_all_features_binary', 'runtime-build-all-features-final.log', [
            CARGO, '+1.95.0', 'build', '--locked', '--all-features', '--bin', 'hepta-runtime']),
    ]
    for name, filename, argv in steps:
        verify_source(manifest_digest, qualified)
        record = {'name': name, 'argv': argv, 'started_at_utc': utc(), 'state': 'running'}
        report['steps'].append(record)
        save(report)
        log = EVIDENCE / filename
        print(json.dumps({'phase': name, 'state': 'started', 'log': str(log)}), flush=True)
        began = time.monotonic()
        with log.open('w') as stream:
            result = subprocess.run(argv, cwd=REPO, stdout=stream, stderr=subprocess.STDOUT)
        record.update({
            'exit_code': result.returncode,
            'elapsed_seconds': round(time.monotonic() - began, 3),
            'finished_at_utc': utc(),
            'state': 'passed' if result.returncode == 0 else 'failed',
            'log': {'path': str(log), 'sha256': sha256(log), 'bytes': log.stat().st_size},
            'summary_lines': [line.strip() for line in log.read_text().splitlines()
                              if 'Summary [' in line or 'Finished ' in line][-5:],
        })
        verify_source(manifest_digest, qualified)
        assert sha256(failed_log) == failed_log_pin, 'prior failed log changed'
        save(report)
        print(json.dumps(record), flush=True)
        if result.returncode:
            report['state'] = 'failed'
            report['finished_at_utc'] = utc()
            save(report)
            print(tail(log), flush=True)
            return result.returncode
    original = REPO / 'target/debug/hepta-runtime'
    destination = TASK / 'bin/hepta-runtime-r4'
    destination.parent.mkdir(mode=0o755, exist_ok=True)
    pending = destination.with_name(destination.name + '.pending')
    shutil.copyfile(original, pending)
    pending.chmod(0o755)
    assert sha256(original) == sha256(pending), 'binary copy differs'
    pending.replace(destination)
    verify_source(manifest_digest, qualified)
    assert sha256(failed_log) == failed_log_pin, 'prior failed log changed'
    report.update({
        'state': 'passed',
        'finished_at_utc': utc(),
        'source_unchanged_after_build': True,
        'binary': {'path': str(destination), 'sha256': sha256(destination),
                   'bytes': destination.stat().st_size, 'mode': oct(destination.stat().st_mode & 0o777)},
    })
    save(report)
    print(json.dumps({'state': 'passed', 'source_commit': COMMIT, 'binary': report['binary'],
                      'summary_path': str(SUMMARY), 'summary_sha256': sha256(SUMMARY)}), flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
