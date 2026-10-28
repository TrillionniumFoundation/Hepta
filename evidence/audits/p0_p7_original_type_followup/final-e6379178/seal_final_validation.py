#!/usr/bin/python3
"""Independently seal closed raw reports without rewriting their manifests."""
import collections
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat

OUT = Path('/tmp/hepta-final-integrated-e6379178')
LAUNCH = Path('/tmp/hepta-final-integrated-e6379178-launch')
EXPECTED = 'e6379178a3e9a682f88c344aaa86b3d74932ffd7'
VM = Path('/tmp/hepta-p2-independent-v2-v7-target/debug/hia-core-shadow')


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def entry(path):
    return {'path': str(path), 'sha256': sha(path), 'bytes': path.stat().st_size}


def write(path, data):
    with path.open('x') as stream:
        json.dump(data, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')


def identity(path):
    value = path.lstat()
    return {'device': value.st_dev, 'inode': value.st_ino, 'mode': value.st_mode,
            'bytes': value.st_size, 'mtime_ns': value.st_mtime_ns, 'ctime_ns': value.st_ctime_ns}


def main():
    summary = json.loads((OUT / 'summary.json').read_bytes())
    manifest = json.loads((OUT / 'manifest.json').read_bytes())
    mismatches = [row['path'] for row in manifest['files']
                  if sha(OUT / row['path']) != row['sha256'] or (OUT / row['path']).stat().st_size != row['bytes']]
    if mismatches:
        raise RuntimeError('Original manifest mismatch: ' + repr(mismatches))
    if (summary['git_commit'] != EXPECTED or summary['ok'] is not True
            or summary['source_unchanged'] is not True or summary['tools_unchanged'] is not True):
        raise RuntimeError('The formal run did not qualify its exact source and tools')
    stages = {row['name']: json.loads(Path(row['report_path']).read_bytes()) for row in summary['stages']}
    for row in summary['stages']:
        if sha(Path(row['report_path'])) != row['report_sha256']:
            raise RuntimeError('Stage report no longer matches its summary')
    raw = (OUT / 'unit-discovery/stderr.log').read_text()
    footer = re.search(r'(?m)^Ran ([0-9]+) tests in ([0-9]+(?:\.[0-9]+)?)s\r?\n\r?\nOK\r?\n?\Z', raw)
    if footer is None:
        raise RuntimeError('No complete zero-skip unittest terminal footer')
    ids = []
    for line in raw.splitlines():
        if not line.startswith('test') or ' (' not in line:
            continue
        display, rest = line.split(' (', 1)
        if any(char.isspace() for char in display) or ')' not in rest:
            continue
        parenthesized = rest.split(')', 1)[0]
        ids.append(parenthesized if parenthesized.rpartition('.')[2] == display else parenthesized + '.' + display)
    counts = collections.Counter(ids)
    unit = stages['unit-discovery']
    if (len(ids) != int(footer.group(1)) or len(counts) != len(ids)
            or ids != unit['canonical_tests']['test_ids']
            or unit['canonical_test_count_matches_footer'] is not True
            or unit['outcome'] != {'tests_run': len(ids), 'skipped': 0, 'failures': 0, 'errors': 0, 'passed': True}
            or unit['returncode'] != 0):
        raise RuntimeError('Canonical methods, footer and structured unittest report disagree')
    ids_path = OUT / 'canonical-unittest-ids.txt'
    with ids_path.open('x') as stream:
        stream.write('\n'.join(ids) + '\n')
    cargo_raw = (OUT / 'cargo-test/stdout.log').read_text()
    cargo_rows = []
    for line in cargo_raw.splitlines():
        if not line.startswith('test result: '):
            continue
        match = re.fullmatch(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in ([0-9.]+s)', line)
        if match is None:
            raise RuntimeError('Unexpected Cargo summary syntax')
        result, passed, failed, ignored, measured, filtered, elapsed = match.groups()
        cargo_rows.append({'result': result, 'passed': int(passed), 'failed': int(failed),
                           'ignored': int(ignored), 'measured': int(measured), 'filtered_out': int(filtered),
                           'duration_display': elapsed})
    cargo_count = sum(row['passed'] for row in cargo_rows)
    if (not cargo_rows or cargo_count <= 0 or stages['cargo-test']['returncode'] != 0
            or not cargo_raw.rstrip().splitlines()[-1].startswith('test result: ok.')
            or any(row['result'] != 'ok' or any(row[key] for key in ('failed', 'ignored', 'measured', 'filtered_out')) for row in cargo_rows)
            or stages['cargo-test']['outcome']['total_passed'] != cargo_count):
        raise RuntimeError('Actual Cargo terminal results do not support a complete unskipped pass')
    before = identity(VM)
    if not stat.S_ISREG(before['mode']):
        raise RuntimeError('The post-validation VM is not an ordinary file')
    vm_hash = sha(VM)
    retained = OUT / 'retained-vm'
    retained.mkdir()
    copied = retained / 'hia-core-shadow'
    with VM.open('rb') as source, copied.open('xb') as target:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            target.write(block)
        target.flush()
        os.fsync(target.fileno())
    os.chmod(copied, stat.S_IMODE(before['mode']))
    if identity(VM) != before or sha(VM) != vm_hash or sha(copied) != vm_hash:
        raise RuntimeError('VM changed during byte-exact post-validation retention')
    vm_receipt = retained / 'copy-receipt.json'
    write(vm_receipt, {'schema': 'hepta.final-postvalidation-vm-retention.v1',
          'git_commit': EXPECTED, 'copied_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'source_path': str(VM), 'source_identity_before_and_after': before,
          'source_sha256_before_and_after': vm_hash, 'retained': entry(copied),
          'byte_exact_copy': True, 'target_modified_by_copy': False,
          'observation_scope': 'VM bytes observed at completion of this frozen validation; this is not a per-invocation binary attestation.'})
    def source_identity(value):
        return {'git_commit': value['git_commit'], 'git_tree': value['git_tree'],
                'git_status': value['git_status'], 'snapshot_sha256': value['official_snapshot']['sha256'],
                'snapshot_file_count': len(value['official_snapshot']['files']), 'capture_errors': value['capture_errors']}
    record = {'schema': 'hepta.final-integrated-completion.v1',
              'sealed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'git_commit': EXPECTED, 'runner_pid': 569566, 'execution_tool_session': 88057,
              'observed_runner_returncode': 0, 'runner_and_validation_stages_completed': True,
              'source_before': source_identity(summary['source_before']),
              'source_after': source_identity(summary['source_after']),
              'source_unchanged': True, 'tools_unchanged': True,
              'controlled_environment': summary['controlled_environment'],
              'unit': {'report': entry(OUT / 'unit-discovery/report.json'),
                  'raw_stdout': entry(OUT / 'unit-discovery/stdout.log'), 'raw_stderr': entry(OUT / 'unit-discovery/stderr.log'),
                  'footer_verbatim': footer.group(0), 'footer_elapsed_seconds': float(footer.group(2)),
                  'command_duration_seconds': unit['duration_seconds'], 'returncode': 0,
                  'tests_run': len(ids), 'canonical_method_count': len(ids), 'unique_canonical_method_count': len(counts),
                  'duplicate_canonical_methods': {}, 'skipped': 0, 'failures': 0, 'errors': 0,
                  'canonical_ids_file': entry(ids_path)},
              'cargo_test': {'report': entry(OUT / 'cargo-test/report.json'),
                  'raw_stdout': entry(OUT / 'cargo-test/stdout.log'), 'raw_stderr': entry(OUT / 'cargo-test/stderr.log'),
                  'returncode': 0, 'command_duration_seconds': stages['cargo-test']['duration_seconds'],
                  'harness_summary_count': len(cargo_rows), 'harness_summaries': cargo_rows,
                  'passed': cargo_count, 'failed': 0, 'ignored': 0, 'measured': 0, 'filtered_out': 0},
              'preflights_separate_from_formal_tests': [{
                  'name': name, 'classification': stages[name]['classification'], 'returncode': stages[name]['returncode'],
                  'duration_seconds': stages[name]['duration_seconds'], 'passed': stages[name]['ok'],
                  'report': entry(OUT / name / 'report.json')}
                  for name in ('cargo-metadata', 'cargo-build')],
              'original_manifest': entry(OUT / 'manifest.json'),
              'original_manifest_files_verified': len(manifest['files']),
              'original_manifest_total_bytes': sum(row['bytes'] for row in manifest['files']),
              'original_manifest_mismatches': mismatches,
              'summary': entry(OUT / 'summary.json'), 'plan': entry(OUT / 'plan.json'),
              'launch_plan': entry(LAUNCH / 'plan.json'),
              'closed_driver_logs': [entry(LAUNCH / name) for name in ('driver.stdout.log', 'driver.stderr.log')],
              'runtime_environment_observation': entry(OUT / 'unit-discovery/runtime-environment-observation.json'),
              'retained_postvalidation_vm': entry(copied), 'retention_receipt': entry(vm_receipt),
              'seal_script': entry(Path(__file__)),
              'original_reports_plans_logs_or_manifests_overwritten': False,
              'old_47_25_and_interrupted_ff_evidence_modified': False,
              'remote_ci_executed': False, 'cold_cache_network_fetch_qualified': False,
              'ff_native_migration_gates_repeated': False, 'all_19_gates_requalified': False,
              'performance_requalified': False, 'model_experiments_or_downloads_executed': False}
    path = OUT / 'execution-completion.json'
    write(path, record)
    print(json.dumps({'completion_receipt': str(path), 'completion_sha256': sha(path),
          'summary_sha256': record['summary']['sha256'], 'manifest_sha256': record['original_manifest']['sha256'],
          'manifest_files_verified': len(manifest['files']), 'unit_methods': len(ids), 'unique_unit_methods': len(counts),
          'cargo_harness_summaries': len(cargo_rows), 'cargo_tests_passed': cargo_count,
          'source_before': record['source_before'], 'source_after': record['source_after'],
          'retained_vm': entry(copied), 'retention_receipt_sha256': sha(vm_receipt)}, sort_keys=True))


if __name__ == '__main__':
    main()
