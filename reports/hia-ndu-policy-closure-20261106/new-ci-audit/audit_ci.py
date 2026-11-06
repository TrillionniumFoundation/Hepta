"""Independently verify the retained PR761 native CI artifact and its source."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import zipfile


ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent / 'hepta-ndu-next'
HEAD = 'a07c5ecae52436234af370779cc440686dbe4139'
UPSTREAM = '8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d'
ARCHIVE_SHA = '22d2a19015f5fea82e62480c956c26d2a5cf437b5fadef509e16640d8739eda7'


def check(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    path = ROOT / 'pr761-ndu-feedback-a07c5ec.zip'
    data = path.read_bytes()
    check(len(data) == 2914149 and sha(data) == ARCHIVE_SHA, 'hosted artifact identity')
    summary = {'schema': 'hepta.ndu.pr761-native-ci-independent-audit.v1',
               'checked_at_utc': datetime.now(timezone.utc).isoformat(), 'passed': False,
               'head_sha': HEAD, 'source_tree': '273e7c458713ede9593c03267245a5bf756fc4f7',
               'run_id': 42205882393, 'job_id': 127852267161, 'artifact_id': 13495254839,
               'run_url': 'https://github.com/TrillionniumFoundation/Hepta/actions/runs/42205882393',
               'job_url': 'https://github.com/TrillionniumFoundation/Hepta/actions/runs/42205882393/job/127852267161',
               'zip_bytes': len(data), 'zip_sha256': sha(data), 'authority': 'DENY_ALL',
               'scope': 'Retained original hosted CI; no scientific or timing experiment rerun.',
               'full_repository_green_claim': False, 'production_activation': False}
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        check(len(names) == len(set(names)), 'duplicate archive names')
        check(all(not PurePosixPath(n).is_absolute() and '..' not in PurePosixPath(n).parts for n in names), 'unsafe archive path')
        inventory = json.loads(archive.read('artifact-inventory.json'))['files']
        check(set(names) == set(inventory) | {'artifact-inventory.json'}, 'artifact inventory completeness')
        for name, entry in inventory.items():
            raw = archive.read(name)
            check(len(raw) == entry['bytes'] and sha(raw) == entry['sha256'], 'output identity: ' + name)
        summary.update(zip_members=len(names), output_hashes_verified=len(inventory), all_output_hashes_verified=True)
        before = json.loads(archive.read('source-before.json'))
        after = json.loads(archive.read('source-after.json'))
        for source in (before, after):
            check(source['head'] == source['expected_head'] == HEAD and source['matches_expected_head'] is True
                  and source['clean'] is True and not source['status_porcelain'], 'source head/clean state')
        check(after['matches_before'] is True and before['files'] == after['files'], 'source before/after drift')
        # Compare all recorded source hashes to immutable Git object bytes, not
        # just to another receipt or an actively edited worktree.
        process = subprocess.Popen(['git', '--no-replace-objects', 'archive', '--format=tar', HEAD],
                                   cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        source_files = {}
        with tarfile.open(fileobj=process.stdout, mode='r|') as git_archive:
            for member in git_archive:
                if member.isdir():
                    continue
                if member.issym():
                    raw = member.linkname.encode()
                    entry = {'mode': '120000', 'bytes': len(raw), 'sha256': sha(raw)}
                else:
                    check(member.isfile(), 'unexpected Git archive member')
                    stream = git_archive.extractfile(member)
                    h = hashlib.sha256()
                    size = 0
                    while chunk := stream.read(1024 * 1024):
                        size += len(chunk)
                        h.update(chunk)
                    entry = {'mode': '100755' if member.mode & 0o111 else '100644',
                             'bytes': size, 'sha256': h.hexdigest()}
                source_files[member.name] = entry
        check(process.wait(timeout=60) == 0, 'Git archive source read failed')
        check(source_files == before['files'], 'hosted source bytes differ from exact Git objects')
        summary.update(source_files_verified_against_git=len(source_files), source_before_after_identical=True)
        suites = {}
        for suite in ('reference-tests', 'native-tests'):
            receipt = json.loads(archive.read(suite + '/receipt.json'))
            log = archive.read(suite + '/unittest.log')
            ids = receipt['test_ids']
            check(sha(log) == receipt['log']['sha256'] and len(log) == receipt['log']['bytes'], 'test log identity')
            logged = re.findall(r'^test\S+ \(([^\n]+)\) \.\.\. ok$', log.decode(), flags=re.MULTILINE)
            check(logged == ids and len(ids) == len(set(ids)) == receipt['tests_run'], 'actual test IDs/count')
            check(receipt['all_passed_zero_skips'] is True and all(receipt[field] == 0 for field in
                  ('failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes')), 'test outcome')
            check(log.decode().rstrip().endswith('\nOK'), 'test terminal outcome')
            suites[suite] = set(ids)
        unique = suites['reference-tests'] | suites['native-tests']
        overlap = suites['reference-tests'] & suites['native-tests']
        check(len(unique) == 184 and len(overlap) == 7, 'unique test count')
        summary.update(reference_tests=len(suites['reference-tests']), native_tests=len(suites['native-tests']),
                       shared_test_ids=len(overlap), unique_tests=len(unique), failures=0, errors=0, skipped=0)
        guards = json.loads(archive.read('source-guard-controls/receipt.json'))
        check(guards['passed'] is True and guards['required_head_cli_rejected'] is True
              and len(guards['controls']) == 4 and all(v['rejected'] is True for v in guards['controls'].values()), 'source guards')
        summary['wrong_head_and_synthetic_merge_rejected'] = True
        builds = {}
        for profile in ('value', 'workload'):
            build = json.loads(archive.read('build-receipts/' + profile + '/build-receipt.json'))
            check(build['upstream']['commit'] == UPSTREAM and all(build[field] is True for field in
                  ('original_rust_sources_unchanged', 'all_original_non_manifest_inputs_unchanged', 'build_inputs_unchanged')), 'original build pin')
            builds[profile] = build['binary_sha256']
        smoke = json.loads(archive.read('native-smoke.json'))
        check(smoke['passed'] is True and smoke['native_returncode'] == 0 and smoke['skipped'] == 0, 'native smoke')
        sessions = {}
        for name, profile in (('engine-native.jsonl', 'value'), ('workload-native.jsonl', 'workload')):
            rows = [json.loads(line) for line in archive.read(name).splitlines()]
            hello, close = rows[0], rows[-1]
            check(hello['event'] == 'hello' and hello['binary_sha256'] == builds[profile], 'executed native binary binding')
            check(close['event'] == 'close' and close['returncode'] == 0 and close['reaped'] is True, 'native close')
            exchanges = [row for row in rows if row['event'] == 'exchange']
            check(len(exchanges) == close['calls'], 'native exchange count')
            for index, row in enumerate(exchanges, 1):
                check(row.get('sequence', row.get('index')) == index, 'native sequence')
                for field in ('request', 'response'):
                    check(sha(row[field].encode()) == row[field + '_sha256'], 'native frame hash')
                response = json.loads(row['response'])
                if profile == 'value':
                    check(response['request_sha256'] == row['request_sha256'] and response['upstream_commit'] == UPSTREAM,
                          'native response binding')
            sessions[profile] = len(exchanges)
        check(sessions['value'] == smoke['native_calls'] == 430, 'native call receipt')
        episode = json.loads(archive.read('native-workload-episode.json'))
        lifecycle = json.loads(archive.read('native-workload-lifecycle.json'))
        check(episode['planned_requests'] == episode['delivered'] == len(lifecycle['rows']) == 2, 'real workload denominator')
        check(all(row['status'] == 'success' and row['output_elements_checked'] == 16 for row in lifecycle['rows']), 'actual output checks')
        check(episode['actual_cost'] == sum(row['workload_wall_ns'] for row in lifecycle['rows']), 'actual feedback accounting')
        summary.update(native_exchange_counts=sessions, original_builds_verified=True,
                       physical_smoke_requests=2, physical_output_elements_checked=32,
                       physical_smoke_scope='Uncalibrated execution smoke, not performance or full-policy confirmation.',
                       passed=True)
    log = (ROOT / 'job-127852267161.log').read_bytes()
    summary['original_job_log'] = {'bytes': len(log), 'sha256': sha(log)}
    output = ROOT / 'AUDIT.json'
    with output.open('x', encoding='utf-8') as stream:
        json.dump(summary, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
