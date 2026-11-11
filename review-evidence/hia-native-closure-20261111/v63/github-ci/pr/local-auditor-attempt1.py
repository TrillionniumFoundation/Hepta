"""Independent exact-source GitHub v63 audit; no native execution or project verifier imports.

Both push and PR are bound to their actual checked-out commit, the API Git tree,
and all frozen source blobs. Every nested archive member is independently read.
"""
from __future__ import annotations

import ast
from datetime import datetime, timezone
from hashlib import sha1, sha256
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import time
import zipfile

HERE = Path(sys.argv[1]).resolve()
REPO = HERE.parent.parent / 'Hepta'
HEAD = '93d66bcc3acb88212c9b153d7852ba22eeab24c8'
TREE = '0a67bf07951505a50e9aeb888f1c2c448d1eb816'
EXPECTED = {
    'push': {'run': 42965207061, 'checkout': HEAD, 'commit_file': 'commit-93.json'},
    'pr': {'run': 42965213564, 'checkout': 'd36fcb90c7b0b46fe9b5dfe391f18e57603e92dd',
           'commit_file': 'commit-pr-merge-d36.json'},
}[HERE.name]
RUN_ID = EXPECTED['run']
CHECKOUT = EXPECTED['checkout']
DOWNLOAD = json.loads((HERE / 'artifact-local.json').read_bytes())
ARTIFACT_ID = DOWNLOAD['artifact_id']
ZIP = Path(DOWNLOAD['path'])
ZIP_SHA = DOWNLOAD['sha256']
FAMILIES = ('capacity', 'cfg', 'elf', 'chain', 'owned', 'bulk', 'loan', 'resource',
            'tail', 'select', 'effects', 'multi', 'keyword', 'signed',
            'scalar-casts', 'explicit-traps', 'cli', 'names', 'exports')


def require(ok, why):
    if not ok:
        raise ValueError(why)


def unique(pairs):
    d = {}
    for k, v in pairs:
        require(k not in d, 'duplicate JSON key: ' + k)
        d[k] = v
    return d


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique)


def digest(raw):
    return sha256(raw).hexdigest()


def canonical(obj):
    return digest(json.dumps(obj, sort_keys=True, separators=(',', ':')).encode())


def file_digest(path):
    h = sha256()
    with path.open('rb') as f:
        while block := f.read(1 << 20):
            h.update(block)
    return h.hexdigest()


def runner_member(path):
    prefix = '/home/runner/work/_temp/'
    require(path.startswith(prefix), 'unexpected runner path: ' + path)
    name = path[len(prefix):]
    require('..' not in PurePosixPath(name).parts, 'unsafe runner member')
    return name


def git_blob_batch(names):
    args = [f'{TREE}:{p}' for p in names]
    result = subprocess.run(['git', '-C', str(REPO), 'cat-file', '--batch'],
                            input=('\n'.join(args) + '\n').encode(),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    stream = io.BytesIO(result.stdout)
    out = {}
    for path in names:
        line = stream.readline().decode().rstrip('\n')
        fields = line.split()
        require(len(fields) == 3 and fields[1] == 'blob', 'missing Git blob: ' + path)
        oid, _, size = fields
        data = stream.read(int(size))
        require(stream.read(1) == b'\n', 'Git batch framing')
        require(sha1(b'blob ' + size.encode() + b'\0' + data).hexdigest() == oid,
                'Git blob object identity: ' + path)
        out[path] = data
    require(not stream.read(), 'Git batch trailing data')
    return out


def main():
    started = time.monotonic_ns()
    result = {'schema': 'hia.independent-github-exact-run-audit.v1', 'status': 'FAIL',
              'audited_at_utc': datetime.now(timezone.utc).isoformat(),
              'program_sha256': file_digest(Path(__file__)),
              'workflow_head_commit': HEAD, 'actual_checkout_commit': CHECKOUT,
              'actual_checkout_tree': TREE, 'run_id': RUN_ID, 'artifact_id': ARTIFACT_ID,
              'native_execution_repeated': False,
              'project_verification_helpers_imported': False,
              'bound_profile_is_v63': True, 'whole_native_stack_complete': False,
              'inner_archive_payloads_independently_read': True}
    try:
        run = decode((HERE / 'run.json').read_bytes())
        head_commit = decode((HERE.parent / 'commit-93.json').read_bytes())
        checkout_commit = decode((HERE.parent / EXPECTED['commit_file']).read_bytes())
        require(head_commit['sha'] == HEAD and head_commit['tree']['sha'] == TREE,
                'workflow head API tree identity')
        require(checkout_commit['sha'] == CHECKOUT and checkout_commit['tree']['sha'] == TREE,
                'actual checkout API tree identity')
        jobs = decode((HERE / 'jobs.json').read_bytes())['jobs']
        artifacts = decode((HERE / 'artifacts.json').read_bytes())['artifacts']
        require(run['id'] == RUN_ID and run['head_sha'] == HEAD and run['run_attempt'] == 1,
                'run identity/attempt')
        require(run['status'] == 'completed' and run['conclusion'] == 'success', 'run status')
        require({j['name'] for j in jobs} == {'native', 'source'} and len(jobs) == 2,
                'job inventory')
        summaries = []
        for job in jobs:
            require(job['head_sha'] == HEAD and job['run_id'] == RUN_ID, 'job source identity')
            require(job['status'] == 'completed' and job['conclusion'] == 'success', 'job status')
            require(all(s['status'] == 'completed' and s['conclusion'] == 'success'
                        for s in job['steps']), 'non-success step')
            raw = (HERE / (job['name'] + '.log')).read_bytes()
            log = raw.decode('utf-8-sig')
            tests = []
            for timestamp, number, seconds in re.findall(
                    r'(?m)^(\S+) Ran (\d+) tests? in ([\d.]+)s\s*$', log):
                possible = [s for s in job['steps'] if s['started_at'] <= timestamp[:19]+'Z'
                            <= s['completed_at']]
                tests.append({'timestamp': timestamp, 'tests': int(number),
                              'seconds': float(seconds),
                              'step_numbers_at_timestamp': [s['number'] for s in possible]})
            lines = log.splitlines()
            observed_checkouts = []
            for i, line in enumerate(lines[:-1]):
                if 'git log -1 --format=%H' in line:
                    match = re.fullmatch(r'\S+ ([0-9a-f]{40})', lines[i + 1])
                    require(match is not None, 'checkout Git log framing')
                    observed_checkouts.append(match.group(1))
            require(observed_checkouts == [CHECKOUT], 'actual job checkout differs from pinned source')
            require('FAILED (' not in log and '##[error]' not in log, 'job error in full log')
            ok_count = len(re.findall(r'(?m)^\S+ OK\s*$', log))
            require(ok_count == len(tests), 'unittest OK/summary count')
            require('skipped=' not in log, 'unexpected unittest skipped summary')
            summaries.append({'id': job['id'], 'name': job['name'],
                              'started_at': job['started_at'], 'completed_at': job['completed_at'],
                              'conclusion': job['conclusion'], 'steps': job['steps'],
                              'actual_checkout_commit_from_log': CHECKOUT,
                              'decoded_log_sha256': digest(raw), 'decoded_log_bytes': len(raw),
                              'unittest_summaries': tests,
                              'unittest_total': sum(t['tests'] for t in tests),
                              'unittest_all_ok': True})
        artifact = next(a for a in artifacts if a['id'] == ARTIFACT_ID)
        require(artifact['workflow_run']['head_sha'] == HEAD
                and artifact['workflow_run']['id'] == RUN_ID, 'artifact run/head identity')
        require(artifact['name'] == 'hia-core-native-' + CHECKOUT + '-1',
                'artifact name does not bind actual GitHub checkout')
        require(artifact['size_in_bytes'] == ZIP.stat().st_size == DOWNLOAD['bytes'], 'artifact extent')
        require(file_digest(ZIP) == ZIP_SHA and artifact['digest'] == 'sha256:' + ZIP_SHA,
                'artifact digest')
        before = ZIP.stat()
        result['run'] = {k: run[k] for k in ('head_sha', 'status', 'conclusion', 'run_attempt',
                                            'created_at', 'run_started_at', 'updated_at', 'html_url')}
        result['jobs'] = summaries
        result['artifact'] = {'path': str(ZIP), 'sha256': ZIP_SHA, 'bytes': before.st_size,
                              'name': artifact['name'], 'download_digest_matches_github': True}
        with zipfile.ZipFile(ZIP) as z:
            names = z.namelist()
            require(len(names) == len(set(names)), 'duplicate outer ZIP member')
            cache = {}

            def raw(name):
                if name not in cache:
                    cache[name] = z.read(name)
                return cache[name]

            def obj(name):
                return decode(raw(name))

            cold = obj('hia-cold.json')
            nested_name = runner_member(cold['nested_report'])
            nested = obj(nested_name)
            require(digest(raw(nested_name)) == cold['nested_report_sha256'], 'nested digest')
            require(cold['status'] == 'COLD_SELFHOST_REPLAY_PASS' and cold['returncode'] == 0,
                    'cold outcome')
            require(len(cold['checks']) == 11 and all(v is True for v in cold['checks'].values()),
                    'cold checks')
            require(nested['status'] == 'SELF_HOSTED_FIXED_CORE_PASS'
                    and len(nested['checks']) == 5049 and all(v is True for v in nested['checks'].values()),
                    'nested checks')
            owner_name = 'hia-cold.cold/process-owner.json'
            owner = obj(owner_name)
            require({**owner, 'receipt_sha256': digest(raw(owner_name)), 'supervisor_returncode': 0}
                    == cold['process_owner'], 'owner receipt binding')
            require(owner['status'] == 'OWNED_PROCESS_COMPLETED' and owner['returncode'] == 0
                    and owner['exit_observed_before_deadline'] is True and owner['timed_out'] is False
                    and owner['cleanup']['complete'] is True and owner['cleanup']['observed_echild'] is True,
                    'process owner or cleanup')
            require(cold['qualification_wall_limit_seconds'] == owner['qualification_seconds'] == 180
                    and cold['cleanup_wall_limit_seconds'] == owner['cleanup_seconds'] == 3,
                    'deadline unchanged')
            pins = cold['source_manifest']
            require(len(pins) == 584 and pins == nested['source_manifest'], 'source pins')
            blobs = git_blob_batch(sorted(pins))
            source_bytes = 0
            for p, expected in pins.items():
                require(digest(blobs[p]) == expected, 'Git source pin: ' + p)
                require(raw('hia-cold.cold/source/' + p) == blobs[p], 'export source pin: ' + p)
                source_bytes += len(blobs[p])
            contract_path = 'docs/HIA_SELFHOST_CORE_SUPPORT.json'
            contract = decode(blobs[contract_path])
            require({**contract['source_identity']['files'], contract_path: digest(blobs[contract_path])}
                    == pins, 'source contract inventory')
            tree = ast.parse(blobs['tools/hia_selfhost_contract.py'])
            declared = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                            and any(isinstance(t, ast.Name) and t.id == 'SOURCE_FILES' for t in n.targets))
            git_paths = subprocess.check_output(['git', '-C', str(REPO), 'ls-tree', '-r', '--name-only', TREE]).decode().splitlines()
            require(set(declared) | {p for p in git_paths if p.startswith('hepta/') and p.endswith('.py')}
                    == set(contract['source_identity']['files']), 'complete declared source inventory')
            require(cold['profile'] == nested['profile'] == contract['profile']
                    == 'selfhost-core-linux-x86_64-v63-native-request-release-signatures-helpers', 'profile identity')
            chain = {}
            for key in ('generations', 'modified_generations'):
                rows = nested[key]
                require(len(rows) == 3, 'generation count')
                got = []
                for i, row in enumerate(rows):
                    label = ('B' if key == 'generations' else 'M') + str(i + 1)
                    require(row['case'] == label, 'generation label')
                    body = raw(runner_member(row['produced_image']))
                    require(digest(body) == row['produced_sha256'] and len(body) == row['produced_bytes'],
                            'generation exact bytes')
                    require(row['status'] == 'returned' and row['abi_status'] == 0
                            and row['source_unchanged'] is True and not row['forbidden_compiler_modules_loaded'],
                            'generation execution receipt')
                    got.append(digest(body))
                chain[key] = got
            b, m = chain['generations'], chain['modified_generations']
            require(b == cold['generation_sha256'] and m == cold['modified_generation_sha256']
                    and b[0] == b[1] == b[2] and m[0] != m[1] and m[1] == m[2] and m[2] != b[2],
                    'independent original and modified fixed points')
            idx = obj('hia-cold.cold/qualification.evidence/phase-index.json')
            require(idx['completed'] == 38 and idx['exceptions'] == 0 and len(idx['phases']) == 38,
                    'phase index outcome')
            expected = {(f, l) for f in FAMILIES for l in ('original', 'modified')}
            seen, pids, checks = set(), set(), set()
            archives = []
            binding = canonical(pins)
            for phase in idx['phases']:
                key = phase['family'], phase['compiler_label']
                require(key in expected and key not in seen, 'phase unique inventory')
                seen.add(key)
                require(phase['state'] == 'completed' and phase['report_status'] == 'PASS', 'phase state')
                process = obj(runner_member(phase['process_receipt']))
                request = obj(runner_member(phase['request']))
                report_name = runner_member(phase['report'])
                report = obj(report_name)
                require(digest(raw(report_name)) == process['report_sha256'], 'phase report digest')
                require(all((d['family'], d['compiler_label']) == key for d in (process, request, report)),
                        'phase label identity')
                require(report['status'] == 'PASS' and process['returncode'] == 0, 'phase pass')
                require(report['source_manifest_sha256'] == request['source_manifest_sha256'] == binding,
                        'phase source identity')
                require(report['input_sha256'] == {k: v['sha256'] for k, v in request['inputs'].items()},
                        'phase input receipt identity')
                for v in request['inputs'].values():
                    require(digest(raw(runner_member(v['path']))) == v['sha256'], 'phase input bytes')
                require(report['input_sha256']['compiler'] == (b[2] if key[1] == 'original' else m[2]),
                        'phase compiler identity')
                require(report['worker_pid'] == process['worker_pid'] and report['worker_pid'] not in pids,
                        'phase PID independence')
                pids.add(report['worker_pid'])
                require(report['fresh_host_oracle_process'] is True and report['successor_process_reuse'] is False,
                        'phase process declarations')
                require(report['checks'] and all(v is True for v in report['checks'].values())
                        and not checks.intersection(report['checks']), 'phase checks')
                require(all(nested['checks'].get(k) is True for k in report['checks']), 'phase merge')
                checks.update(report['checks'])
                receipt = process['raw_artifacts']
                archive_name = runner_member(receipt['archive'])
                packed = z.read(archive_name)
                require(digest(packed) == receipt['archive_sha256'] and len(packed) == receipt['packed_bytes'],
                        'compressed archive bytes')
                archived = obj(runner_member(request['directory']) + '/ARCHIVED.json')
                require(archived == receipt, 'stage retirement receipt')
                with zipfile.ZipFile(io.BytesIO(packed)) as inner:
                    inner_names = inner.namelist()
                    require(len(inner_names) == len(set(inner_names)), 'inner inventory duplicate')
                    manifest_raw = inner.read('HIA_ARCHIVE_MANIFEST.json')
                    manifest = decode(manifest_raw)
                    require(manifest['source_directory'] == request['directory']
                            and canonical(manifest) == receipt['manifest_sha256'], 'archive manifest binding')
                    require(set(inner_names) == set(manifest['files']) | {'HIA_ARCHIVE_MANIFEST.json'},
                            'archive complete manifest inventory')
                    require(len(manifest['files']) == receipt['files'], 'archive count')
                    total = 0
                    for name, row in manifest['files'].items():
                        info = inner.getinfo(name)
                        require(not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts,
                                'unsafe inner member')
                        require(not info.is_dir() and not (info.flag_bits & 1)
                                and stat.S_ISREG(info.external_attr >> 16), 'inner member type')
                        require(info.file_size == row['bytes'] and (info.external_attr >> 16) & 0o777 == row['mode'],
                                'inner member metadata')
                        member_hash, read_bytes = sha256(), 0
                        with inner.open(info) as member:
                            while chunk := member.read(1 << 20):
                                member_hash.update(chunk)
                                read_bytes += len(chunk)
                        require(read_bytes == row['bytes'] and member_hash.hexdigest() == row['sha256'],
                                'independent payload read, extent and SHA-256')
                        require('uid' not in row and 'gid' not in row and not info.extra,
                                'unexpected ownership fields require explicit interpretation')
                        total += read_bytes
                    require(total == manifest['unpacked_bytes'] == receipt['unpacked_bytes'], 'archive total metadata')
                archives.append({'phase': '-'.join(key), 'archive': archive_name,
                                 'sha256': receipt['archive_sha256'], 'packed_bytes_read': len(packed),
                                 'payload_members_declared': receipt['files'],
                                 'payload_uncompressed_bytes_declared': total,
                                 'manifest_bytes_independently_read': len(manifest_raw),
                                 'payload_bytes_independently_read': total,
                                 'every_payload_independently_read_to_eof': True,
                                 'payload_sha256_crc_size_mode_inventory_verified': True,
                                 'historical_payload_uid_gid_not_retained': True})
            require(seen == expected and len(pids) == 38, 'complete independent phase inventory')
            language = obj('hia-language.json')
            require(language['source_manifest'] == pins and language['profile'] == cold['profile'],
                    'language source binding')
            require(language['status'] == 'SELFHOST_LANGUAGE_COVERAGE_PASS'
                    and len(language['checks']) == 1242 and all(v is True for v in language['checks'].values()),
                    'language checks')
            assertions = obj('hia-language.assertions.json')
            require(assertions['report_sha256'] == digest(raw('hia-language.json')) and assertions['passed'] is True
                    and not assertions['errors'] and not assertions['failures'] and not assertions['skipped'],
                    'language assertions')
            install = obj('hia-release-install/observations.json')
            require(install['matching_cold_report'] == '/home/runner/work/_temp/hia-cold.json',
                    'installer cold report reference')
            require(install['whole_native_delivery_qualified'] is False, 'installer scope boundary')
            result['cold'] = {'status': cold['status'], 'sha256': digest(raw('hia-cold.json')),
                              'profile': cold['profile'], 'wall_elapsed_seconds': cold['wall_elapsed_ns'] / 1e9,
                              'wrapper_checks': len(cold['checks']), 'native_checks': len(nested['checks']),
                              'phase_checks': len(checks), 'completed_phases': len(seen),
                              'independent_phase_pids': len(pids), 'process_cleanup_observed_echild': True,
                              'deadline_seconds': 180, 'cleanup_seconds': 3,
                              'nested_sha256': digest(raw(nested_name))}
            result['source'] = {'workflow_head_commit': HEAD, 'actual_checkout_commit': CHECKOUT,
                                'git_tree_used_for_blob_reads': TREE, 'pins': len(pins),
                                'git_blob_bytes_independently_read': source_bytes,
                                'export_bytes_independently_read': source_bytes,
                                'all584_git_and_export_hashes_match': True,
                                'source_contract_sha256': digest(blobs[contract_path]),
                                'canonical_manifest_sha256': binding}
            result['compiler_fixed_points'] = chain
            result['phase_archives'] = {'compressed_and_manifest_validation': 'PASS',
                                        'payload_replay': 'PASS', 'archives': archives,
                                        'packed_bytes_read': sum(a['packed_bytes_read'] for a in archives),
                                        'payload_members_declared': sum(a['payload_members_declared'] for a in archives),
                                        'payload_uncompressed_bytes_declared': sum(a['payload_uncompressed_bytes_declared'] for a in archives),
                                        'manifest_member_bytes_read': sum(a['manifest_bytes_independently_read'] for a in archives),
                                        'payload_bytes_independently_read': sum(a['payload_bytes_independently_read'] for a in archives),
                                        'every_member_independently_opened_and_fully_read': True,
                                        'historical_payload_uid_gid_verified': False,
                                        'ownership_boundary': 'Original payload UID/GID are not retained in archive manifests or ZIP extras.'}
            result['language'] = {'status': language['status'], 'counts': language['counts'],
                                  'wall_elapsed_seconds': language['wall_elapsed_ns'] / 1e9,
                                  'assertions_tests': assertions['tests_run'], 'assertions_all_pass': True}
            result['installer'] = {'executable_sha256': install['executable_sha256'],
                                   'observations': len(install['observations']),
                                   'cases': sorted(set(x['case'] for x in install['observations'])),
                                   'whole_native_delivery_qualified': False}
            extracts = ('hia-cold.json', nested_name, 'hia-cold.cold/process-owner.json',
                        'hia-cold.cold/qualification.evidence/phase-index.json',
                        'hia-language.json', 'hia-language.assertions.json',
                        'hia-release-install/observations.json')
            for name in extracts:
                target = HERE / 'reports' / name
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as f:
                    f.write(raw(name))
            result['artifact']['outer_members'] = len(names)
            result['artifact']['outer_uncompressed_bytes'] = sum(i.file_size for i in z.infolist())
        after = ZIP.stat()
        require((before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                and file_digest(ZIP) == ZIP_SHA, 'artifact changed during audit')
        result['status'] = 'PASS'
    except Exception as exc:
        result['error'] = type(exc).__name__ + ': ' + str(exc)
    result['audit_elapsed_seconds'] = (time.monotonic_ns() - started) / 1e9
    with (HERE / 'audit.json').open('x') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
        f.write('\n')
    print(json.dumps({k: result.get(k) for k in ('status', 'workflow_head_commit', 'actual_checkout_commit', 'run_id', 'error',
                                               'audit_elapsed_seconds', 'cold', 'source', 'language')}, indent=2))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
