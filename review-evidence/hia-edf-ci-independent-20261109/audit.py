"""Read original candidate CI ZIP, checking identities without running native code."""
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import zipfile

ARCHIVE = Path('/workspace/scratch/5e86aa42d2b9/original-exact-source-edf48dc.zip')
SOURCE = Path('/workspace/scratch/5e86aa42d2b9/followup-convergence')
OUTPUT = Path(__file__).resolve().parent
HEAD = 'edf48dcf9190b177740eb2802c26f24cfec3c936'
TREE = '03fed48a967fd33a2cd864c2ac5db8616abb1724'
ENV = dict(os.environ, GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0')

def git(*args):
    return subprocess.check_output(['git', '-C', str(SOURCE), *args], env=ENV, timeout=4)

def digest(data):
    return sha256(data).hexdigest()

def check(condition, name):
    if not condition:
        raise AssertionError(name)

def main():
    check(git('rev-parse', 'HEAD^{tree}').decode().strip() == TREE, 'actual local tree differs')
    check(ARCHIVE.stat().st_size == 38116519, 'archive size')
    archive_sha = digest(ARCHIVE.read_bytes())
    check(archive_sha == 'd053d024bc07cea7a6f290c385ee48ae6a9acee7ce3b0832a0629c8c1a350494', 'archive digest')
    with zipfile.ZipFile(ARCHIVE) as z:
        check(z.testzip() is None, 'CRC')
        names = z.namelist()
        check(len(names) == len(set(names)), 'duplicate ZIP member')
        read_json = lambda name: json.loads(z.read(name))
        cold = read_json('cold-selfhost')
        full = read_json('cold-selfhost.cold/qualification.json')
        language = read_json('selfhost-language.json')
        assertions = read_json('selfhost-language.assertions.json')
        lock_bytes = z.read('release-lock.json')
        lock = json.loads(lock_bytes)
        source = z.read('source.txt').decode().splitlines()
        check(source == [HEAD, TREE], 'source.txt exact head/tree')
        check(digest(z.read('cold-selfhost.cold/qualification.json')) == cold['nested_report_sha256'], 'nested report binding')
        check(cold['source_manifest'] == full['source_manifest'] == language['source_manifest'], 'cold/full/language source manifest differs')
        manifest = cold['source_manifest']
        check(len(manifest) == 253, 'source inventory length')
        records = {}
        for path, expected in manifest.items():
            actual = git('cat-file', 'blob', 'HEAD:' + path)
            check(digest(actual) == expected, 'actual Git source digest: ' + path)
            exported = z.read('cold-selfhost.cold/source/' + path)
            check(exported == actual, 'cold exported original source bytes: ' + path)
            records[path] = expected
        for report in (cold, full, language):
            check(report['profile'] == 'selfhost-core-linux-x86_64-v16', 'profile')
            check(all(v is True for v in report['checks'].values()), 'qualification checks')
        check(cold['status'] == 'COLD_SELFHOST_REPLAY_PASS', 'cold status')
        check(full['status'] == 'SELF_HOSTED_FIXED_CORE_PASS', 'nested status')
        check(language['status'] == 'SELFHOST_LANGUAGE_COVERAGE_PASS', 'language status')
        check(cold['qualification_wall_limit_seconds'] == 180 and cold['cleanup_wall_limit_seconds'] == 3, 'original deadlines')
        check(cold['wall_elapsed_ns'] < 180 * 10**9, 'cold actual elapsed within original contract')
        owner = cold['process_owner']
        owner_bytes = z.read('cold-selfhost.cold/process-owner.json')
        retained_owner = json.loads(owner_bytes)
        check(all(owner[k] == v for k, v in retained_owner.items()), 'retained process owner differs')
        check(digest(owner_bytes) == owner['receipt_sha256'], 'process receipt digest')
        request_bytes = z.read('cold-selfhost.cold/process-owner.json.request.json')
        request = json.loads(request_bytes)
        check(digest(request_bytes) == owner['request_sha256'], 'process request digest')
        check(request['qualification_seconds'] == 180 and request['cleanup_seconds'] == 3, 'request deadlines')
        check(request['deadline_ns'] - request['started_ns'] == 180 * 10**9, 'absolute qualification deadline')
        check(owner['status'] == 'OWNED_PROCESS_COMPLETED' and owner['returncode'] == 0 and owner['supervisor_returncode'] == 0, 'process completion')
        check(owner['exit_observed_before_deadline'] is True and owner['timed_out'] is False, 'process within deadline')
        cleanup = owner['cleanup']
        check(cleanup['complete'] is True and cleanup['observed_echild'] is True and cleanup['leader_reaped'] is True, 'cleanup/reap/ECHILD')
        check(cleanup['errors'] == [] and cleanup['remaining_direct_children'] == [] and cleanup['deadline_exceeded'] is False, 'no live owned direct children')
        check(cleanup['elapsed_ns'] < 3 * 10**9, 'cleanup elapsed')
        check(owner['implementation_sha256'] == manifest['tools/hia_selfhost_process_owner.py'], 'process implementation pin')
        # Read every phase report named by the full cold qualification receipt.
        phases = full['qualification_scheduling']['phases']
        for phase in phases:
            label = phase['family'] + '-' + phase['compiler_label']
            data = z.read('cold-selfhost.cold/qualification.evidence/phase-' + label + '.json')
            check(digest(data) == phase['report_sha256'] and phase['returncode'] == 0, 'phase receipt: ' + label)
        generated = []
        for prefix, report in [('cold-selfhost.cold/qualification.evidence/', full), ('selfhost-language.evidence/', language)]:
            for field in ('generations', 'modified_generations'):
                rows = report[field]
                hashes = [row['produced_sha256'] for row in rows]
                check(len(rows) == 3, 'three generations')
                check(hashes[0] == hashes[1] == hashes[2] if field == 'generations' else hashes[0] != hashes[1] == hashes[2], 'fixed/modified generation hashes')
                for row in rows:
                    name = Path(row['produced_image']).name
                    check(digest(z.read(prefix + name)) == row['produced_sha256'], 'produced image: ' + prefix + name)
                    check(row['source_unchanged'] is True and row['forbidden_compiler_modules_loaded'] == [], 'actual successor source boundary')
                    generated.append({'path': prefix + name, 'sha256': row['produced_sha256']})
        check(full['generations'][1]['produced_sha256'] != full['modified_generations'][1]['produced_sha256'], 'compiler mutation differs')
        check(language['reference']['scalar_cases'] == 1183, 'scalar witness inventory')
        ref = z.read('selfhost-language.evidence/independent-reference.json')
        check(digest(ref) == language['reference']['sha256'], 'language independent reference digest')
        check(assertions['report_sha256'] == digest(z.read('selfhost-language.json')), 'native assertions report binding')
        check(assertions['passed'] is True and assertions['tests_run'] == 10 and not assertions['errors'] and not assertions['failures'] and not assertions['skipped'], 'native report assertions')
        check(lock['sources']['hepta'] == {'commit': HEAD, 'tree': TREE, 'repository': 'https://github.com/TrillionniumFoundation/Hepta.git'}, 'release source pin')
        check(lock['sources']['runtime']['commit'] == '4cd85c99c5f5a480832c48fbde8561bb365f67a9' and lock['sources']['runtime']['tree'] == '6b78d53b53d51a6c070bb37e8e9f6a15ad26d0e8', 'runtime source identity')
        check(lock['selfhost']['profile'] == full['profile'] and lock['selfhost']['support_matrix_sha256'] == manifest['docs/HIA_SELFHOST_CORE_SUPPORT.json'], 'release profile/support identity')
        check(digest(lock_bytes) == z.read('release-lock.sha256').decode().split()[0], 'original release lock digest')
        release_checked, release_unavailable = {}, []
        for path, expected in lock['files']['hepta'].items():
            try:
                data = git('cat-file', 'blob', 'HEAD:' + path)
            except (subprocess.SubprocessError, OSError):
                release_unavailable.append(path)
                continue
            check(digest(data) == expected, 'release file digest: ' + path)
            release_checked[path] = expected
        check(lock['qualification']['source_lock_only'] is True and all(v is False for k,v in lock['qualification'].items() if k != 'source_lock_only'), 'release HOLD scope')
        result = {'schema': 'hepta.hia.edf48dc-independent-source-ci-audit.v1', 'status': 'PASS_SCOPED_CANDIDATE_ARTIFACT_IDENTITY_AUDIT',
            'workflow_run': 42574596830, 'artifact_id': 13654684567, 'run_attempt': 1, 'candidate_head': HEAD, 'tree': TREE,
            'archive': {'bytes': ARCHIVE.stat().st_size, 'sha256': archive_sha, 'members': len(names), 'crc_pass': True},
            'source_entries_verified_against_git_and_cold_export': len(records), 'all_three_report_manifests_equal': True,
            'cold': {'checks_passed': len(cold['checks']), 'elapsed_ns': cold['wall_elapsed_ns'], 'qualification_limit_seconds': 180, 'cleanup_limit_seconds': 3, 'cleanup_elapsed_ns': cleanup['elapsed_ns'], 'observed_echild': True, 'historical_descendant_inventory_complete': owner['historical_descendant_inventory_complete']},
            'full_nested_qualification': {'checks_passed': len(full['checks']), 'elapsed_ns': full['elapsed_ns'], 'phase_receipts_verified': len(phases), 'standalone_warm_report_present': False},
            'language': {'counts': language['counts'], 'elapsed_ns': language['wall_elapsed_ns'], 'native_report_assertions': assertions},
            'generated_images_verified': generated, 'release_lock': {'bytes': len(lock_bytes), 'sha256': digest(lock_bytes), 'hepta_files_total': len(lock['files']['hepta']), 'hepta_files_independently_verified': len(release_checked), 'hepta_files_unavailable': release_unavailable, 'runtime_files': len(lock['files']['runtime']), 'runtime_files_independently_verified': False, 'sources': lock['sources'], 'installation': lock['installation'], 'qualification': lock['qualification']},
            'claims': {'candidate_artifact_only': True, 'merged_source_lock': False, 'new_native_execution': False, 'cold_run_repeated': False, 'whole_core_or_compiler_theorem': False, 'hardware_or_loader_attestation': False, 'online_identity': False, 'agent_adoption': False, 'provider_billing': False, 'economic_benefit': False}}
        (OUTPUT/'audit.json').write_text(json.dumps(result, indent=2, sort_keys=True)+'\n')
        (OUTPUT/'source-identities.json').write_text(json.dumps({'qualification': records, 'release_hepta': release_checked}, indent=2, sort_keys=True)+'\n')
        print(json.dumps({k:result[k] for k in ['status','source_entries_verified_against_git_and_cold_export','cold','full_nested_qualification']}))
        print(json.dumps({'release_hepta_files_verified':len(release_checked), 'release_hepta_unavailable':release_unavailable, 'language_checks':language['counts']['checks_passed']}))

if __name__ == '__main__':
    main()
