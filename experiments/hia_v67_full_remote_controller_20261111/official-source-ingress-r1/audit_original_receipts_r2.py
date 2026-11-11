"""Read and bind actual immutable ingress outputs; never execute remote work."""
from hashlib import sha256
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
REMOTE = '/home/qian-qi/he26v67-source-original-r1'
JOB = '1a1cb7a01ed-2564-b83'


def check(value, message):
    if not value:
        raise RuntimeError(message)


def unwrap(value):
    check(not value.get('isError'), 'original SDK payload reports an error')
    if value.get('structuredContent'):
        return value['structuredContent']
    return json.loads(next(x['text'] for x in value['content'] if x['type'] == 'text'))


def file_record(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def main():
    target = HERE / 'remote-originals-audited-r2'
    target.mkdir(mode=0o700, exist_ok=False)
    sdk = {name: unwrap(json.loads((HERE / (name + '-original-sdk.json')).read_bytes()))
           for name in ('terminal', 'file-info', 'job-output')}
    batch = sdk['terminal']
    check(batch.get('truncated') is False and batch.get('encoding') == 'utf-8', 'batch was truncated')
    expected_files = {
        REMOTE + '/ingress-terminal.json': 'ingress-terminal.json',
        REMOTE + '/guard/guardian.json': 'guardian.json',
        REMOTE + '/launch-intent.json': 'launch-intent.json',
        REMOTE + '/guard/child.stdout.log': 'child.stdout.log',
        REMOTE + '/guard/child.stderr.log': 'child.stderr.log',
    }
    check({row['path'] for row in batch['files']} == set(expected_files), 'original file inventory differs')
    outputs = {}
    records = {}
    for row in batch['files']:
        raw = row['text'].encode()
        check(row['eof'] is True and len(raw) == row['size'] and sha256(raw).hexdigest() == row['sha256'],
              'original raw UTF-8 bytes differ')
        name = expected_files[row['path']]
        with (target / name).open('xb') as stream:
            stream.write(raw)
        records[name] = {'remote_path': row['path'], 'bytes': len(raw), 'sha256': row['sha256']}
        outputs[name] = json.loads(raw) if name.endswith('.json') else raw
    result = sdk['job-output']
    check(result['job_id'] == JOB, 'job output belongs to another producer')
    for name in ('stdout', 'stderr'):
        row = result[name]
        raw = bytes.fromhex(row['bytes_hex'])
        check(row['eof'] is True and row['offset'] == 0 and len(raw) == row['size'] == row['next_offset'],
              'h original output is incomplete')
        with (target / ('h.' + name + '.log')).open('xb') as stream:
            stream.write(raw)
        records['h.' + name + '.log'] = {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
    status = unwrap(json.loads((HERE / 'h-status-r1.json').read_bytes()))
    check(status['job_id'] == JOB and status['state'] == 'succeeded' and status['exit_code'] == 0
          and status['output_complete'] is True and status['output_durable'] is True
          and status['timed_out'] is False and status['terminal_publication_confirmed'] is True,
          'authoritative producer did not terminate successfully')
    guardian = outputs['guardian.json']
    life = guardian['lifecycle']
    cleanup = life['cleanup']
    check(guardian['status'] == 'EXTERNAL_OWNED_PROCESS_COMPLETED'
          and guardian['external_controller_seconds'] == 900
          and guardian['cold_180_second_gate_modified'] is False
          and guardian['qualification'] is None and guardian['input_identity_preserved'] is True
          and guardian['source_identities_before'] == guardian['source_identities_after'],
          'guardian input/terminal condition differs')
    check(life['status'] == 'OWNED_PROCESS_COMPLETED' and life['returncode'] == 0
          and life['exit_observed_before_deadline'] is True and life['timed_out'] is False
          and life['subreaper_enabled'] is True and life['qualification_started'] is True
          and life['interrupted_signals'] == [] and not life.get('owner_error')
          and life['event_overflow'] is False, 'lifecycle did not naturally complete')
    allowed = {'qualification_started', 'owned_child_observed', 'qualification_exit_observed', 'owned_child_reaped'}
    check(life['events'] and all(x['kind'] in allowed for x in life['events']),
          'forced descendant kill or missing event history')
    check(cleanup['attempted'] is True and cleanup['complete'] is True
          and cleanup['observed_echild'] is True and cleanup['leader_reaped'] is True
          and cleanup['deadline_exceeded'] is False and cleanup['errors'] == []
          and cleanup['remaining_direct_children'] == [], 'kernel cleanup proof incomplete')
    for path, digest in guardian['logs'].items():
        check(path in expected_files and records[expected_files[path]]['sha256'] == digest,
              'guardian log digest differs')
    intent = outputs['launch-intent.json']
    for name, digest in intent['control_files'].items():
        check(sha256((HERE / name).read_bytes()).hexdigest() == digest
              and guardian['source_identities_before'][REMOTE + '/control/' + name] == digest,
              'executed source differs from local preexecution control')
    payload = (HERE / 'payload.private.json').read_bytes()
    check(sha256(payload).hexdigest() == intent['stdin_payload_sha256']
          == guardian['source_identities_before'][REMOTE + '/control/bootstrap-stdin.private.json'],
          'original private stdin binding differs')
    ingress = outputs['ingress-terminal.json']
    pins = json.loads((HERE / 'artifact-pins.json').read_bytes())
    artifact = pins['artifact']
    check(ingress['status'] == 'ORIGINAL_BYTES_VERIFIED_PENDING_NATURAL_GUARDIAN'
          and ingress['source_commit'] == pins['source_commit'] and ingress['source_tree'] == pins['source_tree']
          and ingress['artifact_id'] == artifact['artifact_id']
          and ingress['workflow_run_id'] == artifact['workflow_run_id']
          and ingress['run_attempt'] == artifact['run_attempt'], 'exact official artifact identity differs')
    check(ingress['download']['bytes'] == artifact['archive_bytes']
          and ingress['download']['sha256'] == artifact['archive_sha256']
          and ingress['download']['http_attempts'] == 1
          and ingress['download']['redirects'] == ingress['download']['retries'] == 0,
          'download receipt differs')
    before, after = ingress['zip_readback_before_members'], ingress['zip_readback_after_members']
    check(before == after and before['actual_bytes_independently_read'] == artifact['archive_bytes'],
          'two independent full ZIP reads are absent or unstable')
    live = sdk['file-info']
    check(live['path'] == before['path'] == ingress['download']['path']
          and live['size'] == before['bytes'] == artifact['archive_bytes']
          and live['sha256'] == before['sha256'] == artifact['archive_sha256']
          and live['mode'] == before['mode'] == 0o400
          and live['metadata']['uid'] == before['uid'] == 1000
          and live['metadata']['gid'] == before['gid'] == 1000
          and live['metadata']['link_count'] == before['nlink'] == 1,
          'independent live file-info differs from original source producer')
    check(live['version'] == ':'.join(str(before[x]) for x in ('device', 'inode', 'bytes', 'mtime_ns', 'ctime_ns')),
          'live original file binding differs')
    expected = {'package/' + name: row for name, row in artifact['package_files'].items()}
    expected.update(artifact['receipt_files'])
    members = ingress['member_verification']
    check(members['regular_member_count'] == 8 and members['actual_member_bytes_read'] == 300073828
          and {x['name'] for x in members['members']} == set(expected), 'eight-member denominator differs')
    for row in members['members']:
        check(row['bytes'] == expected[row['name']]['bytes']
              and row['sha256'] == expected[row['name']]['sha256']
              and row['posix_mode'] == 0o100644
              and row['actual_entire_member_read'] is True and row['crc_verified_by_zipfile'] is True,
              'an entire member was not read and verified')
    check(all(ingress[x] is False for x in ('source_materialization_requested', 'clone_requested',
          'prerequisite_preparation_requested', 'product_tests_requested', 'whole_native_delivery_qualified')),
          'transport scope expanded')
    audit = {'schema': 'hia.v67.official-source-original-independent-acceptance.v1',
             'status': 'ORIGINAL_ZIP_AND_EIGHT_MEMBERS_RETAINED_WITH_NATURAL_GUARDIAN',
             'job_id': JOB, 'host': 'desktop', 'source_commit': pins['source_commit'],
             'source_tree': pins['source_tree'], 'artifact_id': artifact['artifact_id'],
             'archive': live, 'members': members['members'], 'regular_member_count': 8,
             'member_bytes_actually_read_by_pinned_producer': 300073828,
             'zip_bytes_read_after_download_by_pinned_producer': 2 * artifact['archive_bytes'],
             'independent_live_file_info_full_hash_observed': True,
             'auditor_replayed_payload_members_locally': False,
             'auditor_verified_pinned_producer_full_reads_and_original_receipts': True,
             'multi_file_read_claimed_atomic': False,
             'download_seconds': ingress['download']['elapsed_ns'] / 1e9,
             'total_owned_driver_seconds': ingress['elapsed_ns'] / 1e9,
             'natural_guardian_exit_zero': True, 'observed_echild': True,
             'remaining_direct_children': [], 'forced_live_child_cleanup_accepted': False,
             'original_records': records,
             'sdk_payloads': {name: file_record(HERE / (name + '-original-sdk.json')) for name in sdk},
             'qualification_executed': False, 'whole_native_delivery_qualified': False}
    with (HERE / 'ACCEPTANCE.json').open('xb') as stream:
        stream.write((json.dumps(audit, indent=2, sort_keys=True) + '\n').encode())
    print(json.dumps({k: audit[k] for k in ('status', 'job_id', 'regular_member_count',
          'download_seconds', 'total_owned_driver_seconds')}, indent=2))


if __name__ == '__main__':
    main()
