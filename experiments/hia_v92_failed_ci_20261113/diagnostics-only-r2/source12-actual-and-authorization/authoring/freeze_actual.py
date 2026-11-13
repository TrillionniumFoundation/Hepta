"""Freeze already-closed source12 originals and independent reviews; no execution."""
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile

ROOT = Path('/home/agent/hia-v92-diagnostics-only-execution-ab-20261113-e26e')
FROZEN = Path('/home/agent/hia-v92-diagnostics-only-remote-r2-20261113-e26e')
ACTUAL = Path('/home/agent/hia-v92-source12-independent-readback-r2b-20261113-e26e')
ROOT_REVIEW = Path('/workspace/scratch/e26ed3e2edcf/root/v92-diagnostics-only-source12-r2b-review')
ROOT_INVOCATION = Path('/workspace/scratch/e26ed3e2edcf/root/v92-diagnostics-only-source12-r2b-invocation')
PEER = Path('/home/agent/hia-cold-peer-reviews-20261113-e26e/diagnostics-only-r2-custody-static-review.json')
AUTHOR = Path('/home/agent/hia-v92-diagnostics-source12-actual-authoring-20261113-e26e')
PARENT = 'e72669c33591bd73f5f3feb1c70425263855d34a'
PARENT_TREE = 'afb3bdc86e7499771b137435e8a5d3b1ce253645'
PREFIX = 'experiments/hia_v92_failed_ci_20261113/diagnostics-only-r2/source12-actual-and-authorization'


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode()


def identity(st):
    return [st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns]


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + bytes([0]) + raw).hexdigest()}


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_size <= 8 << 20, str(path)
        chunks = []
        left = before.st_size
        while left:
            chunk = os.read(fd, min(left, 1 << 20))
            assert chunk
            chunks.append(chunk)
            left -= len(chunk)
        assert not os.read(fd, 1)
        raw = b''.join(chunks)
        assert identity(before) == identity(os.fstat(fd)) == identity(os.stat(path, follow_symlinks=False))
        return raw, {'path': str(path), **pin(raw), 'identity': identity(before)}
    finally:
        os.close(fd)


def create(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    restored, observed = read(path)
    assert restored == raw
    return observed


def archive(records):
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0, compresslevel=6) as compressed:
        with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as stream:
            for name, raw, original in records:
                info = tarfile.TarInfo(name)
                st = original['identity']
                info.size = len(raw)
                info.mode = stat.S_IMODE(st[2])
                info.uid, info.gid = st[3:5]
                info.mtime = st[7] // 1_000_000_000
                info.pax_headers = {'mtime': f'{st[7] // 1_000_000_000}.{st[7] % 1_000_000_000:09d}'}
                stream.addfile(info, io.BytesIO(raw))
    raw = output.getvalue()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as stream:
        members = stream.getmembers()
        assert len(members) == len(records)
        for member, (name, expected, original) in zip(members, records):
            assert member.name == name and member.isfile()
            assert stream.extractfile(member).read() == expected
            assert (member.mode, member.uid, member.gid) == (stat.S_IMODE(original['identity'][2]), original['identity'][3], original['identity'][4])
    return raw


def main():
    payload = ROOT / 'payload'
    assert not payload.exists(), 'publication payload already exists; do not replay'
    actual_raw, actual_pin = read(ACTUAL / 'READBACK.json')
    actual = json.loads(actual_raw)
    root_raw, root_pin = read(ROOT_INVOCATION / 'READBACK.json')
    root = json.loads(root_raw)
    assert actual['status'] == 'SOURCE12_ACTUAL_READBACK_PASS_NOT_REMOTE_CUSTODY'
    assert root['status'] == 'SOURCE12_SYNTHETIC_IO_PASS_NOT_ARTIFACT_RECOVERY'
    assert root['source_methods'] == 12 and root['whole_output_entries'] == 918
    assert root['regular_files'] == 748 and root['full_regular_bytes'] == 8380495
    assert root['expected_loaded_executed_success_equal'] and root['all_five_anomalies_loader_and_forbidden_empty']
    assert root_pin['sha256'] == '4b923ea4739a0429a7112ba7a79ba82f414f8fc9fba93ddb54313338c3df4b0e'
    original_archive, original_archive_pin = read(ACTUAL / 'source12.actual-originals.tar.gz')
    assert original_archive_pin['sha256'] == 'c7989555f56414cf9e6692fb417a697ca1e52c91002e6fd25f587ce9981029d8'
    peer_raw, peer_pin = read(PEER)
    assert peer_pin['sha256'] == '9e2e8adb39993fd3c5b2b1b66beeb6c59f70584aafa9d8b6a244ec6ec62dcf96'
    records = []
    for label, directory in [('root-review', ROOT_REVIEW), ('root-invocation', ROOT_INVOCATION),
                             ('independent-authoring', AUTHOR)]:
        for path in sorted(directory.rglob('*')):
            if path.is_dir():
                assert not path.is_symlink()
                continue
            raw, observed = read(path)
            records.append((label + '/' + path.relative_to(directory).as_posix(), raw, observed))
    for name in ('READBACK.json', 'ARCHIVE-MANIFEST.json'):
        raw, observed = read(ACTUAL / name)
        records.append(('independent-actual/' + name, raw, observed))
    records.append(('peer/diagnostics-only-r2-custody-static-review.json', peer_raw, peer_pin))
    for name in ('CANONICAL.json', 'PLAN.r2b.json', 'RAW-READBACK.json',
                 'EVIDENCE-REF-INTENT.json', 'EVIDENCE-REF-ACK.json', 'EVIDENCE-REF-READBACK.json'):
        raw, observed = read(FROZEN / 'publication' / name)
        records.append(('request-publication/' + name, raw, observed))
    raw, observed = read(Path(__file__))
    records.append(('authoring/freeze_actual.py', raw, observed))
    records.sort(key=lambda item: item[0])
    assert len({item[0] for item in records}) == len(records)
    proofs = archive(records)
    archives = []
    for name, archive_raw, count, size in [
        ('source12.actual-originals.tar.gz', original_archive, 918, 8380495),
        ('source12.audit-and-authorization-originals.tar.gz', proofs, len(records), sum(len(item[1]) for item in records))]:
        archive_path = ROOT / 'archives' / name
        archive_pin = create(archive_path, archive_raw)
        pieces = []
        rebuilt = bytearray()
        for index, offset in enumerate(range(0, len(archive_raw), 196608)):
            body = archive_raw[offset:offset + 196608]
            filename = 'archives/' + name + f'.part-{index:02d}.base64'
            encoded = base64.b64encode(body) + b'\n'
            part_pin = create(payload / filename, encoded)
            decoded = base64.b64decode(encoded[:-1], validate=True)
            assert decoded == body
            rebuilt.extend(decoded)
            pieces.append({'path': filename, 'offset': offset, 'decoded_bytes': len(body),
                           'decoded_sha256': hashlib.sha256(body).hexdigest(), **pin(encoded)})
        assert bytes(rebuilt) == archive_raw
        archives.append({'name': name, **pin(archive_raw), 'members': count, 'regular_bytes': size,
                         'parts': pieces, 'full_archive_reread': True})
    proof_inventory = [{'archive_path': name, **observed} for name, _, observed in records]
    create(payload / 'archives/MANIFEST.json', encode({'schema': 'hia.v92.source12.complete-archives.v1',
        'source_request_commit': PARENT, 'archives': archives, 'proof_originals': proof_inventory,
        'original_actual_symlink_and_hardlink_topology': 'ARCHIVE-MANIFEST.json in proof archive; actual aliases retain complete bodies',
        'originals_deleted_or_modified': False}))
    for name, source in [('authoring/audit_source12.py', AUTHOR / 'audit_source12.py'),
                         ('authoring/freeze_actual.py', Path(__file__)),
                         ('root/ROOT-REVIEW.json', ROOT_REVIEW / 'ROOT-REVIEW.json'),
                         ('root/audit_actual.py', ROOT_REVIEW / 'audit_actual.py'),
                         ('root/invoke_once.py', ROOT_REVIEW / 'invoke_once.py'),
                         ('root/OWNER-FIRST-READBACK.json', ROOT_INVOCATION / 'OWNER-FIRST-READBACK.json'),
                         ('peer/diagnostics-only-r2-custody-static-review.json', PEER)]:
        raw, _ = read(source)
        create(payload / name, raw)
    source_review = []
    for path in sorted((FROZEN / 'candidate').iterdir()):
        if path.suffix not in ('.py', '.yml'):
            continue
        raw, observed = read(path)
        text = raw.decode()
        hits = [{'line': number, 'text': line} for number, line in enumerate(text.splitlines(), 1)
                if 'capacity_scope' in line or 'downstream_acceptance' in line]
        assert not hits
        source_review.append({**observed, 'matching_references': hits})
    policy_raw, policy_pin = read(FROZEN / 'candidate/policy.json')
    policy = json.loads(policy_raw)
    assert policy['parts'] == [] and policy['partition_files_created'] is False
    create(payload / 'POLICY-PROSE-REVIEW.json', encode({
        'schema': 'hia.v92.diagnostics-only.inherited-prose-correction.v1',
        'status': 'STATIC_ONLY_NO_FROZEN_SOURCE_OR_POLICY_CHANGE', 'policy': policy_pin,
        'inaccurate_inherited_fields': {k: policy[k] for k in ['capacity_scope', 'downstream_acceptance']},
        'complete_current_python_and_workflow_reference_scan': source_review,
        'field_names_not_read_by_runtime_or_renderer': True,
        'whole_policy_identity_hashing_and_archival_are_preserved': True,
        'actual_executable_scope': {'parts': [], 'partition_files_created': False,
            'one_small_upload': True, 'selected_originals': 460, 'metadata_files': 3,
            'original_missing_reports': policy['expected_diagnostics']['missing_expected']},
        'correction': 'These two descriptive strings retain old three-part wording. They are not dispatch or admission predicates. The frozen executable request has no partition production and exactly one small artifact; no historical receiver status is upgraded.'}))
    summary = {'schema': 'hia.v92.source12-actual-and-remote-readiness.v1',
        'status': 'SOURCE12_ACTUAL_PASS_REMOTE_NOT_TRIGGERED',
        'source_request_commit': PARENT, 'source_request_sha256': actual['source_request_sha256'],
        'expected_loaded_executed_success': 12, 'all_anomalies_and_forbidden_attempts_empty': True,
        'seconds': root['seconds'], 'owner': {'wall_seconds': 20, 'cleanup_seconds': 3,
            'natural_exit_zero': True, 'observed_echild': True, 'remaining_children': [], 'events': 4},
        'actual_typed_entries': 918, 'actual_regular_files': 748, 'actual_regular_bytes': 8380495,
        'independent_checks': len(actual['checks']), 'independent_audit': actual_pin,
        'root_audit': root_pin, 'archive_manifest': pin((payload / 'archives/MANIFEST.json').read_bytes()),
        'positive_synthetic_zip_members': 462, 'positive_selected_originals': 460,
        'positive_selected_bytes': 3012789, 'positive_metadata_files': 3,
        'missing_reports': root['missing5'], 'network_or_product_or_native_executions': 0,
        'source_execution_scope': 'Synthetic local 3.12.14 file/ZIP/owner controls; not actual official artifact recovery or 3.14.4 remote execution.',
        'old_remote_recovery_run_43338002642': 'HOLD_NOT_RECLASSIFIED',
        'old_local_R4_session73219': 'UNKNOWN_NOT_RECLASSIFIED',
        'next_A': {'sole_parent': PARENT, 'parent_tree': PARENT_TREE, 'all4484_parent_leaves_preserved': True,
            'prefix': PREFIX, 'only_new_actual_and_review_paths': True},
        'next_B': {'sole_parent': 'ACTUAL_READBACK_A',
            'only_new_path': '.github/workflows/hia-v92-failed-ci-diagnostics-only-r2-isolated.yml',
            'frozen_renderer': 'candidate/render_workflow.py', 'control_commit_substitutions': 4,
            'policy_sha_substitutions': 3, 'policy_sha256': policy_pin['sha256'],
            'trigger_branch': policy['trigger_branch'], 'Root_is_sole_trigger': True,
            'trigger_created': False, 'artifact_GETs': 0}}
    create(payload / 'HANDOFF.json', encode(summary))
    files = []
    for path in sorted(payload.rglob('*')):
        if path.is_file():
            raw, observed = read(path)
            files.append({'path': path.relative_to(payload).as_posix(), 'repository_path': PREFIX + '/' + path.relative_to(payload).as_posix(),
                          'mode': '100644', 'type': 'blob', **pin(raw), 'local_path': str(path)})
    manifest = {'schema': 'hia.v92.source12-actual-publication-files.v1', 'parent': PARENT,
                'base_tree': PARENT_TREE, 'prefix': PREFIX, 'files': files,
                'all_old_leaves_unchanged': 4484, 'file_count_excluding_self': len(files),
                'bytes_excluding_self': sum(row['bytes'] for row in files)}
    create(payload / 'MANIFEST.json', encode(manifest))
    raw, _ = read(payload / 'MANIFEST.json')
    files.append({'path': 'MANIFEST.json', 'repository_path': PREFIX + '/MANIFEST.json',
                  'mode': '100644', 'type': 'blob', **pin(raw), 'local_path': str(payload / 'MANIFEST.json')})
    create(ROOT / 'publication/FILES.json', encode({'files': files, 'file_count': len(files),
        'bytes': sum(row['bytes'] for row in files), 'parent': PARENT, 'base_tree': PARENT_TREE, 'prefix': PREFIX}))
    print(json.dumps({'status': 'FROZEN_ALREADY_EXECUTED_SOURCE12_EVIDENCE_ONLY',
        'files': len(files), 'bytes': sum(row['bytes'] for row in files),
        'archives': [{k: v for k, v in item.items() if k != 'parts'} for item in archives]}))


if __name__ == '__main__':
    main()
