"""Archive the exact small audit inputs and all attempts, without product execution."""
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile

BASE = Path('/tmp/hia-e26e-6e-ci-independent-review-r1')


def ident(p):
    s = p.lstat()
    assert stat.S_ISREG(s.st_mode) and not p.is_symlink()
    return [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def row(p):
    raw = p.read_bytes()
    return {'path': str(p.relative_to(BASE)), 'bytes': len(raw), 'mode': oct(stat.S_IMODE(p.stat().st_mode)),
            'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def save(path, obj):
    raw = (json.dumps(obj, sort_keys=True, indent=2) + '\n').encode()
    with path.open('xb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    assert path.read_bytes() == raw


def main():
    chosen = []
    for pattern in ('audit_6e_originals*.py', 'audit-r*.stdout.log', 'audit-r*.stderr.log', 'audit-r*.process.json',
                    'api-*.json', 'canonical-*.json', 'canonical-caller-source/*.py', 'blob-upload-*.json',
                    'audit-r1/*', 'audit-r2/*', 'audit-r3/*', 'audit-r4/*', 'preservation.*.log',
                    'preservation.process.json'):
        chosen.extend(BASE.glob(pattern))
    chosen.extend(BASE / n for n in ('ORIGINAL-ZIP-PRESERVATION.json', 'preserve_original_zip.py',
        'restore_original_zip.py', 'package_audit_originals.py', 'restore-roundtrip-r1/RESTORATION.json'))
    chosen = sorted(set(chosen))
    before = {str(p.relative_to(BASE)): ident(p) for p in chosen}
    files = [row(p) for p in chosen]
    archive = BASE / 'audit-originals.tar.xz'
    with archive.open('xb') as raw, tarfile.open(fileobj=raw, mode='w:xz', preset=6) as tar:
        for p, item in zip(chosen, files):
            data = p.read_bytes()
            info = tarfile.TarInfo(item['path'])
            info.size = len(data)
            info.mode = int(item['mode'], 8)
            info.uid = info.gid = info.mtime = 0
            tar.addfile(info, io.BytesIO(data))
    with archive.open('rb') as f:
        os.fsync(f.fileno())
    with tarfile.open(archive, 'r:xz') as tar:
        members = tar.getmembers()
        assert [m.name for m in members] == [i['path'] for i in files]
        for member, item in zip(members, files):
            assert member.isfile() and member.mode == int(item['mode'], 8)
            assert member.size == item['bytes'] and member.uid == member.gid == member.mtime == 0
            stream = tar.extractfile(member)
            assert stream is not None
            data = stream.read()
            assert hashlib.sha256(data).hexdigest() == item['sha256']
            assert data == (BASE / item['path']).read_bytes()
    assert before == {str(p.relative_to(BASE)): ident(p) for p in chosen}
    manifest = {'schema': 'hia.original-audit-inputs-and-results-archive.v1',
        'status': 'ALL_ORIGINAL_MEMBERS_READ_BACK', 'archive': row(archive),
        'files': files, 'file_count': len(files), 'decoded_bytes': sum(i['bytes'] for i in files),
        'all_member_bytes_modes_verified': True, 'input_identities_unchanged': True,
        'prior_three_audit_holds_retained': True, 'product_tests_rerun': False}
    save(BASE / 'AUDIT-ORIGINALS.json', manifest)
    original = json.loads((BASE / 'ORIGINAL-ZIP-PRESERVATION.json').read_bytes())
    final = BASE / 'audit-r4/AUDIT.json'
    assert json.loads(final.read_bytes())['status'] == 'ORIGINAL_EVIDENCE_INTEGRITY_VERIFIED'
    for name, source in [('AUDIT.json', final), ('RESTORATION.json', BASE / 'restore-roundtrip-r1/RESTORATION.json')]:
        data = source.read_bytes()
        with (BASE / name).open('xb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        assert (BASE / name).read_bytes() == data
    custody = {'schema': 'hia.original-ci-artifact-final-local-custody.v1',
        'status': 'FULL_ORIGINAL_AND_AUDIT_BYTES_VERIFIED', 'original': original['original'],
        'compressed': original['compressed'], 'parts': original['parts'],
        'audit': row(BASE / 'AUDIT.json'), 'restoration': row(BASE / 'RESTORATION.json'),
        'audit_originals_archive': row(archive), 'audit_originals_manifest': row(BASE / 'AUDIT-ORIGINALS.json'),
        'all_16_part_git_blobs_uploaded_with_expected_sha': all(json.loads((BASE / f'blob-upload-{i:03d}.json').read_bytes())['result']['sha'] == part['git_blob_sha1'] for i, part in enumerate(original['parts'])),
        'publication_ref_not_yet_created_at_this_receipt': True,
        'original_workflow_status': 'FAILURE', 'product_tests_rerun': False,
        'whole_native_delivery_qualified': False}
    assert custody['all_16_part_git_blobs_uploaded_with_expected_sha']
    save(BASE / 'CUSTODY.json', custody)
    text_names = ['README.md', 'AUDIT.json', 'RESTORATION.json', 'ORIGINAL-ZIP-PRESERVATION.json',
                  'AUDIT-ORIGINALS.json', 'CUSTODY.json', 'audit_6e_originals_r4.py',
                  'preserve_original_zip.py', 'restore_original_zip.py', 'package_audit_originals.py']
    publication = {'prefix': 'experiments/hia_v66_6e_ci_originals_20261111/',
        'parent': '6e048234e19e4dbf02d1cf5040831fba07748f02',
        'base_tree': '440f3fcb9014b2af6c788f78b993af6b25730d46',
        'text_files': [dict(row(BASE / name), content=(BASE / name).read_text()) for name in text_names],
        'binary_files': [row(archive)] + original['parts']}
    save(BASE / 'publication-payload.json', publication)
    print(json.dumps({'archive': row(archive), 'original_files': len(files), 'decoded_bytes': manifest['decoded_bytes'],
        'publication_files': len(text_names) + len(publication['binary_files'])}))


if __name__ == '__main__':
    main()
