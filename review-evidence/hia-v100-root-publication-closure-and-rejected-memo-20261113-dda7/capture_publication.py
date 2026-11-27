from pathlib import Path
import base64
import hashlib
import json
import stat
import zlib

ROOT = Path(__file__).resolve().parent
TARGET = ROOT / 'v100-root-closure'


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def main():
    TARGET.mkdir()
    selected = []
    for name in ('v97-mount', 'v98-addendum', 'v99-reference-recovery-r1',
                 'v99-incremental-v97', 'v99-complete-attempt'):
        selected += [p for p in (ROOT / name).rglob('*') if p.is_file()]
    selected += [ROOT / name for name in ('prepare_ref_recovery_record.py',
                  'INCREMENTAL-V97-HELPER.js', 'capture_root_closure.py')]
    files = []
    for path in sorted(selected):
        raw = path.read_bytes()
        files.append({'path': path.relative_to(ROOT).as_posix(),
                      'mode': stat.S_IMODE(path.stat().st_mode), **pin(raw),
                      'base64': base64.b64encode(raw).decode()})
    logical = json.dumps({'schema': 'hia.root.publication-complete-originals.v1', 'files': files},
                         sort_keys=True, separators=(',', ':')).encode()
    compressed = zlib.compress(logical, 9)
    wrapper = {'schema': 'hia.root.publication-complete-originals-zlib.v1',
               'decoded': pin(logical), 'compressed': pin(compressed), 'paths': len(files),
               'logical_bytes': sum(row['bytes'] for row in files),
               'data_base64': base64.b64encode(compressed).decode()}
    raw = (json.dumps(wrapper, sort_keys=True, separators=(',', ':')) + '\n').encode()
    (TARGET / 'PUBLICATION-ORIGINALS.zlib.json').write_bytes(raw)
    restored = json.loads(zlib.decompress(base64.b64decode(wrapper['data_base64'])))
    for row in restored['files']:
        data = base64.b64decode(row['base64'])
        assert pin(data) == {k: row[k] for k in ('bytes', 'sha256', 'git_blob')}
        path = ROOT / row['path']
        assert path.read_bytes() == data
        assert stat.S_IMODE(path.stat().st_mode) == row['mode']
    mounted = json.loads((ROOT / 'v99-complete-attempt/MOUNT-COMPLETE.json').read_text())
    report = {'schema': 'hia.root.publication-closure.v1', 'status': 'PUBLISHED_AND_READ_BACK',
              'mounted': mounted, 'original_responses_and_scripts': len(files),
              'logical_bytes': wrapper['logical_bytes'], 'archive': pin(raw),
              'all_originals_bytes_modes_hashes_readback': True,
              'initial_failures_retained': True,
              'unknown_ref_requests_not_reported_as_success': True,
              'atomic_contents_single_file': 'a917d149bb46c6207177888146e03d628e998d37',
              'same_exact_V97_V98_collection_tree_identities_preserved': True,
              'generic_server_error_cause': 'UNDETERMINED',
              'source_native_installed_portable_cold_or_whole_qualification_added': False,
              'main_or_product_head_changed': False, 'whole_native': False}
    (TARGET / 'PUBLICATION-CLOSURE.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    readme = '''# Root publication closure and rejected memo successor

The exact V97 and V98 evidence collections are now published at commit
f6eb53589911e05181b6553139a94ecd5919cd51 on the isolated audit branch. The
104-file and 88-file collection trees retain their original identities, and
the 53 earlier review subtrees and 19 non-review root entries are unchanged.
All initial server errors, failed reference requests, read-only reconciliations,
the successful atomic single-file publication and final full publication are
preserved as complete original files in the archive. Generic error messages
do not establish a cause. No policy or access-control bypass was used.

The memo R4 experiment is NOT ADOPTED. A tuple-based argument transfer passed
the earlier carrier-pop and mid-open reference-count probes. A separate actual
CALL observer installed during the first open still observes an added digest
helper entry and raises an exact MemoryError where the original returns. The
unchanged older controls also retain their stale-support-contract error and
private trace-expectation failure. The archive includes both complete source
manifests, the sole changed source file's full before/after bytes, exact original
control scripts, every command, output, return code and failure record. These
private controls execute zero product Native or compiler entries and fix none
of the original three Native budget failures.

This is an evidence-only addition. Source, component Native, installed,
portable, current-source cold and whole-system qualifications remain distinct.
No legacy production code is removed. whole_native=false.
'''
    (TARGET / 'README.md').write_text(readme)
    memo = ROOT.parent / 'v98-source-guard-memo-r4/handoff-r1'
    mapping = [
        ('publication/ORIGINALS.zlib.json', TARGET / 'PUBLICATION-ORIGINALS.zlib.json'),
        ('publication/CLOSURE.json', TARGET / 'PUBLICATION-CLOSURE.json'),
        ('publication/PR889-20-46.md', ROOT / 'v98-addendum/PR889-UPDATED-BODY.md'),
        ('memo-r4/ORIGINALS.zlib.json', memo / 'ORIGINALS.zlib.json'),
        ('memo-r4/RESULT.json', memo / 'RESULT.json'),
        ('memo-r4/READBACK.json', memo / 'READBACK.json'),
        ('capture_publication.py', Path(__file__).resolve()), ('README.md', TARGET / 'README.md')]
    leaves = [{'path': name, 'local_path': str(path), 'mode': '100644', 'type': 'blob',
               **pin(path.read_bytes())} for name, path in mapping]
    (TARGET / 'PUBLICATION-INTENT.json').write_text(json.dumps({'files': leaves}, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'original_files': len(files), 'logical_bytes': wrapper['logical_bytes'],
                      'archive': pin(raw), 'publication_files': len(leaves),
                      'publication_bytes': sum(row['bytes'] for row in leaves)}, sort_keys=True))


if __name__ == '__main__':
    main()
