"""Copy exact frozen input bytes into a new, isolated joint CI harness."""
from pathlib import Path
from hashlib import sha1, sha256
import json
import shutil
import stat

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
HARNESS = HERE / 'harness'
ORIGINAL = BASE / 'v81-service-requests-development-r2/ci-r2/harness'
FRONT = BASE / 'v81-core-assembly-front-development-r4/cpython-ci-r2/inputs'
UNION = BASE / 'v82-requests-front-integration-r1'

def ident(path):
    raw = path.read_bytes()
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'mode': '100755' if stat.S_IMODE(path.stat().st_mode) & 0o111 else '100644'}

def copy(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('xb') as stream:
        stream.write(source.read_bytes())
    target.chmod(0o644)
    assert ident(source) == ident(target)

def main():
    remote = json.loads((HERE / 'R2-GIT-READBACK.json').read_bytes())
    commit, tree = remote['commit'], remote['tree']
    assert commit['sha'] == '8195d810dabb6f1ebdc993ae7372aa387d0d3853'
    assert commit['tree']['sha'] == tree['sha'] == 'e0c6fbe9475b10019a8b6e439755b79ca3280b32'
    assert [p['sha'] for p in commit['parents']] == ['5490b3d24f9fca7796d391018fc538ea60f37bb3']
    assert tree['truncated'] is False
    entries = {row['path']: row for row in tree['tree'] if row['type'] == 'blob'}
    original = {p.relative_to(ORIGINAL).as_posix(): ident(p) for p in ORIGINAL.rglob('*') if p.is_file()}
    assert len(entries) == len(original) == 14
    assert set(entries) == set(original)
    for name, row in original.items():
        assert (row['blob'], row['bytes'], row['mode']) == (entries[name]['sha'], entries[name]['size'], entries[name]['mode'])
    HARNESS.mkdir()
    for name in original:
        copy(ORIGINAL / name, HARNESS / name)
    for name in ('README.md', '.github/workflows/hia-service-requests-v81.yml'):
        copy(ORIGINAL / name, HARNESS / 'inputs/original-r2' / name)
    (HARNESS / 'inputs/R2-ORIGINAL-FILES.json').write_text(json.dumps(original, sort_keys=True, indent=2) + '\n')
    copy(HERE / 'R2-GIT-READBACK.json', HARNESS / 'inputs/R2-GIT-READBACK.json')
    copy(UNION / 'checkpoint-r1/SOURCE-PACKET.zlib.json', HARNESS / 'inputs/union-source.zlib.json')
    copy(UNION / 'SOURCE-LOADER.json', HARNESS / 'inputs/expected-source-901.json')
    copy(BASE / 'v81-default-import-compatibility-r5-r2/AUTHOR-PACKET.json', HARNESS / 'inputs/lazy-four-before-after.json')
    copy(BASE / 'v81-default-import-compatibility-r5-r2/probe_lazy_bindings_r2.py', HARNESS / 'inputs/probe_lazy_bindings_r2.py')
    for name in ('run_default_compatibility_union.py', 'original-two-images.json', 'original-caller-sources.json', 'KIT.json'):
        copy(UNION / 'default311-kit' / name, HARNESS / 'inputs/default64' / name)
    front_names = ('compile_split_ci.py', 'run_split_callers_r1.py', 'run_split_matrix_r1.py',
        'run_r3_controls.py', 'probe_split_capture_r2.py', 'probe_split_admission_r2.py',
        'probe_split_transport_r4.py', 'probe_split_globals_r3.py', 'probe_default_import_r3.py',
        'probe_source_projection.py', 'run_split_development.py', 'r1-source-packet.json', 'r4-source-packet.json',
        'FIXTURE-PROVENANCE.json')
    for name in front_names:
        copy(FRONT / name, HARNESS / 'inputs/front-original' / name)
    record = {'schema': 'hia.requests-front.harness-original-input-custody.v82.r3',
        'original_commit': commit['sha'], 'original_tree': tree['sha'], 'original_files': original,
        'front_originals': {n: ident(FRONT / n) for n in front_names},
        'all_copied_bytes_and_modes_equal': True, 'source_or_test_bodies_executed': 0}
    (HERE / 'SETUP-RESULT.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'original_files': len(original), 'front_original_files': len(front_names), 'status': 'PASS'}))

if __name__ == '__main__':
    main()
