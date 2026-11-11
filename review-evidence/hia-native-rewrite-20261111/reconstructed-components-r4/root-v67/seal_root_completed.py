from pathlib import Path
from hashlib import sha256, sha1
import io, json, stat, tarfile

ROOT = Path('/workspace/scratch/9acdfa9f5639')
OUT = ROOT / 'recovery-completed-r4'
OLD = ROOT / 'hia-v67-reconstructed-development'
FIX = ROOT / 'hia-v67-workflow-fix-development'
rows = {}

def add_file(path, name):
    assert path.is_file() and not path.is_symlink() and name not in rows
    data = path.read_bytes()
    rows[name] = (path, data, stat.S_IMODE(path.stat().st_mode))

def add_tree(root, prefix):
    for path in sorted(root.rglob('*')):
        if path.is_file():
            add_file(path, prefix + '/' + path.relative_to(root).as_posix())

add_tree(OLD / 'source-suite-attempt1', 'v67-source-331')
add_tree(OLD / 'ci-attempt1', 'v67-ci-workflow-rejected')
for name in ['run_full_source.py', 'source-controller.stdout.log', 'source-controller.stderr.log',
             'source-frozen.json', 'publication.json']:
    add_file(OLD / name, 'v67-source-controller/' + name)
for name in ['failures', 'prepare-attempt1-logs']:
    add_tree(FIX / name, 'workflow-fix/' + name)
for name in ['prepare_frozen_source.py', 'initial-inventory.log', 'initial-contract.log',
             'workflow-after-contract-refresh.log', 'prepare.stdout.log', 'prepare.stderr.log',
             'generation.json', 'source-frozen.json', 'source-frozen.tar.xz',
             'freeze-receipt.json', 'publication.json', 'run_full_source.py']:
    add_file(FIX / name, 'workflow-fix/' + name)
manifest = {
    'scope': 'COMPLETED_V67_SOURCE_GATE_AND_WORKFLOW_REPAIR_PREPARATION_ONLY',
    'v67_source_suite': {'tests_run': 331, 'passed': True, 'seconds': 340.818781292,
                        'failures': 0, 'errors': 0, 'skipped': 0, 'xfail': 0, 'xpass': 0},
    'first_ci_run': 43020215648,
    'first_ci_status': 'WORKFLOW_REJECTED_BEFORE_JOBS',
    'repaired_head': '0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5',
    'new_full_source_gate_in_progress_and_not_included': True,
    'cold_run_included': False,
    'whole_stack_closed': False,
    'files': [{'path': name, 'bytes': len(data), 'sha256': sha256(data).hexdigest(), 'mode': mode}
              for name, (path, data, mode) in sorted(rows.items())],
}
encoded = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
archive = OUT / 'root-v67-source-and-workflow-repair.tar.xz'
with tarfile.open(archive, 'x:xz') as tf:
    for name, (path, data, mode) in sorted(rows.items()):
        member = tarfile.TarInfo(name)
        member.size, member.mode = len(data), mode
        tf.addfile(member, io.BytesIO(data))
    member = tarfile.TarInfo('MANIFEST.json')
    member.size, member.mode = len(encoded), 0o644
    tf.addfile(member, io.BytesIO(encoded))
with tarfile.open(archive, 'r:xz') as tf:
    assert len(tf.getmembers()) == len(rows) + 1
    assert tf.extractfile('MANIFEST.json').read() == encoded
    for name, (path, data, mode) in rows.items():
        m = tf.getmember(name)
        assert m.isfile() and m.mode == mode and tf.extractfile(m).read() == data
        assert path.read_bytes() == data and stat.S_IMODE(path.stat().st_mode) == mode
raw = archive.read_bytes()
receipt = {'scope': manifest['scope'], 'archive': str(archive), 'bytes': len(raw),
           'sha256': sha256(raw).hexdigest(),
           'git_sha': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
           'members': len(rows) + 1, 'original_bytes': sum(len(r[1]) for r in rows.values()),
           'all_original_bytes_modes_and_live_readback_equal': True,
           'no_ongoing_test_files_included': True, 'whole_stack_closed': False}
(OUT / 'root-custody.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
print(json.dumps(receipt), flush=True)

