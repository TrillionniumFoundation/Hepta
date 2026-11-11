"""Seal only completed originals; large cold original is separately durable."""
from pathlib import Path
from hashlib import sha256, sha1
import io
import json
import stat
import tarfile

ROOT = Path('/workspace/scratch/9acdfa9f5639')
OUT = ROOT / 'recovery-completed-r5'
FIX = ROOT / 'hia-v67-workflow-fix-development'
COLD = ROOT / 'hia-v67-0ef-qualification-local-01'
AUDIT = ROOT / 'hia-v67-0ef-independent-audit'
EDIT = ROOT / 'native-agent-edit-development'
rows = {}


def add_file(path, name):
    assert path.is_file() and not path.is_symlink() and name not in rows, path
    raw = path.read_bytes()
    rows[name] = (path, raw, stat.S_IMODE(path.stat().st_mode))


def add_tree(root, prefix):
    for path in sorted(root.rglob('*')):
        if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc':
            add_file(path, prefix + '/' + path.relative_to(root).as_posix())


add_tree(FIX / 'source-suite-attempt1', 'source-331-complete')
for name in ('run_full_source.py', 'run_published_cold.py', 'seal_published_cold.py',
             'cold-controller.stdout.log', 'cold-controller.stderr.log',
             'cold-seal.stdout.log', 'cold-seal.stderr.log', 'publication.json', 'source-frozen.json'):
    add_file(FIX / name, 'control/' + name)
for path in sorted(COLD.glob('*')):
    if path.is_file(): add_file(path, 'cold-top-level/' + path.name)
for name in ('qualification.json',):
    add_file(COLD / 'cold.cold' / name, 'cold/' + name)
for name in ('custody.json', 'seal-receipt.json', 'audit_original_cold.py', 'cold-readback.json',
             'library-upload.result.json', 'library-upload.stderr.log'):
    add_file(AUDIT / name, 'independent-audit/' + name)
add_file(ROOT / 'hia-v67-0ef-github-qualification/source.original.log', 'github/source.original.log')
add_tree(ROOT / 'v67-0ef-rog-source-handoff-r2', 'rog-source-handoff')
add_file(ROOT / 'prepare_v67_rog_handoff_r2.py', 'rog-source-handoff/controller.py')
for name in ('facts-source-and-compile-r1', 'facts-native-r1', 'facts-native-r2'):
    add_tree(EDIT / name, 'agent-edit/' + name)
for name in ('facts_harness.py', 'freeze_vm_compile_facts_r1.py', 'test_facts_native_r1.py',
             'test_facts_native_r2.py', 'facts-r1-layout-metadata-erratum.json', 'shared-source-origin.json',
             'facts-generation-r1.stdout.log', 'facts-generation-r1.stderr.log',
             'facts-source-and-compile-r1.stdout.log', 'facts-source-and-compile-r1.stderr.log',
             'facts-native-r1.stdout.log', 'facts-native-r1.stderr.log',
             'facts-native-r2.stdout.log', 'facts-native-r2.stderr.log'):
    add_file(EDIT / name, 'agent-edit/' + name)
manifest = {
    'scope': 'COMPLETED_0EF_SOURCE_COLD_ORIGINAL_READBACK_AND_NEW_EDIT_COMPONENT_ATTEMPTS',
    'source_head': '0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5',
    'source_tests': 331, 'source_seconds': 340.54723329,
    'cold_seconds': 134.765704630, 'cold_original_limit_seconds': 180, 'oracle_workers': 2,
    'cold_outer_checks': 11, 'cold_phases': 38, 'cold_nested_checks': 5051,
    'large_complete_cold_archive': {
        'filename': 'HIA-v67-0ef9541-local-cold-20261111.tar.xz', 'bytes': 29944020,
        'sha256': '24f1fd5eedae9afde032a40b397f180b73661f33f51d7e672f0dcb1fbb73b4b0',
        'library_file_id': 'libfile_fde3_f-a823be6d2fdc819183c0415dff281625_2a707b49f4e88191b36ca8a6f555e3a2',
        'not_included_in_this_archive': True},
    'github_native_job_in_progress_when_sealed': True,
    'edit_component': {'source_sha256': 'ec46bb572dc374486aa1030de501e665d5a937bdb5ed62db0c2c8fc83a52dfcd',
        'actual_compile_pass': True, 'independent_VM_cases_pass': 2,
        'first_native_attempt': 'FAIL: independent VM incorrectly executed inside host-decoder suppression',
        'second_native_attempt': 'FAIL: random test fixture violated whole-function SSA uniqueness after 47 passing resource selections',
        'third_native_attempt_running_and_excluded': True,
        'original_summary_layout_counts_have_separate_erratum': True},
    'whole_stack_closed': False,
    'files': [{'path': name, 'bytes': len(data), 'sha256': sha256(data).hexdigest(), 'mode': mode}
              for name, (path, data, mode) in sorted(rows.items())],
}
encoded = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
archive = OUT / 'root-completed-0ef-and-edit-attempts.tar.xz'
with tarfile.open(archive, 'x:xz') as tf:
    for name, (path, raw, mode) in sorted(rows.items()):
        member = tarfile.TarInfo(name)
        member.size, member.mode = len(raw), mode
        tf.addfile(member, io.BytesIO(raw))
    member = tarfile.TarInfo('MANIFEST.json')
    member.size, member.mode = len(encoded), 0o644
    tf.addfile(member, io.BytesIO(encoded))
with tarfile.open(archive, 'r:xz') as tf:
    assert len(tf.getmembers()) == len(rows) + 1
    assert tf.extractfile('MANIFEST.json').read() == encoded
    for name, (path, raw, mode) in rows.items():
        member = tf.getmember(name)
        assert member.isfile() and member.mode == mode and tf.extractfile(member).read() == raw
        assert path.read_bytes() == raw and stat.S_IMODE(path.stat().st_mode) == mode
raw = archive.read_bytes()
receipt = {'scope': manifest['scope'], 'archive': str(archive), 'bytes': len(raw),
    'sha256': sha256(raw).hexdigest(), 'git_sha': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
    'members': len(rows) + 1, 'original_bytes': sum(len(r[1]) for r in rows.values()),
    'all_original_bytes_modes_and_live_readback_equal': True,
    'no_running_test_files_included': True, 'whole_stack_closed': False}
(OUT / 'root-custody.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
print(json.dumps(receipt), flush=True)
