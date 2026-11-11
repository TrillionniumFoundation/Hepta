"""Retain an interrupted observation exactly; do not execute any product code."""
from hashlib import sha1, sha256
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import time
import zipfile

ROOT = Path('/tmp/hia-e26e-artifact-page-r4')
OUT = ROOT / 'checkpoint-r4'
OUT.mkdir(mode=0o700)

def sha(raw):
    return sha256(raw).hexdigest()

def git(raw):
    return sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()

def write(path, raw):
    with path.open('xb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())

def metadata(path):
    raw = path.read_bytes()
    return {'bytes': len(raw), 'sha256': sha(raw), 'git_blob_sha1': git(raw)}

progress_path = ROOT / 'boundary-r4/progress.json'
progress_raw = progress_path.read_bytes()
progress = json.loads(progress_raw)
assert progress['expected_case_count'] == 42 and len(progress['observations']) == 5
assert not progress['failures']
assert not (ROOT / 'boundary-r4/report.json').exists()
assert not (ROOT / 'boundary-guard-r4/guardian.json').exists()
pattern = '/tmp/hia-e26e-artifact-page-r4/(boundary_controls.py|compile-control/guardian.py)'
probe = subprocess.run(['pgrep', '-af', pattern], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
assert probe.returncode in (0, 1)
observation = {'schema': 'hia.artifact-page.executor-continuity-observation.v1',
               'observed_time_ns': time.time_ns(),
               'current_pid_namespace': os.readlink('/proc/self/ns/pid'),
               'current_boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
               'current_owned_argv_probe': {'command': ['pgrep', '-af', pattern],
                     'returncode': probe.returncode, 'stdout': probe.stdout.decode(), 'stderr': probe.stderr.decode()},
               'original_exec_session_id': 46203,
               'observed_exec_read_error': 'write_stdin failed: Unknown process id 46203',
               'error_text_scope': 'transcribed from the observed tool error, not an original SDK payload archive',
               'original_startup_supervisor_pid': 2,
               'original_start_ticks_and_boot_identity_retained': False,
               'same_original_process_identity_proven_absent': False,
               'original_cleanup_proven': False,
               'original_final_guardian_present': False, 'original_final_product_report_present': False,
               'scope': 'current namespace observation; does not prove historical process-tree cleanup'}
write(OUT / 'LIFECYCLE-OBSERVATION.json', (json.dumps(observation, indent=2, sort_keys=True) + '\n').encode())
material = json.loads((ROOT / 'MATERIALIZATION.json').read_bytes())
expected = material['final_members']
source = ROOT / 'source'
paths = sorted(p.relative_to(source).as_posix() for p in source.rglob('*') if p.is_file())
assert set(paths) == set(expected)
current = {}
for name in paths:
    p = source / name
    s = p.lstat()
    assert stat.S_ISREG(s.st_mode) and s.st_nlink == 1
    raw = p.read_bytes()
    row = {'bytes': len(raw), 'sha256': sha(raw), 'git_blob': git(raw), 'mode': stat.S_IMODE(s.st_mode)}
    assert row == expected[name], name
    assert row['sha256'] == progress['source_before'][name], name
    current[name] = row
archive = OUT / 'executed-source.zip'
with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
    for name in paths:
        info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | current[name]['mode']) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        bundle.writestr(info, (source / name).read_bytes())
with zipfile.ZipFile(archive) as bundle:
    assert bundle.namelist() == paths
    for info in bundle.infolist():
        raw = bundle.read(info)
        row = current[info.filename]
        assert len(raw) == row['bytes'] and sha(raw) == row['sha256'] and git(raw) == row['git_blob']
        assert (info.external_attr >> 16) == stat.S_IFREG | row['mode']
        assert (source / info.filename).read_bytes() == raw
write(OUT / 'executed-source-manifest.json', (json.dumps(current, indent=2, sort_keys=True) + '\n').encode())
status = {'schema': 'hia.artifact-page.development-continuity-status.v1',
          'status': 'HOLD', 'reason': 'UNKNOWN_EXECUTOR_CONTINUITY',
          'scope': 'five completed native differential observations, incomplete original 42-case run',
          'expected_cases': 42, 'completed_cases': 5, 'recorded_failed_cases': 0,
          'full_case_denominator_complete': False, 'full_boundary_suite_pass': False,
          'original_final_guardian_present': False, 'original_cleanup_proven': False,
          'runtime_cause_inferred': False, 'original_run_replayed': False,
          'original_progress': {'path': 'boundary-r4/progress.json', **metadata(progress_path)},
          'completed_observations': progress['observations'],
          'source_preserved_at_checkpoint': True,
          'source_members': len(current), 'executed_source': metadata(archive),
          'executed_source_manifest': metadata(OUT / 'executed-source-manifest.json'),
          'base_commit': material['base_commit'], 'base_tree': material['base_tree'],
          'wire_handoff_commit': material['canonical_wire_handoff'],
          'page_source_pins': material['page_source_pins'],
          'policy_image_sha256': progress['policy_image'], 'wire_image_sha256': progress['wire_image'],
          'ordinary_selector_installed_or_full_capacity_qualification': False,
          'whole_native_delivery_qualified': False,
          'storage_scope': 'development source and SQLite in-memory semantics; no disk durability claim'}
write(OUT / 'STATUS.json', (json.dumps(status, indent=2, sort_keys=True) + '\n').encode())
members = {}
for relative in ['materialize_development.py', 'MATERIALIZATION.json', 'compile_page.py',
                 'boundary_controls.py', 'page-bundle.json', 'checkpoint_interrupted_run.py', 'inputs/B3.image.bin']:
    members[relative] = ROOT / relative
for folder in ['compile-control', 'compile-guard', 'boundary-guard-r4', 'boundary-r4',
               'development-r4', 'wire', 'page-inputs']:
    for p in sorted((ROOT / folder).rglob('*')):
        if p.is_file():
            assert not p.is_symlink()
            members[p.relative_to(ROOT).as_posix()] = p
for relative in ['STATUS.json', 'LIFECYCLE-OBSERVATION.json', 'executed-source-manifest.json']:
    members['checkpoint-r4/' + relative] = OUT / relative
rows = {name: {**metadata(path), 'mode': stat.S_IMODE(path.stat().st_mode)} for name, path in members.items()}
raw_archive = OUT / 'originals.tar.xz'
with tarfile.open(raw_archive, 'x:xz', preset=6) as tar:
    for name, path in sorted(members.items()):
        raw = path.read_bytes()
        info = tarfile.TarInfo(name); info.size = len(raw); info.mode = rows[name]['mode']
        info.uid = info.gid = info.mtime = 0
        tar.addfile(info, io.BytesIO(raw))
with tarfile.open(raw_archive, 'r:xz') as tar:
    assert tar.getnames() == sorted(members)
    for info in tar:
        raw = tar.extractfile(info).read()
        assert info.isfile() and info.mode == rows[info.name]['mode']
        assert len(raw) == rows[info.name]['bytes'] and sha(raw) == rows[info.name]['sha256']
        assert raw == members[info.name].read_bytes()
custody = {'schema': 'hia.artifact-page.interrupted-originals-custody.v1',
           'status': 'ALL_ARCHIVE_MEMBERS_READ_BACK', 'product_status': 'HOLD/UNKNOWN_EXECUTOR_CONTINUITY',
           'source_archive': metadata(archive), 'source_members': len(current),
           'originals_archive': metadata(raw_archive), 'original_members': len(rows),
           'files': rows, 'product_tests_rerun': False, 'original_files_deleted_or_modified': False}
write(OUT / 'CUSTODY.json', (json.dumps(custody, indent=2, sort_keys=True) + '\n').encode())
print(json.dumps({k: custody[k] for k in ['status', 'product_status', 'source_archive', 'source_members', 'originals_archive', 'original_members']}))
