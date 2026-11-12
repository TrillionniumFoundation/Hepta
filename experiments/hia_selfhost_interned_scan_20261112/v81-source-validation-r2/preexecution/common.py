"""Evidence helpers for a fixed source-only v81 validation, not product code."""
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import stat
import subprocess

HERE = Path(__file__).resolve().parent
SOURCE = Path('/workspace/scratch/e26ed3e2edcf/compiler-interned-scan-v81-r1')
SUPPORT = 'docs/HIA_SELFHOST_CORE_SUPPORT.json'
COVERAGE = 'docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json'
MUTABLE = {SUPPORT, COVERAGE}
GENERATOR_SHA = '9337d6704e47c4257b8b3723c0676809e1ba31914d6cfa6b13e07f2789b03ec2'
HIA_SHA = 'c6fbbc080b9167933b8003531a81b3782aa2e57b3a9148fa39c3794a13878699'
GUARD_SHA = 'd0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023'
OWNER_SHA = '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
GROUPS = (
 ('tests.test_hia_selfhost.SelfhostSourceTests', 34),
 ('tests.test_hia_selfhost_names.SelfhostFunctionNameTests', 8),
 ('tests.test_hia_selfhost_chain.ChainSourceTests', 7),
 ('tests.test_hia_selfhost_owned_flow.OwnedFlowSourceTests', 3),
 ('tests.test_hia_selfhost_returned_loans.SelfhostReturnedLoanSourceTests', 3),
 ('tests.test_hia_selfhost_keywords.SelfhostKeywordTests', 6),
 ('tests.test_hia_selfhost_contract.SelfhostContractTests', 7),
 ('tests.test_hia_selfhost_language_coverage.SelfhostLanguageSourceTests', 13),
)
NATIVE_GROUPS = (
 ('tests.test_hia_selfhost.SelfhostNativeTests', 19),
 ('tests.test_hia_selfhost_contract.SelfhostColdReplayTests', 1),
 ('tests.test_hia_selfhost_language_coverage.SelfhostLanguageNativeTests', 10),
)

def require(condition, text):
    if not condition:
        raise RuntimeError(text)

def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()

def save(path, raw):
    path = Path(path)
    require(not path.exists() and not path.is_symlink(), 'create-only output exists: ' + str(path))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    require(path.read_bytes() == raw, 'output readback differs')

def file_record(path):
    path = Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and not path.is_symlink(), 'not a regular source: ' + str(path))
    raw = path.read_bytes()
    after = path.lstat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'source changed while read')
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(f'blob {len(raw)}\0'.encode() + raw).hexdigest(),
            'mode': stat.S_IMODE(after.st_mode)}

def snapshot():
    extra = subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard', '-z'], cwd=SOURCE)
    require(not extra, 'untracked source namespace differs')
    names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=SOURCE).decode().split('\0')[:-1]
    require(len(names) == len(set(names)), 'duplicate tracked names')
    rows = {name: file_record(SOURCE / name) for name in sorted(names)}
    require(rows['tools/generate_hia_selfhost.py']['sha256'] == GENERATOR_SHA, 'generator identity changed')
    require(rows['examples/hia_bootstrap/selfhost.hiaasm']['sha256'] == HIA_SHA, 'generated HIA identity changed')
    return rows

def natural_guardian(record, request):
    life = record['lifecycle']; clean = life['cleanup']
    require(record['schema'] == 'hepta.hia.external-qualification-guardian.v1'
        and record['status'] == 'EXTERNAL_OWNED_PROCESS_COMPLETED'
        and record['command'] == request['command'] and record['cwd'] == request['cwd']
        and record['external_controller_seconds'] == 180
        and record['lifecycle_implementation_sha256'] == OWNER_SHA
        and record['source_identities_before'] == request['source_identities']
        and record['source_identities_after'] == request['source_identities']
        and record['input_identity_preserved'] is True, 'guardian input/command/terminal mismatch')
    require(life['status'] == 'OWNED_PROCESS_COMPLETED' and life['returncode'] == 0
        and life['qualification_seconds'] == 180 and life['cleanup_seconds'] == 3
        and life['exit_observed_before_deadline'] is True and life['timed_out'] is False
        and life['subreaper_enabled'] is True and life['qualification_started'] is True
        and not life.get('owner_error') and life['interrupted_signals'] == []
        and life['event_overflow'] is False, 'owner was not natural success')
    require(clean['complete'] is True and clean['observed_echild'] is True
        and clean['leader_reaped'] is True and clean['remaining_direct_children'] == []
        and clean['errors'] == [] and clean['deadline_exceeded'] is False, 'cleanup did not prove ECHILD')
    kinds = [event['kind'] for event in life['events']]
    require(kinds == ['qualification_started', 'owned_child_observed', 'qualification_exit_observed', 'owned_child_reaped'],
        'unexpected lifecycle event or live-child kill')
    return life['wall_elapsed_ns'] if 'wall_elapsed_ns' in life else life.get('elapsed_ns')
