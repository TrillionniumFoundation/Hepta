"""Prepare one independent integration checkout; no product tests or contracts.

The unchanged external guardian owns this driver and every Git descendant.
Only the new task root is written. Original source and qualification evidence
are pinned before and after. A nonzero merge result is retained as such and is
accepted for resolution only for the one explicitly described resource-list
conflict; every other error leaves PREPARATION_HOLD.
"""
from __future__ import annotations

import ast
from hashlib import file_digest
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

import workflow_process

ROOT = Path('/home/qian-qi/he26v66r1')
SOURCE = ROOT / 's'
CONTROL = ROOT / 'control'
LOGS = ROOT / 'preparation-logs'
BORROW = Path('/home/qian-qi/he26v65r2/s')
BASE_HEAD = '4161e8d12d87906fde144f039da07908ad52d98a'
BASE_TREE = '1c6ab0228f012429149997d1f731833739f433eb'
REPOSITORY = 'https://github.com/TrillionniumFoundation/Hepta.git'
COMMITS = (
    '6d7806e3d3295e760066c229d6d3fe389564ae48',
    'b6c36189fb45adcf26c2528346d14021b9873b05',
    '38c3a511bea4e1733fe9e3be8111f28c07de94d3',
    '42e3b7a6ef529e0f7209ab41184b6bbc89425b02',
    '90536547cf012b8fed6d63e06ede77f49f6b9ee4',
    '6f92eca18aa4447d2f7eb920d680adcc546c41f8',
)
HELPER_SHA = 'f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80'
PINS = {
    '/home/qian-qi/he26v65r2/q/QUALIFICATION.json': 'd91d279d192a9fe6b6a7521d8732197bdc37f4af3a03a694cfccb15929748b60',
    '/home/qian-qi/he26v65r2/q/cold.json': '938b9331e28e53442a21796acb319f3c9683fc26748cad49893b56873bf02ad4',
    '/home/qian-qi/he26v65r2/q/source-tests.json': 'a2a84183bbca9df57ee352524e874420c446cb472bba34a5abd04551556593de',
    '/home/qian-qi/he26v65r2/guard/guardian.json': 'ae721abf9b428acedb43fe99d5b072fed1de3299fd331b457410fdb5858519f1',
    '/home/qian-qi/hia-native-closure-evidence/4161e8d12d87906fde144f039da07908ad52d98a/desktop-full-hold-r2-preservation-r3/PRESERVATION.json': '6edd6d762f9ca2f95c1b3c0b40d1cd543c83e030fa0ecba1a72a2c26507644de',
}
RESOURCE_LINES = {
    'examples/hia_bootstrap/machine_plan.hiaasm',
    'examples/hia_bootstrap/worker_report.hiaasm',
    'examples/hia_bootstrap/json_wire.hiaasm',
}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return file_digest(stream, 'sha256').hexdigest()


def wire(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def create(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def private(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700, 'owned private directory required')
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'symlink ancestor refused')


os.umask(0o077)
for path in (ROOT, CONTROL, ROOT / 'guard'):
    private(path)
require(not os.path.lexists(SOURCE) and not os.path.lexists(LOGS),
        'fresh source and log directory required; reconcile original job')
require(Path(workflow_process.__file__).resolve() == CONTROL / 'workflow_process.py'
        and sha(workflow_process.__file__) == HELPER_SHA, 'adjacent reviewed helper differs')
LOGS.mkdir(mode=0o700)
ENV = {k: v for k, v in os.environ.items()
       if not k.startswith(('HEPTA_HIA_', 'GIT_'))
       and k not in ('PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP', 'LD_PRELOAD')}
ENV.update(PATH='/usr/bin:/bin', LANG='C.UTF-8', LC_ALL='C.UTF-8',
           PYTHONDONTWRITEBYTECODE='1', PYTHONUNBUFFERED='1', PYTHONNOUSERSITE='1',
           GIT_TERMINAL_PROMPT='0', GIT_NO_LAZY_FETCH='1', GIT_OPTIONAL_LOCKS='0')
report = {
    'schema': 'hia.desktop-v66-independent-source-preparation.v1', 'status': 'RUNNING',
    'root': str(ROOT), 'source': str(SOURCE), 'borrowed_source': str(BORROW),
    'base_head': BASE_HEAD, 'base_tree': BASE_TREE, 'requested_commits': list(COMMITS),
    'started_unix_ns': time.time_ns(), 'steps': [], 'resolved_conflicts': [],
    'tests_executed': False, 'contract_refresh_executed': False,
    'qualification_executed': False, 'whole_native_delivery_qualified': False,
}


def checkpoint():
    temporary = ROOT / 'preparation.next.json'
    create(temporary, wire(report))
    os.replace(temporary, ROOT / 'preparation.json')
    fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def run(label, command, *, seconds=120, allow_merge_conflict=False):
    print(json.dumps({'stage': 'INDEPENDENT_SOURCE_PREPARATION', 'step': label}), flush=True)
    stdout = LOGS / (label + '.stdout.log')
    stderr = LOGS / (label + '.stderr.log')
    owner = workflow_process.run_workflow_step(list(map(str, command)), cwd=ROOT, env=ENV,
        stdout_path=stdout, stderr_path=stderr,
        receipt_path=LOGS / (label + '.owner.json'), seconds=seconds)
    report['steps'].append({'label': label, 'owner': owner})
    checkpoint()
    require(owner.get('timed_out') is False and owner.get('cleanup', {}).get('complete') is True
            and owner['cleanup'].get('errors') == [] and owner['cleanup'].get('signalled') == [],
            'process ownership did not close: ' + label)
    code = owner.get('returncode')
    if code == 0:
        require(owner.get('status') == 'WORKFLOW_STEP_COMPLETED', 'inconsistent success receipt')
    else:
        require(allow_merge_conflict and code == 1 and owner.get('status') == 'WORKFLOW_STEP_HOLD',
                'owned command failed: ' + label)
    return code, stdout.read_text().strip()


def git(path, *args):
    return ['/usr/bin/git', '--no-replace-objects', '-c', 'core.hooksPath=/dev/null',
            '-c', 'http.version=HTTP/1.1', '-c', 'user.name=HIA Native Audit',
            '-c', 'user.email=hia-native-audit@localhost', '-c', 'commit.gpgsign=false',
            '-C', str(path), *args]


def complete_independent_objects(path):
    objects = path / '.git/objects'
    require(objects.is_dir() and not objects.is_symlink(), 'real Git object store required')
    require(not (objects / 'info/alternates').exists()
            and not (objects / 'info/http-alternates').exists()
            and not list(objects.rglob('*.promisor')), 'external/promisor object dependencies refused')
    for item in objects.rglob('*'):
        if item.is_file():
            require(not item.is_symlink() and item.stat().st_nlink == 1,
                    'borrowed object hardlink or symlink refused')


def resolve_resource_conflict(number):
    _, paths = run('conflict-paths-' + str(number), git(SOURCE, 'diff', '--name-only', '--diff-filter=U'))
    require(paths.splitlines() == ['hepta/hia_agent_contract.py'], 'unreviewed merge conflict')
    path = SOURCE / 'hepta/hia_agent_contract.py'
    original = path.read_text()
    lines = original.splitlines(keepends=True)
    merged, at, blocks = [], 0, 0
    while at < len(lines):
        if not lines[at].startswith('<<<<<<< '):
            require(not lines[at].startswith(('=======', '>>>>>>> ', '||||||| ')), 'unexpected conflict marker')
            merged.append(lines[at]); at += 1; continue
        blocks += 1
        at += 1
        choices = []
        while at < len(lines) and lines[at].strip() != '=======':
            choices.append(lines[at]); at += 1
        require(at < len(lines), 'unterminated conflict side')
        at += 1
        while at < len(lines) and not lines[at].startswith('>>>>>>> '):
            choices.append(lines[at]); at += 1
        require(at < len(lines), 'unterminated conflict block')
        at += 1
        seen = set()
        for line in choices:
            match = re.fullmatch(r"\s*(['\"])(examples/hia_bootstrap/[A-Za-z_]+\.hiaasm)\1,\s*", line)
            require(match is not None and match[2] in RESOURCE_LINES,
                    'conflict contains more than the three reviewed resource literals')
            if match[2] not in seen:
                seen.add(match[2]); merged.append(line)
    require(blocks == 1, 'unexpected number of resource-list conflicts')
    fixed = ''.join(merged)
    tree = ast.parse(fixed)
    values = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id == 'NATIVE_SOURCE_FILES' for t in node.targets)]
    require(len(values) == 1 and type(values[0]) is tuple
            and RESOURCE_LINES <= set(values[0]) and len(values[0]) == len(set(values[0])),
            'resolved NATIVE_SOURCE_FILES is incomplete or duplicated')
    create(LOGS / ('conflict-' + str(number) + '.before.txt'), original.encode())
    path.write_text(fixed)
    create(LOGS / ('conflict-' + str(number) + '.after.txt'), fixed.encode())
    run('stage-reviewed-conflict-' + str(number), git(SOURCE, 'add', '--', 'hepta/hia_agent_contract.py'))
    report['resolved_conflicts'].append({'merge': number, 'path': 'hepta/hia_agent_contract.py',
        'rule': 'union of exactly the three reviewed HIA resource literal lines', 'after_sha256': sha(path)})


try:
    for name, expected in PINS.items():
        require(sha(name) == expected, 'original qualification evidence identity differs: ' + name)
    report['original_evidence_pins_before'] = dict(PINS)
    _, before = run('borrow-before', git(BORROW, 'rev-parse', 'HEAD', 'HEAD^{tree}'))
    require(before.splitlines() == [BASE_HEAD, BASE_TREE], 'borrowed416 identity differs')
    _, clean = run('borrow-clean-before', git(BORROW, 'status', '--porcelain=v1', '--untracked-files=all'))
    require(not clean, 'borrowed416 source is not clean')
    run('independent-local-clone', ['/usr/bin/git', '-c', 'core.hooksPath=/dev/null',
        'clone', '--local', '--no-hardlinks', '--no-checkout', str(BORROW), str(SOURCE)], seconds=300)
    complete_independent_objects(SOURCE)
    _, shallow = run('shallow-observation', git(SOURCE, 'rev-parse', '--is-shallow-repository'))
    require(shallow in ('true', 'false'), 'unexpected shallow-repository response')
    fetch = ['fetch', '--no-tags', '--no-recurse-submodules']
    if shallow == 'true':
        fetch.append('--unshallow')
    run('fetch-exact-published-commits', git(SOURCE, *fetch, REPOSITORY, *COMMITS), seconds=900)
    _, observed = run('fetched-identities', git(SOURCE, 'rev-parse', *[x + '^{commit}' for x in COMMITS]))
    require(observed.splitlines() == list(COMMITS), 'fetched commit identity differs')
    run('checkout-base', git(SOURCE, 'checkout', '--quiet', '-b', 'codex/hia-v66-desktop-integration-e26e', BASE_HEAD))
    for number, commit in enumerate(COMMITS, 1):
        code, _ = run('merge-' + str(number), git(SOURCE, 'merge', '--no-ff', '--no-edit',
            '-m', 'Integrate HIA owner ' + commit, commit), seconds=120, allow_merge_conflict=True)
        if code == 1:
            resolve_resource_conflict(number)
            run('commit-resolved-merge-' + str(number), git(SOURCE, 'commit', '--no-edit'), seconds=120)
    for number, commit in enumerate(COMMITS, 1):
        run('retained-ancestor-' + str(number), git(SOURCE, 'merge-base', '--is-ancestor', commit, 'HEAD'))
    run('object-integrity', git(SOURCE, 'fsck', '--full', '--strict', '--no-dangling'), seconds=300)
    complete_independent_objects(SOURCE)
    _, current = run('integrated-identity', git(SOURCE, 'rev-parse', 'HEAD', 'HEAD^{tree}'))
    _, clean = run('integrated-clean', git(SOURCE, 'status', '--porcelain=v1', '--untracked-files=all'))
    require(not clean, 'integration source is not clean')
    _, changed = run('integrated-paths', git(SOURCE, 'diff', '--name-only', BASE_HEAD, 'HEAD'))
    _, after = run('borrow-after', git(BORROW, 'rev-parse', 'HEAD', 'HEAD^{tree}'))
    _, clean = run('borrow-clean-after', git(BORROW, 'status', '--porcelain=v1', '--untracked-files=all'))
    require(after == before and not clean, 'borrowed416 source changed')
    after_pins = {name: sha(name) for name in PINS}
    require(after_pins == PINS, 'original evidence changed')
    report.update(status='INTEGRATED_SOURCE_READY_NOT_QUALIFIED_CONTRACT_PENDING',
        integrated_head=current.splitlines()[0], integrated_tree=current.splitlines()[1],
        changed_paths=changed.splitlines(), borrowed_source_preserved=True,
        original_evidence_pins_after=after_pins, source_complete_and_independent=True,
        final_global_contract_and_source_freeze_pending=True)
    checkpoint()
    print(json.dumps({k: report[k] for k in ('status', 'integrated_head', 'integrated_tree',
        'source', 'tests_executed', 'qualification_executed')}), flush=True)
except BaseException as error:
    report.update(status='PREPARATION_HOLD', error_type=type(error).__name__, error=str(error))
    checkpoint()
    raise
