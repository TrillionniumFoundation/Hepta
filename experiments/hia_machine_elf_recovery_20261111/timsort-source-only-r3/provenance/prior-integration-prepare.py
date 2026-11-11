"""Copy exact canonical source once, then install the twelve pinned ELF inputs."""
from pathlib import Path
from hashlib import sha256
import ast
import json
import os
import stat
import subprocess
import sys
import time
import traceback
from common import (ROOT, SOURCE, ORIGINAL, COMPILER, PYTHON, PYTHON_SHA, COMPILER_SHA,
                    HEAD, TREE, PRODUCT_COMMIT, SOURCE_HELPER, SOURCE_HELPER_SHA, PACKAGE_SHA,
                    GENERATED, HIA_SHA, ORACLE_SHA, checked_config, create, environment,
                    load_exact, stable_file, wire, require)
config = checked_config(ROOT / 'control/config.json')
env = environment()
report = {'schema': 'hepta.hia.machine-elf.integration-source-preparation.v1',
          'status': 'HOLD', 'scope': 'SOURCE_PREPARATION_ONLY_NOT_QUALIFICATION',
          'base_commit': HEAD, 'base_tree': TREE, 'product_commit': PRODUCT_COMMIT,
          'commands': [], 'source_metadata': {}, 'native_executed': False}
package = load_exact('elf_exact_source_package', ROOT / 'control/source_package.py', PACKAGE_SHA)
started = time.monotonic()
saved = 0
def save():
    global saved
    saved += 1
    path = ROOT / ('source-preparation-update-' + str(saved) + '.json')
    create(path, wire(report))
    os.replace(path, ROOT / 'source-preparation.json')

def run(label, command, cwd, timeout=120):
    at = time.monotonic()
    stdout, stderr = ROOT / (label + '.stdout'), ROOT / (label + '.stderr')
    result = {'label': label, 'argv': list(command), 'cwd': str(cwd),
              'timeout_seconds': timeout, 'returncode': None, 'timed_out': False}
    try:
        with stdout.open('xb') as out, stderr.open('xb') as err:
            done = subprocess.run(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                  stdout=out, stderr=err, timeout=timeout)
        result['returncode'] = done.returncode
    except subprocess.TimeoutExpired:
        result['timed_out'] = True
        raise
    finally:
        result['seconds'] = time.monotonic() - at
        result['stdout'] = stable_file(stdout)[0]
        result['stderr'] = stable_file(stderr)[0]
        report['commands'].append(result)
        save()
    require(result['returncode'] == 0, label + ' failed')


def original_state(root):
    original = load_exact('elf_original_source_identity', root / SOURCE_HELPER,
                          SOURCE_HELPER_SHA)
    # Original function and body, with explicit GIT_OPTIONAL_LOCKS=0 in this
    # actor's inherited environment; no replacement source checker is used.
    state = original._source_state()
    require(state['head'] == HEAD and state['tree'] == TREE
            and state['status'] == '' and len(state['files']) == 3925,
            'original complete source identity did not admit exact clean 608')
    stable_file(root / SOURCE_HELPER, SOURCE_HELPER_SHA)
    return state


def snapshot(root, expected, name):
    actual = set()
    for current, directories, files in os.walk(root, followlinks=False):
        if Path(current) == root:
            require('.git' in directories, 'complete Git source required')
            directories.remove('.git')
        for directory in directories:
            require(stat.S_ISDIR((Path(current) / directory).lstat().st_mode),
                    'non-directory source member')
        actual.update((Path(current) / file).relative_to(root).as_posix() for file in files)
    require(actual == set(expected), 'physical source denominator differs')
    files = {}
    for relative, pin in sorted(expected.items()):
        info, _ = stable_file(root / relative, pin['sha256'])
        mode = '100755' if (root / relative).stat().st_mode & stat.S_IXUSR else '100644'
        require(mode == pin['mode'], 'source mode differs: ' + relative)
        if 'size' in pin:
            require(info['bytes'] == pin['size'], 'source size differs: ' + relative)
        files[relative] = {**info, 'mode': mode}
    record = {'schema': 'hepta.hia.machine-elf.authoring-source-observation.v1',
              'root': str(root), 'head': HEAD, 'tree': TREE, 'files': files}
    receipt = create(ROOT / name, wire(record))
    report['source_metadata'][name] = receipt
    return record


def canonical_pins(state):
    inventory = package.tree_inventory(ORIGINAL, TREE)
    leaves = [row for row in inventory if row['type'] == 'blob']
    require(len(leaves) == 3925 and set(state['files']) == {row['path'] for row in leaves},
            'raw tree denominator differs')
    return {row['path']: {'sha256': state['files'][row['path']], 'mode': row['mode']}
            for row in leaves}


def reject_object_sharing(root):
    package.reject_external_object_state(root)
    objects = package.git_path(root, 'objects')
    for current, directories, files in os.walk(objects, followlinks=False):
        for directory in directories:
            require(stat.S_ISDIR((Path(current) / directory).lstat().st_mode),
                    'Git object directory is not ordinary')
        for file in files:
            info = (Path(current) / file).lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and info.st_uid == os.geteuid() and not file.endswith('.promisor'),
                    'shared, nonregular or promisor Git object refused')


before = None
old_snapshot = None
old_inputs = None
expected = None
try:
    require(sys.version_info[:3] == (3, 14, 4), 'fixed Python version differs')
    old_inputs = {'python': stable_file(PYTHON, PYTHON_SHA, executable=True, resolve=True)[0],
                  'compiler': stable_file(COMPILER, COMPILER_SHA)[0]}
    fs = os.statvfs(ROOT)
    report['storage'] = {'device': ROOT.stat().st_dev,
        'home_device': Path('/home/qian-qi').stat().st_dev,
        'available_bytes': fs.f_bavail * fs.f_frsize, 'available_inodes': fs.f_favail}
    require(report['storage']['device'] == report['storage']['home_device']
        and report['storage']['available_bytes'] >= 8 << 30
        and report['storage']['available_inodes'] >= 100000, 'ordinary storage gate failed')
    before = original_state(ORIGINAL)
    expected = canonical_pins(before)
    create(ROOT / 'original-source-state-before.json', wire(before))
    old_snapshot = snapshot(ORIGINAL, expected, 'original-source-before.json')
    reject_object_sharing(ORIGINAL)
    run('clone', ['/usr/bin/git', '--no-replace-objects', '-c', 'core.hooksPath=/dev/null',
        'clone', '--local', '--no-hardlinks', '--', str(ORIGINAL), str(SOURCE)], ROOT)
    reject_object_sharing(SOURCE)
    clone_state = original_state(SOURCE)
    require(clone_state == before, 'independent complete canonical clone differs')
    clone_snapshot = snapshot(SOURCE, expected, 'clone-before.json')
    _, oracle = stable_file(ROOT / 'control/oracle.py.txt', ORACLE_SHA, collect=True)
    require((SOURCE / 'hepta/hia_machine_elf.py').read_bytes() == oracle, 'complete oracle differs')
    before_expected = dict(expected)
    applied = {}
    for relative, pin in config['products'].items():
        info, raw = stable_file(ROOT / 'control' / pin['file'], pin['sha256'], collect=True)
        require(info['bytes'] == pin['size'], 'product size differs')
        if relative.endswith('.py'):
            ast.parse(raw, filename=relative)
        target = SOURCE / relative
        if relative in before_expected:
            stable_file(target, before_expected[relative]['sha256'])
            temp = target.with_name(target.name + '.elf-integration-candidate')
            create(temp, raw, 0o644)
            os.replace(temp, target)
        else:
            require(not os.path.lexists(target), 'new product path already exists')
            target.parent.mkdir(parents=True, exist_ok=True)
            create(target, raw, 0o644)
        expected[relative] = {'sha256': pin['sha256'], 'size': pin['size'], 'mode': '100644'}
        applied[relative] = {'sha256': pin['sha256'], 'bytes': pin['size']}
    require((SOURCE / 'hepta/hia_machine_elf.py').read_bytes().startswith(oracle),
            'complete original oracle prefix changed')
    stable_file(SOURCE / GENERATED, HIA_SHA)
    require(len(expected) == 3932 and len(applied) == 12, 'source overlay denominator differs')
    candidate = snapshot(SOURCE, expected, 'candidate-source-before.json')
    for relative, old in clone_snapshot['files'].items():
        if relative not in config['products']:
            require(candidate['files'][relative] == old,
                    'unapproved private clone metadata change: ' + relative)
    _, compiler_raw = stable_file(COMPILER, COMPILER_SHA, collect=True)
    require(len(compiler_raw) == 668608, 'original compiler length differs')
    create(ROOT / 'inputs/B3.image.bin', compiler_raw)
    report['compiler_input'] = {'path': str(ROOT / 'inputs/B3.image.bin'),
        'sha256': COMPILER_SHA, 'bytes': len(compiler_raw),
        'producer_scope': 'FAILED_608_COLD_COMPLETED_B3_GENERATION_ONLY',
        'matching_current_cold': False}
    report['products_installed'] = applied
    report['candidate_source'] = report['source_metadata']['candidate-source-before.json']
    report['complete_independent_clone_checked'] = True
    report['status'] = 'DEVELOPMENT_SOURCE_PREPARED_NO_PRODUCT_EXECUTED'
except BaseException:
    report['exception'] = traceback.format_exc()
finally:
    try:
        if before is not None:
            after = original_state(ORIGINAL)
            create(ROOT / 'original-source-state-after-preparation.json', wire(after))
            original_after = snapshot(ORIGINAL, before_expected if 'before_expected' in globals()
                                     else expected, 'original-source-after-preparation.json')
            report['original_source_state_stable'] = before == after
            report['original_source_metadata_stable'] = old_snapshot == original_after
            require(report['original_source_state_stable'] and report['original_source_metadata_stable'],
                    'old source changed during preparation')
        if old_inputs is not None:
            after_inputs = {'python': stable_file(PYTHON, PYTHON_SHA, executable=True, resolve=True)[0],
                            'compiler': stable_file(COMPILER, COMPILER_SHA)[0]}
            report['inputs_before'] = old_inputs
            report['inputs_after'] = after_inputs
            require(old_inputs == after_inputs, 'original runtime or compiler changed')
    except BaseException:
        report['final_capture_failure'] = traceback.format_exc()
        report['status'] = 'HOLD'
    report['seconds'] = time.monotonic() - started
    save()
    print(json.dumps({'stage': 'source-preparation', 'status': report['status'],
                      'seconds': report['seconds']}), flush=True)
raise SystemExit(0 if report['status'] == 'DEVELOPMENT_SOURCE_PREPARED_NO_PRODUCT_EXECUTED' else 1)
