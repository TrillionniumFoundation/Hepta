"""Fresh complete 608 clone and reconstructed ELF authoring only.

No native compiler, image, product probe, full regression or cold run is invoked.
"""
from pathlib import Path
from hashlib import sha1, sha256
import ast
import json
import os
import stat
import subprocess
import sys
import time
import traceback

from common import (ROOT, SOURCE, COMPILER, PYTHON, PYTHON_SHA, COMPILER_SHA,
                    HEAD, TREE, SOURCE_HELPER, SOURCE_HELPER_SHA, PACKAGE_SHA,
                    OVERLAYS, ALLOWED_SOURCE_DELTA, GENERATED, ORACLE_SHA,
                    checked_config, create, environment, load_exact, read_json,
                    require, source_overlays, stable_file, wire)

config = checked_config(ROOT / 'control' / 'config.json')
source = ROOT / 'source'
env = environment()
report = {
    'schema': 'hepta.hia.machine-elf.reconstructed-authoring.v1',
    'status': 'HOLD', 'scope': 'RECONSTRUCTED_SOURCE_AND_CORE_AUTHORING_ONLY',
    'key': config['key'], 'root': str(ROOT), 'base_commit': HEAD, 'base_tree': TREE,
    'reconstructed_from': 'd080129298af94cf7eaf4b0981aa5a0697ec4be3',
    'filter_key_review': 'cf01a854b1404edaf4a41b3b5aebf718cef15bd3',
    'old_55_51_results_inherited': False, 'native_compilation_executed': False,
    'product_tests_executed': False, 'matching_current_cold': False,
    'whole_writer_qualified': False, 'whole_native_delivery_qualified': False,
    'commands': [], 'check_results': {}, 'source_metadata': {},
    'python': sys.version, 'executable': sys.executable,
}
started = time.monotonic()
package = load_exact('elf_exact_source_package', ROOT / 'control' / 'source_package.py', PACKAGE_SHA)


def save():
    # A task-owned progress report may be atomically replaced; the final bytes
    # and every distinct command/stdout/stderr file remain in this private root.
    raw = wire(report)
    temporary = ROOT / ('report.tmp.' + str(len(report['commands'])))
    counter = 0
    while temporary.exists():
        counter += 1
        temporary = ROOT / ('report.tmp.' + str(len(report['commands'])) + '.' + str(counter))
    create(temporary, raw)
    os.replace(temporary, ROOT / 'report.json')


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
    inventory = package.tree_inventory(SOURCE, TREE)
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
pins = None
try:
    require(sys.version_info[:3] == (3, 14, 4), 'qualified Python version differs')
    old_inputs = {
        'python': stable_file(PYTHON, PYTHON_SHA, executable=True, resolve=True)[0],
        'compiler': stable_file(COMPILER, COMPILER_SHA)[0],
    }
    fs = os.statvfs(ROOT)
    storage = {'device': ROOT.stat().st_dev, 'home_device': Path('/home/qian-qi').stat().st_dev,
               'available_bytes': fs.f_bavail * fs.f_frsize, 'available_inodes': fs.f_favail}
    report['actual_storage_before'] = storage
    require(storage['device'] == storage['home_device']
            and storage['available_bytes'] >= 8 << 30
            and storage['available_inodes'] >= 100000, 'ordinary home capacity gate failed')
    before = original_state(SOURCE)
    pins = canonical_pins(before)
    create(ROOT / 'original-source-state-before.json', wire(before))
    old_snapshot = snapshot(SOURCE, pins, 'original-source-before.json')
    reject_object_sharing(SOURCE)
    run('clone', ['/usr/bin/git', '--no-replace-objects', '-c', 'core.hooksPath=/dev/null',
                  'clone', '--local', '--no-hardlinks', '--', str(SOURCE), str(source)], ROOT)
    reject_object_sharing(source)
    clone_state = original_state(source)
    require(clone_state == before, 'independent clone differs from complete canonical source')
    clone_snapshot = snapshot(source, pins, 'clone-before.json')
    report['check_results']['complete_independent_608_clone'] = True
    oracle_info, oracle = stable_file(ROOT / 'control' / 'oracle-608.py.txt',
                                      ORACLE_SHA, collect=True)
    require((source / 'hepta/hia_machine_elf.py').read_bytes() == oracle,
            'full retained original writer differs')
    overlays = source_overlays(config, 'r2')
    for relative, input_pin in overlays.items():
        info, raw = stable_file(ROOT / 'control' / input_pin['file'],
                                input_pin['sha256'], collect=True)
        require(info['bytes'] == input_pin['size'], 'authoring bytes differ')
        ast.parse(raw)
        target = source / relative
        if relative == 'hepta/hia_machine_elf.py':
            require(raw.startswith(oracle), 'complete original module prefix changed')
            temporary = target.with_name(target.name + '.elf-authoring-new')
            create(temporary, raw, 0o644)
            os.replace(temporary, target)
        else:
            require(not os.path.lexists(target), 'new authoring path already exists')
            create(target, raw, 0o644)
    _, image = stable_file(COMPILER, COMPILER_SHA, collect=True)
    require(len(image) == 668608, 'original B3 length differs')
    create(ROOT / 'inputs' / 'B3.image.bin', image)
    report['development_compiler_input'] = {
        'original_path': str(COMPILER), 'sha256': COMPILER_SHA, 'bytes': len(image),
        'copied_path': str(ROOT / 'inputs' / 'B3.image.bin'),
        'executed': False, 'matching_current_cold': False,
        'producer_scope': 'FAILED_608_COLD_COMPLETED_B3_GENERATION_ONLY'}
    require(not os.path.lexists(source / GENERATED), 'generated ELF source already exists')
    run('generate-elf', [str(PYTHON), '-B', '-m', 'tools.generate_hia_machine_elf'], source, 60)
    sys.path.insert(0, str(source))
    from tools.generate_hia_machine_elf import document
    from hepta.hia_agent_assembly import assemble_program
    raw = (source / GENERATED).read_bytes()
    value = document()
    require(assemble_program(raw).as_dict() == value, 'complete Core roundtrip differs')
    functions = []
    for function in value['functions']:
        values = list(function['params'])
        for block in function['blocks']:
            values.extend(block['params'])
            for op in block['ops']:
                values.extend(op['out'])
        functions.append({
            'name': function['name'], 'blocks': len(function['blocks']),
            'ops': sum(len(block['ops']) for block in function['blocks']),
            'max_ssa_index': max(int(item['name'][1:]) for item in values),
        })
    measurements = {
        'source_bytes': len(raw), 'lines': len(raw.splitlines()), 'functions': len(functions),
        'blocks': sum(row['blocks'] for row in functions),
        'max_blocks_per_function': max(row['blocks'] for row in functions),
        'ops': sum(row['ops'] for row in functions),
        'max_ssa_index': max(row['max_ssa_index'] for row in functions),
    }
    limits = {'source_bytes': 1048576, 'lines': 16384, 'functions': 128,
              'blocks': 1536, 'max_blocks_per_function': 256, 'ops': 8192,
              'max_ssa_index': 2047}
    require(all(measurements[key] <= bound for key, bound in limits.items())
            and measurements['functions'] == 41, 'original authoring limits differ or exceeded')
    report['original_limits'] = limits
    report['generated_source'] = {
        'path': str(source / GENERATED), 'sha256': sha256(raw).hexdigest(),
        'git_blob_sha1': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
        'measurements': measurements, 'functions': functions}
    create(ROOT / 'generated-source.json', wire(report['generated_source']))
    create(ROOT / 'generated-machine-elf.hiaasm', raw)
    expected = dict(pins)
    for relative, input_pin in overlays.items():
        expected[relative] = {'sha256': input_pin['sha256'], 'size': input_pin['size'],
                              'mode': '100644'}
    expected[GENERATED] = {'sha256': sha256(raw).hexdigest(), 'size': len(raw), 'mode': '100644'}
    after = snapshot(source, expected, 'candidate-source-after.json')
    for relative, old in clone_snapshot['files'].items():
        if relative not in ALLOWED_SOURCE_DELTA:
            require(after['files'][relative] == old, 'unapproved source identity change: ' + relative)
    require(len(after['files']) == 3928, 'candidate source denominator differs')
    report['check_results'].update(
        syntax=True, whole_original_oracle_prefix=True, exact_three_authoring_inputs=True,
        core_roundtrip=True, original_limits=True, precisely_four_source_deltas=True)
    report['status'] = 'SOURCE_GENERATED_WITHIN_ORIGINAL_LIMITS_NOT_NATIVE_QUALIFIED'
except BaseException:
    report['exception'] = traceback.format_exc()
finally:
    try:
        if before is not None:
            after_original = original_state(SOURCE)
            create(ROOT / 'original-source-state-after.json', wire(after_original))
            original_after = snapshot(SOURCE, pins, 'original-source-after.json')
            report['original_source_state_stable'] = before == after_original
            report['original_source_metadata_stable'] = old_snapshot == original_after
            require(report['original_source_state_stable'] and report['original_source_metadata_stable'],
                    'old source changed during authoring')
        if old_inputs is not None:
            after_inputs = {
                'python': stable_file(PYTHON, PYTHON_SHA, executable=True, resolve=True)[0],
                'compiler': stable_file(COMPILER, COMPILER_SHA)[0],
            }
            report['old_inputs_before'] = old_inputs
            report['old_inputs_after'] = after_inputs
            require(old_inputs == after_inputs, 'old runtime or B3 changed')
    except BaseException:
        report['after_observation_error'] = traceback.format_exc()
        report['status'] = 'HOLD'
    report['seconds'] = time.monotonic() - started
    save()
    print(json.dumps({key: report.get(key) for key in
        ('status', 'scope', 'seconds', 'exception', 'generated_source',
         'original_source_state_stable', 'original_source_metadata_stable')},
        sort_keys=True), flush=True)
raise SystemExit(0 if report['status'] == 'SOURCE_GENERATED_WITHIN_ORIGINAL_LIMITS_NOT_NATIVE_QUALIFIED' else 1)
