"""Create one exact Core candidate and compile its 32 explicit development units."""
import io
from importlib.metadata import version
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback
from development_common import (
    AUTHOR_ROOT, BASE_HEAD, BASE_SOURCE, BASE_TREE, CANDIDATE, CANDIDATE_TREE,
    COMPILER, LEAVES, OBJECT_SOURCE, OWNER, PREPARE_ROOT, PYTHON, ROOT_TREE,
    binding, blob, candidate_snapshot, digest, git, metadata, private_bytes,
    relative, require, save, snapshot, verify_source, wire)

root = Path(sys.argv[1]).resolve(strict=True)
request = json.loads((root / 'request.json').read_bytes())
source = root / 'source'
started = time.monotonic()
report = {
    'schema': 'hia.core-lowering-development-prepare.v1', 'status': 'STARTED',
    'scope': 'EXPLICIT_DEVELOPMENT_ONLY',
    'candidate_commit': CANDIDATE, 'candidate_tree': CANDIDATE_TREE,
    'source_path': str(source), 'actual_checkout_HEAD': BASE_HEAD,
    'actual_HEAD_is_candidate': False, 'matching_current_cold': False,
    'derived_global_contracts_regenerated': False,
    'derived_global_contracts_parent': '7186dee24f33173c25f2246a6dfe15eeda053992',
    'source_generation_repeated': False, 'product_tests_executed': False,
    'default_activated': False, 'whole_native_delivery': False,
    'compile_wall_seconds': 20, 'compile_CPU_seconds': 10, 'owner_seconds': 180,
    'commands': [], 'native_compiles': [], 'copied_source_inputs': [],
    'python': sys.version, 'executable': sys.executable,
    'original_r3_archive_sha256': '400f59e67817fb9a6fc3ce744b4bb93c64957d932272880af7bb382325a2c450',
}
base_before = objects_before = candidate_before = compiler_before = None
r3_before, controller_before, outputs = [], [], []

def run(label, argv, cwd, data=None):
    at = time.monotonic()
    process = subprocess.run(argv, cwd=cwd, input=data, capture_output=True)
    (root / (label + '.stdout')).write_bytes(process.stdout)
    (root / (label + '.stderr')).write_bytes(process.stderr)
    report['commands'].append({
        'label': label, 'argv': argv, 'cwd': str(cwd), 'returncode': process.returncode,
        'seconds': time.monotonic() - at,
        'stdout_sha256': digest(process.stdout), 'stderr_sha256': digest(process.stderr)})
    require(process.returncode == 0, label + ' failed')
    return process.stdout

def write_source(row, raw):
    target = source / relative(row['path'])
    require(row['mode'] == '100644', 'unexpected frozen product mode')
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        private_bytes(target)
    target.write_bytes(raw)
    target.chmod(0o644)

try:
    require(root == PREPARE_ROOT and request['phase'] == 'prepare', 'fixed preparation root differs')
    require(request['candidate_commit'] == CANDIDATE and request['candidate_tree'] == CANDIDATE_TREE
            and request['candidate_leaf_count'] == LEAVES, 'frozen candidate differs')
    require(digest(Path(sys.executable).resolve().read_bytes()) == PYTHON,
            'actual interpreter binary differs')
    report['python_binary_sha256'] = PYTHON
    dependencies = {name: version(name) for name in ('z3-solver', 'jsonschema', 'setuptools', 'wheel', 'pip')}
    require(dependencies['z3-solver'] == '4.15.4.0', 'original pinned Z3 dependency differs')
    report['actual_dependencies'] = dependencies
    controller_before = [binding(root / name) for name in (
        'development_common.py', 'worker.py', 'request.json', 'source-files.json',
        'launch-payload.original.json')]
    base_before = metadata(BASE_SOURCE, BASE_TREE)
    objects_before = metadata(OBJECT_SOURCE, ROOT_TREE)
    require(base_before['head'] == objects_before['head'] == BASE_HEAD
            and base_before['head_tree'] == objects_before['head_tree'] == BASE_TREE
            and not base_before['tracked_status']
            and base_before['owner_sha256'] == objects_before['owner_sha256'] == OWNER,
            'readonly original Git identity differs')
    report['original_base_before'] = base_before
    report['original_objects_before'] = objects_before
    space = os.statvfs(root)
    report['storage_before'] = {'available_bytes': space.f_bavail * space.f_frsize,
                               'available_inodes': space.f_favail}
    require(space.f_bavail * space.f_frsize >= 2 * (1 << 30),
            'insufficient space for an independent exact clone and retained native outputs')
    inline = json.loads((root / 'source-files.json').read_bytes())
    core_rows = request['core_overlay']
    root_rows = request['root_overlay']
    require(len(core_rows) == 47 and len({r['path'] for r in core_rows}) == 47
            and len(root_rows) == 24 and len({r['path'] for r in root_rows}) == 24,
            'exact overlay population differs')
    require(set(inline) == {r['path'] for r in core_rows if r['origin'] == 'stdin'},
            'inline source set differs')
    for row in core_rows:
        if row['origin'] == 'original-r3-readonly':
            origin = Path(row['original']['path'])
            require(AUTHOR_ROOT in origin.parents, 'source origin escaped original r3 root')
            raw, actual_mode = private_bytes(origin)
            require(actual_mode == row['original']['mode'], 'original r3 source mode changed')
            verify_source(raw, row)
            r3_before.append(binding(origin))
        else:
            require(row['origin'] == 'stdin', 'unknown source origin')
            verify_source(inline[row['path']].encode(), row)
    require(len(r3_before) == 37 and len(inline) == 10, 'original and inline source counts differ')
    report['original_r3_source_inputs_before'] = r3_before
    run('clone', ['git', '--no-replace-objects', 'clone', '--quiet', '--no-local',
                  '--no-hardlinks', '--no-checkout', '--', str(BASE_SOURCE), str(source)], root)
    run('checkout', ['git', '--no-replace-objects', 'checkout', '--quiet', '--detach', 'HEAD'], source)
    require(git(source, ['rev-parse', 'HEAD']).decode().strip() == BASE_HEAD,
            'independent checkout HEAD differs')
    raw_objects = run('root-objects', ['git', '--no-replace-objects', 'cat-file', '--batch'],
                      OBJECT_SOURCE, ''.join(r['git_blob'] + '\n' for r in root_rows).encode())
    stream = io.BytesIO(raw_objects)
    for row in root_rows:
        head = stream.readline().decode().rstrip('\n').split()
        require(head == [row['git_blob'], 'blob', str(row['bytes'])], 'Git object header differs')
        raw = stream.read(row['bytes'])
        require(stream.read(1) == b'\n' and len(raw) == row['bytes']
                and blob(raw) == row['git_blob'], 'Git object bytes differ')
        write_source(row, raw)
    require(stream.read() == b'', 'unexpected additional Git objects')
    run('root-stage', ['git', '--no-replace-objects', 'add', '--', *[r['path'] for r in root_rows]], source)
    require(run('root-tree', ['git', '--no-replace-objects', 'write-tree'], source).decode().strip() == ROOT_TREE,
            'root product overlay tree differs')
    for row in core_rows:
        if row['origin'] == 'original-r3-readonly':
            raw, _ = private_bytes(Path(row['original']['path']))
        else:
            raw = inline[row['path']].encode()
        verify_source(raw, row)
        write_source(row, raw)
        report['copied_source_inputs'].append({k: v for k, v in row.items() if k != 'content'})
    run('core-stage', ['git', '--no-replace-objects', 'add', '--', *[r['path'] for r in core_rows]], source)
    require(run('candidate-tree', ['git', '--no-replace-objects', 'write-tree'], source).decode().strip() == CANDIDATE_TREE,
            'complete candidate index tree differs')
    candidate_before = candidate_snapshot(source)
    report['candidate_before'] = save(root, 'candidate-before.json', candidate_before)
    require(git(source, ['rev-parse', 'HEAD']).decode().strip() == BASE_HEAD,
            'actual checkout provenance changed')
    compiler_origin = Path(request['compiler_origin'])
    require(compiler_origin == Path('/home/qian-qi/he26instructions-native-prepare-r1/inputs/B3.image.bin'),
            'development compiler origin differs')
    compiler_before = binding(compiler_origin)
    require(compiler_before['bytes'] == 668608 and compiler_before['sha256'] == COMPILER,
            'original development compiler differs')
    inputs = root / 'inputs'
    inputs.mkdir(mode=0o700)
    compiler = inputs / 'B3.image.bin'
    compiler.write_bytes(compiler_origin.read_bytes())
    compiler.chmod(0o400)
    report['compiler_original_before'] = compiler_before
    report['compiler_copy'] = binding(compiler)
    require(report['compiler_copy']['sha256'] == COMPILER, 'compiler copy differs')
    sys.path.insert(0, str(source))
    from hepta.hia_core_lowering_selection import ABI_SOURCE, SCHEMA, UNIT_SCHEMA, checked_abi
    from tools import qualify_hia_selfhost as qualify
    require(qualify.CAPACITY == 1 << 20 and qualify.NATIVE_OBSERVER is None
            and qualify.NATIVE_LINKED_OBSERVER is None, 'original compiler transport or capacity differs')
    abi_raw = (source / ABI_SOURCE).read_bytes()
    abi = checked_abi(abi_raw)
    names = ['core_lowering_pool', *abi['units']]
    require(len(names) == 32 and len(set(names)) == 32 and len(abi['modes']) == 28,
            'complete generated unit or mode inventory differs')
    require(abi['modes']['_native_globals']['number'] == 28,
            'private fixture mode28 differs')
    bundle_directory = root / 'bundle'
    bundle_directory.mkdir(mode=0o700)
    manifests = {}
    for name in names:
        directory = bundle_directory / name
        directory.mkdir(mode=0o700)
        relative_source = 'examples/hia_bootstrap/' + name + '.hiaasm'
        source_raw = (source / relative_source).read_bytes()
        image, receipt = qualify.compile_stage(directory, name, compiler, source_raw)
        image_raw = image.read_bytes()
        unit = {'schema': UNIT_SCHEMA, 'source_sha256': digest(source_raw),
                'image_path': image.name, 'image_sha256': digest(image_raw),
                'compiler_sha256': COMPILER}
        manifest = directory / 'manifest.json'
        manifest.write_bytes(wire(unit))
        manifests[name] = name + '/manifest.json'
        outputs.extend([binding(image), binding(manifest)])
        report['native_compiles'].append({
            'name': name, 'source': relative_source, 'source_sha256': digest(source_raw),
            'manifest': unit, 'manifest_file': binding(manifest),
            'image_file': binding(image), 'compile_receipt_file': binding(directory / (name + '.receipt.json')),
            'native_compile_receipt': receipt})
        save(root, 'report.json', report)
    bundle = {'schema': SCHEMA, 'abi_sha256': digest(abi_raw), 'compiler_sha256': COMPILER,
              'unit_manifests': manifests}
    manifest = bundle_directory / 'manifest.json'
    manifest.write_bytes(wire(bundle))
    from development_common import inspect_bundle
    observed = inspect_bundle(manifest, source)
    require(len(report['native_compiles']) == 32 and len(observed['input_bindings']) == 65,
            'complete development build did not finish')
    build = {
        'schema': 'hepta.hia.core-lowering-development-build.v1',
        'status': 'EXPLICIT_DEVELOPMENT_IMAGES_BUILT_NOT_CALLER_QUALIFIED',
        'candidate_commit': CANDIDATE, 'candidate_tree': CANDIDATE_TREE,
        'source': report['candidate_before'], 'compiler_copy': report['compiler_copy'],
        'compiler_original': compiler_before, 'abi_sha256': digest(abi_raw),
        'bundle': bundle, 'units': report['native_compiles'],
        'expected_units': 32, 'actual_units': 32, 'matching_current_cold': False,
        'derived_global_contracts_regenerated': False,
        'source_generation_repeated': False, 'caller_tests_executed': False,
        'literal_pool_functional_admission_executed': False,
        'whole_native_delivery': False, 'default_activated': False,
    }
    build_path = bundle_directory / 'development-build.json'
    build_path.write_bytes(wire(build))
    outputs.extend([binding(manifest), binding(build_path)])
    report['manifest'] = str(manifest)
    report['bundle_observation'] = observed
    report['development_build'] = binding(build_path)
    report['build_inputs'] = [*observed['input_bindings'], binding(build_path), binding(compiler)]
    report['status'] = 'EXPLICIT_DEVELOPMENT_IMAGES_BUILT_NOT_CALLER_QUALIFIED'
except BaseException:
    report['status'] = 'HOLD'
    report['exception'] = traceback.format_exc()
finally:
    try:
        if candidate_before is not None:
            after = candidate_snapshot(source)
            report['candidate_after'] = save(root, 'candidate-after.json', after)
            report['candidate_stable'] = after == candidate_before
            require(report['candidate_stable'], 'complete candidate source changed')
        if base_before is not None:
            report['original_base_after'] = metadata(BASE_SOURCE, BASE_TREE)
            require(report['original_base_after'] == base_before, 'original base metadata changed')
        if objects_before is not None:
            report['original_objects_after'] = metadata(OBJECT_SOURCE, ROOT_TREE)
            require(report['original_objects_after'] == objects_before, 'original object repository changed')
        if r3_before:
            report['original_r3_source_inputs_after'] = [binding(Path(v['path'])) for v in r3_before]
            require(report['original_r3_source_inputs_after'] == r3_before, 'original r3 source changed')
        if compiler_before is not None:
            report['compiler_original_after'] = binding(Path(compiler_before['path']))
            require(report['compiler_original_after'] == compiler_before, 'original compiler changed')
        report['output_bindings_after'] = [binding(Path(v['path'])) for v in outputs]
        require(report['output_bindings_after'] == outputs, 'development outputs changed')
        report['controller_bindings_after'] = [binding(Path(v['path'])) for v in controller_before]
        require(report['controller_bindings_after'] == controller_before, 'frozen control inputs changed')
    except BaseException:
        report['status'] = 'HOLD'
        report['final_identity_error'] = traceback.format_exc()
    report['seconds'] = time.monotonic() - started
    save(root, 'report.json', report)
    print(json.dumps({k: report.get(k) for k in (
        'schema', 'scope', 'status', 'candidate_commit', 'candidate_tree',
        'candidate_stable', 'seconds', 'exception', 'final_identity_error')}, sort_keys=True), flush=True)
raise SystemExit(0 if report['status'] == 'EXPLICIT_DEVELOPMENT_IMAGES_BUILT_NOT_CALLER_QUALIFIED' else 1)
