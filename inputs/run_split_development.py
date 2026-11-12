"""Exact Git source -> two independent front owners, actual interpreter gates.

The native job uses CPython 3.14.4 and two new 20-second HIA compilations.
The compatibility job uses an actual CPython 3.11: default public callers and
explicit unsupported-native rejection only. Neither job supplies cold authority.
"""
from __future__ import annotations
import argparse
import base64
from hashlib import sha1, sha256
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import traceback
import zlib

from source_custody import digest, wire, write, safe, metadata, files, admit_git_snapshot, export_source

BASE = '64f67ae897c3cb49d45a1e1a4622db974812e3fe'
TREE = 'b7cf3502931d5fae8f58444b0af04cc642414a4a'
PARENT = '4b19af89a766593f7d5f1cc2db256e81aba7afcb'
R1_PACKET = ('760d4f401407b3ddb93880681bbfb93125b6a00d25f8ae79ba46c49b17bad1a7', 183809)
R4_PACKET = ('55d7833b7943491281171ad21bdfb3dc87db3620a13b7d797b635d22fd35dee0', 183695)
R1_GUARD = '9575730d64ee1b37c3189eeef6fc3a7f6dbd602627a6e6c080797163afe3079f'
COMPILER_PACKET = 'df542582525e52f7855f2746ae9dc7501f6835e41aa46b209e59f2e121177b8b'
COMPILER_SHA = '81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109'
GENERATED = {'examples/hia_bootstrap/core_verification.hiaasm',
    'examples/hia_bootstrap/assembly_front.hiaasm',
    'hepta/hia_core_verification_ports.py', 'hepta/hia_assembly_front_ports.py'}
PACKAGES = {'setuptools': '78.1.1', 'wheel': '0.46.3',
            'z3-solver': '4.15.4.0', 'jsonschema': '4.26.0'}

def capsule(path, identity, original):
    raw = path.read_bytes()
    if (digest(raw), len(raw)) != identity:
        raise ValueError('exact source packet differs: ' + path.name)
    wrapper = json.loads(raw)
    if identity == R1_PACKET:
        if (set(wrapper) != {'schema', 'encoding', 'data', 'bytes', 'sha256', 'git_blob'}
                or wrapper['schema'] != 'hia.zlib-source-capsule.v1'
                or wrapper['encoding'] != 'zlib+base64'):
            raise ValueError('exact original R1 capsule shape differs')
        compressed = base64.b64decode(wrapper['data'], validate=True)
        payload_size, payload_sha = wrapper['bytes'], wrapper['sha256']
    elif identity == R4_PACKET:
        if set(wrapper) != {'schema', 'payload_bytes', 'payload_sha256', 'zlib_bytes', 'zlib_sha256', 'zlib_base64'}:
            raise ValueError('exact R4 capsule shape differs')
        compressed = base64.b64decode(wrapper['zlib_base64'], validate=True)
        if len(compressed) != wrapper['zlib_bytes'] or digest(compressed) != wrapper['zlib_sha256']:
            raise ValueError('source compressed bytes differ')
        payload_size, payload_sha = wrapper['payload_bytes'], wrapper['payload_sha256']
    else:
        raise ValueError('unreviewed source capsule identity')
    decoder = zlib.decompressobj()
    payload = decoder.decompress(compressed, payload_size + 1)
    if decoder.unconsumed_tail:
        raise ValueError('source packet exceeds original extent')
    payload += decoder.flush()
    if (not decoder.eof or decoder.unused_data or decoder.unconsumed_tail
            or len(payload) != payload_size or digest(payload) != payload_sha):
        raise ValueError('source payload differs')
    if identity == R1_PACKET and sha1(b'blob ' + str(len(payload)).encode() + b'\0' + payload).hexdigest() != wrapper['git_blob']:
        raise ValueError('original R1 payload Git identity differs')
    value = json.loads(payload)
    if (value['base_commit'] != BASE or value['base_tree'] != TREE
            or value['base_files'] != 3255 or len(value['files']) != 22):
        raise ValueError('split source base or inventory differs')
    for name, row in value['files'].items():
        safe(name)
        data = row['text'].encode('utf-8')
        if (type(row['mode']) is not int or row['mode'] != 0o644
                or len(data) != row['bytes'] or digest(data) != row['sha256']
                or sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() != row['git_blob']):
            raise ValueError('exact owner source differs: ' + name)
        before = row['before']
        if before is None:
            if name in original:
                raise ValueError('new owner source overwrites existing file')
        elif name not in original or {
                'bytes': original[name]['bytes'], 'sha256': original[name]['sha256'],
                'mode': int(original[name]['posix_mode'], 8)} != before:
            raise ValueError('source baseline differs: ' + name)
    return value

def apply_packet(root, value):
    for name, row in value['files'].items():
        path = root / safe(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(row['text'].encode('utf-8'))
        path.chmod(row['mode'])
        actual = metadata(path)
        if (actual['sha256'] != row['sha256'] or actual['bytes'] != row['bytes']
                or actual['git_blob_sha'] != row['git_blob'] or int(actual['posix_mode'], 8) != row['mode']):
            raise ValueError('owner source publication differs: ' + name)

def copy_source(root, target, observed):
    target.mkdir(parents=True, exist_ok=False)
    for name in observed:
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / name, path)
    if files(target) != observed:
        raise ValueError('complete source copy differs')

def restore_compiler(path, out):
    raw = path.read_bytes()
    if digest(raw) != COMPILER_PACKET:
        raise ValueError('original retained compiler capsule differs')
    saved = json.loads(raw)
    packed = base64.b64decode(saved['compiler_zlib_base64'], validate=True)
    if len(packed) != saved['compressed_bytes'] or digest(packed) != saved['compressed_sha256']:
        raise ValueError('original retained compiler compression differs')
    decoder = zlib.decompressobj()
    image = decoder.decompress(packed, 669495)
    if decoder.unconsumed_tail:
        raise ValueError('retained compiler exceeds original extent')
    image += decoder.flush()
    if (not decoder.eof or decoder.unused_data or decoder.unconsumed_tail
            or len(image) != 669494 or digest(image) != COMPILER_SHA):
        raise ValueError('original retained compiler bytes differ')
    out.mkdir(exist_ok=False)
    path = out / 'retained-B3.image.bin'
    write(path, image)
    path.chmod(0o444)
    receipt = saved['original_receipt_utf8'].encode()
    if digest(receipt) != saved['original_receipt_sha256']:
        raise ValueError('original retained compiler receipt differs')
    write(out / 'retained-B3.original-receipt.json', receipt)
    return path, {'bytes': 669494, 'sha256': COMPILER_SHA,
        'original_artifact': saved['original_artifact'],
        'scope': 'BORROWED_DEVELOPMENT_INPUT_NO_CURRENT_COLD_AUTHORITY'}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--profile', choices=('native314', 'default311'), required=True)
    args = parser.parse_args()
    root, inputs = args.source.resolve(strict=True), args.inputs.resolve(strict=True)
    work = args.workspace.absolute()
    work.mkdir(mode=0o700, exist_ok=False)
    out = work / 'driver-evidence'
    out.mkdir()
    before_inputs = files(inputs)
    selected = {}
    expected = None
    reference_expected = None
    runtime_root = work / 'source'
    reference_root = work.with_name('v81-core-assembly-front-development-r1') / 'source'
    report = {'schema': 'hia.front.two-owner.actual-interpreter-ci.v81.r4',
        'status': 'STARTED', 'profile': args.profile, 'python': sys.version,
        'base_commit': BASE, 'base_tree': TREE, 'commands': [],
        'current_cold': False, 'whole_normalization': False, 'physical_recursion': False,
        'default_activated': False, 'legacy_deleted': False,
        'old_thirteen_root_results_inherited': False,
        'compiler_child_seconds': 20, 'group_seconds': 1800}
    env = os.environ.copy()
    report['cleared_environment'] = sorted(k for k in env if k.startswith('HEPTA_'))
    for key in report['cleared_environment']:
        del env[key]
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    started = time.monotonic_ns()

    spec = importlib.util.spec_from_file_location('frozen_original_workflow_process',
        root / 'review-evidence/hia-native-rewrite-20261111/workflow_process.py')
    supervisor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(supervisor)

    def guard(label):
        observed = files(root)
        write(out / (label + '.source.json'), wire(observed))
        if expected is not None and observed != expected:
            raise ValueError('actual Git source drifted: ' + label)
        if runtime_root.exists() and files(runtime_root) != expected:
            raise ValueError('runtime source export drifted: ' + label)
        if reference_expected is not None and files(reference_root) != reference_expected:
            raise ValueError('frozen original R1 source drifted: ' + label)
        if files(inputs) != before_inputs:
            raise ValueError('frozen CI input changed: ' + label)
        for path, identity in selected.items():
            if metadata(path) != identity:
                raise ValueError('held actual image/manifest/receipt changed: ' + str(path))

    def command(label, argv, *, seconds=1800, allow_failure=False, cwd=None):
        receipt = supervisor.run_workflow_step(list(map(str, argv)), cwd=root if cwd is None else cwd,
            env=env, stdout_path=out / (label + '.stdout.log'),
            stderr_path=out / (label + '.stderr.log'),
            receipt_path=out / (label + '.supervisor.json'), seconds=seconds)
        report['commands'].append({'label': label, 'supervisor': receipt})
        if expected is not None:
            guard('after-' + label)
        if receipt['status'] != 'WORKFLOW_STEP_COMPLETED' and not allow_failure:
            raise RuntimeError('original bounded command failed: ' + label)
        return (out / (label + '.stdout.log')).read_bytes()

    try:
        if (sys.implementation.name != 'cpython' or platform.system() != 'Linux'
                or platform.machine() != 'x86_64'
                or platform.freedesktop_os_release().get('ID') != 'ubuntu'
                or platform.freedesktop_os_release().get('VERSION_ID') != '24.04'
                or (args.profile == 'native314' and sys.version_info[:3] != (3, 14, 4))
                or (args.profile == 'default311' and sys.version_info[:2] != (3, 11))):
            raise ValueError('requested actual interpreter/platform differs')
        report['packages'] = {name: importlib.metadata.version(name) for name in PACKAGES}
        if report['packages'] != PACKAGES:
            raise ValueError('pinned prerequisite versions differ')
        if command('base-head', ['git', 'rev-parse', 'HEAD'], seconds=30).decode().strip() != BASE:
            raise ValueError('actual Git base commit differs')
        if command('base-tree', ['git', 'rev-parse', 'HEAD^{tree}'], seconds=30).decode().strip() != TREE:
            raise ValueError('actual Git base tree differs')
        if command('base-parent', ['git', 'rev-parse', 'HEAD^'], seconds=30).decode().strip() != PARENT:
            raise ValueError('actual Git base parent differs')
        if command('base-status', ['git', 'status', '--porcelain=v1', '--untracked-files=all'], seconds=30):
            raise ValueError('base Git checkout is not clean')
        original = files(root)
        admit_git_snapshot(root, original, command('base-records',
            ['git', 'ls-tree', '-r', '-z', '--full-tree', 'HEAD'], seconds=30))
        if len(original) != 3255:
            raise ValueError('complete actual 3255-file base required')
        write(out / 'source-before.json', wire(original))
        r1 = capsule(inputs / 'r1-source-packet.json', R1_PACKET, original)
        r4 = capsule(inputs / 'r4-source-packet.json', R4_PACKET, original)
        copy_source(root, reference_root, original)
        apply_packet(reference_root, r1)
        reference_expected = files(reference_root)
        reference_guard = {name: {'sha256': row['sha256'], 'mode': int(row['posix_mode'], 8)}
                           for name, row in reference_expected.items()}
        if len(reference_guard) != 3273 or digest(wire(reference_guard)) != R1_GUARD:
            raise ValueError('exact original R1 source reconstruction differs')
        write(work / 'ORIGINAL-R1-SOURCE-GUARD.json', wire(reference_guard))
        write(work / 'BASE.json', wire({'base_commit': BASE, 'base_tree': TREE,
            'count': len(original), 'actual_git_admitted': True,
            'files': {name: {'bytes': row['bytes'], 'sha256': row['sha256'],
                            'mode': int(row['posix_mode'], 8)} for name, row in original.items()}}))
        apply_packet(root, r4)
        authored = files(root)
        if len(authored) != 3273 or set(authored) != set(original) | set(r4['files']):
            raise ValueError('complete authored source inventory differs')
        for name in original.keys() - r4['files'].keys():
            if authored[name] != original[name]:
                raise ValueError('unrelated authored source changed')
        write(out / 'source-authored.json', wire(authored))
        if args.profile == 'native314':
            command('generate-core', [sys.executable, '-B', '-m', 'tools.generate_hia_core_verification'], seconds=240)
            command('generate-assembly', [sys.executable, '-B', '-m', 'tools.generate_hia_assembly_front'], seconds=240)
        expected = files(root)
        changed = {name for name in set(authored) | set(expected) if authored.get(name) != expected.get(name)}
        if not changed <= GENERATED or set(expected) != set(authored):
            raise ValueError('generation changed source outside the four exact generated paths')
        report['actual_generated_delta'] = sorted(changed)
        report['runtime_source_files'] = len(expected)
        copy_source(root, runtime_root, expected)
        write(out / 'frozen-runtime-source.json', wire(expected))
        for path in sorted(inputs.glob('*.py')):
            dest = work / path.name
            shutil.copy2(path, dest)
            if dest.read_bytes() != path.read_bytes():
                raise ValueError('executed fixture copy differs')
            selected[dest] = metadata(dest)
        command('stage-source', ['git', 'add', '--', *sorted(r4['files'])], seconds=30)
        report['development_write_tree'] = command('write-tree', ['git', 'write-tree'], seconds=30).decode().strip()
        command('source-patch', ['git', 'diff', '--cached', '--binary', '--full-index', 'HEAD'], seconds=30)
        command('source-whitespace', ['git', 'diff', '--cached', '--check'], seconds=30, allow_failure=True)
        guard('before-groups')
        command('pure-transport-source-projection', [sys.executable, '-B', work / 'probe_source_projection.py',
            '--source', runtime_root, '--output', work / 'pure-source-projection'],
            allow_failure=True, cwd=runtime_root)
        if args.profile == 'native314':
            compiler, report['retained_compiler'] = restore_compiler(inputs / 'retained-compiler.json', work / 'retained-inputs')
            selected[compiler] = metadata(compiler)
            command('two-new-compilations', [sys.executable, '-B', work / 'compile_split_ci.py'],
                    allow_failure=True, cwd=runtime_root)
            build_path = work / 'native-build-r1/RESULT.json'
            build = json.loads(build_path.read_bytes()) if build_path.exists() else None
            report['native_build'] = build
            if build is not None and build['status'] == 'DEVELOPMENT_TWO_IMAGES_BUILT':
                for item in build['images'].values():
                    manifest = Path(item['manifest_path'])
                    selected[manifest] = metadata(manifest)
                    image = manifest.parent / item['manifest']['image_path']
                    selected[image] = metadata(image)
                command('full-original-controls', [sys.executable, '-B', work / 'run_r3_controls.py'],
                        allow_failure=True, cwd=runtime_root)
                command('global-anchor-controls', [sys.executable, '-B', work / 'probe_split_globals_r3.py'],
                        allow_failure=True, cwd=runtime_root)
            else:
                report['blocked_groups'] = ['full-original-controls', 'global-anchor-controls']
        else:
            command('default-import', [sys.executable, '-B', work / 'probe_default_import_r3.py',
                '--source', runtime_root, '--output', work / 'default-import-r3'],
                allow_failure=True, cwd=runtime_root)
            command('default-callers-and-unsupported-native', [sys.executable, '-B', work / 'run_default_compatibility.py',
                '--source', runtime_root, '--inputs', inputs, '--output', work / 'default311-controls'],
                allow_failure=True, cwd=runtime_root)
        guard('after-all-groups')
        if args.profile == 'native314':
            expected_reports = [
                ('pure-source-projection/REPORT.json', None),
                ('controls-r3/RESULT.json', None),
                ('caller-matrix-r1/core-program-composite/REPORT.json', 46),
                ('caller-matrix-r1/core-assembly/REPORT.json', 18),
                ('caller-matrix-r1/assembly-assembly/REPORT.json', 18),
                ('caller-matrix-r1/both-all/REPORT.json', 64),
                ('caller-matrix-r1/default-all/REPORT.json', 64),
                ('capture-controls-r2/REPORT.json', 9), ('transport-controls-r3/REPORT.json', 10),
                ('admission-controls-r2/REPORT.json', 4), ('global-controls-r3/REPORT.json', 3)]
        else:
            expected_reports = [('pure-source-projection/REPORT.json', None),
                ('default-import-r3/REPORT.json', None), ('default311-controls/REPORT.json', 64)]
        report['actual_groups'] = []
        for name, count in expected_reports:
            path = work / name
            observed = json.loads(path.read_bytes())
            if observed['status'] != 'PASS' or (count is not None and observed['tests_run'] != count):
                raise ValueError('original group did not pass: ' + name)
            report['actual_groups'].append({'path': name, 'tests_run': count, 'sha256': digest(path.read_bytes())})
        if any(row['supervisor']['status'] != 'WORKFLOW_STEP_COMPLETED' for row in report['commands']):
            raise ValueError('an actual preparation or test command failed')
        report['status'] = 'DEVELOPMENT_PASS'
    except BaseException:
        report.update(status='FAIL', traceback=traceback.format_exc())
    finally:
        try:
            if expected is not None:
                guard('final')
                report['source_and_inputs_unchanged'] = True
            observed = files(root)
            write(out / 'source-final-observed.json', wire(observed))
            report['complete_source_export'] = export_source(root, out, observed)
        except BaseException:
            report.update(status='FAIL', custody_error=traceback.format_exc())
        report['elapsed_ns'] = time.monotonic_ns() - started
        write(out / 'REPORT.json', wire(report))
        write(out / 'ARTIFACT-FILES.json', wire({p.relative_to(work).as_posix(): metadata(p)
            for p in sorted(work.rglob('*')) if p.is_file() and runtime_root not in p.parents}))
        print(json.dumps({'status': report['status'], 'profile': args.profile,
            'runtime_source_files': report.get('runtime_source_files'),
            'current_cold': False, 'whole_normalization': False}), flush=True)
    return 0 if report['status'] == 'DEVELOPMENT_PASS' else 1

if __name__ == '__main__':
    raise SystemExit(main())
