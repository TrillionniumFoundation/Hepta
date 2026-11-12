"""Exact f8 + frozen context r6: isolated actual development, never cold."""
from __future__ import annotations

import argparse
import base64
from hashlib import sha1, sha256
import importlib.metadata
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time
import traceback
import zlib

BASE = 'f8d9680a9b0ae609850c006480a7d1f68ea00979'
TREE = '473404cdccc38a7e6bba633ef4a894877540d70e'
BASE_PARENT = '7e9c5a796a29746d169f9db97392ec774f627c03'
BASE_FILES = 3120
OWNER_SHA = 'c02c4965776e0f16c229553290937476b842f1fe50cdc279dd278876fe37f8f5'
COMPILER_PACKET_SHA = 'df542582525e52f7855f2746ae9dc7501f6835e41aa46b209e59f2e121177b8b'
ORIGINAL_SUITE_SHA = '9397c321d04b2c55c3cf297065c27a12ef58908f10e14d546a9cad765493e7e4'
COMPILER_SHA = '81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109'
SOURCE_SHA = '11548b403f7e9a623ab180cd88c3c2f879bcce288bf6c722c43871c14f4fd5ca'
IMAGE_SHA = '63d44f44adf0b87ab7c6925fc5a2ac657335d1547c590d2d10cb3654fe50f3a0'
SOURCE_NAME = 'examples/hia_bootstrap/service_context.hiaasm'
SHARED_CURRENT_SHA = '65c61a71fa90c2a757fc24aef8eca5e36af6e6b355d2537c63345e98f8d338d2'
PACKAGES = {'setuptools': '78.1.1', 'wheel': '0.46.3',
            'z3-solver': '4.15.4.0', 'jsonschema': '4.26.0'}


def digest(raw):
    return sha256(raw).hexdigest()


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def write(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
    if path.read_bytes() != raw:
        raise ValueError('publication readback differs: ' + str(path))


def safe(name):
    if type(name) is not str or not name or '\\' in name or '\x00' in name:
        raise ValueError('ordinary relative source path required')
    p = PurePosixPath(name)
    if p.is_absolute() or '.git' in p.parts or p.as_posix() != name or any(x in ('', '.', '..') for x in p.parts):
        raise ValueError('ordinary relative source path required')
    return name


def metadata(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('regular source file required: ' + str(path))
    raw = path.read_bytes()
    after = path.lstat()
    keys = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if any(getattr(before, key) != getattr(after, key) for key in keys) or len(raw) != before.st_size:
        raise ValueError('source changed during read: ' + str(path))
    return {'bytes': len(raw), 'sha256': digest(raw),
            'git_blob_sha': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'git_mode': '100755' if before.st_mode & 0o111 else '100644',
            'posix_mode': format(stat.S_IMODE(before.st_mode), '04o')}


def files(root):
    result = {}
    for folder, dirs, names in os.walk(root):
        dirs[:] = [name for name in dirs if name not in ('.git', '__pycache__')]
        for name in dirs:
            if (Path(folder) / name).is_symlink():
                raise ValueError('source directory symlink refused')
        for name in names:
            path = Path(folder) / name
            result[safe(path.relative_to(root).as_posix())] = metadata(path)
    return result


def admit_git_snapshot(root, observed, tree_records):
    tracked = {}
    for row in tree_records.split(b'\0'):
        if not row:
            continue
        header, name = row.split(b'\t', 1)
        mode, kind, blob = header.decode('ascii').split()
        if kind != 'blob' or mode not in ('100644', '100755'):
            raise ValueError('regular Git blob required')
        path = safe(name.decode('utf-8'))
        if path in tracked:
            raise ValueError('duplicate Git source path')
        tracked[path] = {'git_mode': mode, 'git_blob_sha': blob}
    if set(tracked) != set(observed):
        raise ValueError('Git and actual source inventories differ')
    for path, expected in tracked.items():
        if any(observed[path][key] != value for key, value in expected.items()):
            raise ValueError('Git source bytes or mode differs: ' + path)
    return tracked


def append_development_tuple(root, relative, name, additions):
    path = root / relative
    before = path.read_bytes()
    suffix = ('\n# Isolated service-context development export; not product activation.\n'
              + name + ' += ' + repr(tuple(additions)) + '\n').encode()
    path.write_bytes(before + suffix)
    if path.read_bytes() != before + suffix:
        raise ValueError('development tuple publication differs')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--inputs', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = args.source.resolve(strict=True)
    inputs = args.inputs.resolve(strict=True)
    out = args.output.absolute()
    out.mkdir(mode=0o700, exist_ok=False)
    report = {'schema': 'hia.service-context.v76.development-ci.v1',
              'status': 'STARTED', 'source_base': BASE, 'source_tree': TREE,
              'base_parent': BASE_PARENT, 'python': sys.version,
              'platform': platform.platform(), 'commands': [],
              'development_only': True, 'current_source_cold': False,
              'default_changed': False, 'whole_stack_native': False,
              'all_input_equivalence_proved': False, 'live_deployment': False,
              'legacy_deletion': False, 'original_tests_modified': False,
              'compiler_child_timeout_seconds': 20,
              'component_supervisor_seconds': 240, 'original_agent_supervisor_seconds': 1800}
    expected = None
    selected_inputs = {}
    before_inputs = files(inputs)
    started = time.monotonic_ns()
    env = os.environ.copy()
    report['cleared_inherited_selector_names'] = sorted(key for key in env if key.startswith('HEPTA_'))
    clang = env.get('HEPTA_CLANG', '/usr/bin/clang-20')
    for key in report['cleared_inherited_selector_names']:
        del env[key]
    env.update(PYTHONDONTWRITEBYTECODE='1', CLANG=clang, HEPTA_CLANG=clang)

    def command(label, argv, *, seconds=240, environment=None, allow_failure=False):
        row = {'label': label, 'argv': list(map(str, argv)), 'cwd': str(root),
               'timeout_seconds': seconds}
        report['commands'].append(row)
        stdout, stderr = out / (label + '.stdout.log'), out / (label + '.stderr.log')
        begin = time.monotonic_ns()
        try:
            with stdout.open('xb') as so, stderr.open('xb') as se:
                child = subprocess.Popen(list(map(str, argv)), cwd=root,
                    env=env if environment is None else environment,
                    stdin=subprocess.DEVNULL, stdout=so, stderr=se, start_new_session=True)
                row['pid'] = child.pid
                try:
                    row['returncode'] = child.wait(timeout=seconds)
                    row['timed_out'] = False
                except subprocess.TimeoutExpired:
                    row['timed_out'] = True
                    os.killpg(child.pid, signal.SIGKILL)
                    row['returncode'] = child.wait()
                    raise
        finally:
            row['elapsed_ns'] = time.monotonic_ns() - begin
            for kind, path in (('stdout', stdout), ('stderr', stderr)):
                if path.exists():
                    row[kind] = {'path': path.name, 'bytes': path.stat().st_size,
                                 'sha256': digest(path.read_bytes())}
            write(out / (label + '.terminal.json'), wire(row))
        if row['returncode'] and not allow_failure:
            raise RuntimeError('original command failed: ' + label)
        return stdout.read_bytes()

    def guard(label):
        observed = files(root)
        write(out / (label + '.source.json'), wire(observed))
        if observed != expected:
            raise ValueError('frozen source bytes/modes changed: ' + label)
        if files(inputs) != before_inputs:
            raise ValueError('harness inputs changed: ' + label)
        for path, original in selected_inputs.items():
            if metadata(path) != original:
                raise ValueError('held executable/build input changed: ' + str(path))

    try:
        if sys.version_info[:3] != (3, 14, 4) or platform.system() != 'Linux' or platform.machine() != 'x86_64':
            raise ValueError('actual CPython 3.14.4 Linux x86-64 required')
        report['packages'] = {name: importlib.metadata.version(name) for name in PACKAGES}
        if report['packages'] != PACKAGES:
            raise ValueError('original pinned Python prerequisite differs')
        import z3
        if z3.get_version() != (4, 15, 4, 0):
            raise ValueError('actual Z3 prerequisite differs')
        report['z3_version'] = list(z3.get_version())
        report['tools'] = {}
        for label, name in (('clang', clang), ('ld', 'ld'), ('gcc', 'gcc'), ('strace', 'strace')):
            resolved = shutil.which(name)
            if resolved is None:
                raise ValueError('required real tool missing: ' + name)
            actual = Path(resolved).resolve(strict=True)
            version = command('prerequisite-' + label, [actual, '--version'], seconds=30).decode('utf-8', 'replace')
            if label == 'clang' and 'clang version 20.' not in version:
                raise ValueError('actual Clang 20 required')
            report['tools'][label] = {'path': str(actual), 'identity': metadata(actual), 'version': version}
        head = command('base-head', ['git', 'rev-parse', 'HEAD']).decode().strip()
        tree = command('base-tree', ['git', 'rev-parse', 'HEAD^{tree}']).decode().strip()
        parent = command('base-parent', ['git', 'rev-parse', 'HEAD^']).decode().strip()
        if (head, tree, parent) != (BASE, TREE, BASE_PARENT):
            raise ValueError('exact original base commit/tree/parent required')
        if command('base-status', ['git', 'status', '--porcelain=v1', '--untracked-files=all']):
            raise ValueError('original checkout is not clean')
        original = files(root)
        tree_rows = command('base-tree-records', ['git', 'ls-tree', '-r', '-z', '--full-tree', 'HEAD'])
        admit_git_snapshot(root, original, tree_rows)
        if len(original) != BASE_FILES:
            raise ValueError('complete original 3120-file checkout required')
        write(out / 'source-before.json', wire(original))
        owner_raw = (inputs / 'context-owner.json').read_bytes()
        if digest(owner_raw) != OWNER_SHA:
            raise ValueError('frozen context r6 source packet differs')
        owner = json.loads(owner_raw)
        if len(owner['owned_files']) != 10:
            raise ValueError('exact ten owner files required')
        if digest((inputs / 'original-agent-suite.json').read_bytes()) != ORIGINAL_SUITE_SHA:
            raise ValueError('original Agent suite identity differs')
        for name, row in owner['external_dependencies'].items():
            observed = metadata(root / safe(name))
            expected_sha = SHARED_CURRENT_SHA if name == 'hepta/hia_exception_delivery.py' else row['sha256']
            if observed['sha256'] != expected_sha:
                raise ValueError('parent shared dependency differs: ' + name)
        report['shared_exception_bridge_sha256'] = SHARED_CURRENT_SHA
        service = 'hepta/hia_agent_service.py'
        if original[service]['sha256'] != owner['parent_integration']['original_service']['sha256']:
            raise ValueError('original service changed; function merge required')
        for name, row in owner['owned_files'].items():
            path = root / safe(name)
            if name != service and name in original:
                raise ValueError('owner addition would overwrite an existing owner: ' + name)
            raw = row['utf8'].encode('utf-8')
            if len(raw) != row['bytes'] or digest(raw) != row['sha256']:
                raise ValueError('owner source bytes differ: ' + name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(int(row['mode'], 8))
            if metadata(path)['sha256'] != row['sha256']:
                raise ValueError('owner publication differs: ' + name)
        # These two append-only changes are an explicit development export.
        # The product branch and original contract bytes remain unchanged.
        append_development_tuple(root, 'hepta/hia_agent_contract.py',
                                 'NATIVE_SOURCE_FILES', (SOURCE_NAME,))
        append_development_tuple(root, 'tools/hia_selfhost_contract.py',
                                 'SOURCE_FILES', tuple(owner['owned_files']))
        post_overlay = files(root)
        if len(post_overlay) != BASE_FILES + 9:
            raise ValueError('unexpected owner source inventory')
        overlay_changed = {name for name in set(original) | set(post_overlay)
                           if original.get(name) != post_overlay.get(name)}
        if overlay_changed != set(owner['owned_files']) | {'hepta/hia_agent_contract.py', 'tools/hia_selfhost_contract.py'}:
            raise ValueError('development overlay changed an unrelated path')
        write(out / 'source-after-overlay.json', wire(post_overlay))
        command('generate-context', [sys.executable, '-B', '-m', 'tools.generate_hia_service_context'])
        if digest((root / SOURCE_NAME).read_bytes()) != SOURCE_SHA or files(root) != post_overlay:
            raise ValueError('context generation does not reproduce frozen bytes')
        command('generate-development-contract', [sys.executable, '-B', '-m', 'tools.generate_hia_selfhost_contract'])
        expected = files(root)
        generated_changed = {name for name in set(post_overlay) | set(expected)
                             if post_overlay.get(name) != expected.get(name)}
        if generated_changed != {'docs/HIA_SELFHOST_CORE_SUPPORT.json'}:
            raise ValueError('unexpected development contract generation delta')
        command('check-development-contract', [sys.executable, '-B', '-m', 'tools.generate_hia_selfhost_contract', '--check'])
        write(out / 'frozen-source.json', wire(expected))
        report['source_files'] = len(expected)
        report['development_export_paths'] = sorted(overlay_changed | generated_changed)
        command('stage-development-source', ['git', 'add', '--', *sorted(overlay_changed | generated_changed)])
        report['development_write_tree'] = command('development-write-tree', ['git', 'write-tree']).decode().strip()
        command('development-source-patch', ['git', 'diff', '--cached', '--binary', '--full-index', 'HEAD'])
        compiler_raw = (inputs / 'retained-compiler.json').read_bytes()
        if digest(compiler_raw) != COMPILER_PACKET_SHA:
            raise ValueError('retained compiler input differs')
        saved = json.loads(compiler_raw)
        compressed = base64.b64decode(saved['compiler_zlib_base64'], validate=True)
        if len(compressed) != saved['compressed_bytes'] or digest(compressed) != saved['compressed_sha256']:
            raise ValueError('retained compiler compressed bytes differ')
        decoder = zlib.decompressobj()
        compiler_bytes = decoder.decompress(compressed) + decoder.flush()
        if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise ValueError('retained compiler compression framing differs')
        if len(compiler_bytes) != 669494 or digest(compiler_bytes) != COMPILER_SHA:
            raise ValueError('actual retained B3 bytes differ')
        compiler = out / 'retained-B3.image.bin'
        write(compiler, compiler_bytes)
        compiler.chmod(0o444)
        original_receipt = saved['original_receipt_utf8'].encode()
        if digest(original_receipt) != saved['original_receipt_sha256']:
            raise ValueError('retained original receipt differs')
        write(out / 'retained-B3.original-receipt.json', original_receipt)
        report['retained_compiler'] = {'path': str(compiler), 'bytes': len(compiler_bytes),
                                       'sha256': COMPILER_SHA, 'original_artifact': saved['original_artifact'],
                                       'scope': saved['scope']}
        selected_inputs[compiler] = metadata(compiler)
        guard('before-build')
        command('build-context-development', [sys.executable, '-B', '-m', 'tools.build_hia_service_context',
            '--compiler', compiler, '--development', '--output', out / 'build'])
        manifest = out / 'build/development-manifest.json'
        value = json.loads(manifest.read_bytes())
        if (value['schema'] != 'hepta.hia.service-context-native.v3'
                or value['source_sha256'] != SOURCE_SHA or value['compiler_sha256'] != COMPILER_SHA
                or value['image_sha256'] != IMAGE_SHA):
            raise ValueError('actual selected image identity differs')
        image = manifest.parent / value['image_path']
        if metadata(image)['sha256'] != IMAGE_SHA:
            raise ValueError('actual compiled image differs')
        for path in (manifest, image, out / 'build/development-build.json', out / 'build/service-context.receipt.json'):
            selected_inputs[path] = metadata(path)
        report['selected_inputs_before'] = {str(path): row for path, row in selected_inputs.items()}
        guard('after-build')
        component_env = env.copy()
        component_env['HEPTA_HIA_SERVICE_CONTEXT_DEVELOPMENT_MANIFEST'] = str(manifest)
        component_env['HEPTA_HIA_SERVICE_CONTEXT_EVIDENCE'] = str(out / 'component-observations')
        command('component-46', [sys.executable, '-B', inputs / 'run_context_suite.py',
            '--source', root, '--kind', 'component', '--original-suite', inputs / 'original-agent-suite.json',
            '--output', out / 'component-46.json'], seconds=240, environment=component_env, allow_failure=True)
        guard('after-component-46')
        agent_env = env.copy()
        agent_env['HEPTA_HIA_SERVICE_CONTEXT_MANIFEST'] = str(manifest)
        command('original-agent-48', [sys.executable, '-B', inputs / 'run_context_suite.py',
            '--source', root, '--kind', 'original-agent', '--original-suite', inputs / 'original-agent-suite.json',
            '--output', out / 'original-agent-48.json'], seconds=1800, environment=agent_env, allow_failure=True)
        guard('after-original-agent-48')
        report['component'] = json.loads((out / 'component-46.json').read_bytes())
        report['original_agent'] = json.loads((out / 'original-agent-48.json').read_bytes())
        if report['component']['status'] != 'PASS' or report['component']['tests_run'] != 46:
            raise ValueError('complete context component group failed')
        if report['original_agent']['status'] != 'PASS' or report['original_agent']['tests_run'] != 48:
            raise ValueError('complete original Agent group failed')
        if any(row.get('returncode') != 0 or row.get('timed_out') is not False for row in report['commands']):
            raise ValueError('one original command failed')
        report['status'] = 'DEVELOPMENT_PASS'
    except BaseException:
        report.update(status='FAIL', traceback=traceback.format_exc())
    finally:
        if expected is not None:
            try:
                guard('final')
                report['source_and_inputs_unchanged'] = True
                with tarfile.open(out / 'complete-development-source.tar.gz', 'x:gz') as archive:
                    for name in sorted(expected):
                        archive.add(root / name, arcname='source/' + name, recursive=False)
                with tarfile.open(out / 'complete-development-source.tar.gz', 'r:gz') as archive:
                    members = archive.getmembers()
                    if len(members) != len(expected):
                        raise ValueError('source export inventory differs')
                    for item in members:
                        name = item.name.removeprefix('source/')
                        row = expected[name]
                        if not item.isfile() or item.size != row['bytes'] or format(item.mode & 0o777, '04o') != row['posix_mode']:
                            raise ValueError('source export mode or shape differs')
                        if digest(archive.extractfile(item).read()) != row['sha256']:
                            raise ValueError('source export bytes differ')
                report['source_export'] = metadata(out / 'complete-development-source.tar.gz')
            except BaseException:
                report.update(status='FAIL', source_and_inputs_unchanged=False,
                              final_custody_error=traceback.format_exc())
        report['elapsed_ns'] = time.monotonic_ns() - started
        write(out / 'REPORT.json', wire(report))
        identity = {path.relative_to(out).as_posix(): metadata(path)
                    for path in sorted(out.rglob('*')) if path.is_file()}
        write(out / 'ARTIFACT-FILES.json', wire(identity))
        print(json.dumps({'status': report['status'], 'elapsed_ns': report['elapsed_ns'],
                          'current_source_cold': False, 'whole_stack_native': False}), flush=True)
    return 0 if report['status'] == 'DEVELOPMENT_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
