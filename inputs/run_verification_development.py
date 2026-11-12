"""Exact 4b19 + frozen verification owner and source-owned original Agent48 gate.

Independent CPython 3.14.4 DEVELOPMENT; no prior result grants current cold
authority. Retains original test methods, assertions, limits and failures.
"""
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

BASE = '4b19af89a766593f7d5f1cc2db256e81aba7afcb'
TREE = '1bc7c90996e1910ad66ba771b0bfee1d5bfa655c'
BASE_PARENT = '5f7f95367e8e395863801487e969d286b9091110'
BASE_FILES = 3153
OVERLAY_SHA = '6a8842ccf02910032fe02a7469fd03bff8b658ab22f7ea4ad837a97a1f7130ab'
OVERLAY_BYTES = 2441217
OVERLAY_SOURCE_SHA = '28fe3ec4d0c8b2e4626999bde94950eb96ddb83199d11ad4c6a166d854e20e4c'
COMPONENT_SHA = 'a580ab7c0b57f0609c4f9fe4bf5a6b0de092bf4e56d783591cc0b6ce8842ae91'
COMPILER_PACKET_SHA = 'df542582525e52f7855f2746ae9dc7501f6835e41aa46b209e59f2e121177b8b'
ORIGINAL_SUITE_SHA = '9397c321d04b2c55c3cf297065c27a12ef58908f10e14d546a9cad765493e7e4'
COMPILER_SHA = '81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109'
SOURCE_SHA = '10a6d4861b81771ca040fc462b9232c44e1b63381339647f3772ada99aa0c81f'
IMAGE_SHA = 'debc53962d004ff6853f900dff8a4b1d9bcd91611fc9a1d86dfda89e64b4b041'
SOURCE_NAME = 'examples/hia_bootstrap/service_verification.hiaasm'
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


from development_literal_registry import extend_development_tuple


def source_identity(row):
    return {'bytes': row['bytes'], 'sha256': row['sha256'],
            'git_blob_sha': row['git_blob_sha'], 'mode': row.get('mode', row.get('git_mode'))}


def read_overlay(path):
    raw = Path(path).read_bytes()
    if digest(raw) != OVERLAY_SHA:
        raise ValueError('frozen cumulative source capsule differs')
    capsule = json.loads(raw)
    if capsule['schema'] != 'hia.zlib-source-capsule.v1' or capsule['encoding'] != 'zlib+base64':
        raise ValueError('exact source capsule framing required')
    compressed = base64.b64decode(capsule['payload'], validate=True)
    decoder = zlib.decompressobj()
    body = decoder.decompress(compressed, OVERLAY_BYTES + 1)
    if len(body) > OVERLAY_BYTES or decoder.unconsumed_tail:
        raise ValueError('source capsule exceeds frozen extent')
    body += decoder.flush()
    expected = capsule['source_packet']
    if (not decoder.eof or decoder.unused_data or decoder.unconsumed_tail
            or len(body) != OVERLAY_BYTES or digest(body) != OVERLAY_SOURCE_SHA
            or expected['bytes'] != len(body) or expected['sha256'] != digest(body)
            or expected['mode'] != '100644'
            or expected['git_blob_sha'] != sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()):
        raise ValueError('complete frozen source capsule bytes differ')
    value = json.loads(body)
    if (value['schema'] != 'hia.service-verification.cumulative-development-overlay.r3'
            or value['base_commit'] != BASE or value['base_tree'] != TREE
            or value['base_file_count'] != BASE_FILES or value['source_file_count'] != 3185
            or value['deleted'] != [] or len(value['files']) != 40
            or len(value['source_manifest']) != 3185):
        raise ValueError('exact 40-path cumulative verification source required')
    for name, row in value['files'].items():
        safe(name)
        text = row['text'].encode('utf-8')
        if (type(row['bytes']) is not int or len(text) != row['bytes'] or digest(text) != row['sha256']
                or row['mode'] != '100644'
                or sha1(b'blob ' + str(len(text)).encode() + b'\0' + text).hexdigest() != row['git_blob_sha']
                or source_identity(row) != source_identity(value['source_manifest'][name])):
            raise ValueError('frozen cumulative source bytes or mode differs: ' + name)
    for name in value['source_manifest']:
        safe(name)
    return value


def admit_overlay_base(overlay, original):
    for name, row in overlay['files'].items():
        before = row['before']
        if before is None:
            if name in original:
                raise ValueError('source addition overwrites an existing owner: ' + name)
        elif name not in original or source_identity(original[name]) != source_identity(before):
            raise ValueError('exact shared/base owner input differs: ' + name)


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
    report = {'schema': 'hia.service-verification.v78.development-ci.r1',
              'status': 'STARTED', 'source_base': BASE, 'source_tree': TREE,
              'base_parent': BASE_PARENT, 'python': sys.version,
              'platform': platform.platform(), 'commands': [],
              'development_only': True, 'current_source_cold': False,
              'default_forwarder_bytes_changed': True, 'native_default_activated': False, 'whole_stack_native': False,
              'all_input_equivalence_proved': False, 'live_deployment': False,
              'legacy_deletion': False, 'original_test_ids_and_assertions_preserved': True,
              'frozen_component_r3_definitions_preserved': True,
              'cumulative_overlay_paths': 40, 'cumulative_overlay_source_files': 3185,
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
                    if not allow_failure:
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
            raise ValueError('complete original 3153-file checkout required')
        write(out / 'source-before.json', wire(original))
        command('harness-source-controls', [sys.executable, '-B', inputs / 'test_verification_ci_driver.py'], seconds=60)
        literal_env = dict(env, HIA_VERIFICATION_BASE=str(root))
        command('literal-registry-controls', [sys.executable, '-B', inputs / 'test_development_literal_registry.py'], seconds=60, environment=literal_env)
        overlay = read_overlay(inputs / 'verification-overlay.json')
        selected_sources = overlay['files']
        if digest((inputs / 'component-43.json').read_bytes()) != COMPONENT_SHA:
            raise ValueError('frozen component denominator evidence differs')
        suite_raw = (inputs / 'original-agent-suite.json').read_bytes()
        if digest(suite_raw) != ORIGINAL_SUITE_SHA:
            raise ValueError('original Agent suite identity differs')
        original_suite = json.loads(suite_raw)
        if metadata(root / 'hepta/hia_exception_delivery.py')['sha256'] != SHARED_CURRENT_SHA:
            raise ValueError('parent shared exception dependency differs')
        report['shared_exception_bridge_sha256'] = SHARED_CURRENT_SHA
        admit_overlay_base(overlay, original)
        for name, row in selected_sources.items():
            path = root / name
            raw = row['text'].encode('utf-8')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw); path.chmod(0o644)
            if source_identity(metadata(path)) != source_identity(row):
                raise ValueError('owner publication differs: ' + name)
        reconstructed = files(root)
        if ({name: source_identity(row) for name, row in reconstructed.items()}
                != {name: source_identity(row) for name, row in overlay['source_manifest'].items()}):
            raise ValueError('complete 3185-file cumulative source reconstruction differs')
        write(out / 'source-reconstructed-before-development-registration.json', wire(reconstructed))
        # Literal edits preserve the real setup.py resource reader and all five
        # existing resource roles. Only this isolated development export changes.
        native_edit = extend_development_tuple(root, 'hepta/hia_agent_contract.py',
                                              'NATIVE_SOURCE_FILES', (SOURCE_NAME,))
        source_edit = extend_development_tuple(root, 'tools/hia_selfhost_contract.py',
            'SOURCE_FILES', tuple(selected_sources) + tuple(original_suite['files']))
        write(out / 'literal-development-registration.json', wire([native_edit, source_edit]))
        post_overlay = files(root)
        if len(post_overlay) != 3185:
            raise ValueError('unexpected owner source inventory')
        overlay_changed = {name for name in set(original) | set(post_overlay)
                           if original.get(name) != post_overlay.get(name)}
        if overlay_changed != set(selected_sources) | {'hepta/hia_agent_contract.py', 'tools/hia_selfhost_contract.py'}:
            raise ValueError('development overlay changed an unrelated path')
        write(out / 'source-after-overlay.json', wire(post_overlay))
        command('generate-verification', [sys.executable, '-B', '-m', 'tools.generate_hia_service_verification'])
        command('generate-verification-foreign', [sys.executable, '-B', '-m', 'tools.generate_hia_service_verification_foreign'])
        if digest((root / SOURCE_NAME).read_bytes()) != SOURCE_SHA or files(root) != post_overlay:
            raise ValueError('verification generation does not reproduce frozen bytes')
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
        command('build-verification-development', [sys.executable, '-B', '-m', 'tools.build_hia_service_verification',
            '--compiler', compiler, '--development', '--output', out / 'build'])
        manifest = out / 'build/development-manifest.json'
        value = json.loads(manifest.read_bytes())
        if (value['schema'] != 'hepta.hia.service-verification-native.v1'
                or value['source_sha256'] != SOURCE_SHA or value['compiler_sha256'] != COMPILER_SHA
                or value['image_sha256'] != IMAGE_SHA):
            raise ValueError('actual selected image identity differs')
        image = manifest.parent / value['image_path']
        if metadata(image)['sha256'] != IMAGE_SHA:
            raise ValueError('actual compiled image differs')
        for path in (manifest, image, out / 'build/development-build.json', out / 'build/service-verification.receipt.json'):
            selected_inputs[path] = metadata(path)
        report['selected_inputs_before'] = {str(path): row for path, row in selected_inputs.items()}
        guard('after-build')
        component_env = env.copy()
        component_env['HEPTA_HIA_SERVICE_VERIFICATION_DEVELOPMENT_MANIFEST'] = str(manifest)
        component_env['HEPTA_HIA_SERVICE_VERIFICATION_EVIDENCE'] = str(out / 'component-observations')
        command('component-43', [sys.executable, '-B', inputs / 'run_verification_group.py',
            '--source', root, '--denominator', inputs / 'component-43.json',
            '--output', out / 'component-43'], seconds=240, environment=component_env, allow_failure=True)
        guard('after-component-43')
        # The original public Agent group remains independent of component
        # failure, including timeout. No original test or deadline is changed.
        command('original-agent-48', [sys.executable, '-B', '-m', 'tools.qualify_hia_service_verification',
            '--development-compiler', compiler, '--evidence', out / 'original-agent-48'],
            seconds=1800, environment=env, allow_failure=True)
        guard('after-original-agent-48')
        report['component'] = json.loads((out / 'component-43/REPORT.json').read_bytes())
        report['original_agent'] = json.loads((out / 'original-agent-48/report.json').read_bytes())
        if report['component']['status'] != 'PASS' or report['component']['tests_run'] != 43:
            raise ValueError('complete verification component group failed')
        if (report['original_agent']['status'] != 'DEVELOPMENT_CALLERS_PASS'
                or report['original_agent']['original_agent']['tests_run'] != 48):
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
