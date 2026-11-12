"""Isolated exact-7e9 plus frozen-overlay ELF development gate.

No source-cold, complete project, default, deployment or retirement authority is
granted. Original physical compiler and test limits are unchanged.
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
import signal
import stat
import subprocess
import sys
import time
import traceback
import zlib

BASE = '7e9c5a796a29746d169f9db97392ec774f627c03'
TREE = '79843bddc6df7306299f0be6475a2fcd187b4d97'
OVERLAY_SHA = '9c066bdddbf0568be9013ad6d7db242caccd49690c08972df00ec18fefe8c98c'
COMPILER_SHA = '81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109'
SOURCE_SHA = 'd8ea1f2f83dd043729b22d371c400a97c321d2171b633ab2df71e58ab0c6b8e3'
IMAGE_SHA = '101d018e41cab653844c4ceee32919c737e7f40adcd647901d1dcffdaac7c0b6'
PACKAGES = {'setuptools': '78.1.1', 'wheel': '0.46.3',
            'z3-solver': '4.15.4.0', 'jsonschema': '4.26.0'}

def digest(raw):
    return sha256(raw).hexdigest()

def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()

def write(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
    assert path.read_bytes() == raw

def safe(name):
    p = PurePosixPath(name)
    assert type(name) is str and name and not p.is_absolute()
    assert '\\' not in name and '\x00' not in name and all(x not in ('', '.', '..') for x in p.parts)
    assert '.git' not in p.parts and p.as_posix() == name
    return name

def bytes_wrapper(raw):
    value = json.loads(raw)
    assert value['schema'] == 'hia.zlib-base64-bytes.v1'
    compressed = base64.b64decode(value['zlib_base64'], validate=True)
    assert len(compressed) == value['compressed_bytes'] and digest(compressed) == value['compressed_sha256']
    stream = zlib.decompressobj()
    decoded = stream.decompress(compressed) + stream.flush()
    assert stream.eof and not stream.unused_data and not stream.unconsumed_tail
    assert len(decoded) == value['raw_bytes'] and digest(decoded) == value['raw_sha256']
    return decoded

def metadata(path):
    observed = path.lstat()
    assert stat.S_ISREG(observed.st_mode) and not path.is_symlink()
    raw = path.read_bytes()
    return {'bytes': len(raw), 'sha256': digest(raw),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'git_mode': '100755' if observed.st_mode & 0o111 else '100644',
            'posix_mode': format(observed.st_mode & 0o777, '04o')}

def files(root):
    result = {}
    for directory, subdirs, filenames in os.walk(root):
        subdirs[:] = [name for name in subdirs if name not in ('.git', '__pycache__')]
        for name in subdirs:
            assert not (Path(directory) / name).is_symlink()
        for name in filenames:
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            result[safe(relative)] = metadata(path)
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--inputs', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root, inputs = args.source.resolve(strict=True), args.inputs.resolve(strict=True)
    out = args.output.absolute()
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    steps = []
    report = {'schema': 'hia.elf.v76.development-ci.v1', 'status': 'STARTED',
              'phase': 'ISOLATED_COMPONENT_DEVELOPMENT_CONTROLS',
              'base_commit': BASE, 'base_tree': TREE, 'overlay_sha256': OVERLAY_SHA,
              'python': sys.version, 'platform': platform.platform(), 'commands': steps,
              'cold_qualified': False, 'whole_qualified': False, 'default_changed': False,
              'live_worker_changed': False, 'old_stack_deleted': False,
              'original_compiler_child_timeout_seconds': 20,
              'original_public_object_limit': 67108864, 'original_symbol_limit': 65536,
              'original_peer_zip_and_executable_recovered': False}
    env = os.environ.copy()
    inherited = sorted(key for key in env if key.startswith('HEPTA_'))
    for key in inherited:
        del env[key]
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    report['cleared_inherited_selector_names'] = inherited
    expected = None
    started = time.monotonic()

    def command(label, argv, *, allow_failure=False, environment=None):
        row = {'label': label, 'argv': list(map(str, argv)), 'cwd': str(root),
               'outer_custody_timeout_seconds': 2400}
        steps.append(row)
        stdout, stderr = out / (label + '.stdout'), out / (label + '.stderr')
        child = None
        begin = time.monotonic()
        try:
            with stdout.open('xb') as so, stderr.open('xb') as se:
                child = subprocess.Popen(list(map(str, argv)), cwd=root,
                    env=env if environment is None else environment,
                    stdin=subprocess.DEVNULL, stdout=so, stderr=se, start_new_session=True)
                row['pid'] = child.pid
                try:
                    row['returncode'] = child.wait(timeout=2400)
                except subprocess.TimeoutExpired:
                    row['timeout'] = True
                    os.killpg(child.pid, signal.SIGKILL)
                    row['returncode'] = child.wait()
                    raise
            row['timeout'] = False
        finally:
            row['seconds'] = time.monotonic() - begin
            row['stdout'] = {'path': stdout.name, 'bytes': stdout.stat().st_size, 'sha256': digest(stdout.read_bytes())}
            row['stderr'] = {'path': stderr.name, 'bytes': stderr.stat().st_size, 'sha256': digest(stderr.read_bytes())}
            write(out / (label + '.terminal.json'), wire(row))
        if row['returncode'] and not allow_failure:
            raise RuntimeError('original command failed: ' + label)
        return stdout.read_bytes()

    def guard(label):
        observed = files(root)
        write(out / (label + '.source.json'), wire(observed))
        assert observed == expected, 'frozen source bytes or modes changed: ' + label

    try:
        assert sys.version_info[:3] == (3, 14, 4)
        assert platform.system() == 'Linux' and platform.machine() == 'x86_64'
        report['packages'] = {name: importlib.metadata.version(name) for name in PACKAGES}
        assert report['packages'] == PACKAGES
        import z3
        assert z3.get_version() == (4, 15, 4, 0)
        report['z3_version'] = list(z3.get_version())
        head = command('base-head', ['git', 'rev-parse', 'HEAD']).decode().strip()
        tree = command('base-tree', ['git', 'rev-parse', 'HEAD^{tree}']).decode().strip()
        assert head == BASE and tree == TREE
        assert command('base-status', ['git', 'status', '--porcelain=v1', '--untracked-files=all']) == b''
        entries = command('base-ls-tree', ['git', 'ls-tree', '-r', '-z', '--full-tree', 'HEAD'])
        tracked = {}
        for record in entries.split(b'\0'):
            if not record:
                continue
            header, name = record.split(b'\t', 1)
            mode, kind, blob = header.decode().split()
            assert kind == 'blob' and mode in ('100644', '100755')
            tracked[safe(name.decode())] = {'git_mode': mode, 'git_blob': blob}
        before = files(root)
        assert len(tracked) == len(before) == 3084 and set(tracked) == set(before)
        assert all(all(before[name][key] == value for key, value in row.items()) for name, row in tracked.items())
        write(out / 'source-before.json', wire(before))
        report['base_source_files'] = len(before)
        parts_raw = (inputs / 'overlay.parts.json').read_bytes()
        parts = json.loads(parts_raw)
        chunks = []
        for row in parts['parts']:
            name = safe(row['path'])
            assert PurePosixPath(name).name == name
            raw = (inputs / name).read_bytes()
            assert len(raw) == row['bytes'] and digest(raw) == row['sha256']
            chunks.append(raw)
        combined = b''.join(chunks)
        assert len(combined) == parts['bytes'] and digest(combined) == parts['sha256']
        overlay_raw = bytes_wrapper(combined)
        assert digest(overlay_raw) == OVERLAY_SHA
        overlay = json.loads(overlay_raw)
        assert overlay['base_commit'] == BASE and overlay['base_tree'] == TREE
        assert len(overlay['files']) == 18 and overlay['source_after_files'] == 3096
        for name, row in overlay['files'].items():
            path = root / safe(name)
            original = row['base']
            if original is None:
                assert name not in before and not path.exists() and not path.is_symlink()
            else:
                assert name in before and all(before[name][key] == value for key, value in original.items())
            raw = base64.b64decode(row['base64'], validate=True)
            assert len(raw) == row['bytes'] and digest(raw) == row['sha256']
            assert sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == row['git_blob']
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(int(row['posix_mode'], 8))
            assert all(metadata(path)[key] == row[key] for key in ('bytes', 'sha256', 'git_blob', 'git_mode', 'posix_mode'))
        expected = overlay['source_after']
        assert len(expected) == 3096
        guard('source-after-overlay')
        report['source_after_files'] = len(expected)
        write(out / 'overlay.json', overlay_raw)
        compiler = bytes_wrapper((inputs / 'compiler.wrapper.json').read_bytes())
        assert len(compiler) == 669494 and digest(compiler) == COMPILER_SHA
        compiler_path = out / 'retained-B3.image.bin'
        write(compiler_path, compiler)
        report['compiler'] = {'bytes': len(compiler), 'sha256': COMPILER_SHA,
                              'scope': 'RETAINED_AC3_B3_DEVELOPMENT_ONLY'}
        command('generate-elf', [sys.executable, '-B', '-m', 'tools.generate_hia_machine_elf'])
        assert digest((root / 'examples/hia_bootstrap/machine_elf.hiaasm').read_bytes()) == SOURCE_SHA
        guard('after-generation')
        command('build-development', [sys.executable, '-B', '-m', 'tools.build_hia_machine_elf',
            '--compiler', compiler_path, '--development', '--output', out / 'build'])
        manifest = out / 'build/manifest.json'
        manifest_value = json.loads(manifest.read_bytes())
        assert manifest_value['source_sha256'] == SOURCE_SHA and manifest_value['compiler_sha256'] == COMPILER_SHA
        assert manifest_value['image_sha256'] == IMAGE_SHA
        image_path = manifest.parent / manifest_value['image_path']
        assert digest(image_path.read_bytes()) == IMAGE_SHA
        report['image_sha256'] = IMAGE_SHA
        guard('after-build')
        selected = env.copy()
        selected['HEPTA_HIA_MACHINE_ELF_DEVELOPMENT_MANIFEST'] = str(manifest)
        selected['HEPTA_HIA_MACHINE_ELF_FIXTURE_EVIDENCE'] = str(out / 'component-evidence')
        command('component-37', [sys.executable, '-B', inputs / 'run_component_suite.py',
            root, out / 'component-SUMMARY.json', '37',
            'tests.test_hia_machine_elf_native', 'tests.test_hia_machine_elf_protocol'],
            allow_failure=True, environment=selected)
        guard('after-component-controls')
        command('original-callers-51', [sys.executable, '-B', '-m', 'tools.qualify_hia_machine_elf',
            '--development-manifest', manifest, '--output', out / 'original-callers'],
            allow_failure=True)
        guard('after-original-callers')
        component = json.loads((out / 'component-SUMMARY.json').read_bytes())
        callers = json.loads((out / 'original-callers/report.json').read_bytes())
        report['component'] = component
        report['original_callers'] = callers
        assert component['status'] == 'PASS' and component['tests_run'] == 37
        assert not component['failures'] and not component['errors'] and not component['skips']
        assert callers['status'] == 'SELECTED_NATIVE_ELF_CALLERS_PASS' and callers['tests_run'] == 51
        assert not any(callers['anomaly_counts'].values())
        assert all(row['returncode'] == 0 and not row['timeout'] for row in steps)
        assert compiler_path.read_bytes() == compiler
        report['status'] = 'PASS'
    except BaseException as error:
        report.update(status='FAIL', error_type=type(error).__qualname__, traceback=traceback.format_exc())
    finally:
        if expected is not None:
            try:
                guard('final')
                report['source_unchanged'] = True
            except BaseException:
                report.update(status='FAIL', source_unchanged=False,
                              source_custody_error=traceback.format_exc())
        report['seconds'] = time.monotonic() - started
        write(out / 'REPORT.json', wire(report))
        # Lossless compact text evidence permits review through job logs even
        # when the artifact channel is unavailable. Large native inputs and
        # wheels remain in the complete Actions artifact with explicit hashes.
        text_evidence = {}
        identities = {}
        for path in sorted(out.rglob('*')):
            if not path.is_file():
                continue
            name = path.relative_to(out).as_posix()
            raw = path.read_bytes()
            identities[name] = {'bytes': len(raw), 'sha256': digest(raw)}
            if name in ('REPORT.json', 'component-SUMMARY.json', 'original-callers/report.json') or path.parent == out and path.suffix in ('.stdout', '.stderr', '.json'):
                text_evidence[name] = base64.b64encode(raw).decode()
        capsule = wire({'schema': 'hia.elf.v76.lossless-text-evidence.v1',
                        'files_base64': text_evidence, 'all_file_identities': identities})
        compressed = zlib.compress(capsule, 9)
        write(out / 'TEXT-EVIDENCE.json.zlib', compressed)
        encoded = base64.b64encode(compressed).decode()
        chunks = [encoded[offset:offset + 10000] for offset in range(0, len(encoded), 10000)]
        for index, data in enumerate(chunks):
            print('HIA_ELF_V76_EVIDENCE ' + json.dumps({
                'index': index, 'count': len(chunks), 'raw_bytes': len(capsule),
                'raw_sha256': digest(capsule), 'compressed_bytes': len(compressed),
                'compressed_sha256': digest(compressed), 'base64': data}, separators=(',', ':')), flush=True)
        print(json.dumps({'status': report['status'], 'seconds': report['seconds'],
                          'cold_qualified': False, 'whole_qualified': False}), flush=True)
    return 0 if report['status'] == 'PASS' else 1

if __name__ == '__main__':
    raise SystemExit(main())
