"""New Proof recovery on exact 4b plus acknowledged Verification R6.

Pure-source reconstruction and actual Python 3.14.4 DEVELOPMENT. No lost
3202-file candidate, lost64 result, prior foreign17, or old cold authority is
inherited. Component85 and unchanged original22+18 remain separate gates.
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
OVERLAY_SHA = '1f6e199a21b0a0dac0197b18dd63947244f779919e6d223ff99afb84391836f8'
OVERLAY_BYTES = 2449043
OVERLAY_SOURCE_SHA = 'f7c6242157adefbd5c8a3e2dca36eb3b42de92298e853c794b3e5c5ec8479af4'
PROOF_PACKET_SHA = '567baf1ffa67a7a994db164bf8f58194a0d1fbc989a630d994a5f032c5932fa3'
PROOF_PACKET_BYTES = 625476
COMPONENT_SHA = '35b8ad4a6494dd71c69a1972af036954b6e38be6eea7648262c0b217197e31ac'
COMPILER_PACKET_SHA = 'df542582525e52f7855f2746ae9dc7501f6835e41aa46b209e59f2e121177b8b'
COMPILER_SHA = '81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109'
SOURCE_NAME = 'examples/hia_bootstrap/proof_contract.hiaasm'
OLD_SOURCE_SHA = '20415328e0b1b86069be3da960efd17416d97cbc3812ee422af97da9b266e72c'
OLD_TABLE_SHA = '437dde3b20de2925c162fecb47eb03e6e61898a117c4ac2a886f9673e324e86a'
OLD_IMAGE_SHA = '3b2f96169a6f657b3ef96e95bba8d899eb544ddabf7a1ccf47ebb5f189a58c89'
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
    if (value['schema'] != 'hia.service-verification.cumulative-development-overlay.r6'
            or value['base_commit'] != BASE or value['base_tree'] != TREE
            or value['base_file_count'] != BASE_FILES or value['source_file_count'] != 3186
            or value['deleted'] != [] or len(value['files']) != 41
            or len(value['source_manifest']) != 3186):
        raise ValueError('exact 41-path cumulative verification source required')
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



def read_proof_overlay(path):
    raw = path.read_bytes()
    if len(raw) != PROOF_PACKET_BYTES or digest(raw) != PROOF_PACKET_SHA:
        raise ValueError('complete new Proof source packet differs')
    value = json.loads(raw)
    if (value['schema'] != 'hia.proof-contract.new-recovery-overlay.v79.r1'
            or value['base_commit'] != BASE or value['base_tree'] != TREE
            or value['parent_source_count'] != 3186 or value['deleted'] != []
            or len(value['files']) != 21 or value['lost64_qualification_inherited'] is not False
            or value['generated_outputs'] != [SOURCE_NAME, 'docs/HIA_SELFHOST_CORE_SUPPORT.json']):
        raise ValueError('new Proof recovery source boundary differs')
    for name, row in value['files'].items():
        safe(name)
        raw = row['text'].encode('utf-8')
        if (type(row['bytes']) is not int or len(raw) != row['bytes'] or digest(raw) != row['sha256']
                or row['mode'] != '100644'
                or sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() != row['git_blob_sha']):
            raise ValueError('new Proof file bytes differ: ' + name)
    return value


def apply_files(root, rows):
    for name, row in rows.items():
        target = root / safe(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(row['text'].encode('utf-8')); target.chmod(0o644)
        if source_identity(metadata(target)) != source_identity(row):
            raise ValueError('source publication differs: ' + name)


def export_source(root, output, observed):
    target = output / 'complete-development-source.tar.gz'
    with tarfile.open(target, 'x:gz') as archive:
        for name in sorted(observed):
            archive.add(root / name, arcname='source/' + name, recursive=False)
    with tarfile.open(target, 'r:gz') as archive:
        members = archive.getmembers()
        if len(members) != len(observed):
            raise ValueError('complete source export count differs')
        for member in members:
            name = member.name.removeprefix('source/')
            row = observed[name]
            if (not member.isfile() or member.size != row['bytes']
                    or format(member.mode & 0o777, '04o') != row['posix_mode']
                    or digest(archive.extractfile(member).read()) != row['sha256']):
                raise ValueError('source export bytes or mode differ: ' + name)
    return metadata(target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--inputs', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root, inputs = args.source.resolve(strict=True), args.inputs.resolve(strict=True)
    out = args.output.absolute(); out.mkdir(mode=0o700, exist_ok=False)
    report = {'schema': 'hia.proof-contract.new-recovery.development-ci.v79.r1', 'status': 'STARTED',
        'base_commit': BASE, 'base_tree': TREE, 'base_parent': BASE_PARENT,
        'python': sys.version, 'platform': platform.platform(), 'commands': [],
        'scope': 'NEW_RECOVERY_DEVELOPMENT_ONLY', 'lost64_qualification_inherited': False,
        'old_foreign17_rerun_or_transferred': False, 'current_source_cold': False,
        'whole_stack_native': False, 'default_activated': False, 'legacy_deleted': False,
        'component_seconds': 1800, 'original40_seconds': 1800, 'compile_child_seconds': 20}
    expected = None; selected_inputs = {}; started = time.monotonic_ns()
    before_inputs = files(inputs)
    env = os.environ.copy()
    clang = env.get('HEPTA_CLANG', '/usr/bin/clang-20')
    report['cleared_inherited_selector_names'] = sorted(key for key in env if key.startswith('HEPTA_'))
    for key in report['cleared_inherited_selector_names']: del env[key]
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
                    if not allow_failure: raise
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
        if observed != expected: raise ValueError('frozen source bytes/modes changed: ' + label)
        if files(inputs) != before_inputs: raise ValueError('harness input changed: ' + label)
        for path, row in selected_inputs.items():
            if metadata(path) != row: raise ValueError('held build input changed: ' + str(path))

    try:
        if (sys.implementation.name != 'cpython' or sys.version_info[:3] != (3, 14, 4)
                or platform.system() != 'Linux' or platform.machine() != 'x86_64'
                or platform.freedesktop_os_release().get('ID') != 'ubuntu'
                or platform.freedesktop_os_release().get('VERSION_ID') != '24.04'):
            raise ValueError('actual CPython3.14.4 Ubuntu24.04 x86_64 required')
        report['packages'] = {name: importlib.metadata.version(name) for name in PACKAGES}
        if report['packages'] != PACKAGES: raise ValueError('pinned Python dependency differs')
        import z3
        if z3.get_version() != (4, 15, 4, 0): raise ValueError('actual pinned Z3 differs')
        report['tools'] = {}
        for label, name in (('clang', clang), ('ld', 'ld'), ('gcc', 'gcc'), ('strace', 'strace')):
            path = shutil.which(name)
            if path is None: raise ValueError('real tool missing: ' + name)
            path = Path(path).resolve(strict=True)
            version = command('prerequisite-' + label, [path, '--version'], seconds=30).decode('utf-8', 'strict')
            if label == 'clang' and 'clang version 20.' not in version:
                raise ValueError('actual Clang20 required')
            report['tools'][label] = {'path': str(path), 'identity': metadata(path), 'version': version}
        head = command('base-head', ['git', 'rev-parse', 'HEAD']).decode().strip()
        tree = command('base-tree', ['git', 'rev-parse', 'HEAD^{tree}']).decode().strip()
        parent = command('base-parent', ['git', 'rev-parse', 'HEAD^']).decode().strip()
        if (head, tree, parent) != (BASE, TREE, BASE_PARENT): raise ValueError('exact base identity differs')
        if command('base-status', ['git', 'status', '--porcelain=v1', '--untracked-files=all']):
            raise ValueError('base checkout is not clean')
        original = files(root)
        admit_git_snapshot(root, original,
            command('base-tree-records', ['git', 'ls-tree', '-r', '-z', '--full-tree', 'HEAD']))
        if len(original) != BASE_FILES: raise ValueError('actual full3153 source required')
        write(out / 'source-before.json', wire(original))
        command('harness-mechanical-controls', [sys.executable, '-B', inputs / 'test_proof_ci_driver.py'], seconds=60)
        r6 = read_overlay(inputs / 'verification-r6-overlay.json')
        admit_overlay_base(r6, original)
        apply_files(root, r6['files'])
        reconstructed = files(root)
        if ({name: source_identity(row) for name, row in reconstructed.items()}
                != {name: source_identity(row) for name, row in r6['source_manifest'].items()}):
            raise ValueError('acknowledged complete R6 reconstruction differs')
        write(out / 'source-r6-reconstructed.json', wire(reconstructed))
        proof = read_proof_overlay(inputs / 'proof-recovery-overlay.json')
        admit_overlay_base(proof, reconstructed)
        apply_files(root, proof['files'])
        authored = files(root)
        wanted = {name: source_identity(row) for name, row in reconstructed.items()}
        wanted.update({name: source_identity(row) for name, row in proof['files'].items()})
        if ({name: source_identity(row) for name, row in authored.items()} != wanted
                or len(authored) != 3200):
            raise ValueError('new authored recovery source differs')
        write(out / 'source-authored-before-generation.json', wire(authored))
        # The actual generation is new work. The old204153 target is compared
        # only after complete bytes exist, never accepted as a stand-in.
        command('generate-proof', [sys.executable, '-B', '-m', 'tools.generate_hia_proof_contract'])
        generated = files(root)
        delta = {name for name in set(authored) | set(generated) if authored.get(name) != generated.get(name)}
        if delta != {SOURCE_NAME}: raise ValueError('proof generation changed an unrelated source')
        command('regenerate-proof-check', [sys.executable, '-B', '-m', 'tools.generate_hia_proof_contract', '--check'])
        if files(root) != generated: raise ValueError('proof check mutated input source')
        command('generate-support', [sys.executable, '-B', '-m', 'tools.generate_hia_selfhost_contract'])
        expected = files(root)
        delta = {name for name in set(generated) | set(expected) if generated.get(name) != expected.get(name)}
        if delta != {'docs/HIA_SELFHOST_CORE_SUPPORT.json'} or len(expected) != 3201:
            raise ValueError('new complete contract generation differs')
        command('check-support', [sys.executable, '-B', '-m', 'tools.generate_hia_selfhost_contract', '--check'])
        guard('frozen-before-compile')
        report['source_files'] = len(expected)
        report['source_byte_matches_lost_target'] = expected[SOURCE_NAME]['sha256'] == OLD_SOURCE_SHA
        changes = sorted(name for name in set(original) | set(expected) if original.get(name) != expected.get(name))
        if set(changes) != set(r6['files']) | set(proof['files']) | set(proof['generated_outputs']):
            raise ValueError('complete recovery changed an unrelated path')
        write(out / 'frozen-source.json', wire(expected))
        command('stage-source', ['git', 'add', '--', *changes])
        report['development_write_tree'] = command('write-tree', ['git', 'write-tree']).decode().strip()
        command('source-patch', ['git', 'diff', '--cached', '--binary', '--full-index', 'HEAD'])
        # Whitespace failure is preserved but cannot hide later semantic runs.
        command('source-whitespace', ['git', 'diff', '--cached', '--check'], allow_failure=True)
        raw = (inputs / 'retained-compiler.json').read_bytes()
        if digest(raw) != COMPILER_PACKET_SHA: raise ValueError('retained compiler packet differs')
        saved = json.loads(raw)
        compressed = base64.b64decode(saved['compiler_zlib_base64'], validate=True)
        if len(compressed) != saved['compressed_bytes'] or digest(compressed) != saved['compressed_sha256']:
            raise ValueError('retained compiler compressed bytes differ')
        decoder = zlib.decompressobj()
        compiler_bytes = decoder.decompress(compressed, 669495)
        if decoder.unconsumed_tail: raise ValueError('compiler exceeds exact extent')
        compiler_bytes += decoder.flush()
        if (not decoder.eof or decoder.unused_data or decoder.unconsumed_tail
                or len(compiler_bytes) != 669494 or digest(compiler_bytes) != COMPILER_SHA):
            raise ValueError('actual retained compiler differs')
        compiler = out / 'retained-B3.image.bin'; write(compiler, compiler_bytes); compiler.chmod(0o444)
        receipt = saved['original_receipt_utf8'].encode()
        if digest(receipt) != saved['original_receipt_sha256']: raise ValueError('original compiler receipt differs')
        write(out / 'retained-B3.original-receipt.json', receipt)
        report['retained_compiler'] = {'sha256': COMPILER_SHA, 'bytes': 669494,
            'original_artifact': saved['original_artifact'], 'scope': 'BORROWED_OLD_COMPILER_DEVELOPMENT_ONLY'}
        selected_inputs[compiler] = metadata(compiler)
        guard('before-build')
        command('build-proof', [sys.executable, '-B', '-m', 'tools.build_hia_proof_contract',
            '--compiler', compiler, '--development', '--output', out / 'build'], seconds=240)
        manifest = out / 'build/development-manifest.json'
        record = json.loads(manifest.read_bytes())
        image = manifest.parent / record['image_path']
        if (record['schema'] != 'hepta.hia.proof-contract-native.v1'
                or record['source_sha256'] != expected[SOURCE_NAME]['sha256']
                or record['compiler_sha256'] != COMPILER_SHA
                or record['image_sha256'] != digest(image.read_bytes())):
            raise ValueError('actual new image identity differs')
        for path in (manifest, image, out / 'build/development-build.json', out / 'build/proof-contract.receipt.json'):
            selected_inputs[path] = metadata(path)
        report['image_byte_matches_lost_target'] = record['image_sha256'] == OLD_IMAGE_SHA
        report['selected_manifest'] = record
        report['selected_inputs'] = {str(path): row for path, row in selected_inputs.items()}
        guard('after-build')
        table_program = (
            "import json,hashlib,struct,sys;from pathlib import Path;"
            "from hepta.hia_machine_plan_control_native import NativeMachinePlanControl;"
            "raw=Path(sys.argv[1]).read_bytes();"
            "image=NativeMachinePlanControl(raw,hashlib.sha256(raw).hexdigest());"
            "result={'table_bytes':len(image.table),'table_sha256':hashlib.sha256(image.table).hexdigest(),"
            "'functions':image.function_count,'instructions':struct.unpack_from('<Q',image.table,24)[0],"
            "'source_kind':'actual selected HIA image emission; no policy corpus execution'};"
            "Path(sys.argv[2]).write_text(json.dumps(result,sort_keys=True,indent=2)+'\\n')")
        command('actual-table-emission', [sys.executable, '-B', '-c', table_program, image, out / 'actual-table.json'])
        report['actual_table'] = json.loads((out / 'actual-table.json').read_bytes())
        report['table_byte_matches_lost_target'] = report['actual_table']['table_sha256'] == OLD_TABLE_SHA
        guard('after-table-emission')
        component = inputs / 'component-85.json'
        if digest(component.read_bytes()) != COMPONENT_SHA: raise ValueError('new85 definitions differ')
        component_env = dict(env,
            HEPTA_HIA_PROOF_CONTRACT_DEVELOPMENT_MANIFEST=str(manifest),
            HEPTA_HIA_PROOF_CONTRACT_EVIDENCE=str(out / 'component-evidence'))
        command('component-85', [sys.executable, '-B', inputs / 'run_proof_group.py',
            '--source', root, '--denominator', component, '--output', out / 'component-85'],
            seconds=1800, environment=component_env, allow_failure=True)
        guard('after-component-85')
        # A component failure or timeout does not skip the original40 gate.
        command('original-proof-40', [sys.executable, '-B', '-m', 'tools.qualify_hia_proof_contract',
            '--development-compiler', compiler, '--evidence', out / 'original-proof-40'],
            seconds=1800, environment=env, allow_failure=True)
        guard('after-original-proof-40')
        report['component'] = json.loads((out / 'component-85/REPORT.json').read_bytes())
        report['original40'] = json.loads((out / 'original-proof-40/report.json').read_bytes())
        if (report['component']['status'] != 'PASS' or report['component']['tests_run'] != 85
                or report['component']['source_unchanged'] is not True):
            raise ValueError('complete new85 component group failed')
        if (report['original40']['status'] != 'DEVELOPMENT_CALLERS_PASS'
                or report['original40']['original_agent']['tests_run'] != 40):
            raise ValueError('unchanged original22+18 gate failed')
        if any(row.get('returncode') != 0 or row.get('timed_out') is not False for row in report['commands']):
            raise ValueError('an actual command failed')
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
            report['source_export'] = export_source(root, out, observed)
            report['source_export_scope'] = 'COMPLETE_ACTUAL_SOURCE_NO_COLD_AUTHORITY'
        except BaseException:
            report.update(status='FAIL', final_custody_error=traceback.format_exc())
        report['elapsed_ns'] = time.monotonic_ns() - started
        write(out / 'REPORT.json', wire(report))
        identity = {path.relative_to(out).as_posix(): metadata(path)
                    for path in sorted(out.rglob('*')) if path.is_file()}
        write(out / 'ARTIFACT-FILES.json', wire(identity))
        print(json.dumps({'status': report['status'], 'source_files': report.get('source_files'),
                          'current_source_cold': False, 'whole_stack_native': False}), flush=True)
    return 0 if report['status'] == 'DEVELOPMENT_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
