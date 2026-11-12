"""Verify exact checkout plus six-path overlay, then run original development gates.

This harness does not regenerate a cold report or qualify a source release. The
retained 81b6 compiler is an explicitly separate development input. Full evidence
is uploaded as an artifact; the lossless log capsule contains text records only.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import signal
import stat
import subprocess
import sys
import time
import traceback
import zlib

BASE = '5f7f95367e8e395863801487e969d286b9091110'
TREE = '4f4e58e06a6e03adcd6548bd8ea4ef591c20359f'
OVERLAY_WRAPPER = 'e9c5e18494984764a118a288a30b6693ef502359b443676ca6fec4edc59a9031'
OVERLAY_RAW = '41ecbbd144ecdf928dcce42eb0102b14a2fded5072f7a5dc8bba817ca21c2b04'
COMPILER_WRAPPER = 'a3f2a781974471a85f6e6a25d6b5d59b232d444d10f221e8269d221fc2636f00'
COMPILER_SHA = '81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109'
ASSET_SHA = 'fa1dd4dc425f4f647669fff68d61d85b68fc8e45dead5769fad3373f024ec973'
PATHS = frozenset(('tools/hia_heap_live_engine.py', 'tools/hia_heap_live_transfers.py',
    'examples/hia_bootstrap/heap_live_engine.hiaasm', 'tests/test_hia_heap_live_engine_native.py',
    'tests/test_hia_heap_graphs_native.py', 'docs/HIA_HEAP_BOUND_NATIVE.md'))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE).stdout


def bounded_name(name):
    value = PurePosixPath(name)
    assert type(name) is str and name and not value.is_absolute() and value.as_posix() == name
    assert all(part not in ('', '.', '..', '.git') for part in value.parts)
    return value


def source_map(root):
    result = {}
    for path in sorted(root.rglob('*')):
        rel = path.relative_to(root)
        if '.git' in rel.parts or '__pycache__' in rel.parts:
            continue
        if path.is_file() or path.is_symlink():
            info = path.lstat()
            assert stat.S_ISREG(info.st_mode) and not path.is_symlink(), str(rel)
            raw = path.read_bytes()
            result[rel.as_posix()] = {'bytes': len(raw), 'sha256': sha(raw), 'git_blob': blob(raw),
                                      'git_mode': '100755' if info.st_mode & 0o111 else '100644'}
    return result


def decode(path, wanted_sha, wanted_bytes, wanted_raw_sha):
    raw = path.read_bytes()
    assert sha(raw) == wanted_sha, path
    value = json.loads(raw)
    compressed = base64.b64decode(value['zlib_base64'], validate=True)
    assert len(compressed) == value['compressed_bytes'] and sha(compressed) == value['compressed_sha256']
    stream = zlib.decompressobj()
    decoded = stream.decompress(compressed, wanted_bytes + 1)
    assert stream.eof and not stream.unused_data and not stream.unconsumed_tail
    assert len(decoded) == value['bytes'] == wanted_bytes and sha(decoded) == value['sha256'] == wanted_raw_sha
    return decoded


def run(command, root, output, label, limit, environment):
    start = time.perf_counter()
    record = {'command': command, 'cwd': str(root), 'outer_timeout_seconds': limit,
              'timeout': False, 'owned_cleanup': False}
    with (output / (label + '.stdout')).open('xb') as stdout, (output / (label + '.stderr')).open('xb') as stderr:
        process = subprocess.Popen(command, cwd=root, stdout=stdout, stderr=stderr,
                                   env=environment, start_new_session=True)
        record['pid'] = process.pid
        try:
            record['returncode'] = process.wait(timeout=limit)
        except subprocess.TimeoutExpired:
            record['timeout'] = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            record['returncode'] = process.returncode
            record['owned_cleanup'] = True
    record['wall_seconds'] = time.perf_counter() - start
    for suffix in ('stdout', 'stderr'):
        path = output / (label + '.' + suffix)
        raw = path.read_bytes()
        record[suffix] = {'path': path.name, 'bytes': len(raw), 'sha256': sha(raw)}
    write(output / (label + '-PROCESS.json'), record)
    return record


def text_capsule(output, report):
    files = {}
    inventory = {}
    for path in sorted(output.rglob('*')):
        if not path.is_file() or path.name.startswith('LOG-CAPSULE'):
            continue
        raw = path.read_bytes()
        name = path.relative_to(output).as_posix()
        inventory[name] = {'bytes': len(raw), 'sha256': sha(raw)}
        if path.suffix.lower() in ('.json', '.log', '.txt', '.stdout', '.stderr'):
            try:
                files[name] = {'bytes': len(raw), 'sha256': sha(raw), 'utf8': raw.decode('utf-8')}
            except UnicodeDecodeError:
                inventory[name]['log_capsule_omitted'] = 'non-UTF-8; full bytes remain in artifact'
    write(output / 'EVIDENCE-MANIFEST.json', inventory)
    payload = (json.dumps({'schema': 'hia.heap-optimization.log-text-capsule.v1',
        'scope': 'TEXT_SUBSET_ONLY_FULL_RAW_RETAINED_IN_ARTIFACT', 'report': report,
        'inventory': inventory, 'files': files}, sort_keys=True) + '\n').encode()
    compressed = zlib.compress(payload, 9)
    encoded = base64.b64encode(compressed).decode('ascii')
    count = (len(encoded) + 9999) // 10000
    manifest = {'schema': 'hia.heap-optimization.log-capsule-manifest.v1',
                'raw_bytes': len(payload), 'raw_sha256': sha(payload), 'compressed_bytes': len(compressed),
                'compressed_sha256': sha(compressed), 'encoding': 'zlib+base64', 'chunks': count}
    (output / 'LOG-CAPSULE.json.zlib').write_bytes(compressed)
    write(output / 'LOG-CAPSULE-MANIFEST.json', manifest)
    print('HIA_HEAP_OPTIMIZATION_CAPSULE ' + json.dumps({'manifest': manifest}, sort_keys=True), flush=True)
    for index in range(count):
        line = json.dumps({'index': index, 'chunks': count, 'base64': encoded[index * 10000:(index + 1) * 10000]}, sort_keys=True)
        assert len(line.encode()) < 12000
        print('HIA_HEAP_OPTIMIZATION_CAPSULE ' + line, flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    root, inputs, output = args.source.resolve(), args.inputs.resolve(), args.evidence.resolve()
    output.mkdir(parents=True, exist_ok=False)
    assert output != root and root not in output.parents
    report = {'schema': 'hia.heap-optimization.development-ci.v1',
              'scope': 'EXACT_SOURCE_OVERLAY_AND_RETAINED_COMPILER_DEVELOPMENT',
              'status': 'ERROR', 'qualification': False, 'current_source_cold': False,
              'whole_product': False, 'default_flip': False, 'base': BASE, 'base_tree': TREE,
              'python': sys.version, 'phases': [], 'started': time.time()}
    expected = compiler = compiler_bytes = None
    try:
        assert sys.version_info[:3] == (3, 14, 4), sys.version
        assert git(root, 'rev-parse', 'HEAD').decode().strip() == BASE
        assert git(root, 'rev-parse', 'HEAD^{tree}').decode().strip() == TREE
        assert not git(root, 'status', '--porcelain=v1', '--untracked-files=all')
        listing = git(root, 'ls-tree', '-rz', '--full-tree', 'HEAD')
        (output / 'BASE-GIT-TREE.z').write_bytes(listing)
        declared = {}
        for item in listing.split(b'\0'):
            if not item:
                continue
            header, raw_name = item.split(b'\t', 1)
            mode, kind, oid = header.decode('ascii').split(' ')
            name = raw_name.decode('utf-8')
            bounded_name(name)
            assert kind == 'blob' and mode in ('100644', '100755') and name not in declared
            declared[name] = {'git_mode': mode, 'git_blob': oid}
        assert len(declared) == 3120, len(declared)
        before = source_map(root)
        assert before.keys() == declared.keys()
        for name, data in declared.items():
            assert all(before[name][key] == value for key, value in data.items()), name
        write(output / 'SOURCE-BASE.json', before)
        packet_bytes = decode(inputs / 'source-overlay.json', OVERLAY_WRAPPER, 580877, OVERLAY_RAW)
        packet = json.loads(packet_bytes)
        assert packet['source_base'] == BASE and packet['source_tree'] == TREE
        assert len(packet['files']) == 6 and {item['path'] for item in packet['files']} == PATHS
        assert packet['qualification'] is False and packet['original134_methods_changed'] is False
        expected = dict(before)
        for item in packet['files']:
            name = item['path']
            bounded_name(name)
            old, new = item['before'], item['after']
            assert before[name]['bytes'] == old['bytes'] and before[name]['sha256'] == old['sha256'], name
            raw = new['utf8'].encode('utf-8')
            assert len(raw) == new['bytes'] and sha(raw) == new['sha256'] and blob(raw) == new['git_blob']
            assert new['mode'] == '0644'
            (root / name).write_bytes(raw)
            (root / name).chmod(0o644)
            expected[name] = {'bytes': len(raw), 'sha256': sha(raw), 'git_blob': blob(raw), 'git_mode': '100644'}
        assert source_map(root) == expected
        write(output / 'SOURCE-OVERLAY.json', expected)
        (output / 'OVERLAY-PACKET.json').write_bytes(packet_bytes)
        (output / 'SOURCE-OVERLAY.diff').write_bytes(git(root, 'diff', '--binary', '--', *sorted(PATHS)))
        assert set(git(root, 'diff', '--name-only').decode().splitlines()) == PATHS
        compiler_bytes = decode(inputs / 'retained-compiler.json', COMPILER_WRAPPER, 669494, COMPILER_SHA)
        compiler = output / 'retained-development-compiler.bin'
        compiler.write_bytes(compiler_bytes)
        compiler.chmod(0o600)
        report['source_count'] = len(expected)
        report['overlay_paths'] = sorted(PATHS)
        report['compiler'] = {'bytes': len(compiler_bytes), 'sha256': COMPILER_SHA,
                              'scope': 'RETAINED_DEVELOPMENT_COMPILER_NOT_CURRENT_SOURCE_COLD'}
        environment = dict(os.environ)
        removed = sorted(key for key in environment if key.startswith('HEPTA_'))
        for key in removed:
            environment.pop(key)
        environment['PYTHONDONTWRITEBYTECODE'] = '1'
        report['removed_selector_names'] = removed
        generation = run([sys.executable, '-B', '-m', 'tools.generate_hia_heap_kernels'],
                         root, output, 'regenerate-actual-heap-kernels', 60, environment)
        report['phases'].append(generation)
        assert not generation['timeout'] and generation['returncode'] == 0
        assert sha((root / 'examples/hia_bootstrap/heap_live_engine.hiaasm').read_bytes()) == ASSET_SHA
        assert source_map(root) == expected
        runner = Path(__file__).resolve().with_name('run_heap_suite.py')
        execution = run([sys.executable, '-I', '-B', str(runner), '--source', str(root),
                         '--evidence', str(output / 'suite'), '--compiler', str(compiler)],
                        root, output, 'original-development-suite', 1800, environment)
        report['phases'].append(execution)
        result = output / 'suite' / 'RESULT.json'
        if result.exists():
            raw = result.read_bytes()
            report['suite_result'] = json.loads(raw)
            report['suite_result_identity'] = {'bytes': len(raw), 'sha256': sha(raw)}
        assert not execution['timeout'] and execution['returncode'] == 0
        assert report['suite_result']['status'] == 'PASS'
        report['status'] = 'PASS'
    except BaseException:
        report['status'] = 'FAIL'
        report['traceback'] = traceback.format_exc()
    finally:
        try:
            after = source_map(root)
            write(output / 'SOURCE-AFTER.json', after)
            report['source_preserved_after_overlay'] = expected is not None and after == expected
            report['compiler_preserved'] = compiler is not None and compiler.read_bytes() == compiler_bytes
            report['git_head_preserved'] = git(root, 'rev-parse', 'HEAD').decode().strip() == BASE
            if not all(report[key] for key in ('source_preserved_after_overlay', 'compiler_preserved', 'git_head_preserved')):
                report['status'] = 'FAIL'
        except BaseException:
            report['final_custody_error'] = traceback.format_exc()
            report['status'] = 'FAIL'
        report['finished'] = time.time()
        write(output / 'RESULT.json', report)
        text_capsule(output, report)
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
