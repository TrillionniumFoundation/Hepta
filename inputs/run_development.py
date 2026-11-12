"""Independent CPython 3.14.4 development controls for the frozen Core/Plan R3 plus Core emitter.

This is a harness branch, not a product commit or matching-source cold report.
The retained compiler is explicitly admitted as development input. Every
original runtime test, caller inventory and inner deadline stays in source.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import traceback
import zlib

HEAD = '4b19af89a766593f7d5f1cc2db256e81aba7afcb'
TREE = '1bc7c90996e1910ad66ba771b0bfee1d5bfa655c'
PACKET_SHA = 'dbcb8dc0115b15c712b944e09f5cd56004e10f3e677eb59c98cadfe75319628c'
COMPILER_SHA = '81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109'
SUPERVISOR_SHA = 'f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80'
INPUTS = Path(__file__).resolve().parent
LABELS = ('machine_encoding', 'machine_state', 'machine_instructions',
          'machine_elf', 'machine_plan', 'core_lowering', 'core_emitter')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def describe(path):
    path = Path(path)
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw),
            'git_blob_sha1': blob(raw), 'posix_mode': stat.S_IMODE(path.stat().st_mode)}


def write(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    with Path(path).open('xb') as stream:
        stream.write(raw)


def git(source, *arguments):
    return subprocess.check_output(['git', '-C', str(source), *arguments], timeout=30)


def clean_environment():
    env = dict(os.environ)
    removed = {}
    for name in tuple(env):
        if (name.startswith('HEPTA_HIA_') and
                (name.endswith('_MANIFEST') or name.endswith('_COLD_REPORT')
                 or '_DEVELOPMENT' in name)) or name == 'PYTHONPATH':
            removed[name] = env.pop(name)
    env.update(PYTHONDONTWRITEBYTECODE='1', PYTHONUNBUFFERED='1')
    return env, removed


def tree_id(entries):
    root = {}
    for path, record in entries.items():
        parts = path.split('/')
        target = root
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        target[parts[-1]] = (record['git_mode'], record['git_blob_sha1'])
    def digest(node):
        body = bytearray()
        for name in sorted(node, key=lambda n: (n + ('/' if isinstance(node[n], dict) else '')).encode()):
            value = node[name]
            mode, ident = ('40000', digest(value)) if isinstance(value, dict) else value
            body.extend(mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(ident))
        return hashlib.sha1(b'tree ' + str(len(body)).encode() + b'\0' + body).hexdigest()
    return digest(root)


def snapshot(source, paths):
    result = {}
    for name in sorted(paths):
        path = source / name
        if not path.is_file() or path.is_symlink():
            raise AssertionError('expected ordinary source file: ' + name)
        record = describe(path)
        record.pop('path')
        record['git_mode'] = '100755' if path.stat().st_mode & 0o111 else '100644'
        result[name] = record
    return result


def source_matches(source, expected):
    actual_names = {p.decode() for p in git(source, 'ls-files', '-z', '--cached',
                                           '--others', '--exclude-standard').split(b'\0') if p}
    return (actual_names == set(expected) and snapshot(source, expected) == expected
            and git(source, 'rev-parse', 'HEAD').decode().strip() == HEAD
            and git(source, 'rev-parse', 'HEAD^{tree}').decode().strip() == TREE)


def development_inputs(out):
    paths = [out / 'retained-development-compiler.bin',
             out / 'composition-manifests-r1.json']
    for label in LABELS:
        path = out / 'development-r1' / label / 'manifest.json'
        manifest = json.loads(path.read_bytes())
        paths.extend((path, path.parent / manifest['image_path']))
    return [describe(path) for path in paths]


def tool_inputs():
    result = {'python': sys.version, 'implementation': platform.python_implementation(),
              'platform': platform.platform(), 'architecture': platform.machine(),
              'executable': describe(sys.executable), 'tools': {}, 'distributions': {}}
    for name in ('cc', 'as', 'ld', 'nm', 'objdump', 'readelf', 'strace'):
        path = shutil.which(name)
        if path is None:
            raise AssertionError('required original tool absent: ' + name)
        row = describe(Path(path).resolve())
        row['selected_path'] = path
        result['tools'][name] = row
    for name in ('setuptools', 'wheel', 'jsonschema', 'z3-solver'):
        dist = importlib.metadata.distribution(name)
        record = {'version': dist.version, 'identity_records': []}
        for member in dist.files or ():
            if member.name in ('METADATA', 'RECORD') and '.dist-info' in str(member):
                record['identity_records'].append(describe(dist.locate_file(member)))
        if not record['identity_records']:
            raise AssertionError('package identity is unavailable: ' + name)
        result['distributions'][name] = record
    return result


def decode_source_packet():
    raw = (INPUTS / 'source-packet.json').read_bytes()
    if len(raw) != 925269 or sha(raw) != PACKET_SHA:
        raise AssertionError('frozen exact frozen overlay packet changed')
    wrapper = json.loads(raw)
    compressed = base64.b64decode(wrapper['data'], validate=True)
    if len(compressed) != wrapper['compressed_bytes'] or sha(compressed) != wrapper['compressed_sha256']:
        raise AssertionError('source packet compressed identity differs')
    content = zlib.decompress(compressed)
    if len(content) != wrapper['bytes'] or sha(content) != wrapper['sha256']:
        raise AssertionError('source packet raw identity differs')
    packet = json.loads(content)
    if packet['reference_product_head'] != HEAD or packet['reference_product_tree'] != TREE:
        raise AssertionError('source packet base differs')
    if len(packet['files']) != 40:
        raise AssertionError('exact frozen overlay inventory differs')
    result = {}
    for item in packet['files']:
        name = item['path']
        if not name.startswith('source/'):
            raise AssertionError('overlay path is outside source')
        name = name[len('source/'):]
        if (name in result or '\\' in name or Path(name).is_absolute()
                or any(part in ('', '.', '..') for part in name.split('/'))):
            raise AssertionError('duplicate or unsafe overlay path')
        data = item['content'].encode('utf-8') if item['encoding'] == 'utf-8' else base64.b64decode(item['content'], validate=True)
        if (len(data) != item['bytes'] or sha(data) != item['sha256']
                or blob(data) != item['git_blob_sha1'] or item['mode'] != 0o644):
            raise AssertionError('overlay byte/mode identity differs: ' + name)
        result[name] = data
    return result


def prepare(source, out):
    out.mkdir(mode=0o700)
    report = {'scope': 'INDEPENDENT_CPYTHON3144_DEVELOPMENT', 'status': 'PREPARING',
              'base_head': HEAD, 'base_tree': TREE, 'current_cold': False,
              'whole_native': False, 'default_changed': False, 'legacy_deleted': False}
    try:
        if (sys.implementation.name != 'cpython' or sys.version_info[:3] != (3, 14, 4)
                or sys.platform != 'linux' or platform.machine() != 'x86_64'):
            raise AssertionError('this independent scope requires actual CPython 3.14.4 Linux x86-64')
        if git(source, 'rev-parse', 'HEAD').decode().strip() != HEAD or git(source, 'rev-parse', 'HEAD^{tree}').decode().strip() != TREE:
            raise AssertionError('authentic product checkout differs')
        if git(source, 'status', '--porcelain=v1', '--untracked-files=all'):
            raise AssertionError('original checkout is dirty')
        entries = {}
        for line in git(source, 'ls-tree', '-rz', '--full-tree', 'HEAD').split(b'\0'):
            if not line:
                continue
            metadata, path = line.split(b'\t', 1)
            mode, kind, ident = metadata.decode().split()
            if kind != 'blob' or mode not in ('100644', '100755'):
                raise AssertionError('unexpected original Git member kind')
            entries[path.decode()] = {'git_mode': mode, 'git_blob_sha1': ident}
        if len(entries) != 3153 or tree_id(entries) != TREE:
            raise AssertionError('complete original tree inventory differs')
        before = snapshot(source, entries)
        for name, record in before.items():
            if any(record[key] != entries[name][key] for key in ('git_blob_sha1', 'git_mode')):
                raise AssertionError('original source bytes differ: ' + name)
        write(out / 'ORIGINAL-SOURCE.json', before)
        overlay = decode_source_packet()
        for name, data in overlay.items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o644)
        after = snapshot(source, set(entries) | set(overlay))
        write(out / 'CANDIDATE-SOURCE.json', after)
        changed = [name for name in after if name not in before or
                   any(after[name][key] != before[name][key] for key in ('git_blob_sha1', 'git_mode'))]
        if not set(changed) <= set(overlay):
            raise AssertionError('unexpected overlay changes')
        report.update(tracked_original=len(entries), candidate_files=len(after), changed_paths=changed,
                      candidate_content_tree=tree_id(after), authentic_head_still=HEAD,
                      overlay_packet=describe(INPUTS / 'source-packet.json'))
        write(out / 'TOOLS-BEFORE.json', tool_inputs())
        wrapper = json.loads((INPUTS / 'retained-compiler.json').read_bytes())
        packed = base64.b64decode(wrapper['data'], validate=True)
        if len(packed) != wrapper['compressed_bytes'] or sha(packed) != wrapper['compressed_sha256']:
            raise AssertionError('retained compiler packet differs')
        compiler_raw = zlib.decompress(packed)
        if len(compiler_raw) != 669494 or sha(compiler_raw) != COMPILER_SHA or wrapper['sha256'] != COMPILER_SHA:
            raise AssertionError('retained compiler original identity differs')
        compiler = out / 'retained-development-compiler.bin'
        compiler.write_bytes(compiler_raw)
        compiler.chmod(0o444)
        if sha((INPUTS / 'workflow_process.py').read_bytes()) != SUPERVISOR_SHA:
            raise AssertionError('original 1800-second supervisor changed')
        env, removed = clean_environment()
        report['removed_environment'] = removed
        os.environ.clear()
        os.environ.update(env)
        os.chdir(source)
        sys.path.insert(0, str(source))
        from tools.qualify_hia_selfhost import compile_stage
        report['compiled'] = []
        (out / 'development-r1').mkdir()
        for label in LABELS:
            module = importlib.import_module('hepta.hia_' + label + '_native')
            expected = source / ('examples/hia_bootstrap/' + label + '.hiaasm')
            if module.SOURCE.resolve() != expected:
                raise AssertionError('selected checkout source resource differs: ' + label)
            folder = out / 'development-r1' / label
            folder.mkdir(mode=0o700)
            raw = expected.read_bytes()
            image, receipt = compile_stage(folder, label, compiler, raw)
            manifest = {'schema': module.SCHEMA, 'source_sha256': sha(raw),
                        'image_path': image.name, 'image_sha256': sha(image.read_bytes()),
                        'compiler_sha256': COMPILER_SHA}
            write(folder / 'manifest.json', manifest)
            if expected.read_bytes() != raw or compiler.read_bytes() != compiler_raw:
                raise AssertionError('actual compilation inputs changed')
            report['compiled'].append({'label': label, 'manifest': manifest, 'receipt': receipt})
            print('ACTUAL_DEVELOPMENT_COMPILE', label, manifest['image_sha256'], flush=True)
        write(out / 'composition-manifests-r1.json',
              {name: str(out / 'development-r1' / name / 'manifest.json') for name in LABELS[:-1]})
        write(out / 'DEVELOPMENT-INPUTS.json', development_inputs(out))
        if not source_matches(source, after):
            raise AssertionError('source changed during actual compilation')
        report['status'] = 'DEVELOPMENT_INPUTS_READY_NOT_COLD'
    except BaseException:
        report.update(status='PREPARATION_FAIL_OR_INCOMPLETE', exception=traceback.format_exc())
    finally:
        write(out / 'PREPARE.json', report)
        print(json.dumps({'stage': 'prepare', 'status': report['status']}, sort_keys=True), flush=True)
    return 0 if report['status'] == 'DEVELOPMENT_INPUTS_READY_NOT_COLD' else 1


def run_stage(source, out, stage):
    from workflow_process import run_workflow_step
    prepared = json.loads((out / 'PREPARE.json').read_bytes())
    if prepared['status'] != 'DEVELOPMENT_INPUTS_READY_NOT_COLD':
        raise AssertionError('development preparation is incomplete')
    paths = json.loads((out / 'CANDIDATE-SOURCE.json').read_bytes())
    if not source_matches(source, paths):
        raise AssertionError('frozen candidate source changed before stage')
    held_inputs = json.loads((out / 'DEVELOPMENT-INPUTS.json').read_bytes())
    if development_inputs(out) != held_inputs:
        raise AssertionError('frozen actual development inputs changed before stage')
    env, removed = clean_environment()
    folder = out / stage
    folder.mkdir(mode=0o700)
    manifest = out / 'development-r1/core_emitter/manifest.json'
    if stage != 'complete116':
        raise AssertionError('unknown independent emitter gate')
    command = [sys.executable, '-B', 'tools/qualify_hia_core_emitter_callers.py',
               '--development-manifest', str(manifest), '--composition-manifests',
               str(out / 'composition-manifests-r1.json'), '--evidence', str(folder / 'evidence')]
    write(folder / 'INTENT.json', {'command': command, 'cwd': str(source),
          'outer_seconds': 1800, 'removed_environment': removed,
          'original_inner_limits_unchanged': True, 'current_cold': False})
    receipt = run_workflow_step(command, cwd=source, env=env,
                               stdout_path=folder / 'stdout.log', stderr_path=folder / 'stderr.log',
                               receipt_path=folder / 'PROCESS.json', seconds=1800)
    unchanged = source_matches(source, paths)
    inputs_unchanged = development_inputs(out) == held_inputs
    write(folder / 'SOURCE-CUSTODY.json', {'before_map': '../CANDIDATE-SOURCE.json',
                                         'all_source_bytes_and_modes_unchanged': unchanged,
                                         'all_actual_development_inputs_unchanged': inputs_unchanged})
    print(json.dumps({'stage': stage, 'process': receipt, 'source_unchanged': unchanged,
                      'development_inputs_unchanged': inputs_unchanged}, sort_keys=True), flush=True)
    return 0 if unchanged and inputs_unchanged and receipt['status'] == 'WORKFLOW_STEP_COMPLETED' else 1


def finish(source, out):
    result = {'scope': 'INDEPENDENT_CPYTHON3144_DEVELOPMENT',
              'current_cold': False, 'whole_native': False, 'default_changed': False,
              'legacy_deleted': False, 'stages': {}, 'status': 'FAIL_OR_INCOMPLETE'}
    try:
        paths = json.loads((out / 'CANDIDATE-SOURCE.json').read_bytes())
        after = snapshot(source, paths)
        write(out / 'SOURCE-AFTER.json', after)
        result['source_unchanged'] = source_matches(source, paths)
        inputs_after = development_inputs(out)
        write(out / 'DEVELOPMENT-INPUTS-AFTER.json', inputs_after)
        result['development_inputs_unchanged'] = inputs_after == json.loads((out / 'DEVELOPMENT-INPUTS.json').read_bytes())
        tools_after = tool_inputs()
        write(out / 'TOOLS-AFTER.json', tools_after)
        result['tools_unchanged'] = tools_after == json.loads((out / 'TOOLS-BEFORE.json').read_bytes())
        result['compiler_unchanged'] = sha((out / 'retained-development-compiler.bin').read_bytes()) == COMPILER_SHA
        result['authentic_checkout_head'] = git(source, 'rev-parse', 'HEAD').decode().strip()
        for stage in ('complete116',):
            p = out / stage / 'PROCESS.json'
            result['stages'][stage] = json.loads(p.read_bytes()) if p.exists() else {'status': 'NOT_COMPLETED'}
        result['actual_reports'] = {}
        for name, path in [('complete116', out / 'complete116/evidence/REPORT.json')]:
            result['actual_reports'][name] = describe(path) if path.exists() else None
        passed = (result['source_unchanged'] and result['development_inputs_unchanged'] and result['tools_unchanged']
                  and result['compiler_unchanged'] and result['authentic_checkout_head'] == HEAD
                  and all(r['status'] == 'WORKFLOW_STEP_COMPLETED' for r in result['stages'].values())
                  and all(result['actual_reports'].values()))
        result['status'] = 'ALL_DECLARED_DEVELOPMENT_GATES_PASS' if passed else 'FAIL_OR_INCOMPLETE'
    except BaseException:
        result['exception'] = traceback.format_exc()
    finally:
        result['workflow_steps'] = json.loads(os.environ.get('HIA_STEP_OUTCOMES', '{}'))
        write(out / 'RESULT.json', result)
        members = [describe(path) for path in sorted(out.rglob('*')) if path.is_file()]
        for record in members:
            record['path'] = Path(record['path']).relative_to(out).as_posix()
        write(out / 'EVIDENCE-MANIFEST.json', {'files': members, 'complete_raw_preserved': True,
              'self_excluded': True, 'source_base': HEAD, 'source_tree': TREE})
        print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result['status'] == 'ALL_DECLARED_DEVELOPMENT_GATES_PASS' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--stage', choices=('prepare', 'complete116', 'finish'), required=True)
    args = parser.parse_args()
    source, out = args.source.resolve(strict=True), args.out.resolve()
    if args.stage == 'prepare':
        return prepare(source, out)
    if args.stage == 'finish':
        return finish(source, out)
    return run_stage(source, out, args.stage)


if __name__ == '__main__':
    raise SystemExit(main())
