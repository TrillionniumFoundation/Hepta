"""Compose only frozen recoverable owner bytes for independent source generation."""
from __future__ import annotations

import argparse
import ast
import base64
import difflib
from hashlib import sha1, sha256
import json
import os
import subprocess
from pathlib import Path, PurePosixPath
import stat
import traceback
import zlib


def require(ok, message):
    if not ok:
        raise ValueError(message)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=pairs)


def identity(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def read_owned(root, relative, expected):
    path = PurePosixPath(relative)
    require(not path.is_absolute() and '..' not in path.parts and str(path) == relative,
            'unsafe harness input path')
    real = root / relative
    require(stat.S_ISREG(real.lstat().st_mode) and not real.is_symlink(),
            'harness input is not an ordinary file: ' + relative)
    raw = real.read_bytes()
    require(identity(raw) == expected, 'harness input bytes differ: ' + relative)
    return raw


def unpack(wrapper):
    if isinstance(wrapper, dict) and ('data' in wrapper or 'payload' in wrapper):
        compressed = base64.b64decode(wrapper.get('data', wrapper.get('payload')), validate=True)
        if 'compressed_bytes' in wrapper:
            require(len(compressed) == wrapper['compressed_bytes']
                    and sha256(compressed).hexdigest() == wrapper['compressed_sha256'],
                    'compressed source wrapper identity differs')
        decoder = zlib.decompressobj()
        raw = decoder.decompress(compressed) + decoder.flush()
        require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,
                'source wrapper has trailing or incomplete compressed bytes')
        if 'source_packet' in wrapper:
            expected = wrapper['source_packet']
            size, digest = expected['bytes'], expected['sha256']
        else:
            size = wrapper.get('bytes', wrapper.get('raw_bytes'))
            digest = wrapper.get('sha256', wrapper.get('raw_sha256'))
        require(len(raw) == size and sha256(raw).hexdigest() == digest,
                'decoded source wrapper identity differs')
        return decode(raw)
    return wrapper


def normalize(packet):
    if packet.get('schema') == 'hia.native-finish.success-retirement.source.v1':
        records = []
        for change in packet['changes']:
            before, after, edit = change['before'], change['after'], change['exact_replacement']
            require(before['content'].count(edit['before']) == 1
                    and before['content'].replace(edit['before'], edit['after']) == after['content'],
                    'finish source is not the exact reviewed single replacement')
            require(identity(before['content'].encode('utf-8')) == {
                'bytes': before['bytes'], 'sha256': before['sha256'], 'blob': before['git_blob_sha1']},
                'finish original bytes differ')
            records.append(dict(after, path=change['path']))
    else:
        records = packet['files']
    if isinstance(records, dict):
        records = [dict(row, path=path) for path, row in records.items()]
    require(type(records) is list and records, 'source member inventory missing')
    result = {}
    for item in records:
        path = item['path']
        if path.startswith('source/'):
            path = path[7:]
        posix = PurePosixPath(path)
        require(not posix.is_absolute() and '..' not in posix.parts and str(posix) == path
                and not any(ord(c) < 32 for c in path), 'unsafe source path: ' + path)
        require(path not in result, 'duplicate normalized source member: ' + path)
        text = item.get('content', item.get('text'))
        require(type(text) is str, 'source text missing: ' + path)
        raw = text.encode('utf-8', 'strict')
        actual = identity(raw)
        expected_blob = next(item[key] for key in
                             ('blob', 'git_blob', 'git_blob_sha', 'git_blob_sha1') if key in item)
        require(actual == {'bytes': item['bytes'], 'sha256': item['sha256'], 'blob': expected_blob},
                'source member identity differs: ' + path)
        mode = item.get('git_mode', item.get('mode', '100644'))
        if type(mode) is int:
            require(mode in (0o644, 0o755), 'unreviewed source POSIX mode')
            mode = '100755' if mode == 0o755 else '100644'
        require(mode in ('100644', '100755'), 'unreviewed source Git mode')
        result[path] = dict(path=path, mode=mode, content=text, **actual)
    return result


def publish(path, value):
    raw = (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
    require(path.read_bytes() == raw, 'publication readback differs')
    return identity(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--harness', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.harness.resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=True)
    report = {'schema': 'hia.recoverable-owner-composition.r1', 'status': 'RUNNING',
              'native_executed': False, 'current_cold': False, 'source_tests_executed': False,
              'historical_results_transferred': False, 'inputs': {}, 'selections': []}
    try:
        index = decode((root / 'inputs/INPUTS.json').read_bytes())
        plan = decode((root / 'inputs/MERGE-PLAN.json').read_bytes())
        snapshots = {}
        head = subprocess.check_output(['git', '--no-replace-objects', '-C', str(root), 'rev-parse', 'HEAD']).decode().strip()
        tree = subprocess.check_output(['git', '--no-replace-objects', '-C', str(root), 'rev-parse', 'HEAD^{tree}']).decode().strip()
        require(head == os.environ['GITHUB_SHA'], 'independent harness HEAD differs from its actual workflow event')
        entries = subprocess.check_output(['git', '--no-replace-objects', '-C', str(root), 'ls-tree', '-r', '-z', 'HEAD'])
        harness_sources = {}
        for item in entries.split(b'\0'):
            if not item:
                continue
            metadata, raw_path = item.split(b'\t', 1)
            mode, kind, blob = metadata.decode('ascii').split()
            path = raw_path.decode('utf-8', 'strict')
            real = root / path
            require(kind == 'blob' and mode in ('100644', '100755') and not real.is_symlink(),
                    'invalid harness tracked entry')
            raw = real.read_bytes()
            require(identity(raw)['blob'] == blob
                    and ('100755' if real.stat().st_mode & 0o111 else '100644') == mode,
                    'independent harness tracked bytes or mode differ: ' + path)
            harness_sources[path] = dict(mode=mode, **identity(raw))
        report['harness'] = {'head': head, 'tree': tree, 'files': harness_sources}
        require(plan['base_commit'] == '4b19af89a766593f7d5f1cc2db256e81aba7afcb'
                and plan['base_tree'] == '1bc7c90996e1910ad66ba771b0bfee1d5bfa655c',
                'composition requires exact 4b base')
        owners = {}
        for name, entry in index['owners'].items():
            raw = read_owned(root, entry['path'], entry['identity'])
            snapshots[entry['path']] = raw
            owners[name] = normalize(unpack(decode(raw)))
            report['inputs'][name] = {'path': entry['path'], **identity(raw),
                                     'verified_members': len(owners[name])}
        derived_entry = index['derived']
        raw = read_owned(root, derived_entry['path'], derived_entry['identity'])
        snapshots[derived_entry['path']] = raw
        derived = normalize(decode(raw))
        report['terminal_blank_line_repairs'] = []
        for fix in plan['terminal_blank_line_repairs']:
            path = fix['path']
            before = owners[fix['before_owner']][path]['content']
            after = derived[path]['content']
            require(before.rstrip('\n') + '\n' == after,
                    'terminal format repair changed nonterminal bytes: ' + path)
            require(ast.dump(ast.parse(before), include_attributes=True)
                    == ast.dump(ast.parse(after), include_attributes=True),
                    'terminal format repair changed actual complete Python AST: ' + path)
            report['terminal_blank_line_repairs'].append({
                'path': path, 'before': identity(before.encode('utf-8')),
                'after': identity(after.encode('utf-8')),
                'complete_ast_including_positions_equal': True})
        report['documentation_reference_repairs'] = []
        for fix in plan.get('documentation_reference_repairs', ()):
            path = fix['path']
            before = owners[fix['before_owner']][path]['content']
            after = derived[path]['content']
            edit = fix['exact_replacement']
            require(before.count(edit['before']) == 1
                    and before.replace(edit['before'], edit['after']) == after,
                    'documentation correction exceeds its exact reviewed text: ' + path)
            require(identity(before.encode('utf-8')) == fix['before']
                    and identity(after.encode('utf-8')) == fix['after'],
                    'documentation correction identity differs')
            report['documentation_reference_repairs'].append(fix)
        result = []
        for path, selected in sorted(plan['selected_files'].items()):
            source = derived if selected['owner'] == 'semantic-union' else owners[selected['owner']]
            require(path in source, 'selected path absent from its declared source')
            row = source[path]
            require({key: row[key] for key in ('bytes', 'sha256', 'blob', 'mode')}
                    == selected['expected'], 'selected source bytes differ: ' + path)
            result.append(row)
            report['selections'].append({'path': path, 'owner': selected['owner'],
                                         **selected['expected']})
        require(len(result) == plan['overlay_file_count'], 'overlay denominator differs')
        require(not any(row['path'] == 'tools/check_hia_core_only.py' for row in result),
                'unchanged Core-only boundary cannot be overlaid')
        for relative, raw in snapshots.items():
            require((root / relative).read_bytes() == raw, 'source packet changed: ' + relative)
        overlay = {'schema': 'hepta.hia.source-overlay.v1',
                   'base_commit': plan['base_commit'], 'base_tree': plan['base_tree'],
                   'files': result,
                   'expected_generated_paths': plan['expected_generated_paths'],
                   'extra_controls': []}
        target = root / 'overlay/source-overlay.json'
        report['overlay'] = {'path': str(target), **publish(target, overlay)}
        report['plan'] = identity((root / 'inputs/MERGE-PLAN.json').read_bytes())
        report['input_index'] = identity((root / 'inputs/INPUTS.json').read_bytes())
        report['status'] = 'PASS'
    except BaseException:
        report['status'] = 'FAIL'
        report['exception'] = traceback.format_exc()
        raise
    finally:
        publish(args.output / 'COMPOSITION-RESULT.json', report)
        print(json.dumps({'composition_status': report['status'],
                          'overlay': report.get('overlay'),
                          'scope': 'SOURCE_COMPOSITION_NOT_QUALIFICATION'}, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
