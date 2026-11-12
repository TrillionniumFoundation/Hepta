"""Exact, declared R2 -> front/Requests union preparation; no policy execution."""
from __future__ import annotations
import ast
import base64
from hashlib import sha1
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import zlib

import run_requests_development as r2
from source_custody import digest, wire, write, safe, metadata, files, admit_git_snapshot

UNION_BLOB = '5b00590136a08a866f3bd1edf81c6966485f1a6e'
UNION_BYTES = 852920
UNION_SHA = '08f1a4236739688e4cc0673933b970681c2f969a73e6428def0be2077f951b42'
R2_TREE = '98eff57e40af422cd69c39f2aa9588fdbf86a2ad'
UNION_TREE = 'ea19b301b495ca02f6301a237111d97835fdc476'
REFERENCE_COMMIT = '64f67ae897c3cb49d45a1e1a4622db974812e3fe'
REFERENCE_TREE = 'b7cf3502931d5fae8f58444b0af04cc642414a4a'
REFERENCE_PARENT = '4b19af89a766593f7d5f1cc2db256e81aba7afcb'
LAZY_SHA = 'b1b9ddf6a30bb40700a1923be2ece99cd15914a75f59373ca4e357f85fb8882f'

def git_blob(raw):
    return sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()

def row_for(raw, mode='100644'):
    if mode not in ('100644', '100755'):
        raise ValueError('exact regular source mode required')
    return {'bytes': len(raw), 'sha256': digest(raw), 'blob': git_blob(raw), 'mode': mode}

def tree_identity(rows):
    root = {}
    for path, row in rows.items():
        safe(path)
        directory = root
        parts = path.split('/')
        for part in parts[:-1]:
            if part in directory and type(directory[part]) is not dict:
                raise ValueError('source file-directory collision')
            directory = directory.setdefault(part, {})
        if parts[-1] in directory:
            raise ValueError('source path collision')
        if row['mode'] not in ('100644', '100755') or not re.fullmatch('[0-9a-f]{40}', row['blob']):
            raise ValueError('exact Git source identity required')
        directory[parts[-1]] = (row['mode'], row['blob'])
    def encode(directory):
        rows = []
        for name, value in directory.items():
            if type(value) is dict:
                rows.append(((name + '/').encode(), '40000', name, encode(value)))
            else:
                rows.append((name.encode(), value[0], name, value[1]))
        raw = b''.join(mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(blob)
                       for _, mode, name, blob in sorted(rows))
        return sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    return encode(root)

def load_union(inputs):
    raw = (inputs / 'union-source.zlib.json').read_bytes()
    if (len(raw), digest(raw), git_blob(raw)) != (UNION_BYTES, UNION_SHA, UNION_BLOB):
        raise ValueError('complete acknowledged union packet differs')
    wrapper = json.loads(raw)
    if set(wrapper) != {'schema','bytes','sha256','git_blob_sha','zlib_bytes','zlib_sha256','zlib_base64'}:
        raise ValueError('union transport shape differs')
    packed = base64.b64decode(wrapper['zlib_base64'], validate=True)
    if len(packed) != wrapper['zlib_bytes'] or digest(packed) != wrapper['zlib_sha256']:
        raise ValueError('union compressed identity differs')
    decode = zlib.decompressobj()
    payload = decode.decompress(packed, wrapper['bytes'] + 1)
    if decode.unconsumed_tail:
        raise ValueError('union payload exceeds recorded extent')
    payload += decode.flush()
    if (not decode.eof or decode.unused_data or decode.unconsumed_tail
            or len(payload) != wrapper['bytes'] or digest(payload) != wrapper['sha256']
            or git_blob(payload) != wrapper['git_blob_sha']):
        raise ValueError('complete union payload identity differs')
    return json.loads(payload)

def validate_union(value, before):
    if (len(before) != 3272 or tree_identity(before) != R2_TREE
            or value['base']['tree'] != R2_TREE or value['base']['files'] != 3272
            or value['candidate']['tree'] != UNION_TREE or value['candidate']['files'] != 3291
            or value['candidate']['changed_files'] != 32 or value['candidate']['new_files'] != 19
            or len(value['files']) != 32):
        raise ValueError('exact R2 and union source identities differ')
    result = dict(before)
    prepared = {}
    for name, pair in value['files'].items():
        safe(name)
        if pair['before'] != before.get(name):
            raise ValueError('union delta exact predecessor differs: ' + name)
        raw = pair['text'].encode('utf-8')
        after = row_for(raw, pair['after']['mode'])
        if after != pair['after']:
            raise ValueError('union delta complete bytes or mode differ: ' + name)
        if pair['before'] == after:
            raise ValueError('unnecessary unchanged union delta')
        prepared[name] = (raw, after)
        result[name] = after
    if (len(result) != 3291 or len(set(result) - set(before)) != 19
            or result != value['all_source_metadata'] or tree_identity(result) != UNION_TREE):
        raise ValueError('whole union source readback inventory differs')
    for name, row in value['root_protected_exact'].items():
        if before.get(name) != row or result.get(name) != row:
            raise ValueError('frozen Requests/ABI/finish/input changed: ' + name)
    return prepared, result

def replace_private(path, raw, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.joint-private-write')
    write(temporary, raw)
    temporary.chmod(0o755 if mode == '100755' else 0o644)
    os.replace(temporary, path)
    if r2.compact(metadata(path)) != row_for(raw, mode):
        raise ValueError('private source publication readback differs')

def apply_union(source, inputs, before):
    observed = {name: r2.compact(row) for name, row in files(source).items()}
    if observed != before:
        raise ValueError('R2 source changed before union preparation')
    value = load_union(inputs)
    prepared, expected = validate_union(value, before)
    for name, (raw, row) in prepared.items():
        replace_private(source / name, raw, row['mode'])
    actual = files(source)
    if {name: r2.compact(row) for name, row in actual.items()} != expected:
        raise ValueError('whole actual union source differs')
    return value, actual

def workflow_inventory(source):
    raw = (source / '.github/workflows/hia-core.yml').read_text()
    block = raw.split('      - name: Core source and independent reference controls\n', 1)
    if len(block) != 2:
        raise ValueError('exact source step name differs')
    block = block[1].split('\n  native:', 1)[0]
    match = re.search(r'names\s*=\s*(\([\s\S]*?\))\n', block)
    if match is None:
        raise ValueError('complete source selector tuple missing')
    names = ast.literal_eval(match.group(1))
    if type(names) is not tuple or len(names) != 175 or any(type(x) is not str for x in names):
        raise ValueError('complete 175-selector source tuple differs')
    generation = re.findall(r'for component in ([^;\n]+); do', raw)
    if len(generation) != 1:
        raise ValueError('one complete original generator sequence required')
    generators = generation[0].split()
    if len(generators) != 93 or len(set(generators)) != 93:
        raise ValueError('complete 93-generator sequence differs')
    return names, generators

def reference_module(inputs):
    path = inputs / 'front-original/run_split_development.py'
    spec = importlib.util.spec_from_file_location('frozen_front_original_preparer', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def prepare_front_reference(checkout, inputs, work):
    old = reference_module(inputs)
    raw_commit = r2.git(checkout, 'cat-file', 'commit', 'HEAD')
    parents = [x.removeprefix(b'parent ').decode() for x in raw_commit.split(b'\n\n',1)[0].splitlines()
               if x.startswith(b'parent ')]
    if (r2.git(checkout,'rev-parse','HEAD').decode().strip() != REFERENCE_COMMIT
            or r2.git(checkout,'rev-parse','HEAD^{tree}').decode().strip() != REFERENCE_TREE
            or parents != [REFERENCE_PARENT] or r2.git(checkout,'status','--porcelain=v1','--untracked-files=all')):
        raise ValueError('authentic original front reference Git source differs')
    original = files(checkout)
    admit_git_snapshot(checkout, original, r2.git(checkout,'ls-tree','-r','-z','HEAD'))
    compact = {name:r2.compact(row) for name,row in original.items()}
    if len(original) != 3255 or tree_identity(compact) != REFERENCE_TREE:
        raise ValueError('whole 3255-file front reference differs')
    packet = old.capsule(inputs/'front-original/r1-source-packet.json', old.R1_PACKET, original)
    target = work.with_name('v81-core-assembly-front-development-r1') / 'source'
    target.parent.mkdir(exist_ok=False)
    old.copy_source(checkout, target, original)
    old.apply_packet(target, packet)
    actual = files(target)
    guard = {name:{'sha256':row['sha256'],'mode':int(row['posix_mode'],8)} for name,row in actual.items()}
    if len(guard) != 3273 or digest(wire(guard)) != old.R1_GUARD:
        raise ValueError('frozen original front R1 complete guard differs')
    write(work/'ORIGINAL-R1-SOURCE-GUARD.json', wire(guard))
    write(work/'FRONT-REFERENCE-CUSTODY.json', wire({'base_commit':REFERENCE_COMMIT,
        'base_tree':REFERENCE_TREE,'base_parent':REFERENCE_PARENT,'base_manifest':original,
        'reference_manifest':actual,'reference_path':str(target),
        'meaning':'frozen original input; not the union candidate or a newly qualified reference'}))
    return target, actual

def prepare_front_scripts(inputs, work, compiler):
    original = inputs / 'front-original'
    copied = {}
    for path in sorted(original.glob('*.py')):
        if path.name == 'run_split_development.py':
            continue
        target = work / path.name
        shutil.copy2(path, target)
        if metadata(path) != metadata(target):
            raise ValueError('original front test script copy differs')
        copied[target] = metadata(target)
    retained = work/'retained-inputs'
    retained.mkdir(exist_ok=False)
    target = retained/'retained-B3.image.bin'
    shutil.copy2(compiler,target)
    if metadata(target) != metadata(compiler):
        raise ValueError('front compiler path projection changed actual bytes')
    copied[target] = metadata(target)
    base = r2.source_packet(inputs)['base_manifest']
    write(work/'BASE.json',wire({'base_commit':r2.BASE,'base_tree':r2.TREE,'files':base,
        'meaning':'authentic unchanged original caller module bytes, read by the frozen test fixture'}))
    return copied

def prepare_binding_view(source, inputs, work, expected):
    raw = (inputs/'lazy-four-before-after.json').read_bytes()
    if digest(raw) != LAZY_SHA:
        raise ValueError('exact four-owner mutation packet differs')
    packet = json.loads(raw)
    if len(packet['files']) != 4:
        raise ValueError('exact four foreign-owner projection required')
    changes = {}
    view_expected = {name:r2.compact(row) for name,row in expected.items()}
    for name,pair in packet['files'].items():
        safe(name)
        for role,key in (('before','before_text'),('after','text')):
            text = pair[key].encode()
            row = row_for(text,pair[role]['mode'])
            target = {**pair[role]}; target['blob'] = target.pop('git_blob_sha')
            if row != target:
                raise ValueError('four-owner original bytes differ')
            if role == 'after' and view_expected[name] != row:
                raise ValueError('four-owner candidate is not the exact tested repair')
        changes[name] = (pair['before_text'].encode(),pair['before']['mode'])
        view_expected[name] = row_for(changes[name][0],changes[name][1])
    target = work/'binding-before-view'
    target.mkdir(exist_ok=False)
    for name in expected:
        path = target/safe(name); path.parent.mkdir(parents=True,exist_ok=True)
        os.link(source/name,path)
    for name,(text,mode) in changes.items():
        replace_private(target/name,text,mode)
    actual = files(target)
    if {name:r2.compact(row) for name,row in actual.items()} != view_expected or files(source) != expected:
        raise ValueError('four-owner before view damaged candidate or readback differs')
    write(work/'BINDING-BEFORE-MANIFEST.json',wire(actual))
    return target,actual

def compare_bindings(before_path, after_path):
    before,after = (json.loads(p.read_bytes()) for p in (before_path,after_path))
    if (before['role'] != 'before' or after['role'] != 'after'
            or before['observations'] != 64 or after['observations'] != 64
            or before['actual_native_entries'] != 0 or after['actual_native_entries'] != 0
            or len(before['initial_foreign_modules']) != 4
            or after['initial_foreign_modules'] or after['initial_profile_calls']
            or before['rows'] != after['rows']):
        raise ValueError('original complete 64 mutable foreign binding observations differ')
    return {'status':'PASS','observations':64,'actual_native_entries':0,
        'scope':'actual interpreter; controlled foreign-port/global lookup only',
        'before_sha256':digest(before_path.read_bytes()),'after_sha256':digest(after_path.read_bytes())}
