"""Independent bare-object audit of the fixed v67 official source artifact.

No product imports, qualification, checkout or clone are performed. Git is used
only to decode the exact package into a private object database. Raw object
hashes and tree/commit grammar are checked independently here.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import time
import traceback
import zipfile

BASE = Path('/tmp/hia-e26e-v67-independent-audit-r1')
OUT = BASE / 'audit-r1'
BARE = OUT / 'objects.git'
ARTIFACT = Path('/workspace/scratch/hia-v67-exact-git-20261111/hia-source-608157e5-43055736977-1.zip')
ZIP_SHA = '837e8fecfa42012d0749ef7464a083e8a46743e49915ee0b99ebb6bf00df45c2'
MANIFEST_SHA = 'cec14d50ede38a6bcd11595476975cc376b3606d211098a565a5b1593249e3af'
HEAD = '608157e52b0b94e0d294f6b99c4e809869f183aa'
TREE = 'e7c29a60796a1a78946a2c667aa80df86529e532'
TOOL_SHA = 'af243e692ee5b6e9289f6226a0269ae40b02e1b460521471e199dfb8981dca5a'
EXPECTED_MEMBERS = {'IDENTITY.json', 'package/manifest.json', 'package/export-report.json',
    'package/source-package.py', 'package/source-state-after.json', 'package/source-state-before.json',
    'package/source.pack', 'reconstruction.json'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def oid(kind, raw):
    return hashlib.sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            raise ValueError('duplicate JSON key: ' + key)
        result[key] = value
    return result


def parse(raw):
    return json.loads(raw, object_pairs_hook=pairs)


def signature(path):
    s = path.lstat()
    assert stat.S_ISREG(s.st_mode) and not path.is_symlink(), str(path)
    return [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def file_hash(path):
    before = signature(path)
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    assert signature(path) == before
    return h.hexdigest()


def write(path, data):
    if not isinstance(data, bytes):
        data = (json.dumps(data, sort_keys=True, indent=2) + '\n').encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as f:
        f.write(data); f.flush(); os.fsync(f.fileno())
    assert path.read_bytes() == data
    return {'path': str(path.relative_to(BASE)), 'bytes': len(data), 'sha256': sha(data)}


def env():
    result = {k: v for k, v in os.environ.items() if not k.startswith('GIT_') and k not in {'PYTHONPATH', 'PYTHONHOME'}}
    result.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_SYSTEM='/dev/null', GIT_CONFIG_GLOBAL='/dev/null',
                  GIT_TERMINAL_PROMPT='0', GIT_NO_LAZY_FETCH='1', GIT_OPTIONAL_LOCKS='0', LC_ALL='C')
    return result


def command(*args):
    return ['git', '--no-replace-objects', '-c', 'core.hooksPath=/dev/null', '-c', 'gc.auto=0',
            '-c', 'core.fsmonitor=false', '--git-dir=' + str(BARE), *args]


def finish(process, timeout):
    try:
        return process.wait(timeout=timeout)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def run(label, args):
    before = time.monotonic_ns()
    with (OUT / (label + '.stdout.log')).open('xb') as out, (OUT / (label + '.stderr.log')).open('xb') as err:
        process = subprocess.Popen(args, cwd=OUT, env=env(), stdin=subprocess.DEVNULL,
            stdout=out, stderr=err, start_new_session=True)
        try:
            rc = finish(process, 90)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=5)
    write(OUT / (label + '.process.json'), {'argv': args, 'returncode': rc,
        'wall_elapsed_ns': time.monotonic_ns() - before, 'direct_child_reaped': True,
        'scope': 'private local read-only Git audit command; no product qualification'})
    assert rc == 0, label
    return (OUT / (label + '.stdout.log')).read_bytes()


def feed_pack(archive):
    before = time.monotonic_ns()
    with (OUT / 'index-pack.stdout.log').open('xb') as out, (OUT / 'index-pack.stderr.log').open('xb') as err:
        process = subprocess.Popen(command('index-pack', '--stdin', '--strict'), cwd=OUT, env=env(),
            stdin=subprocess.PIPE, stdout=out, stderr=err, start_new_session=True)
        sent = 0
        try:
            os.set_blocking(process.stdin.fileno(), False)
            deadline = time.monotonic() + 120
            with archive.open('package/source.pack') as stream:
                while block := stream.read(1024 * 1024):
                    view = memoryview(block)
                    while view:
                        remaining = deadline - time.monotonic()
                        assert remaining > 0, 'index-pack input deadline'
                        assert select.select([], [process.stdin.fileno()], [], remaining)[1]
                        amount = os.write(process.stdin.fileno(), view)
                        assert amount > 0
                        sent += amount; view = view[amount:]
            process.stdin.close()
            rc = finish(process, max(0.01, deadline - time.monotonic()))
        finally:
            if not process.stdin.closed:
                process.stdin.close()
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=5)
    write(OUT / 'index-pack.process.json', {'argv': command('index-pack', '--stdin', '--strict'),
        'returncode': rc, 'bytes_streamed_directly_from_zip': sent,
        'wall_elapsed_ns': time.monotonic_ns() - before, 'direct_child_reaped': True,
        'no_extracted_second_pack': True, 'qualification_executed': False})
    assert rc == 0 and (OUT / 'index-pack.stderr.log').read_bytes() == b''


class Reader:
    def __init__(self, stream, deadline):
        self.fd = stream.fileno(); self.deadline = deadline; self.buffer = b''
    def fill(self):
        remaining = self.deadline - time.monotonic()
        assert remaining > 0 and select.select([self.fd], [], [], remaining)[0], 'cat-file read deadline'
        block = os.read(self.fd, 1024 * 1024)
        assert block, 'cat-file premature EOF'
        self.buffer += block
    def line(self):
        while b'\n' not in self.buffer:
            assert len(self.buffer) <= 4096
            self.fill()
        result, self.buffer = self.buffer.split(b'\n', 1)
        return result
    def read(self, count):
        while len(self.buffer) < count:
            self.fill()
        result, self.buffer = self.buffer[:count], self.buffer[count:]
        return result


def safe_component(raw):
    assert raw and raw not in (b'.', b'..', b'.git') and b'/' not in raw and b'\\' not in raw
    return raw.decode('utf-8')


def raw_tree(raw):
    result = []; position = 0; names = set(); order = []
    while position < len(raw):
        sep = raw.index(b' ', position); nul = raw.index(b'\0', sep + 1)
        mode = raw[position:sep]; name_raw = raw[sep + 1:nul]
        assert mode in (b'40000', b'100644', b'100755')
        name = safe_component(name_raw)
        assert name not in names; names.add(name)
        end = nul + 21; assert end <= len(raw)
        kind = 'tree' if mode == b'40000' else 'blob'
        order.append(name_raw + (b'/' if kind == 'tree' else b''))
        result.append({'name': name, 'mode': '040000' if kind == 'tree' else mode.decode(),
                       'type': kind, 'oid': raw[nul + 1:end].hex()})
        position = end
    assert position == len(raw) and order == sorted(order)
    return result


def selected_text(path):
    # Capture complete installed/module/tool and Rust texts, not embedded evidence copies.
    return (path.startswith(('hepta/', 'tools/', 'rust/')) and path.endswith(('.py', '.rs', '.toml', '.lock', '.sh'))) or path in {
        'pyproject.toml', 'setup.py', 'setup.cfg', 'MANIFEST.in', 'README.md'}


def main():
    OUT.mkdir(mode=0o700)
    report = {'schema': 'hia.exact-source-package-independent-audit.v1', 'status': 'HOLD',
        'commit': HEAD, 'tree': TREE, 'scope': 'BARE_OBJECT_INDEPENDENT_AUDIT',
        'formal_local_consumer_or_clone_claimed': False, 'qualification_executed': False,
        'product_tests_rerun': False, 'whole_native_delivery_qualified': False}
    before = signature(ARTIFACT); started = time.monotonic_ns()
    try:
        assert before[3] == 300074958 and file_hash(ARTIFACT) == ZIP_SHA
        api_tree = parse((BASE / 'canonical-tree.json').read_bytes())
        api_commit = parse((BASE / 'canonical-commit.json').read_bytes())
        official = parse((BASE / 'official-artifacts.json').read_bytes())
        workflow = parse((BASE / 'official-workflow.json').read_bytes())
        assert api_tree['sha'] == TREE and api_tree['truncated'] is False
        assert api_commit['sha'] == HEAD and api_commit['tree']['sha'] == TREE
        assert workflow['id'] == 43055736977 and workflow['head_sha'] == HEAD and workflow['conclusion'] == 'success'
        item = next(x for x in official['artifacts'] if x['id'] == 13870963554)
        assert item['size_in_bytes'] == before[3] and item['digest'] == 'sha256:' + ZIP_SHA
        assert item['workflow_run']['id'] == workflow['id'] and item['workflow_run']['head_sha'] == HEAD
        with zipfile.ZipFile(ARTIFACT) as archive:
            infos = archive.infolist()
            assert len(infos) == 8 and {i.filename for i in infos} == EXPECTED_MEMBERS
            members = []; pack_sha1 = hashlib.sha1(); pack_tail = b''
            for info in infos:
                assert not info.is_dir() and stat.S_ISREG(info.external_attr >> 16)
                h = hashlib.sha256(); count = 0
                with archive.open(info) as stream:
                    while block := stream.read(1024 * 1024):
                        h.update(block); count += len(block)
                        if info.filename == 'package/source.pack':
                            joined = pack_tail + block
                            pack_sha1.update(joined[:-20]); pack_tail = joined[-20:]
                assert count == info.file_size
                members.append({'path': info.filename, 'bytes': count, 'sha256': h.hexdigest(),
                    'crc32': f'{info.CRC:08x}', 'mode': oct(info.external_attr >> 16)})
            assert pack_sha1.digest() == pack_tail
            write(OUT / 'all-zip-members.json', {'members': members, 'all_crc_verified': True,
                'pack_trailer_sha1': pack_tail.hex(), 'pack_trailer_verified': True})
            raw = archive.read('package/manifest.json'); assert sha(raw) == MANIFEST_SHA
            manifest = parse(raw)
            assert manifest['schema'] == 'hepta.hia.git-source-package.v1' and manifest['object_format'] == 'sha1'
            assert manifest['scope'] == 'EXACT_COMMIT_TREE_BLOB_CLOSURE_WITH_EXPLICIT_SHALLOW_BOUNDARY'
            assert manifest['commit']['oid'] == HEAD and manifest['tree'] == manifest['commit']['tree'] == TREE
            assert manifest['commit']['parents'] == [p['sha'] for p in api_commit['parents']]
            assert len(manifest['commit']['parents']) == 5
            assert manifest['shallow'] == {'source_boundary': [HEAD], 'exported_boundary': [HEAD],
                'ancestor_history_included': False, 'original_parent_headers_preserved': True}
            pack = next(x for x in members if x['path'] == 'package/source.pack')
            assert manifest['pack'] == {'file': 'source.pack', 'size': pack['bytes'], 'sha256': pack['sha256']}
            assert pack['bytes'] == 294622374
            with archive.open('package/source.pack') as stream:
                header = stream.read(12)
            assert header[:4] == b'PACK' and int.from_bytes(header[4:8], 'big') == 2
            assert int.from_bytes(header[8:], 'big') == manifest['counts']['objects'] == 4194
            assert manifest['counts'] == {'entries': 4462, 'leaf_bytes': 400417773, 'leaves': 3925, 'objects': 4194}
            entries = [{'path': x['path'], 'mode': x['mode'], 'type': x['type'], 'oid': x['sha']} for x in api_tree['tree']]
            assert sorted(entries, key=lambda x: x['path']) == manifest['entries']
            for entry in entries:
                assert entry['path'] and not entry['path'].startswith('/')
                for component in entry['path'].split('/'):
                    assert safe_component(component.encode('utf-8')) == component
                assert (entry['mode'], entry['type']) in {('040000', 'tree'), ('100644', 'blob'), ('100755', 'blob')}
            assert {x['path'] for x in manifest['leaves']} == {x['path'] for x in entries if x['type'] == 'blob'}
            for name in EXPECTED_MEMBERS - {'package/source.pack'}:
                data = archive.read(name)
                write(OUT / 'official-small-originals' / name, data)
            assert sha(archive.read('package/source-package.py')) == TOOL_SHA == manifest['transport_program']['sha256']
            states = [parse(archive.read('package/' + n)) for n in ('source-state-before.json', 'source-state-after.json')]
            for name in ('source-state-before.json', 'source-state-after.json'):
                data = archive.read('package/' + name)
                assert manifest['source_states'][name] == {'size': len(data), 'sha256': sha(data)}
            expected_state = {'head': HEAD, 'tree': TREE, 'status': '',
                              'files': {x['path']: x['sha256'] for x in manifest['leaves']}}
            assert len(expected_state['files']) == 3925 and states == [expected_state, expected_state]
            identity = parse(archive.read('IDENTITY.json')); export = parse(archive.read('package/export-report.json'))
            reconstructed = parse(archive.read('reconstruction.json'))
            for value in (identity, export, reconstructed):
                assert value['status'] == 'PASS' and value['commit'] == HEAD and value['tree'] == TREE
                assert value['manifest_sha256'] == MANIFEST_SHA and value['counts'] == manifest['counts']
                assert value['qualification_executed'] is False
            assert identity['run_id'] == '43055736977' and identity['run_attempt'] == '1'
            assert identity['workflow_sha'] == HEAD and identity['ancestor_history_included'] is False
            assert reconstructed['original_source_state_before'] == reconstructed['original_source_state_after'] == expected_state
            clone = reconstructed['clone_reproduction']
            assert clone['status'] == 'PASS' and clone['original_source_state_before'] == clone['original_source_state_after'] == expected_state
            assert clone['object_storage_hardlinks'] == 0 and clone['ancestor_history_included'] is False
            assert clone['fsck_full_strict'] and clone['exact_object_database'] and clone['all_leaves_bytes_modes_verified']
            run('init', ['git', '-c', 'core.hooksPath=/dev/null', 'init', '--bare', '--quiet', '--template=', str(BARE)])
            write(BARE / 'shallow', (HEAD + '\n').encode())
            feed_pack(archive)
        inventory_raw = run('stored-object-inventory', command('cat-file', '--batch-all-objects', '--unordered', '--batch-check=%(objectname) %(objecttype)'))
        actual_inventory = inventory_raw.decode('ascii').splitlines()
        expected = {x['oid']: x for x in manifest['objects']}
        assert len(expected) == 4194 and len(actual_inventory) == len(set(actual_inventory)) == 4194
        assert sorted(actual_inventory) == sorted(k + ' ' + v['type'] for k, v in expected.items())
        reverse = {}
        for leaf in manifest['leaves']:
            reverse.setdefault(leaf['oid'], []).append(leaf['path'])
        objects = []; trees = {}; commit_raw = None; captured = []
        with (OUT / 'cat-file.stderr.log').open('xb') as errors:
            process = subprocess.Popen(command('cat-file', '--batch'), cwd=OUT, env=env(), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=errors, start_new_session=True)
            reader = Reader(process.stdout, time.monotonic() + 180)
            try:
                for key, info in sorted(expected.items()):
                    process.stdin.write(key.encode() + b'\n'); process.stdin.flush()
                    header = reader.line().split(b' ')
                    assert header == [key.encode(), info['type'].encode(), str(info['size']).encode()]
                    kind = info['type']; checksum = hashlib.sha256()
                    raw_hash = hashlib.sha1(kind.encode() + b' ' + str(info['size']).encode() + b'\0')
                    keep = kind in {'commit', 'tree'} or any(selected_text(p) for p in reverse.get(key, []))
                    fragments = [] if keep else None; remaining = info['size']
                    while remaining:
                        block = reader.read(min(1024 * 1024, remaining)); remaining -= len(block)
                        checksum.update(block); raw_hash.update(block)
                        if keep: fragments.append(block)
                    assert reader.read(1) == b'\n'
                    assert raw_hash.hexdigest() == key and checksum.hexdigest() == info['sha256']
                    objects.append({'oid': key, 'type': kind, 'size': info['size'], 'sha256': checksum.hexdigest()})
                    if keep:
                        content = b''.join(fragments)
                        if kind == 'commit':
                            assert key == HEAD and commit_raw is None; commit_raw = content
                        elif kind == 'tree': trees[key] = raw_tree(content)
                        else:
                            for path in reverse[key]:
                                if selected_text(path):
                                    content.decode('utf-8')
                                    captured.append({'repository_path': path, 'git_blob_sha1': key,
                                        **write(OUT / 'owner-sources' / path, content)})
                process.stdin.close()
                assert not reader.buffer
                assert select.select([process.stdout.fileno()], [], [], 10)[0]
                assert os.read(process.stdout.fileno(), 1) == b''
                assert finish(process, 10) == 0
            finally:
                if not process.stdin.closed: process.stdin.close()
                if process.poll() is None: os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=5)
                process.stdout.close()
        assert (OUT / 'cat-file.stderr.log').read_bytes() == b''
        assert objects == manifest['objects']
        assert oid('commit', commit_raw) == HEAD and len(commit_raw) == manifest['commit']['size']
        assert sha(commit_raw) == manifest['commit']['sha256']
        heads, separator, message = commit_raw.partition(b'\n\n'); assert separator
        lines = heads.splitlines()
        tree_headers = [x[5:].decode('ascii') for x in lines if x.startswith(b'tree ')]
        parents = [x[7:].decode('ascii') for x in lines if x.startswith(b'parent ')]
        assert tree_headers == [TREE] and parents == manifest['commit']['parents']
        assert sum(x.startswith(b'author ') for x in lines) == sum(x.startswith(b'committer ') for x in lines) == 1
        write(OUT / 'original-commit.raw', commit_raw)
        write(OUT / 'commit-headers.json', {'oid': HEAD, 'sha256': sha(commit_raw), 'size': len(commit_raw),
            'raw_headers_utf8': heads.decode(), 'parents_in_original_order': parents, 'tree': TREE,
            'ancestor_objects_included': False, 'explicit_shallow_boundary': [HEAD]})
        walked = []; empty_trees = []; used = {HEAD, TREE}
        def walk(key, prefix, stack):
            assert key not in stack and key in trees
            records = trees[key]
            if not records: empty_trees.append(prefix)
            for entry in records:
                path = prefix + entry['name']
                row = {'path': path, 'mode': entry['mode'], 'type': entry['type'], 'oid': entry['oid']}
                walked.append(row); used.add(entry['oid'])
                assert expected[entry['oid']]['type'] == entry['type']
                if entry['type'] == 'tree': walk(entry['oid'], path + '/', stack + (key,))
        walk(TREE, '', ())
        assert len({x['path'] for x in walked}) == len(walked) == 4462
        assert sorted(walked, key=lambda x: x['path']) == manifest['entries']
        assert used == set(expected)
        leaves = [dict(x, size=expected[x['oid']]['size'], sha256=expected[x['oid']]['sha256'])
                  for x in sorted(walked, key=lambda x: x['path']) if x['type'] == 'blob']
        assert leaves == manifest['leaves'] and len(leaves) == 3925
        assert sum(x['size'] for x in leaves) == 400417773
        api_leaves = {x['path']: x for x in api_tree['tree'] if x['type'] == 'blob'}
        for leaf in leaves:
            value = api_leaves[leaf['path']]
            assert (value['sha'], value['size'], value['mode']) == (leaf['oid'], leaf['size'], leaf['mode'])
        stored_packs = list((BARE / 'objects' / 'pack').glob('*.pack'))
        assert len(stored_packs) == 1 and file_hash(stored_packs[0]) == manifest['pack']['sha256']
        assert not (BARE / 'objects/info/alternates').exists() and not (BARE / 'info/grafts').exists()
        assert not list((BARE / 'objects/pack').glob('*.promisor'))
        assert (BARE / 'shallow').read_bytes() == (HEAD + '\n').encode()
        write(OUT / 'all-4194-object-bytes.json', {'objects': objects, 'all_raw_sha1_sha256_and_sizes_verified': True})
        write(OUT / 'all-4462-tree-records.json', {'entries': sorted(walked, key=lambda x: x['path']),
            'empty_tree_paths': empty_trees, 'all_record_boundaries_safe_names_unique_names_modes_sort_order_verified': True})
        write(OUT / 'all-3925-leaf-bytes-and-modes.json', {'leaves': leaves, 'all_bytes_bound_via_raw_blob_hash': True})
        write(OUT / 'owner-source-capture.json', {'files': captured, 'full_utf8_bytes_captured': True})
        assert signature(ARTIFACT) == before
        report.update(status='EXACT_OFFICIAL_GIT_OBJECT_AND_LEAF_CLOSURE_VERIFIED',
            artifact={'id': 13870963554, 'run_id': 43055736977, 'bytes': before[3], 'sha256': ZIP_SHA,
                      'all_eight_members_crc_sha_size_verified': True},
            manifest_sha256=MANIFEST_SHA, pack=manifest['pack'], counts=manifest['counts'],
            original_commit_parent_headers=parents, empty_tree_paths=empty_trees,
            all_raw_object_sha1_sha256_sizes_verified=True, all_leaf_bytes_modes_canonical_git_verified=True,
            source_input_identity_unchanged=True, private_bare_only=True,
            official_prior_reconstruction_report_bound=True,
            official_prior_reconstruction_is_not_current_local_consumer_execution=True,
            captured_owner_text_files=len(captured), elapsed_ns=time.monotonic_ns()-started)
        write(OUT / 'AUDIT.json', report)
        print(json.dumps(report), flush=True)
    except BaseException as exc:
        report.update(error_type=type(exc).__name__, error=str(exc), traceback=traceback.format_exc(),
                      elapsed_ns=time.monotonic_ns()-started)
        write(OUT / 'AUDIT-HOLD.json', report)
        raise


if __name__ == '__main__':
    main()
