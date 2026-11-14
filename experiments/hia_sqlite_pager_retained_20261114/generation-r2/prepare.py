"""Frozen Pager qualification evidence IO; inherited single-link/nofollow reads."""
from contextlib import contextmanager
from pathlib import Path
import hashlib
import json
import os
import stat

MAX_INPUT = 64 << 20

def require(value, message):
    if not value:
        raise RuntimeError(message)

def identity(value):
    return [value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns]

@contextmanager
def held_parent(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'absolute fixed input required')
    descriptors = [os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    edges = []
    try:
        for name in path.parts[1:-1]:
            parent = descriptors[-1]
            descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            descriptors.append(descriptor)
            current = os.fstat(descriptor)
            edges.append((parent, name, descriptor, (current.st_dev, current.st_ino)))
        yield descriptors[-1], path.name
        for parent, name, descriptor, expected in edges:
            a = os.fstat(descriptor)
            b = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require(stat.S_ISDIR(b.st_mode) and (a.st_dev, a.st_ino) == expected
                    == (b.st_dev, b.st_ino), 'parent directory identity changed')
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)

def read(path, maximum=MAX_INPUT):
    with held_parent(path) as (parent, name):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size <= maximum, 'fixed single-link regular file required')
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            require(identity(os.fstat(descriptor)) == identity(before), 'open identity differs')
            pieces, count, digest = [], 0, hashlib.sha256()
            while True:
                block = os.read(descriptor, min(1 << 20, maximum + 1 - count))
                if not block:
                    break
                count += len(block)
                require(count <= maximum, 'whole original exceeds bound')
                digest.update(block); pieces.append(block)
            require(count == before.st_size and identity(os.fstat(descriptor)) == identity(before)
                    == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'original identity changed during full read')
        finally:
            os.close(descriptor)
    raw = b''.join(pieces)
    return {'path': str(path), 'bytes': count, 'sha256': digest.hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(count).encode() + b'\0' + raw).hexdigest(),
            'identity': identity(before)}, raw

def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()

def create(path, value, raw=False):
    body = value if raw else wire(value)
    with held_parent(path) as (parent, name):
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(body); stream.flush(); os.fsync(stream.fileno())
        os.fsync(parent)
    record, actual = read(path, max(len(body), 1))
    require(actual == body, 'new original independent readback differs')
    return record

def input_records(root, request):
    records = {}
    for name, expected in request['inputs'].items():
        require(type(name) is str and not name.startswith('/') and '..' not in Path(name).parts,
                'fixed relative source pin required')
        actual, _ = read(root / name)
        require(all(actual[key] == expected[key] for key in ('bytes', 'sha256', 'git_blob')),
                'frozen input byte pin differs: ' + name)
        records[name] = actual
    return records


# Metadata materialization only: no author, compiler, VM or product imports.
import ast
import platform
import resource
import sys
import time
import traceback

P = Path('/home/qq/hia-rewrite-20261113-e26e-r1')
ROOT = P/'pager-retained-generation-r2'
OUTPUT = P/'pager-retained-generation-r2-actual'
REPORT = P/'pager-retained-generation-r2-PREPARE-REPORT.json'
SOURCE = P/'core-put-mask-elision-derive8-r1/source'
PYTHON = '/usr/bin/python3.14'
SOURCE_COMMIT = '146ccce813785ff788850f4d2e5d840df233b1b5'
SOURCE_TREE = 'a5d9ce2d6fdff616bf91611c650e0fd3dc1786f2'
EXPECTED_PINS = json.loads(r'''{"bundle":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-sources-r2.json","bytes":117614,"sha256":"97984189c02edd2a7e04b0e46200027a368ab9ed00af873463d746e08cd1e72d","git":"9d2ae2d3b2230e0c1b1fb326dee304068476ce18","version":"66306:79482957:117614:1794685465113733023:1794685465113824701","mode":384,"uid":1000,"gid":1000,"nlink":1},"source":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-expected-source-r1.json","bytes":833153,"sha256":"4196815b3592342c7672a83d1df5ddc9d2ed4cacf6c78318836a0e22a9c6fea7","git":"f2a5428131e459ea91d90c8d23793d61a366dd3a","version":"66306:79482944:833153:1794681765286495963:1794681765287649664","mode":384,"uid":1000,"gid":1000,"nlink":1},"map901":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-expected-map901-r1.json","bytes":98339,"sha256":"28348495a949b9c94ffafcfb14a79b93f4bf7e1e4a8dbb435d0da376ee73c843","git":"3365116eb13231b13c469998b58e5d9ad8f4b828","version":"66306:79482946:98339:1794681767453376185:1794681767464185101","mode":384,"uid":1000,"gid":1000,"nlink":1},"system":{"bytes":2048191,"git_blob":"c636380b7cb2d4e4733aa8fe3ed6063d7d700147","identity":[66306,80647142,33152,1000,1000,1,2048191,"1794630845128928214","1794630845128928214"],"path":"/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-pager-read-owner-native-r3/SYSTEM-INPUTS.json","sha256":"f6dea8875c638cfaf79f8e9af1e109df3d114ec150d65482215692423fccee09"}}''')
EXPECTED_PINS['system']['identity'] = [
    int(value) for value in EXPECTED_PINS['system']['identity']]
EXPECTED_ASSETS = set(json.loads(r'''["inputs/tools/generate_hia_pager_elf_linker.py","inputs/tools/generate_hia_sqlite_pager_retained_owner_r1.py","inputs/tools/pager_owner_common_source_r2.py","inputs/tools/pager_owner_lock_source_r3.py","inputs/tools/pager_owner_page_source.py","inputs/tools/sqlite_pager_retained_owner.hia","qualification/pager_clean_exec_r1.py","qualification/pager_common_r1.py","qualification/pager_generation_r1.py","qualification/pager_launch_r1.py","qualification/pager_policy_r1.py","qualification/pager_support_r1.py","qualification/pager_worker_r1.py","qualification/process_owner_impl.py"]'''))
ENVIRONMENT = {
    'LANG':'C', 'LC_ALL':'C', 'PATH':'',
    'PYTHONDONTWRITEBYTECODE':'1', 'PYTHONHASHSEED':'0', 'TZ':'UTC',
    'TMPDIR':str(OUTPUT/'tmp')}

def new_directory(path):
    with held_parent(path) as (parent, name):
        os.mkdir(name, 0o700, dir_fd=parent)
        os.fsync(parent)

def put(path, value, *, raw=False):
    body = value if raw else wire(value)
    require(len(body) <= 4 << 20, 'metadata original physical file exceeds 4MiB')
    return create(path, body, raw=True)

def read_staged(expected):
    pin, body = read(expected['path'], 4 << 20)
    i = pin['identity']
    version = ':'.join(str(i[index]) for index in (0,1,6,7,8))
    require(pin['bytes'] == expected['bytes']
        and pin['sha256'] == expected['sha256']
        and pin['git_blob'] == expected['git']
        and version == expected['version']
        and i[2]&0o7777 == expected['mode']
        and i[3] == expected['uid'] and i[4] == expected['gid']
        and i[5] == expected['nlink'] == 1,
        'complete previously observed staged input identity')
    return pin, body

def git_tree(source_rows):
    root = {}
    for name, pin in source_rows.items():
        pieces = name.split('/')
        branch = root
        for part in pieces[:-1]:
            branch = branch.setdefault(part, {})
            require(type(branch) is dict, 'Git path prefix collision')
        require(pieces[-1] not in branch, 'duplicate Git path')
        branch[pieces[-1]] = (
            '100755' if pin['identity'][2]&0o111 else '100644', pin['git_blob'])
    def tree(node):
        body = bytearray()
        for name in sorted(node, key=lambda value:
                           (value+('/' if type(node[value]) is dict else '')).encode('utf-8')):
            item = node[name]
            if type(item) is dict:
                mode, digest = '40000', tree(item)
            else:
                mode, digest = item
            body.extend(mode.encode('ascii')+b' '+name.encode('utf-8')+b'\0')
            body.extend(bytes.fromhex(digest))
        return hashlib.sha1(b'tree '+str(len(body)).encode('ascii')+b'\0'+body).hexdigest()
    return tree(root)

def source_snapshot(expected):
    require(type(expected) is list and len(expected) == 4136,
            'original exact 4136 Git source catalogue')
    rows = {}
    for item in expected:
        require(set(item) == {'path','mode','type','sha','size'},
                'exact expected source catalogue entry')
        name = item['path']
        require(type(name) is str and name and not name.startswith('/')
            and str(Path(name)) == name and '..' not in Path(name).parts
            and name not in rows and item['type'] == 'blob'
            and item['mode'] in ('100644','100755')
            and type(item['size']) is int and 0 <= item['size'] <= 64 << 20,
            'fixed regular source role')
        pin, _ = read(SOURCE/name)
        require(pin['bytes'] == item['size'] and pin['git_blob'] == item['sha']
            and ('100755' if pin['identity'][2]&0o111 else '100644') == item['mode'],
            'whole actual source body and Git mode: '+name)
        rows[name] = pin
    require(sum(pin['bytes'] for pin in rows.values()) == 412713085
        and git_tree(rows) == SOURCE_TREE,
        'complete current source bytes and independently reconstructed Git tree')
    return rows

def profile_snapshot(support, doc):
    require(doc['count'] == len(doc['files']) == 4815
        and doc['bytes'] == 181643507 and doc['host'] == 'ai395',
        'original complete selected system profile')
    require(not Path('/etc/ld.so.preload').exists(), 'ld.so.preload absent before metadata')
    rows = {}
    for expected in doc['files']:
        require(set(expected) == {'path','bytes','sha256','git_blob','identity'}
            and expected['path'] not in rows and len(expected['identity']) == 9
            and all(type(value) is int for value in expected['identity']),
            'exact system original full pin')
        pin = support.system_read(expected['path'])
        require(pin == expected, 'fresh original system role differs: '+expected['path'])
        rows[expected['path']] = pin
    require(sum(pin['bytes'] for pin in rows.values()) == 181643507,
            'actual complete system body bytes')
    for alias, target in doc['aliases'].items():
        require(str(Path(alias).resolve(strict=True)) == target,
                'metadata system alias target changed')
    for label in ('directory_aliases', 'executable_aliases'):
        for alias in doc[label]:
            actual = os.lstat(alias['path'])
            require(identity(actual) == alias['identity']
                and str(Path(alias['path']).resolve(strict=True)) == alias['target'],
                'metadata complete alias identity/target changed')
            if label == 'directory_aliases':
                require(stat.S_ISLNK(actual.st_mode) and Path(alias['target']).is_dir(),
                        'metadata directory alias differs')
    require(not Path('/etc/ld.so.preload').exists(), 'ld.so.preload absent after metadata')
    return rows

def main():
    report = {
        'schema':'hia.pager-retained-generation-materialization.v1',
        'status':'HOLD', 'root':str(ROOT), 'output':str(OUTPUT),
        'exception':None, 'secondary_errors':[], 'created':[],
        'source_files':4136, 'source_bytes':412713085, 'source_map_entries':901,
        'system_files':4815, 'system_bytes':181643507,
        'author_document_calls':0, 'project_imports':[],
        'native_entries':0, 'VM_calls':0, 'subprocess_calls':0,
        'actual_output_precreated':False}
    started = time.monotonic_ns()
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0,0))
        resource.setrlimit(resource.RLIMIT_CPU, (180,180))
        resource.setrlimit(resource.RLIMIT_AS, (256 << 20,256 << 20))
        resource.setrlimit(resource.RLIMIT_STACK, (8 << 20,8 << 20))
        resource.setrlimit(resource.RLIMIT_FSIZE, (4 << 20,4 << 20))
        require(len(sys.argv) == 2 and len(sys.argv[1]) == 64,
                'one expected complete materializer SHA')
        self_pin, _ = read(Path(__file__).resolve(), 1 << 20)
        require(self_pin['sha256'] == sys.argv[1], 'exact materializer body')
        report['script'] = self_pin
        require(sys.executable == PYTHON and sys.version_info[:3] == (3,14,4)
            and sys.version == '3.14.4 (main, Aug 20 2026, 10:41:58) [GCC 15.2.0]'
            and sys.platform == 'linux' and platform.machine() == 'x86_64'
            and sys.flags.isolated == 1 and sys.flags.no_site == 1
            and sys.dont_write_bytecode,
            'exact isolated metadata interpreter')
        require(not os.path.lexists(ROOT) and not os.path.lexists(OUTPUT)
            and not os.path.lexists(REPORT), 'new disjoint metadata and actual namespaces')
        os.environ.clear()
        os.environ.update(ENVIRONMENT)
        bp, bundle_raw = read_staged(EXPECTED_PINS['bundle'])
        ep, expected_raw = read_staged(EXPECTED_PINS['source'])
        mp, map_raw = read_staged(EXPECTED_PINS['map901'])
        system_pin, system_raw = read(EXPECTED_PINS['system']['path'],4 << 20)
        require(system_pin == EXPECTED_PINS['system'], 'exact original system-map physical pin')
        bundle, expected, cold, system = (
            json.loads(bundle_raw), json.loads(expected_raw),
            json.loads(map_raw), json.loads(system_raw))
        require(bundle['schema'] == 'hia.pager-retained-generation-source-bundle.v1'
            and bundle['root'] == str(ROOT) and bundle['product_execution'] is False
            and len(bundle['files']) == 14
            and {item['name'] for item in bundle['files']} == EXPECTED_ASSETS,
            'exact frozen fourteen source/control assets')
        report['staged_inputs'] = {'bundle':bp,'expected_source':ep,'source_map901':mp,
                                  'original_system_map':system_pin}
        for path in (ROOT, ROOT/'qualification', ROOT/'inputs', ROOT/'inputs/tools',
                     ROOT/'reference'):
            new_directory(path)
        for item in bundle['files']:
            name = item['name']
            body = item['text'].encode('utf-8')
            require(name in EXPECTED_ASSETS and len(body) == item['bytes']
                and hashlib.sha256(body).hexdigest() == item['sha256']
                and hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest()
                    == item['git_blob'], 'complete frozen copied asset')
            if name.endswith(('.py','.hia')):
                ast.parse(body.decode('utf-8'), filename=str(ROOT/name))
            report['created'].append(put(ROOT/name, body, raw=True))
        sys.path.insert(0, str(ROOT/'qualification'))
        import pager_support_r1 as support
        import pager_policy_r1 as policy
        import pager_generation_r1 as generation
        require(support.ROOT == ROOT and policy.ROOT == ROOT and generation.ROOT == ROOT,
                'all passive metadata helper roots')
        support.capacity(P, True)
        source_before = source_snapshot(expected)
        require(type(cold) is dict and len(cold) == 901
            and all(name in source_before and source_before[name]['sha256'] == digest
                    for name,digest in cold.items()), 'entire901 joins current4136')
        require(source_before['tools/generate_hia_elf_linker.py']['sha256'] ==
            'cc57ae400052a47aa9861606eb9681e585d20b19a9b1f0a29fbc30b849a4071d',
            'exact old adapter author supply')
        system_before = profile_snapshot(support, system)
        require(read(EXPECTED_PINS['system']['path'],4 << 20) == (system_pin,system_raw),
                'original system-map unchanged during fresh4815 read')
        source_base = {
            'source_commit':SOURCE_COMMIT, 'source_tree':SOURCE_TREE,
            'source_root':str(SOURCE), 'input_count':4136, 'bytes':412713085,
            'files':[{'path':name, **{key:pin[key] for key in
                      ('bytes','sha256','git_blob','identity')}}
                     for name,pin in sorted(source_before.items())]}
        for name, body in (
            ('SOURCE-BASE.json',wire(source_base)),
            ('SOURCE-MAP.json',map_raw),
            ('SYSTEM-INPUTS.json',system_raw),
            ('reference/EXPECTED-SOURCE.json',expected_raw)):
            report['created'].append(put(ROOT/name,body,raw=True))
        names = sorted(EXPECTED_ASSETS | {'SOURCE-BASE.json','SOURCE-MAP.json',
                                         'SYSTEM-INPUTS.json','reference/EXPECTED-SOURCE.json'})
        inputs = {name:read(ROOT/name)[0] for name in names}
        runtime = support.system_read(PYTHON)
        require(runtime == system['runtime'], 'actual exact runtime system pin')
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        require(boot == 'b1620269-aaef-43e7-bf47-bc6eb1c1a447', 'same fixed host boot')
        request = {
            'schema':policy.SCHEMA, 'status':policy.STATUS, 'host':'ai395',
            'root':str(ROOT), 'output':str(OUTPUT),
            'command':[PYTHON,'-I','-S','-B',str(ROOT/'qualification/pager_worker_r1.py'),
                       str(ROOT/'REQUEST.json'),'@REQUEST_SHA256@'],
            'environment':ENVIRONMENT, 'population':policy.PROFILE,
            'limits':policy.LIMITS, 'original_caps':generation.CAPS,
            'qualification_seconds':180, 'cleanup_seconds':3,
            'source_root':str(SOURCE), 'source_commit':SOURCE_COMMIT,
            'source_tree':SOURCE_TREE, 'source_count':4136, 'source_bytes':412713085,
            'source_map_count':901,
            'source_map_sha256':'28348495a949b9c94ffafcfb14a79b93f4bf7e1e4a8dbb435d0da376ee73c843',
            'system_map':'SYSTEM-INPUTS.json','system_count':4815,'system_bytes':181643507,
            'runtime':runtime,'python_version':sys.version,'boot_id':boot,
            'inputs':inputs,'qualification_namespace':list(policy.QUALIFICATION),
            'source_immutable':True, 'CPython_author_tooling':True,
            'native_execution_authorized':False, 'VM_execution_authorized':False,
            'interop_qualification':False,'matching_current_cold_compiler':False,
            'full_SQLite_or_AgentStore_qualification':False}
        require(len(wire(request)) <= 1 << 20, 'bounded original request')
        request_pin = put(ROOT/'REQUEST.json',request)
        policy.validate(request,request_pin,new_output=True)
        require(support.runtime(request) == runtime
            and support.input_records(request) == inputs
            and support.source_records(request) == source_before
            and support.system_records(request) == system_before,
            'complete fresh input/source/system/runtime after preparation')
        for role in ('bundle','source','map901'):
            read_staged(EXPECTED_PINS[role])
        require(read(EXPECTED_PINS['system']['path'],4 << 20) == (system_pin,system_raw),
                'original system-map still exact after complete materialization')
        actual = support.catalog(ROOT)
        require({row['relative_path'] for row in actual['files']} == set(names)|{'REQUEST.json'}
            and actual['file_count'] == 19
            and all(row['bytes'] <= 4 << 20 for row in actual['files']),
            'complete exact nineteen-file materialization')
        for row in actual['files']:
            relative = row['relative_path']
            pin = {key:value for key,value in row.items() if key != 'relative_path'}
            require(pin == (request_pin if relative == 'REQUEST.json' else inputs[relative]),
                    'all final materialized nine-field identities')
        project = [name for name in sys.modules if name == 'hepta' or name.startswith('hepta.')
                   or name == 'tools' or name.startswith('tools.')
                   or name == 'tests' or name.startswith('tests.')]
        require(project == [] and not os.path.lexists(OUTPUT),
                'metadata stage must not import projects or create actual qualification output')
        report.update(status='MATERIALIZED_GENERATION_ONLY_REQUEST',request=request_pin,
            input_count=len(inputs),source_tree=SOURCE_TREE,source_commit=SOURCE_COMMIT,
            materialized_file_count=actual['file_count'],materialized_bytes=actual['bytes'],
            project_imports=project,capacity_after=support.capacity(P),
            complete_fresh_source_system_before_after=True)
    except BaseException as exc:
        report['status'] = 'HOLD'
        report['exception'] = {
            'type':type(exc).__module__+'.'+type(exc).__qualname__,
            'message':str(exc)[:2048],'traceback':traceback.format_exc()}
    finally:
        report['elapsed_ns'] = time.monotonic_ns()-started
        try:
            report_pin = put(REPORT,report)
        except BaseException as secondary:
            report['status'] = 'HOLD'
            report['secondary_errors'].append({
                'type':type(secondary).__module__+'.'+type(secondary).__qualname__,
                'message':str(secondary)[:2048]})
            print(json.dumps(report,sort_keys=True),file=sys.stderr)
            return 1
        print(json.dumps({'status':report['status'],'report':report_pin,
                          'request':report.get('request'),'elapsed_ns':report['elapsed_ns']}))
    return 0 if report['status'] == 'MATERIALIZED_GENERATION_ONLY_REQUEST' else 1

if __name__ == '__main__':
    raise SystemExit(main())
