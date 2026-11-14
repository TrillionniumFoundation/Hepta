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

# Passive archival only: no product imports, authors, compiler, VM or child process.
import gzip
import resource
import sys
import time

EXPECTED = json.loads(r'''[{"name":"OWNER-RETURN.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/OWNER-RETURN.json","bytes":2011,"sha256":"c4778480da6d35deb1da2b6c7ce2d980d3ede697dfdfbf6f2c3b2b5f72bdc42e","git_blob":"6a928e58542ae0278012ce8140565e8be14c2700","identity":[66306,79742681,33152,1000,1000,1,2011,"1794685987050405448","1794685987050405448"]}},{"name":"PARENT-INPUTS-BEFORE.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/PARENT-INPUTS-BEFORE.json","bytes":8847,"sha256":"939da309f59743a6268c6d8fc3cf3fc387d5125a3f3b99c7c924a00677209359","git_blob":"a5c0dcc0ad90a33ff0d179929951aa094f58689c","identity":[66306,79742657,33152,1000,1000,1,8847,"1794685982220357965","1794685982220357965"]}},{"name":"PARENT-SOURCE-BEFORE.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/PARENT-SOURCE-BEFORE.json","bytes":2303247,"sha256":"22bc43ae5cbd64ee8d7870f2fe49344e8a9cb35aa6bec31244aebe8a759f348d","git_blob":"33a073b7adce5dbadc1e3f9126e72d2d0b0759d9","identity":[66306,79742658,33152,1000,1000,1,2303247,"1794685982226285532","1794685982226285532"]}},{"name":"PARENT-SYSTEM-BEFORE.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/PARENT-SYSTEM-BEFORE.json","bytes":2076795,"sha256":"845ccb6c1ecf2f9b65369bd61131a7745a20201e28e69ef1f22a6fcb21e146ee","git_blob":"93b689630b62b06bc6259d348bf0d75673ace7b7","identity":[66306,79742659,33152,1000,1000,1,2076795,"1794685982265174745","1794685982265174745"]}},{"name":"REQUEST.original.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/REQUEST.original.json","bytes":13286,"sha256":"a973717e1015401502c0cadf5f17ba18eb388dec4515e30bd8fc78bad08dc6be","git_blob":"ce154db398ee2ec5f30dc1a66ff6c9a2d14c724c","identity":[66306,79742656,33152,1000,1000,1,13286,"1794685982219473525","1794685982219473525"]}},{"name":"WORKER-INPUTS-AFTER.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/WORKER-INPUTS-AFTER.json","bytes":8847,"sha256":"939da309f59743a6268c6d8fc3cf3fc387d5125a3f3b99c7c924a00677209359","git_blob":"a5c0dcc0ad90a33ff0d179929951aa094f58689c","identity":[66306,79742676,33152,1000,1000,1,8847,"1794685986905435248","1794685986905435248"]}},{"name":"WORKER-INPUTS-BEFORE.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/WORKER-INPUTS-BEFORE.json","bytes":8847,"sha256":"939da309f59743a6268c6d8fc3cf3fc387d5125a3f3b99c7c924a00677209359","git_blob":"a5c0dcc0ad90a33ff0d179929951aa094f58689c","identity":[66306,79742665,33152,1000,1000,1,8847,"1794685984112708448","1794685984112708448"]}},{"name":"WORKER-SOURCE-AFTER.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/WORKER-SOURCE-AFTER.json","bytes":2303247,"sha256":"22bc43ae5cbd64ee8d7870f2fe49344e8a9cb35aa6bec31244aebe8a759f348d","git_blob":"33a073b7adce5dbadc1e3f9126e72d2d0b0759d9","identity":[66306,79742677,33152,1000,1000,1,2303247,"1794685986913158384","1794685986913158384"]}},{"name":"WORKER-SOURCE-BEFORE.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/WORKER-SOURCE-BEFORE.json","bytes":2303247,"sha256":"22bc43ae5cbd64ee8d7870f2fe49344e8a9cb35aa6bec31244aebe8a759f348d","git_blob":"33a073b7adce5dbadc1e3f9126e72d2d0b0759d9","identity":[66306,79742666,33152,1000,1000,1,2303247,"1794685984118068065","1794685984118068065"]}},{"name":"WORKER-SYSTEM-AFTER.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/WORKER-SYSTEM-AFTER.json","bytes":2076795,"sha256":"845ccb6c1ecf2f9b65369bd61131a7745a20201e28e69ef1f22a6fcb21e146ee","git_blob":"93b689630b62b06bc6259d348bf0d75673ace7b7","identity":[66306,79742678,33152,1000,1000,1,2076795,"1794685986936462348","1794685986936462348"]}},{"name":"WORKER-SYSTEM-BEFORE.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/WORKER-SYSTEM-BEFORE.json","bytes":2076795,"sha256":"845ccb6c1ecf2f9b65369bd61131a7745a20201e28e69ef1f22a6fcb21e146ee","git_blob":"93b689630b62b06bc6259d348bf0d75673ace7b7","identity":[66306,79742667,33152,1000,1000,1,2076795,"1794685984142955096","1794685984142955096"]}},{"name":"WORKER.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/WORKER.json","bytes":32448,"sha256":"848761c854001cf22b313878cacb6313cda302587832893f0106946d2560c54e","git_blob":"c7260ab3a921d7c9aa4c6011978cf001fe031f72","identity":[66306,79742679,33152,1000,1000,1,32448,"1794685986945342345","1794685986945342345"]}},{"name":"lifecycle.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/lifecycle.json","bytes":1491,"sha256":"85fb7c6411b543f339dfd31ccb0f9b0e395d7b148fc8526b1295977b75d3cab9","git_blob":"410ff117a26c00fd227e9afce0a01ceb46381af0","identity":[66306,79742680,33152,1000,1000,1,1491,"1794685986993809510","1794685986993809510"]}},{"name":"lifecycle.json.request.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/lifecycle.json.request.json","bytes":1146,"sha256":"44f1e8a685163cc0eca6d8680389c1f8c381b9f9eb8aefe4ae58ee227d7d29db","git_blob":"f6c295599c0005ead92aef3169ce3f157c2db8eb","identity":[66306,79742662,33152,1000,1000,1,1146,"1794685982277458695","1794685982277458695"]}},{"name":"lifecycle.json.stderr.log","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/lifecycle.json.stderr.log","bytes":0,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","git_blob":"e69de29bb2d1d6434b8b29ae775ad8c2e48c5391","identity":[66306,79742664,33152,1000,1000,1,0,"1794685982278400663","1794685982278400663"]}},{"name":"lifecycle.json.stdout.log","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/lifecycle.json.stdout.log","bytes":0,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","git_blob":"e69de29bb2d1d6434b8b29ae775ad8c2e48c5391","identity":[66306,79742663,33152,1000,1000,1,0,"1794685982277626729","1794685982277626729"]}},{"name":"stderr.log","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/stderr.log","bytes":0,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","git_blob":"e69de29bb2d1d6434b8b29ae775ad8c2e48c5391","identity":[66306,79742661,33152,1000,1000,1,0,"1794685982276391131","1794685982276391131"]}},{"name":"stdout.log","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/stdout.log","bytes":128,"sha256":"9ef971e0d410c2fc72f957595943faaad0c4bb6a047857f04e609a85254cdbb7","git_blob":"152ddfcf8548da7be3f868d534f317ecebf5f574","identity":[66306,79742660,33152,1000,1000,1,128,"1794685986948813346","1794685986948813346"]}},{"name":"generation/GENERATION.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/generation/GENERATION.json","bytes":7566,"sha256":"31ba66ea40c8434c086f86ab6d7a00ba4d51fbbe9547216d6aaf3aec61ecaed7","git_blob":"53c05d21712f77534900285d072ff41910588930","identity":[66306,79742675,33152,1000,1000,1,7566,"1794685985342498031","1794685985342498031"]}},{"name":"generation/linker.GENERATION.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/generation/linker.GENERATION.json","bytes":2069,"sha256":"230d2381c867af3326e34689f256dadc15f9158edaac81dc6e740e223c030e3f","git_blob":"2b89bd1213872c3d86029da7b64c1758aaca3965","identity":[66306,79742674,33152,1000,1000,1,2069,"1794685985330172102","1794685985330172102"]}},{"name":"generation/linker.core.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/generation/linker.core.json","bytes":786740,"sha256":"3668758fdb8ab8aaaced1b7f8dc79d9923e7c7b070990a008338bb90799f569b","git_blob":"6c4577e30eacdba16673358f5cdc53d14169e75d","identity":[66306,79742672,33152,1000,1000,1,786740,"1794685985168088266","1794685985168088266"]}},{"name":"generation/linker.hiaasm","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/generation/linker.hiaasm","bytes":95566,"sha256":"c16b62cd3b712a3c4606f06ff4c0df924d903b6016983961c9c7a2f30c095f7b","git_blob":"391164b8c50a86c1fbcd76a8d9a38a88f4074654","identity":[66306,79742673,33152,1000,1000,1,95566,"1794685985171126442","1794685985171126442"]}},{"name":"generation/pager.GENERATION.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/generation/pager.GENERATION.json","bytes":2084,"sha256":"3c6e0ee736937f6558778269e4e9ec567a5f3d87281dbc41aadf52dcf053d9e9","git_blob":"f5394a070a9dfecdd11a3506ecd4aa4946968d19","identity":[66306,79742671,33152,1000,1000,1,2084,"1794685984945540824","1794685984945540824"]}},{"name":"generation/pager.core.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/generation/pager.core.json","bytes":1516495,"sha256":"976a9a5f5cb4117949a2ea351d79b2cc75ce7222ee19961689ee42f1f60a7ede","git_blob":"3b1937973e0dbfce1f5b8094597ad689dfb8ea6e","identity":[66306,79742669,33152,1000,1000,1,1516495,"1794685984594432112","1794685984594432112"]}},{"name":"generation/pager.hiaasm","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/generation/pager.hiaasm","bytes":181253,"sha256":"32ef4220129b4a59c94b174ae2afebf407a1f1814c36e5ad810cf636a8ecb517","git_blob":"ba7591fabe78a83901ed1e02c6146ed8949ac253","identity":[66306,79742670,33152,1000,1000,1,181253,"1794685984607346001","1794685984607346001"]}},{"name":"PARENT-INPUTS-AFTER.json","pin":{"bytes":8847,"git_blob":"a5c0dcc0ad90a33ff0d179929951aa094f58689c","identity":[66306,79742683,33152,1000,1000,1,8847,"1794685988037972228","1794685988037972228"],"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/PARENT-INPUTS-AFTER.json","sha256":"939da309f59743a6268c6d8fc3cf3fc387d5125a3f3b99c7c924a00677209359"}},{"name":"PARENT-SOURCE-AFTER.json","pin":{"bytes":2303247,"git_blob":"33a073b7adce5dbadc1e3f9126e72d2d0b0759d9","identity":[66306,79742684,33152,1000,1000,1,2303247,"1794685988055023556","1794685988055023556"],"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/PARENT-SOURCE-AFTER.json","sha256":"22bc43ae5cbd64ee8d7870f2fe49344e8a9cb35aa6bec31244aebe8a759f348d"}},{"name":"PARENT-SYSTEM-AFTER.json","pin":{"bytes":2076795,"git_blob":"93b689630b62b06bc6259d348bf0d75673ace7b7","identity":[66306,79742685,33152,1000,1000,1,2076795,"1794685988063948381","1794685988063948381"],"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/PARENT-SYSTEM-AFTER.json","sha256":"845ccb6c1ecf2f9b65369bd61131a7745a20201e28e69ef1f22a6fcb21e146ee"}},{"name":"CLOSED-ORIGINAL-CATALOG.json","pin":{"bytes":13395,"git_blob":"5400d4e80667c5aa20609449fa62175ec89d857e","identity":[66306,79742682,33152,1000,1000,1,13395,"1794685987066809239","1794685987066809239"],"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/CLOSED-ORIGINAL-CATALOG.json","sha256":"816bd3a3cbb044e2ca9c93cec4fbe0965c3dd2d74523f8836722ab8566383b36"}},{"name":"FINAL.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual/FINAL.json","bytes":9814,"sha256":"485d9ea2b7471339abee7b99b631a0392428910bada44e304a1df5ce49d43877","git_blob":"346864718d7a3c7f155af63e0c75ac1e77f99a5f","identity":[66306,79742686,33152,1000,1000,1,9814,"1794685988088571631","1794685988088571631"]}}]''')
OUTPUT = Path("/home/qq/hia-rewrite-20261113-e26e-r1/pager-generation-r2-originals-transport-r1.json.gz")
REPORT = Path("/home/qq/hia-rewrite-20261113-e26e-r1/pager-generation-r2-originals-transport-r1-REPORT.json")

ORIGINAL_ROOT = Path("/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r2-actual")

def original_namespace():
    files, directories, pending = [], [], [ORIGINAL_ROOT]
    while pending:
        current = pending.pop()
        with held_parent(current) as (parent, name):
            descriptor = os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            try:
                before = os.fstat(descriptor)
                require(stat.S_ISDIR(before.st_mode),'original namespace directory')
                directories.append({'path':str(current),'identity':identity(before)})
                with os.scandir(descriptor) as entries:
                    children = list(entries)
                for child in children:
                    observed = child.stat(follow_symlinks=False)
                    path = current/child.name
                    if stat.S_ISDIR(observed.st_mode):
                        pending.append(path)
                    else:
                        require(stat.S_ISREG(observed.st_mode) and observed.st_nlink == 1,
                                'original namespace single-link regular file')
                        files.append(str(path.relative_to(ORIGINAL_ROOT)))
                require(identity(os.fstat(descriptor)) == identity(before)
                    == identity(os.stat(name,dir_fd=parent,follow_symlinks=False)),
                    'original namespace changed during enumeration')
            finally:
                os.close(descriptor)
    require(len(files) <= 192 and len(directories) <= 192,
            'unchanged bounded original namespace')
    return {'files':sorted(files),'directories':sorted(directories,key=lambda row:row['path'])}

def main():
    resource.setrlimit(resource.RLIMIT_CPU, (180,180))
    resource.setrlimit(resource.RLIMIT_AS, (256 << 20,256 << 20))
    resource.setrlimit(resource.RLIMIT_STACK, (8 << 20,8 << 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (4 << 20,4 << 20))
    resource.setrlimit(resource.RLIMIT_CORE, (0,0))
    started = time.monotonic_ns()
    require(sys.executable == '/usr/bin/python3.14' and len(sys.argv) == 2,
            'fixed passive archive invocation')
    script_pin, script_raw = read(Path(__file__), 1 << 20)
    require(script_pin['sha256'] == sys.argv[1], 'frozen passive script')
    require(not os.path.lexists(OUTPUT) and not os.path.lexists(REPORT),
            'new-only passive archive namespace')
    namespace_before = original_namespace()
    require(namespace_before['files'] == sorted(entry['name'] for entry in EXPECTED),
            'exact complete original final namespace')
    records = []
    source_bytes = 0
    for entry in EXPECTED:
        expected = entry['pin']
        expected['identity'] = [int(value) for value in expected['identity']]
        before, raw = read(expected['path'], 8 << 20)
        require(all(before[key] == value for key,value in expected.items()),
                'exact original archive input pin: '+entry['name'])
        after, again = read(expected['path'],8 << 20)
        require(after == before and again == raw, 'original changed between passive reads')
        source_bytes += len(raw)
        records.append({'name':entry['name'], 'pin_before':before,
                        'pin_after':after, 'text':raw.decode('utf-8',errors='strict')})
    body = wire({'schema':'hia.closed-originals.lossless-transport.v1',
        'files':records, 'file_count':len(records), 'source_bytes':source_bytes,
        'product_execution':False, 'qualification_inherited':False})
    require(len(body) <= 32 << 20, 'bounded original transport expansion')
    packed = gzip.compress(body,compresslevel=9,mtime=0)
    require(len(packed) <= 4 << 20, 'original 4MiB output physical cap')
    output_pin = create(OUTPUT,packed,raw=True)
    output_pin_after, packed_after = read(OUTPUT,4 << 20)
    require(output_pin_after == output_pin and packed_after == packed
        and gzip.decompress(packed_after) == body, 'complete passive transport roundtrip')
    final_inputs = []
    for entry in EXPECTED:
        actual, raw = read(entry['pin']['path'],8 << 20)
        require(all(actual[key] == value for key,value in entry['pin'].items()),
                'original changed after compressed transport')
        final_inputs.append({'name':entry['name'],'pin':actual})
    namespace_after = original_namespace()
    require(namespace_after == namespace_before, 'complete original namespace changed')
    require(read(Path(__file__),1 << 20) == (script_pin,script_raw), 'passive script changed')
    result = {'schema':'hia.closed-originals.transport-report.v1',
        'status':'PASSIVE_ORIGINAL_BYTES_RETAINED_ONLY', 'script':script_pin,
        'source_bytes':source_bytes, 'file_count':len(records), 'files':final_inputs,
        'namespace_before':namespace_before, 'namespace_after':namespace_after,
        'uncompressed_bytes':len(body), 'uncompressed_sha256':hashlib.sha256(body).hexdigest(),
        'uncompressed_git_blob':hashlib.sha1(b'blob '+str(len(body)).encode()+bytes([0])+body).hexdigest(),
        'gzip':output_pin, 'elapsed_ns':time.monotonic_ns()-started,
        'product_imports':[], 'author_document_calls':0, 'HIA_compiler_calls':0,
        'VM_calls':0, 'native_product_entries':0, 'subprocess_calls':0,
        'qualification_inherited':False, 'original_failures_unchanged':True}
    report_pin = create(REPORT,result)
    print(json.dumps({'status':result['status'],'files':len(records),
        'source_bytes':source_bytes,'gzip_bytes':output_pin['bytes'],
        'report':report_pin['path'],'elapsed_ns':result['elapsed_ns']},sort_keys=True))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
