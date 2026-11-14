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

EXPECTED = json.loads(r'''[{"name":"pager-generation-r1/OWNER-RETURN.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r1-actual/OWNER-RETURN.json","bytes":2008,"sha256":"656562639e4788acbe390c813745ec5f83437d36a1e89cf9030af51fef1ed148","git_blob":"cd12a44351370bb6de8c79129997b9f9747ebc56","identity":[66306,79742627,33152,1000,1000,1,2008,"1794684262923324391","1794684262923324391"]}},{"name":"pager-generation-r1/PARENT-INPUTS-BEFORE.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r1-actual/PARENT-INPUTS-BEFORE.json","bytes":8847,"sha256":"e847d052dfe83665ba6335af9c1fa3a0826012e721b821d722241bde18304ac2","git_blob":"4772666817bf8e02a473aad6dc4ff5728b1733ba","identity":[66306,79742613,33152,1000,1000,1,8847,"1794684261782329350","1794684261782329350"]}},{"name":"pager-generation-r1/PARENT-SOURCE-BEFORE.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r1-actual/PARENT-SOURCE-BEFORE.json","bytes":2303247,"sha256":"22bc43ae5cbd64ee8d7870f2fe49344e8a9cb35aa6bec31244aebe8a759f348d","git_blob":"33a073b7adce5dbadc1e3f9126e72d2d0b0759d9","identity":[66306,79742614,33152,1000,1000,1,2303247,"1794684261787818807","1794684261787818807"]}},{"name":"pager-generation-r1/PARENT-SYSTEM-BEFORE.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r1-actual/PARENT-SYSTEM-BEFORE.json","bytes":2076795,"sha256":"845ccb6c1ecf2f9b65369bd61131a7745a20201e28e69ef1f22a6fcb21e146ee","git_blob":"93b689630b62b06bc6259d348bf0d75673ace7b7","identity":[66306,79742615,33152,1000,1000,1,2076795,"1794684261795612853","1794684261795612853"]}},{"name":"pager-generation-r1/REQUEST.original.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r1-actual/REQUEST.original.json","bytes":13286,"sha256":"dc5663f4f20d524289f99244bbc0a53f8f1698356b9dde549d135cd985cfe650","git_blob":"220ae8d24e5a5b9912ddcc38d61be97eddeaf63e","identity":[66306,79742612,33152,1000,1000,1,13286,"1794684261781289117","1794684261781289117"]}},{"name":"pager-generation-r1/WORKER-INPUTS-BEFORE.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r1-actual/WORKER-INPUTS-BEFORE.json","bytes":8847,"sha256":"e847d052dfe83665ba6335af9c1fa3a0826012e721b821d722241bde18304ac2","git_blob":"4772666817bf8e02a473aad6dc4ff5728b1733ba","identity":[66306,79742621,33152,1000,1000,1,8847,"1794684262722344480","1794684262722344480"]}},{"name":"pager-generation-r1/WORKER-SOURCE-BEFORE.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r1-actual/WORKER-SOURCE-BEFORE.json","bytes":2303247,"sha256":"22bc43ae5cbd64ee8d7870f2fe49344e8a9cb35aa6bec31244aebe8a759f348d","git_blob":"33a073b7adce5dbadc1e3f9126e72d2d0b0759d9","identity":[66306,79742622,33152,1000,1000,1,2303247,"1794684262741208686","1794684262741208686"]}},{"name":"pager-generation-r1/WORKER-SYSTEM-BEFORE.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r1-actual/WORKER-SYSTEM-BEFORE.json","bytes":2076795,"sha256":"845ccb6c1ecf2f9b65369bd61131a7745a20201e28e69ef1f22a6fcb21e146ee","git_blob":"93b689630b62b06bc6259d348bf0d75673ace7b7","identity":[66306,79742623,33152,1000,1000,1,2076795,"1794684262750077324","1794684262750077324"]}},{"name":"pager-generation-r1/WORKER.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r1-actual/WORKER.json","bytes":5954,"sha256":"6e47504296fcf7551611f0dded7c81611184f3cdfbb0dd2b0db8700d0e819db7","git_blob":"cdd42cbd7297bde40af9a44e9504bc3a83cd0f2f","identity":[66306,79742625,33152,1000,1000,1,5954,"1794684262867933139","1794684262867933139"]}},{"name":"pager-generation-r1/lifecycle.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r1-actual/lifecycle.json","bytes":1488,"sha256":"45df8b3230e510c7654599b5d7b46cd3ebc08463f30c4fb8b63dded4eafcc648","git_blob":"5d857920da411b2c3dc4f3656c6465ec6decd2e8","identity":[66306,79742626,33152,1000,1000,1,1488,"1794684262909454649","1794684262909454649"]}},{"name":"pager-generation-r1/lifecycle.json.request.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r1-actual/lifecycle.json.request.json","bytes":1146,"sha256":"5c16013d9554e92533443095664cb4735bae0763d0d90e2eae9abb1a0b06f07c","git_blob":"7854383e1f42781e60b17ffa630ebafc2b055573","identity":[66306,79742618,33152,1000,1000,1,1146,"1794684261805764656","1794684261805764656"]}},{"name":"pager-generation-r1/lifecycle.json.stderr.log","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r1-actual/lifecycle.json.stderr.log","bytes":0,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","git_blob":"e69de29bb2d1d6434b8b29ae775ad8c2e48c5391","identity":[66306,79742620,33152,1000,1000,1,0,"1794684261805785510","1794684261805785510"]}},{"name":"pager-generation-r1/lifecycle.json.stdout.log","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r1-actual/lifecycle.json.stdout.log","bytes":0,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","git_blob":"e69de29bb2d1d6434b8b29ae775ad8c2e48c5391","identity":[66306,79742619,33152,1000,1000,1,0,"1794684261805785510","1794684261805785510"]}},{"name":"pager-generation-r1/stderr.log","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r1-actual/stderr.log","bytes":0,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","git_blob":"e69de29bb2d1d6434b8b29ae775ad8c2e48c5391","identity":[66306,79742617,33152,1000,1000,1,0,"1794684261803785582","1794684261803785582"]}},{"name":"pager-generation-r1/stdout.log","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r1-actual/stdout.log","bytes":104,"sha256":"1db9c1c97acc3454b0ac6172f94a832e1761f6545e2c7841f5e073ef32ed2915","git_blob":"ecad9055bb1366cf65937fbef7ed7a2f9bc3d0e5","identity":[66306,79742616,33152,1000,1000,1,104,"1794684262875747166","1794684262875747166"]}},{"name":"pager-generation-r1/FINAL.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r1-actual/FINAL.json","bytes":2703,"sha256":"0c02d257ff39029600f270ac4371367089f37fc06967cc8d0d0a13146c5579df","git_blob":"18f72a5971910587e7576dbe9a4581f167735801","identity":[66306,79742629,33152,1000,1000,1,2703,"1794684262935745014","1794684262935745014"]}},{"name":"pager-generation-r1/CLOSED-ORIGINAL-CATALOG.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/pager-retained-generation-r1-actual/CLOSED-ORIGINAL-CATALOG.json","bytes":7988,"sha256":"5f01babb6b3b5b3734899036254a7692e76eb5f2b74e24eed8a10ba344f5ddce","git_blob":"1b2de5b5e12400d8f9da19c1cc850410c3c77df0","identity":[66306,79742628,33152,1000,1000,1,7988,"1794684262934451100","1794684262934451100"]}},{"name":"prior-core-put-mask/MATERIALIZATION.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/core-put-mask-elision-r1/MATERIALIZATION.json","bytes":5822224,"sha256":"bb1c4faa77f949119e0d1d9f0b525e6ad7adaecdb7640c717b8a0c23c54b8247","identity":[66306,79611688,33152,1000,1000,1,5822224,"1794666522682832349","1794666522682832349"]}},{"name":"prior-core-put-mask/generation1-source-before.json","pin":{"path":"/home/qq/hia-rewrite-20261113-e26e-r1/core-put-mask-elision-r1/generation1-actual-r1/source-before.json","bytes":2331662,"sha256":"54e0b9713a8361a2a13847b55f6d50653ef6c70aabdc555875228ce9ad6c4742","identity":[66306,80397636,33152,1000,1000,1,2331662,"1794667367380170652","1794667367380170652"]}}]''')
OUTPUT = Path("/home/qq/hia-rewrite-20261113-e26e-r1/pager-generation-r1-originals-transport-r1.json.gz")
REPORT = Path("/home/qq/hia-rewrite-20261113-e26e-r1/pager-generation-r1-originals-transport-r1-REPORT.json")

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
    require(read(Path(__file__),1 << 20) == (script_pin,script_raw), 'passive script changed')
    result = {'schema':'hia.closed-originals.transport-report.v1',
        'status':'PASSIVE_ORIGINAL_BYTES_RETAINED_ONLY', 'script':script_pin,
        'source_bytes':source_bytes, 'file_count':len(records), 'files':final_inputs,
        'uncompressed_bytes':len(body), 'uncompressed_sha256':hashlib.sha256(body).hexdigest(),
        'uncompressed_git_blob':hashlib.sha1(b'blob '+str(len(body)).encode()+b'\\0'+body).hexdigest(),
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
