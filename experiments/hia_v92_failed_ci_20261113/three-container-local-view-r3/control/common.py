"""Fixed three-container reader. No project import or product execution."""
from pathlib import Path
from contextlib import contextmanager
import hashlib
import importlib.util
import math
import os
import stat
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value

io = module('v92_view_network_io', ROOT / 'control/local_io.py')
require = io.require
CHUNK = 1 << 20

@contextmanager
def held_parent(path):
    """Hold every ancestor from / and compare both edges at exit."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'fixed absolute path required')
    fds = [os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    edges = []
    try:
        for name in path.parts[1:-1]:
            parent = fds[-1]
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            fds.append(fd)
            a, b = os.fstat(fd), os.stat(name, dir_fd=parent, follow_symlinks=False)
            key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid)
            require(key(a) == key(b), 'opened parent edge differs')
            edges.append((parent, name, fd, key(a)))
        yield fds[-1], path.name
        for parent, name, fd, expected in edges:
            key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid)
            require(key(os.fstat(fd)) == key(os.stat(name, dir_fd=parent, follow_symlinks=False)) == expected,
                    'parent directory chain changed')
    finally:
        for fd in reversed(fds):
            os.close(fd)

def seal(path, maximum, *, body=False, deadline=None):
    with held_parent(path) as (parent, name):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and 0 <= before.st_size <= maximum, 'bounded single-link original required')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        parts, count, digest = [], 0, hashlib.sha256()
        try:
            require(io.ident(os.fstat(fd)) == io.ident(before), 'opened file identity differs')
            while True:
                if deadline is not None: io.check_deadline(deadline)
                raw = os.read(fd, min(CHUNK, maximum + 1 - count))
                if not raw: break
                count += len(raw); require(count <= maximum, 'whole file exceeds bound')
                digest.update(raw)
                if body: parts.append(raw)
            require(count == before.st_size and io.ident(before) == io.ident(os.fstat(fd))
                    == io.ident(os.stat(name, dir_fd=parent, follow_symlinks=False)), 'original changed during read')
        finally:
            os.close(fd)
    pin = {'path': str(path), 'bytes': count, 'sha256': digest.hexdigest(), 'identity': io.ident(before)}
    return (pin, b''.join(parts)) if body else pin

def document(path, maximum=16 << 20, deadline=None):
    pin, raw = seal(path, maximum, body=True, deadline=deadline)
    return io.json_value(raw), pin, raw

def create(path, value, *, raw=False, budget=None, category='metadata', deadline=None):
    if deadline is not None: io.check_deadline(deadline)
    content = value if raw else io.wire(value)
    if budget is not None: budget.reserve(len(content), category)
    with held_parent(path) as (parent, name):
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            before = os.fstat(fd)
            view = memoryview(content)
            while view:
                count = os.write(fd, view); require(count > 0, 'new file write made no progress'); view = view[count:]
                if budget is not None: budget.wrote(count, category)
            os.fsync(fd); os.lseek(fd, 0, os.SEEK_SET)
            actual = bytearray()
            while len(actual) <= len(content):
                if deadline is not None: io.check_deadline(deadline)
                block = os.read(fd, min(CHUNK, len(content) + 1 - len(actual)))
                if not block: break
                actual.extend(block)
            after = os.fstat(fd)
            require(bytes(actual) == content and after.st_uid == os.geteuid() and after.st_nlink == 1
                    and stat.S_IMODE(after.st_mode) == 0o600
                    and io.ident(after) == io.ident(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'new whole file descriptor readback differs')
            require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino), 'new inode changed')
            os.fsync(parent)
        finally:
            os.close(fd)
    if deadline is not None: io.check_deadline(deadline)
    return {'path': str(path), 'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest(),
            'identity': io.ident(after)}

def mkdir(path):
    with held_parent(path) as (parent, name):
        os.mkdir(name, 0o700, dir_fd=parent)
        s = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISDIR(s.st_mode) and stat.S_IMODE(s.st_mode) == 0o700 and s.st_uid == os.geteuid(),
                'new private directory differs')
        os.fsync(parent)

class VolumeBudget:
    """Whole future reservation minus actual bytes written, on each device."""
    def __init__(self, path, limits, written=None):
        self.path = Path(path); self.limits = dict(limits)
        self.written = {key: 0 for key in ('container', 'selected', 'metadata', 'parent')}
        if written is not None: self.written.update(written)
        self.reserved = dict(self.written)
    def capacity(self, upcoming=0):
        # The fixed future container total already includes this download.
        require(type(upcoming) is int and upcoming >= 0, 'nonnegative expected download remainder required')
        remaining = sum(self.limits[key] - self.written[key] for key in self.written)
        require(remaining >= 0, 'fixed persistent quota exceeded')
        s = os.statvfs(self.path)
        require(s.f_bavail * s.f_frsize >= self.limits['reserve'] + remaining
                and s.f_favail >= self.limits['inodes'], 'per-volume full future reservation unavailable')
        return {'device': self.path.stat().st_dev, 'free_bytes': s.f_bavail * s.f_frsize,
                'free_inodes': s.f_favail, 'remaining_reserved_bytes': remaining,
                'reserve_bytes': self.limits['reserve'], 'written': dict(self.written)}
    def reserve(self, count, category):
        require(type(count) is int and count >= 0 and category in self.written, 'fixed whole-file category required')
        self.capacity()
        require(self.reserved[category] + count <= self.limits[category], 'whole category reservation exceeds cap')
        self.reserved[category] += count
    def wrote(self, count, category):
        self.written[category] += count
        require(self.written[category] <= self.reserved[category], 'unreserved file bytes written')
        self.capacity()

class DownloadBudget:
    """Adapter for unchanged io.download: record physical container writes."""
    def __init__(self, volume, directory, size):
        self.volume, self.directory, self.size = volume, Path(directory), size
        self.seen = 0; volume.reserve(size, 'container')
    def capacity(self, upcoming=0):
        # io.download calls this before every read. Observe only our fixed leaf.
        path = self.directory / 'official-part.original.zip.partial'
        if path.exists():
            s = path.lstat(); require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_uid == os.geteuid(),
                                      'download partial identity is not owned')
            require(self.seen <= s.st_size <= self.size, 'download partial size changed backwards or overflowed')
            delta = s.st_size - self.seen; self.seen = s.st_size
            self.volume.written['container'] += delta
        return self.volume.capacity()
    def reserve(self, count, category): self.volume.reserve(count, 'metadata')
    def wrote(self, count, category): self.volume.wrote(count, 'metadata')
    def finish(self, path):
        s = Path(path).lstat(); require(s.st_size == self.size, 'sealed official container size differs')
        self.volume.written['container'] += self.size - self.seen; self.seen = self.size
        self.volume.capacity()

def inputs(policy, deadline=None):
    rows = {}
    for name, expected in policy['inputs'].items():
        actual = seal(ROOT / name, 64 << 20, deadline=deadline)
        require(actual['bytes'] == expected['bytes'] and actual['sha256'] == expected['sha256'],
                'fixed consumer source or prior original differs')
        rows[str(ROOT / name)] = actual
    return rows

def fixed_clock(value, policy_sha):
    require(set(value) == {'schema', 'policy_sha256', 'start', 'deadline', 'seconds'}
            and value['schema'] == 'hia.v92-three-part-single-clock.v1' and value['policy_sha256'] == policy_sha
            and value['seconds'] == 720 and type(value['start']) is float and type(value['deadline']) is float
            and math.isfinite(value['start']) and 0 < value['start'] <= time.monotonic()
            and value['deadline'] == value['start'] + 720, 'bound single operation clock differs')
    io.check_deadline(value['deadline'])
    return value['deadline']

def private_inputs(policy, refs_sha, proxy_sha):
    refs, refs_pin, _ = document(Path(policy['provider_references_path']), 65536)
    require(refs_pin['sha256'] == refs_sha and refs_pin['identity'][3] == os.geteuid()
            and stat.S_IMODE(refs_pin['identity'][2]) == 0o600
            and set(refs) == {'schema', 'receiver_run_id', 'parts'}
            and refs['schema'] == 'hia.v92.three-official-provider-references.v1'
            and refs['receiver_run_id'] == policy['receiver']['run_id']
            and type(refs['parts']) is list and len(refs['parts']) == 3
            and [r['ordinal'] for r in refs['parts']] == [0, 1, 2]
            and all(type(r['ordinal']) is int and type(r['artifact_id']) is int for r in refs['parts'])
            and [r['artifact_id'] for r in refs['parts']] == [p['artifact']['id'] for p in policy['parts']],
            'exact private three-reference set differs')
    for item in refs['parts']:
        require(set(item) == {'ordinal', 'artifact_id', 'url'}, 'private reference shape differs')
        io.provider_host(item['url'])
    proxy, proxy_pin = io.read_private_proxy(Path(policy['proxy_configuration_path']),
                                            policy['operation_root'], proxy_sha)
    return refs['parts'], refs_pin, proxy, proxy_pin

def policy_read():
    policy, pin, raw = document(ROOT / 'POLICY.json')
    require(policy['schema'] == 'hia.v92.three-stored-container-view-policy.v1'
            and policy['limits']['owner_seconds'] == 900 and policy['limits']['cleanup_seconds'] == 3
            and policy['limits']['complete_seconds'] == 720 and len(policy['parts']) == 3
            and policy['product_execution_permitted'] is False, 'fixed read-only operation limits differ')
    return policy, pin, raw
