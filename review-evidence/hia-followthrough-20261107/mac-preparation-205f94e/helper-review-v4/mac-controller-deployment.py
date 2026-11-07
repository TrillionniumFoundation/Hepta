#!/usr/bin/env python3
"""One explicit Mac controller deployment; all credentials stay local.

This task helper reuses the selected runtime's HTTP client and catalog verifier.
It does not implement a gateway, worker owner, or credential transport.
"""
import argparse
import base64
import ctypes
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import stat
import subprocess
import sys
import time

ROOT = Path('/Users/qianqi/work/hia-runtime-9f60-20261107-372e7da9')
PREPARED = ROOT / 'prepared-mac-205f94e'
LIVE_CONFIG = Path('/Users/qianqi/.config/hepta-runtime-mac/runtime.json')
TOKEN = Path('/Users/qianqi/.config/hepta-runtime-mac/token')
CURRENT = Path('/Users/qianqi/.local/lib/hepta-runtime/current')
OLD_TARGET = '/Users/qianqi/.local/lib/hepta-runtime/releases/e1eb14ae8eff-macos-arm64-d7a618286d6b'
OLD_CONFIG_SHA = 'a3556d614da0123a5b252ce1da10bb3f0917233b888a3c8b4f02bb5bbb0bf1eb'
NEW_CONFIG_SHA = '2636bde8d440cd677090c0eab4db784b26e25185cecf57c4ab8e766c27c85a36'
STAGE_CONFIG_SHA = '12d41576ae3b4da439438d07f60d349416f478dfa31d173b5189aa5dc8cc6409'
PLIST = Path('/Users/qianqi/Library/LaunchAgents/org.trillionnium.hepta.runtime-controller.plist')
PLIST_SHA = '8321d54b6959647af202c61115af7a4330293f13b3d0f9f206870c366d467cfe'
NEW_PLIST_SHA = '7425729f95d18044c1d6077ad8209756d340218297b2d7604ef46b7e75bd1f2a'
TRUSTED_TMPDIR = '/Users/qianqi/.local/state/hepta-runtime-mac/tmp-hia-205f94e'
LABEL = 'gui/501/org.trillionnium.hepta.runtime-controller'
CONTRACT_SHA = '5ba7036ef4d388191365da745c028c248babc52c3d00257399ff25e0380c11f9'
CATALOG_SHA = '954670433d118607f1ad55fb330a139e6d8fd998b740a9f62a41a212cc722b0e'
PINS = {
    'worker_sha256': 'cb5933bb1d08bd18b13a26e522b0d7c040db9597b49cf926874b44f9684aee6f',
    'backend_sha256': '1fd7feedfd68a0cc4f1aec1ba053d7066505817bfe2366a0ca8db1dfb7617873',
    'catalog_sha256': '8b880cc02efc93e10d920bf812bccbb33197aa00f6b92282536a000238ba5e9e',
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def trusted_bytes(path, expected=None, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as f:
        s = os.fstat(f.fileno())
        assert stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and s.st_nlink == 1
        assert not s.st_mode & 0o022
        if private:
            assert stat.S_IMODE(s.st_mode) == 0o600
        raw = f.read()
    if expected is not None:
        assert sha(raw) == expected, ('file identity mismatch', str(path))
    return raw


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_new(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        os.fchmod(f.fileno(), mode)
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()


def dump(path, value):
    write_new(path, json_bytes(value))


def launch_pid():
    p = subprocess.run(['/bin/launchctl', 'print', LABEL], capture_output=True, text=True, timeout=20)
    assert p.returncode == 0, ('launchctl print failed', p.returncode, p.stderr)
    match = re.search(r'^\s*pid = (\d+)\s*$', p.stdout, re.M)
    assert match, 'controller pid missing'
    return int(match.group(1))


class PublicationConflict(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise PublicationConflict(message)


def read_xattrs(fd):
    if sys.platform != 'darwin':
        return {name: os.getxattr(fd, name) for name in os.listxattr(fd)}
    library = ctypes.CDLL(None, use_errno=True)
    listing = library.flistxattr
    listing.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    listing.restype = ctypes.c_ssize_t
    getter = library.fgetxattr
    getter.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
    getter.restype = ctypes.c_ssize_t
    count = listing(fd, None, 0, 0)
    if count < 0:
        raise OSError(ctypes.get_errno(), 'flistxattr failed')
    require(count <= 1024 * 1024, 'extended attribute names exceed the deployment bound')
    if not count:
        return {}
    buffer = ctypes.create_string_buffer(count)
    used = listing(fd, buffer, count, 0)
    if used < 0:
        raise OSError(ctypes.get_errno(), 'flistxattr changed or failed')
    require(used <= count and buffer.raw[:used].endswith(b'\0'), 'malformed extended attribute names')
    values = {}
    total = 0
    for name in buffer.raw[:used].split(b'\0')[:-1]:
        require(name and os.fsdecode(name) not in values, 'duplicate/empty extended attribute name')
        size = getter(fd, name, None, 0, 0, 0)
        if size < 0:
            raise OSError(ctypes.get_errno(), 'fgetxattr size failed')
        total += size
        require(total <= 8 * 1024 * 1024, 'extended attributes exceed the deployment bound')
        value = ctypes.create_string_buffer(max(1, size))
        received = getter(fd, name, value, size, 0, 0)
        if received < 0:
            raise OSError(ctypes.get_errno(), 'fgetxattr changed or failed')
        require(received == size, 'extended attribute changed during reading')
        values[os.fsdecode(name)] = value.raw[:size]
    return values


def copy_xattrs(path, attrs):
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if sys.platform == 'darwin':
            setter = ctypes.CDLL(None, use_errno=True).fsetxattr
            setter.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
            setter.restype = ctypes.c_int
            for name, value in attrs.items():
                buffer = ctypes.create_string_buffer(value, max(1, len(value)))
                if setter(fd, os.fsencode(name), buffer, len(value), 0, 0):
                    raise OSError(ctypes.get_errno(), 'fsetxattr failed')
        else:
            for name, value in attrs.items():
                os.setxattr(fd, name, value)
        os.fsync(fd)
    finally:
        os.close(fd)


def entry(path, kind, private=False):
    """Read one named inode; snapshots intentionally exclude file contents."""
    path = Path(path)
    if kind == 'symlink':
        before = path.lstat()
        require(stat.S_ISLNK(before.st_mode), 'expected symlink: ' + str(path))
        value = os.readlink(path)
        after = path.lstat()
        attrs = {}
    else:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode), 'expected ordinary file: ' + str(path))
            require(before.st_size <= 8 * 1024 * 1024, 'deployment input is too large')
            raw = stream.read(8 * 1024 * 1024 + 1)
            value = sha(raw)
            attrs = read_xattrs(stream.fileno())
            after = os.fstat(stream.fileno())
        require(len(raw) == before.st_size, 'file changed while reading: ' + str(path))
        require(not before.st_mode & 0o022, 'group/other-writable deployment file')
        if private:
            require(stat.S_IMODE(before.st_mode) == 0o600, 'private deployment file requires mode 0600')
    stable = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink, s.st_size,
                        s.st_mtime_ns, s.st_ctime_ns)
    require(stable(before) == stable(after), 'entry changed while reading: ' + str(path))
    require(before.st_uid == os.getuid() and before.st_nlink == 1, 'deployment entry owner/link mismatch')
    return {'device': before.st_dev, 'inode': before.st_ino,
            'mode': stat.S_IMODE(before.st_mode), 'uid': before.st_uid,
            'kind': kind, 'value': value,
            'xattr_sha256': {n: sha(v) for n, v in attrs.items()}}, attrs


_SWAP_FLAG = None


def verify_swap_sdk():
    """Verify the installed SDK rather than assuming a Darwin flag value."""
    global _SWAP_FLAG
    require(sys.platform == 'darwin', 'production exchange requires macOS')
    sdk = subprocess.check_output(['/usr/bin/xcrun', '--show-sdk-path'], text=True, timeout=20).strip()
    header = Path(sdk) / 'usr/include/sys/stdio.h'
    raw = header.read_bytes()
    definition = re.search(rb'^\s*#\s*define\s+RENAME_SWAP\s+(0x[0-9A-Fa-f]+|[0-9]+)\b', raw, re.M)
    require(definition is not None, 'installed SDK does not define RENAME_SWAP')
    flag = int(definition[1], 0)
    require(flag == 0x00000002 and b'renameatx_np(int, const char *, int, const char *, unsigned int)' in raw,
            'installed SDK exchange contract differs from the reviewed contract')
    _SWAP_FLAG = flag
    xattr_header = Path(sdk) / 'usr/include/sys/xattr.h'
    xattr_raw = xattr_header.read_bytes()
    for function in ('flistxattr', 'fgetxattr', 'fsetxattr'):
        require(re.search(rb'\b' + function.encode() + rb'\s*\(', xattr_raw) is not None,
                'installed SDK is missing the descriptor extended-attribute API')
        require(hasattr(ctypes.CDLL(None), function), 'runtime lacks ' + function)
    return {'sdk': sdk, 'header': str(header), 'header_sha256': sha(raw),
            'rename_swap': flag, 'function': 'renameatx_np',
            'xattr_header': str(xattr_header), 'xattr_header_sha256': sha(xattr_raw),
            'xattr_api': 'Darwin flistxattr/fgetxattr/fsetxattr; descriptor-based, position/options zero'}


def atomic_exchange(left, right, published):
    """Keep the actual displaced directory entry; never use force replacement."""
    require(_SWAP_FLAG == 2, 'RENAME_SWAP SDK verification has not completed')
    left, right = Path(left), Path(right)
    require(left.parent == right.parent, 'exchange must remain in one pinned directory')
    directory = os.open(left.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(directory)
        require(info.st_uid == os.getuid() and not info.st_mode & 0o022, 'unsafe exchange parent')
        function = ctypes.CDLL(None, use_errno=True).renameatx_np
        function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        function.restype = ctypes.c_int
        if function(directory, os.fsencode(left.name), directory, os.fsencode(right.name), _SWAP_FLAG):
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))
        published()  # Even an error closing the directory cannot hide this swap.
    finally:
        os.close(directory)


class OwnedSwap:
    """Optimistic exchange with retained displacement and conditional rollback.

    The shared deployment lock excludes another copy of this helper. A writer
    outside that lock can still race, so a displaced-identity mismatch is a
    conflict, never a successful CAS. All displaced entries stay recoverable.
    """
    def __init__(self, path, replacement, expected, *, kind='file', private=False):
        self.path, self.kind, self.private = Path(path), kind, private
        self.before, attrs = entry(self.path, kind, private)
        require(self.before['value'] == expected, 'pre-publication value changed: ' + str(path))
        self.temp = self.path.with_name('.' + self.path.name + '.hia-swap-' + secrets.token_hex(12))
        if kind == 'symlink':
            os.symlink(replacement, self.temp)
        else:
            write_new(self.temp, replacement, self.before['mode'])
            copy_xattrs(self.temp, attrs)
        self.new, _ = entry(self.temp, kind, private)
        self.ever_applied = self.active = self.rollback_verified = False
        self.displaced = None

    def publish(self):
        require(entry(self.path, self.kind, self.private)[0] == self.before, 'live entry changed before exchange')
        require(entry(self.temp, self.kind, self.private)[0] == self.new, 'staged entry changed before exchange')
        def published():
            self.ever_applied = self.active = True
        atomic_exchange(self.temp, self.path, published)
        self.displaced, _ = entry(self.temp, self.kind, self.private)
        require(self.displaced == self.before, 'concurrent entry displaced; retained for conditional rollback')
        require(entry(self.path, self.kind, self.private)[0] == self.new, 'published entry changed after exchange')

    def rollback(self):
        if not self.active:
            return
        require(entry(self.path, self.kind, self.private)[0] == self.new,
                'rollback refused: live inode/value is not owned by this deployment')
        displaced, _ = entry(self.temp, self.kind, self.private)
        if self.displaced is not None:
            require(displaced == self.displaced, 'rollback refused: retained displacement changed')
        def published():
            self.active = False
        atomic_exchange(self.temp, self.path, published)
        require(entry(self.temp, self.kind, self.private)[0] == self.new,
                'rollback raced with a writer; displaced conflict is retained, no force overwrite attempted')
        require(entry(self.path, self.kind, self.private)[0] == displaced,
                'rollback publication changed after exchange')
        self.rollback_verified = True

    def receipt(self):
        return {'path': str(self.path), 'retained_displacement_path': str(self.temp),
                'before': self.before, 'replacement': self.new, 'displaced': self.displaced,
                'ever_applied': self.ever_applied, 'active': self.active,
                'rollback_verified': self.rollback_verified}


def publish_swap(mutations, path, replacement, expected, **kwargs):
    change = OwnedSwap(path, replacement, expected, **kwargs)
    mutations.append(change)  # Caller owns recovery even if publish raises.
    change.publish()


def deployment_lock():
    fd = os.open(PREPARED / 'deployment.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, 'unsafe deployment lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise


def reload_service(records):
    for phase, argv in [('bootout', ['/bin/launchctl', 'bootout', LABEL]),
                        ('bootstrap', ['/bin/launchctl', 'bootstrap', 'gui/501', str(PLIST)])]:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=40)
        records.append({'phase': phase, 'returncode': result.returncode,
                        'stdout': result.stdout, 'stderr': result.stderr})
        if result.returncode:
            # A previous bootout may have completed before an interrupted client.
            if phase == 'bootout':
                observed = subprocess.run(['/bin/launchctl', 'print', LABEL], capture_output=True, text=True, timeout=20)
                if observed.returncode != 0 and 'Could not find service' in observed.stderr:
                    records[-1]['already_absent_observed'] = True
                    continue
            raise RuntimeError('controller ' + phase + ' failed')


def mapped_executable(pid, path):
    observed = subprocess.run(['/usr/sbin/lsof', '-a', '-p', str(pid), '-d', 'txt', '-Fn'],
                              capture_output=True, text=True, timeout=20)
    require(observed.returncode == 0 and ('n' + str(path)) in observed.stdout.splitlines(),
            'mapped runtime identity not observed')
    return {'pid': pid, 'mapped_executable': str(path), 'lsof_output': observed.stdout}


def controller_resources():
    observed = subprocess.run(['/bin/launchctl', 'print', LABEL], capture_output=True, text=True, timeout=20)
    require(observed.returncode == 0, 'controller resource observation failed')
    limits = {}
    block = re.search(r'(?mi)^\s*resource limits = \{([^{}]*)\}', observed.stdout)
    require(block is not None, 'controller resource limits missing')
    for kind in ('soft', 'hard'):
        counts = re.findall(r'(?mi)^\s*maxfiles \(' + kind + r'\)\s*=>\s*(\d+)\s*$', block[1])
        require(len(counts) == 1 and int(counts[0]) == 8192, 'controller ' + kind + ' file limit is not 8192')
        limits[kind] = int(counts[0])
    environment = re.search(r'(?m)^\s*environment = \{([^{}]*)\}', observed.stdout)
    require(environment is not None and re.search(r'(?m)^\s*TMPDIR\s*=>\s*' + re.escape(TRUSTED_TMPDIR) + r'\s*$', environment[1]) is not None,
            'controller trusted TMPDIR was not observed')
    return {'number_of_files': limits, 'TMPDIR': TRUSTED_TMPDIR,
            'launchctl_print_sha256': sha(observed.stdout.encode()),
            'scope': 'launchctl controller service definition; not inferred from an SSH child'}


def sentinel_source(marker, ready, release):
    return ("from pathlib import Path\nimport time\n"
            + 'p=Path(' + repr(str(marker)) + ')\n'
            + 'ready=Path(' + repr(str(ready)) + ')\n'
            + 'release=Path(' + repr(str(release)) + ')\n'
            + "with p.open('x') as f: f.write('1')\n"
            + "print('RESTART_BEGIN',flush=True)\n"
            + "with ready.open('x') as f: f.write('ready')\n"
            + "deadline=time.monotonic()+150\n"
            + "while not release.exists():\n"
            + "    if time.monotonic()>deadline: raise TimeoutError('sentinel release not observed')\n"
            + "    time.sleep(.1)\n"
            + "print('ONCE_CONTENT='+p.read_text(),flush=True)\nprint('RESTART_END',flush=True)\n")


def verify_sentinel_completion(terminal, logs, sentinel_id):
    """Require the original job's durable terminal and complete, consistent logs.

    A legacy status may say succeeded without durability or publication fields.
    Such a receipt cannot qualify this controller restart.
    """
    require(isinstance(terminal, dict) and isinstance(logs, dict),
            'sentinel terminal and logs must be original objects')
    require(isinstance(sentinel_id, str) and sentinel_id
            and terminal.get('job_id') == sentinel_id and logs.get('job_id') == sentinel_id,
            'sentinel terminal/read identity does not match the original job')
    require(terminal.get('state') == 'succeeded', 'sentinel did not succeed')
    for name in ('output_complete', 'output_durable', 'terminal_publication_confirmed'):
        require(terminal.get(name) is True, 'sentinel requires confirmed ' + name)
    streams = {}
    for name in ('stdout', 'stderr'):
        part = logs.get(name)
        require(isinstance(part, dict), 'sentinel ' + name + ' receipt is missing')
        require(part.get('eof') is True, 'sentinel ' + name + ' is not complete')
        for field in ('offset', 'next_offset', 'size'):
            require(type(part.get(field)) is int and part[field] >= 0,
                    'sentinel ' + name + ' has an invalid ' + field)
        require(part['offset'] == 0 and part['next_offset'] == part['size'],
                'sentinel ' + name + ' does not cover the complete stream from offset zero')
        encoded = part.get('bytes_hex')
        require(isinstance(encoded, str) and re.fullmatch(r'(?:[0-9a-fA-F]{2})*', encoded) is not None,
                'sentinel ' + name + ' has invalid byte encoding')
        raw = bytes.fromhex(encoded)
        require(len(raw) == part['size'] and part.get('text') == raw.decode('utf-8', errors='replace'),
                'sentinel ' + name + ' bytes, text and reported length disagree')
        if name == 'stdout':
            require(raw == b'RESTART_BEGIN\nONCE_CONTENT=1\nRESTART_END\n',
                    'sentinel stdout is not the exact one-execution transcript')
        streams[name] = {'bytes': len(raw), 'sha256': sha(raw), 'eof': True,
                         'offset': 0, 'next_offset': part['next_offset']}
    return {'job_id': sentinel_id, 'state': 'succeeded', 'output_complete': True,
            'output_durable': True, 'terminal_publication_confirmed': True,
            'stdout_exact_once_transcript': True, 'streams': streams}


def check_config_addition(old, new):
    a, b = json.loads(old), json.loads(new)
    require(type(a) is dict and type(b) is dict and 'hia_worker' not in a and 'hia_worker' in b,
            'expected one new HIA worker configuration')
    require(type(b.pop('hia_worker')) is dict, 'HIA worker configuration must be an object')
    require(a == b, 'non-HIA runtime configuration changed')


def check_plist_change(old, new):
    expected = plistlib.loads(old)
    expected.setdefault('SoftResourceLimits', {})['NumberOfFiles'] = 8192
    expected.setdefault('HardResourceLimits', {})['NumberOfFiles'] = 8192
    expected.setdefault('EnvironmentVariables', {})['TMPDIR'] = TRUSTED_TMPDIR
    require(plistlib.loads(new) == expected, 'unrelated controller plist configuration changed')


def pending_hia_identity(response):
    assert response['contract_version'] == 'hepta.hia.agent-native.v1'
    assert response['status'] in ('accepted', 'unknown')
    operation = response['operation']
    assert operation['host'] == 'x230'
    assert re.fullmatch('[a-zA-Z0-9_-]+', operation['job_id'])
    assert re.fullmatch('[0-9a-f]{64}', operation['request_sha256'])
    assert operation['report_artifact'] is None
    assert response['request_id'] == 'hia_' + operation['request_sha256']
    return operation['host'], operation['job_id'], operation['request_sha256']


def original_hia_report(client, identity, tool):
    host, job_id, request_sha = identity
    deadline = time.monotonic() + 180
    while True:
        terminal = client.call('process_wait', {'host': host, 'job_id': job_id, 'timeout_seconds': 10})
        assert terminal['job_id'] == job_id
        if terminal['state'] in ('queued', 'pending', 'starting', 'running'):
            assert time.monotonic() < deadline, 'original HIA job did not settle within the observation bound'
            continue
        assert terminal['state'] == 'succeeded' and terminal['exit_code'] == 0, terminal
        for field in ('output_complete', 'output_durable', 'terminal_publication_confirmed'):
            assert terminal.get(field) is True, ('original HIA output is not final', field, terminal)
        break
    streams = {'stdout': bytearray(), 'stderr': bytearray()}
    sizes = None
    for _ in range(65):
        page = client.call('process_read', {'host': host, 'job_id': job_id, 'limit': 16384,
                                          'stdout_offset': len(streams['stdout']),
                                          'stderr_offset': len(streams['stderr'])})
        assert page['job_id'] == job_id
        current_sizes = {name: page[name]['size'] for name in streams}
        assert all(type(n) is int and 0 <= n <= 512 * 1024 for n in current_sizes.values())
        assert sum(current_sizes.values()) <= 512 * 1024, 'original HIA output exceeds its bound'
        if sizes is None:
            sizes = current_sizes
        assert sizes == current_sizes, 'terminal HIA output changed while reading'
        progressed = False
        for name, output in streams.items():
            part = page[name]
            assert type(part['offset']) is int and part['offset'] == len(output)
            encoded = part['bytes_hex']
            assert type(encoded) is str and re.fullmatch('[0-9a-f]*', encoded) and len(encoded) % 2 == 0
            raw = bytes.fromhex(encoded)
            assert len(raw) <= 16384 and part['text'] == raw.decode('utf-8', 'replace')
            assert type(part['next_offset']) is int and part['next_offset'] == len(output) + len(raw)
            assert part['next_offset'] <= sizes[name]
            assert type(part['eof']) is bool and part['eof'] == (part['next_offset'] == sizes[name])
            output.extend(raw)
            progressed = progressed or bool(raw)
        if all(len(streams[name]) == sizes[name] for name in streams):
            break
        assert progressed, 'original HIA output cursor made no progress'
    else:
        raise RuntimeError('original HIA output pagination incomplete')
    report = json.loads(bytes(streams['stdout']).decode('utf-8'))
    assert set(report) == {'schema', 'tool', 'request_sha256', 'profile_sha256', 'catalog_sha256',
                           'worker_sha256', 'backend_sha256', 'complete', 'response'}
    assert report['schema'] == 'hia-agent-worker-report-v1' and report['complete'] is True
    assert report['tool'] == tool and report['request_sha256'] == request_sha
    assert re.fullmatch('[0-9a-f]{64}', report['profile_sha256'])
    assert {key: report[key] for key in PINS} == PINS
    assert report['response']['status'] == 'completed', report['response']
    return report


def call_hia(client, tool, arguments, original=None):
    # An exact repeated HIA call is the provider's existing-binding observation
    # path. It validates the private profile and output schema without relaunch.
    response = client.call(tool, arguments) if original is None else original
    if response['status'] == 'completed':
        return response
    identity = pending_hia_identity(response)
    report = original_hia_report(client, identity, tool)
    observed = client.call(tool, arguments)
    if observed['status'] in ('accepted', 'unknown'):
        assert pending_hia_identity(observed) == identity, 'HIA observation changed the original job'
        raise RuntimeError('original HIA report remains unadmitted by the provider; preserve the original job')
    assert observed['status'] == 'completed', observed
    # Pending IDs are hia_<worker digest>; completed IDs belong to the HIA
    # service. Compare the actual full response in the bound original report.
    assert observed == report['response'], 'provider result differs from the original HIA report'
    return observed


def resume_hia_describe(directory, report_identity):
    previous = json.loads(trusted_bytes(directory / 'result.json', private=True))
    assert previous['mode'] == 'probe' and previous['status'] == 'failed'
    assert previous['production_modified'] is False and previous['publication_changes'] == []
    for field in ('binary_sha256', 'jobctl_sha256', 'runtime_commit', 'runtime_patch_sha256'):
        assert previous[field] == report_identity[field], ('resume candidate identity differs', field)
    raw = trusted_bytes(directory / 'http-events.jsonl', previous['http_events_sha256'], private=True)
    assert len(raw) <= 8 * 1024 * 1024
    events = [json.loads(line) for line in raw.splitlines()]
    assert len(events) == previous['event_count']
    legacy_events_sha = '57011f740bba24a55aa11276e3c8ecfe2f378ba9c0dc0dee7e50f3c901b679bd'
    for event in events:
        if 'url' in event:
            assert event['url'] == 'http://127.0.0.1:8791/mcp', 'resume endpoint differs'
        else:
            assert previous['http_events_sha256'] == legacy_events_sha, 'only the known v3 probe may lack endpoint fields'
    relevant = [event for event in events if event['method'] == 'tools/call']
    assert len(relevant) == 1 and relevant[0]['params'] == {
        'name': 'hia_describe', 'arguments': {'section': 'manifest'}}
    rpc_result = relevant[0]['result']
    assert rpc_result.get('isError') is not True
    response = json.loads('\n'.join(part.get('text', '') for part in rpc_result['content']
                                    if part.get('type') == 'text'))
    pending_hia_identity(response)
    return response


def shadow_server_identity(pid, release):
    assert type(pid) is int and pid > 1
    observed = mapped_executable(pid, release / 'hepta-runtime')
    listening = subprocess.run(['/usr/sbin/lsof', '-nP', '-a', '-p', str(pid),
                                '-iTCP:8791', '-sTCP:LISTEN', '-Fn'],
                               capture_output=True, text=True, timeout=20)
    require(listening.returncode == 0 and 'n127.0.0.1:8791' in listening.stdout.splitlines(),
            'the mapped shadow runtime does not own its exact loopback listener')
    observed['listener'] = '127.0.0.1:8791'
    observed['listener_lsof_output'] = listening.stdout
    return observed


def main():
    if sys.flags.optimize:
        raise RuntimeError('deployment requires assertions enabled')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['probe', 'cutover'])
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--contract', type=Path, required=True)
    parser.add_argument('--release', type=Path, required=True)
    parser.add_argument('--binary-sha256', required=True)
    parser.add_argument('--jobctl-sha256', required=True)
    parser.add_argument('--runtime-commit', required=True)
    parser.add_argument('--patch-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--shadow-report', type=Path)
    parser.add_argument('--resume-probe', type=Path)
    parser.add_argument('--shadow-pid', type=int)
    args = parser.parse_args()
    assert os.getuid() == 501
    for v in [args.binary_sha256, args.jobctl_sha256, args.patch_sha256]:
        assert re.fullmatch('[0-9a-f]{64}', v)
    assert re.fullmatch('[0-9a-f]{40}', args.runtime_commit)
    assert args.release.parent == CURRENT.parent / 'releases'
    trusted_bytes(args.release / 'hepta-runtime', args.binary_sha256)
    trusted_bytes(args.release / 'hepta-runtime-jobctl', args.jobctl_sha256)
    args.output.mkdir(mode=0o700)
    http = load_module('hia_selected_http', args.source / 'tests/runtime_http_acceptance.py')
    contracts = load_module('hia_selected_contract', args.source / 'deploy/mcp_tool_contract.py')
    contract = contracts.ToolContract.load(args.contract, CONTRACT_SHA)
    assert contract.catalog_sha256 == CATALOG_SHA
    token = trusted_bytes(TOKEN, private=True).decode().strip()
    events = args.output / 'http-events.jsonl'
    records = []

    class Client(http.Client):
        def rpc(self, method, params, notify=False):
            started = time.monotonic_ns()
            record = {'url': self.url, 'method': method, 'params': params, 'notify': notify}
            try:
                result = super().rpc(method, params, notify=notify)
                record['result'] = result
                return result
            except BaseException as e:
                record['error_type'] = type(e).__name__
                record['error'] = str(e)
                raise
            finally:
                record['elapsed_ns'] = time.monotonic_ns() - started
                records.append(record)
                with events.open('ab') as f:
                    os.chmod(events, 0o600)
                    f.write(json.dumps(record, ensure_ascii=False, separators=(',', ':')).encode() + b'\n')
                    f.flush()
                    os.fsync(f.fileno())

    def probe(url):
        client = Client(url, token)
        tools, pages, params = [], [], {}
        for _ in range(16):
            page = client.rpc('tools/list', params)
            pages.append(page)
            tools.extend(page['tools'])
            if page.get('nextCursor') is None:
                break
            params = {'cursor': page['nextCursor']}
        else:
            raise RuntimeError('catalog pagination incomplete')
        contract.verify(tools)
        hia = sorted(t['name'] for t in tools if t['name'].startswith('hia_'))
        assert len(tools) == 113 and len(hia) == 11
        original = resume_hia_describe(args.resume_probe, report) if args.resume_probe is not None else None
        described = call_hia(client, 'hia_describe', {'section': 'manifest'}, original=original)
        description = described['result']
        assert description['catalog_sha256'] == PINS['catalog_sha256']
        ref = description['manifest']
        raw, cursor = bytearray(), None
        for _ in range(32):
            fields = {'catalog_sha256': PINS['catalog_sha256'], 'artifact': ref, 'max_bytes': 65536}
            if cursor is not None:
                fields['cursor'] = cursor
            response = call_hia(client, 'hia_read', fields)
            page = response['result']
            assert page['artifact'] == ref
            raw.extend(page['content'].encode() if page['encoding'] == 'utf8'
                       else base64.b64decode(page['content'], validate=True))
            assert len(raw) <= 8 * 1024 * 1024
            cursor = page['next_cursor']
            if cursor is None:
                break
        else:
            raise RuntimeError('manifest pagination incomplete')
        assert sha(raw) == ref['sha256']
        manifest = json.loads(raw)
        assert manifest['schema'] == 'hepta.hia.agent.manifest.v1'
        assert {key: manifest['installation'][key] for key in PINS} == PINS
        return client, {'tool_count': len(tools), 'hia_tools': hia,
                        'whole_catalog_sha256': contract.catalog_sha256,
                        'installation': {key: manifest['installation'][key] for key in PINS},
                        'manifest_sha256': ref['sha256'], 'url': url}

    report = {'schema': 'hepta.hia.mac-controller-deployment.v1', 'mode': args.mode,
              'runtime_commit': args.runtime_commit, 'runtime_patch_sha256': args.patch_sha256,
              'binary_sha256': args.binary_sha256, 'jobctl_sha256': args.jobctl_sha256,
              'prior_plist_sha256': PLIST_SHA, 'new_plist_sha256': NEW_PLIST_SHA,
              'hepta_commit': '205f94ec811018f89fbf68c987c6ab8e826bb15b',
              'started_unix_ns': time.time_ns(), 'production_modified': False}
    mutations, lock_fd, sentinel_release = [], None, None
    old_binary_sha = None
    try:
        assert args.resume_probe is None or args.mode == 'probe', 'resume is only available for an isolated probe'
        if args.mode == 'probe':
            report['atomic_swap_contract'] = verify_swap_sdk()
            trusted_bytes(PREPARED / 'runtime-staged.json', STAGE_CONFIG_SHA, private=True)
            trusted_bytes(LIVE_CONFIG, OLD_CONFIG_SHA, private=True)
            assert os.readlink(CURRENT) == OLD_TARGET
            report['live_config_entry'], _ = entry(LIVE_CONFIG, 'file', private=True)
            report['live_plist_entry'], _ = entry(PLIST, 'file')
            report['shadow_server_before'] = shadow_server_identity(args.shadow_pid, args.release)
            _, report['observation'] = probe('http://127.0.0.1:8791/mcp')
            report['shadow_server_after'] = shadow_server_identity(args.shadow_pid, args.release)
        else:
            lock_fd = deployment_lock()
            report['atomic_swap_contract'] = verify_swap_sdk()
            assert args.shadow_report is not None
            shadow = json.loads(trusted_bytes(args.shadow_report))
            assert shadow['status'] == 'passed' and shadow['mode'] == 'probe'
            for name in ['binary_sha256', 'jobctl_sha256', 'runtime_commit', 'runtime_patch_sha256']:
                assert shadow[name] == report[name]
            for side in ('before', 'after'):
                identity = shadow['shadow_server_' + side]
                assert identity['mapped_executable'] == str(args.release / 'hepta-runtime')
                assert identity['listener'] == '127.0.0.1:8791'
            assert shadow['shadow_server_before']['pid'] == shadow['shadow_server_after']['pid']
            old = trusted_bytes(PREPARED / 'prior-runtime.json', OLD_CONFIG_SHA, private=True)
            new = trusted_bytes(PREPARED / 'runtime-live.json', NEW_CONFIG_SHA, private=True)
            check_config_addition(old, new)
            old_plist = trusted_bytes(PREPARED / 'prior-controller.plist', PLIST_SHA, private=True)
            new_plist = trusted_bytes(PREPARED / 'controller-staged.plist', NEW_PLIST_SHA, private=True)
            check_plist_change(old_plist, new_plist)
            temp_info = Path(TRUSTED_TMPDIR).lstat()
            assert stat.S_ISDIR(temp_info.st_mode) and temp_info.st_uid == os.getuid()
            assert stat.S_IMODE(temp_info.st_mode) == 0o700 and Path(TRUSTED_TMPDIR).resolve() == Path(TRUSTED_TMPDIR)
            trusted_bytes(LIVE_CONFIG, OLD_CONFIG_SHA, private=True)
            trusted_bytes(PLIST, PLIST_SHA)
            assert CURRENT.is_symlink() and os.readlink(CURRENT) == OLD_TARGET
            before_pid = launch_pid()
            old_binary_sha = sha(trusted_bytes(Path(OLD_TARGET) / 'hepta-runtime'))
            old_mapping = mapped_executable(before_pid, Path(OLD_TARGET) / 'hepta-runtime')
            old_client = Client('http://127.0.0.1:8790/mcp', token)
            marker = args.output / 'sentinel-once.txt'
            ready = args.output / 'sentinel-ready.txt'
            sentinel_release = args.output / 'sentinel-release.txt'
            sentinel_code = sentinel_source(marker, ready, sentinel_release)
            request = {'host': 'main', 'executable': sys.executable,
                       'args': ['-c', sentinel_code], 'cwd': str(args.output),
                       'idempotency_key': 'hia-controller-cutover-205-' + sha((args.binary_sha256 + str(args.output)).encode())[:24],
                       'timeout_seconds': 180}
            dump(args.output / 'sentinel-request.json', request)
            started = old_client.call('process_start', request)
            sentinel_id = started['job']['id']
            assert not started.get('reused'), 'cutover sentinel key was already used'
            ready_deadline = time.monotonic() + 40
            while True:
                running = old_client.call('process_status', {'host': 'main', 'job_id': sentinel_id})
                if ready.exists() and running['state'] == 'running':
                    assert trusted_bytes(ready) == b'ready' and trusted_bytes(marker) == b'1'
                    pre_logs = old_client.call('process_read', {'host': 'main', 'job_id': sentinel_id, 'limit': 16384})
                    assert 'RESTART_BEGIN' in pre_logs['stdout']['text'] and 'RESTART_END' not in pre_logs['stdout']['text']
                    break
                assert running['state'] in ('queued', 'pending', 'starting', 'running'), running
                assert time.monotonic() < ready_deadline, 'sentinel did not enter the ready gate'
                time.sleep(.2)
            assert launch_pid() == before_pid and not sentinel_release.exists()
            report['before'] = {'pid': before_pid, 'config_sha256': OLD_CONFIG_SHA,
                                'plist_sha256': PLIST_SHA, 'current_target': OLD_TARGET,
                                'sentinel_id': sentinel_id, 'sentinel_ready': True,
                                'sentinel_running': running, 'old_mapping': old_mapping,
                                'binary_sha256': old_binary_sha}
            dump(args.output / 'before-cutover.json', report['before'])
            publish_swap(mutations, LIVE_CONFIG, new, OLD_CONFIG_SHA, private=True)
            publish_swap(mutations, CURRENT, str(args.release), OLD_TARGET, kind='symlink')
            publish_swap(mutations, PLIST, new_plist, PLIST_SHA)
            report['production_modified'] = True
            report['service_reload'] = []
            reload_service(report['service_reload'])
            last_error = None
            for _ in range(60):
                try:
                    client = Client('http://127.0.0.1:8790/mcp', token)
                    break
                except (OSError, ValueError) as e:
                    last_error = str(e)
                    time.sleep(1)
            else:
                raise RuntimeError('controller did not return: ' + str(last_error))
            client, report['observation'] = probe('http://127.0.0.1:8790/mcp')
            after_pid = launch_pid()
            assert after_pid != before_pid
            executable = str(args.release / 'hepta-runtime')
            mapping = mapped_executable(after_pid, executable)
            resources = controller_resources()
            again = client.call('process_start', request)
            assert again.get('reused') is True and again['job']['id'] == sentinel_id
            still_running = client.call('process_status', {'host': 'main', 'job_id': sentinel_id})
            assert still_running['state'] == 'running' and not sentinel_release.exists(), still_running
            write_new(sentinel_release, b'new-controller-verified\n')
            terminal = client.call('process_wait', {'host': 'main', 'job_id': sentinel_id, 'timeout_seconds': 30})
            logs = client.call('process_read', {'host': 'main', 'job_id': sentinel_id, 'limit': 16384})
            sentinel_verification = verify_sentinel_completion(terminal, logs, sentinel_id)
            assert marker.read_text() == '1'
            trusted_bytes(LIVE_CONFIG, NEW_CONFIG_SHA, private=True)
            trusted_bytes(PLIST, NEW_PLIST_SHA)
            assert os.readlink(CURRENT) == str(args.release)
            trusted_bytes(args.release / 'hepta-runtime', args.binary_sha256)
            trusted_bytes(args.release / 'hepta-runtime-jobctl', args.jobctl_sha256)
            report['after'] = {'pid': after_pid, 'mapped_executable': executable,
                               'mapping': mapping, 'controller_resources': resources,
                               'config_sha256': NEW_CONFIG_SHA, 'plist_sha256': NEW_PLIST_SHA,
                               'current_target': str(args.release), 'sentinel_running_after_restart': still_running,
                               'sentinel_id': sentinel_id, 'same_job_reused': True,
                               'sentinel_once': True, 'sentinel_terminal': terminal,
                               'sentinel_verification': sentinel_verification}
            report['production_deployed'] = True
        report['status'] = 'passed'
    except BaseException as e:
        report['status'] = 'failed'
        report['error_type'] = type(e).__name__
        report['error'] = str(e)
        if any(change.ever_applied for change in mutations):
            rollback = {'changes': [], 'service_reload': []}
            report['production_modified'] = True
            for change in reversed(mutations):
                if change.active:
                    try:
                        change.rollback()
                        rollback['changes'].append({'path': str(change.path), 'verified': change.rollback_verified})
                    except BaseException as rollback_error:
                        rollback['changes'].append({'path': str(change.path), 'verified': False,
                                                    'error_type': type(rollback_error).__name__, 'error': str(rollback_error)})
            try:
                rollback['config_restored'] = sha(trusted_bytes(LIVE_CONFIG, private=True)) == OLD_CONFIG_SHA
                rollback['plist_restored'] = sha(trusted_bytes(PLIST)) == PLIST_SHA
                rollback['link_restored'] = os.readlink(CURRENT) == OLD_TARGET
                assert all(row['verified'] for row in rollback['changes']) and all(rollback[k] for k in
                       ('config_restored', 'plist_restored', 'link_restored')), 'rollback conflict retained; service not force-reloaded'
                trusted_bytes(Path(OLD_TARGET) / 'hepta-runtime', old_binary_sha)
                reload_service(rollback['service_reload'])
                rollback['mapping'] = mapped_executable(launch_pid(), Path(OLD_TARGET) / 'hepta-runtime')
                rollback['complete'] = True
                report['production_deployed'] = False
            except BaseException as rollback_error:
                rollback['complete'] = False
                rollback['error_type'] = type(rollback_error).__name__
                rollback['error'] = str(rollback_error)
                report['production_deployed'] = None
            report['rollback'] = rollback
    finally:
        if sentinel_release is not None and not sentinel_release.exists():
            try:
                write_new(sentinel_release, b'deployment-finished-without-success\n')
                report['sentinel_release_on_failure'] = True
            except BaseException as release_error:
                report['sentinel_release_error'] = str(release_error)
        report['publication_changes'] = [change.receipt() for change in mutations]
        report['production_modified'] = report['production_modified'] or any(change.ever_applied for change in mutations)
        if lock_fd is not None:
            os.close(lock_fd)
        report['finished_unix_ns'] = time.time_ns()
        report['event_count'] = len(records)
        if events.exists():
            report['http_events_sha256'] = sha(events.read_bytes())
        dump(args.output / 'result.json', report)
        print(json.dumps(report, ensure_ascii=False), flush=True)
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
