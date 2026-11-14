"""Immutable original bridge; independent fake foreign observations, no child/VM."""
from __future__ import annotations
from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT / 'tests/fixtures/hia_artifact_delivery_bridge_5da589f0.py.txt'
ORIGINAL_SHA256 = '68f7f0641f1a5ab9f1152823d8e42faffd0d64436a3470016d311e31fc81b5d6'
NONCE = bytes(range(16))


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':')).encode()


def original_namespace():
    raw = ORIGINAL.read_bytes()
    if sha256(raw).hexdigest() != ORIGINAL_SHA256:
        raise AssertionError('complete original artifact bridge changed')
    namespace = {'__name__': 'hepta._frozen_artifact_delivery_original',
                 '__package__': 'hepta', '__file__': str(ORIGINAL)}
    exec(compile(raw, str(ORIGINAL), 'exec'), namespace)
    return namespace


def exact_image(private=False):
    """Literal fake ABI image, never assembled or executed."""
    public, selected = 0x400160, 0x4001F0
    header = (b'\x7fELF\x02\x01\x01' + bytes(9)
              + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, selected if private else public,
                            64, 0, 0, 64, 56, 3, 0, 0, 0)
              + struct.pack('<II6Q', 1, 5, 0, 0x400000, 0x400000, 512, 512, 4096)
              + struct.pack('<II6Q', 0x6474E551, 6, 0, 0, 0, 0, 0, 16)
              + struct.pack('<II6Q', 4, 4, 232, 0x4000E8, 0x4000E8, 120, 120, 4)
              + struct.pack('<III', 9, 96, 1) + b'HIADELIV\0' + bytes(3)
              + struct.pack('<12Q', int.from_bytes(b'HIADCTL1', 'little'), 1,
                            public, selected, 16, 128, 96, 24, 0, 0, 63, 0))
    assert len(header) == 352
    return header + bytes([0x90]) * (512 - len(header))


def fake_ack(operation, status, stdout, input_size, nonce=NONCE):
    """Fake observation only; the separate frozen matrix checks actual HIA."""
    op = {'publish': 1, 'verify': 2, 'withdraw': 3,
          'store-put': 4, 'store-get': 5, 'store-hash': 6}[operation]
    words = [int.from_bytes(b'HIAPDLV1', 'little'), 1, *struct.unpack('<2Q', nonce),
             op, 1 if status == 0 else 2, status, 19 if status == 0 else 1,
             input_size, len(stdout), 16384 | (1536 if status == 0 else 0),
             0 if status == 0 else 1, 0, 0, 0, int.from_bytes(b'HIAPEND1', 'little')]
    raw = bytearray(struct.pack('<16Q', *words))
    raw[104:120] = sha256(raw[:104]).digest()[:16]
    return bytes(raw)


class Fixture:
    def __init__(self, case):
        self.case = case
        self.events, self.transport, self.closed = [], [], []
        self.storage = {}
        self.candidate = False
        self.next_fd = 43
        kinds = {'OSError': OSError, 'AttributeError': AttributeError,
                 'ValueError': ValueError, 'TypeError': TypeError,
                 'MemoryError': MemoryError, 'RuntimeError': RuntimeError,
                 'KeyboardInterrupt': KeyboardInterrupt, 'SystemExit': SystemExit}
        self.fault = kinds.get(case.get('error'), ValueError)('original-' + case['name'])
        self.data = bytes.fromhex(case.get('data_hex', '610062ff'))
        self.namespace = original_namespace()
        self.active_namespace = self.namespace
        self.last_stdout = None
        self.os = SimpleNamespace(memfd_create=self.memfd_create, write=self.write,
            fstat=self.fstat, pread=self.pread, close=self.close, fspath=self.fspath,
            MFD_CLOEXEC=1, MFD_ALLOW_SEALING=2)
        self.fcntl = SimpleNamespace(fcntl=self.fcntl_call)
        self.subprocess = SimpleNamespace(run=self.run)

    def point(self, name, *values):
        self.events.append([name, *values])
        if self.case.get('fault') == name:
            raise self.fault

    def validated(self, manifest):
        self.point('admit', str(manifest))
        return exact_image(self.candidate)

    def memfd_create(self, name, flags):
        self.point('memfd_create', name, flags)
        fd = self.next_fd
        self.next_fd += 1
        self.storage[fd] = bytearray()
        return fd

    def write(self, fd, view):
        self.point('write', fd, len(view))
        if self.case.get('zero_write'):
            return 0
        count = min(len(view), self.case.get('write_chunk', len(view)))
        self.storage[fd].extend(view[:count])
        return count

    def fcntl_call(self, fd, command, *args):
        self.point('add_seals' if command == 1033 else 'get_seals', fd, command, list(args))
        return self.case.get('seals', 15) if command == 1034 else 0

    def fstat(self, fd):
        self.point('fstat', fd)
        return SimpleNamespace(st_size=len(self.storage[fd]) + self.case.get('extent_delta', 0))

    def pread(self, fd, count, offset):
        self.point('pread', fd, count, offset)
        return bytes(self.storage[fd]) if not self.case.get('readback_changed') else b'changed'

    def close(self, fd):
        self.point('close', fd)
        self.closed.append(fd)

    def fspath(self, value):
        text = os.fspath(value)
        label = 'stage' if text == '/stage' else 'destination' if text == '/destination' else 'path'
        self.point('fspath_' + label, text)
        return text

    def run(self, argv, *, input, capture_output, pass_fds, env):
        assert len(argv) == 4 and argv[0].startswith('/proc/self/fd/')
        fd = int(argv[0].rsplit('/', 1)[1])
        assert capture_output is True and pass_fds == (fd,) and env == {'PATH': ''}
        image = bytes(self.storage[fd])
        private = struct.unpack_from('<Q', image, 24)[0] == 0x4001F0
        assert image == exact_image(private)
        original = input
        if private:
            assert input[:16] == NONCE
            original = input[16:]
        self.point('run', argv, original.hex(), capture_output, list(pass_fds), env)
        self.transport.append({'sealed_sha256': sha256(image).hexdigest(),
                               'stdin_hex': input.hex(), 'private': private})
        code = self.case.get('status', 0)
        if code:
            stdout = b''
        elif argv[1] == 'withdraw':
            stdout = b'{"withdrawn":' + (b'true' if self.case.get('withdrawn', True) else b'false') + b'}\n'
        elif argv[1] == 'store-get':
            stdout = self.data
        else:
            stdout = ('{"sha256":"' + 'ab' * 32 + '","bytes":' + str(len(original)) + '}\n').encode()
        self.last_stdout = stdout
        size = len(stdout) if argv[1] == 'store-get' else len(original)
        stderr = fake_ack(argv[1], code, stdout, size) if private else b''
        return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)

    @contextmanager
    def providers(self, namespace, *, candidate=False):
        self.candidate = candidate
        self.active_namespace = namespace
        with patch.dict(namespace, {'os': self.os, 'fcntl': self.fcntl,
                                    'subprocess': self.subprocess, '_validated_code': self.validated}):
            yield

    def arguments(self):
        op, data = self.case['operation'], self.data
        if self.case.get('invalid_data') == 'bytearray':
            data = bytearray(data)
        if self.case.get('invalid_data') == 'none':
            data = None
        root = '/stage'
        if self.case.get('root_reentrant_direct'):
            fixture = self
            class Root:
                def __fspath__(self):
                    fixture.point('root_fspath')
                    fixture.active_namespace['_execute_native'](
                        'selected', 'withdraw', '/nested-stage', '/nested-destination', b'')
                    return '/stage'
            root = Root()
        if op.startswith('store-'):
            return ('selected', op, root), {'data': data, 'digest': self.case.get('digest', 'ab' * 32)}
        return ('selected', op, root, '/destination', data), {}

    def snapshot(self, value):
        if isinstance(value, bytes):
            return {'bytes': value.hex(), 'is_stdout': value is self.last_stdout}
        if type(value) is dict:
            return {'dict': [[self.snapshot(k), self.snapshot(v)] for k, v in value.items()]}
        if type(value) in (str, int, bool) or value is None:
            return value
        return {'type': type(value).__name__}

    def error(self, error):
        return {'type': type(error).__name__, 'message': str(error),
                'is_injected': error is self.fault,
                'cause': None if error.__cause__ is None else self.error(error.__cause__)}

    def observe(self, owner=None):
        args, kwargs = self.arguments()
        try:
            if owner is None:
                name = 'invoke_artifact_store' if self.case['operation'].startswith('store-') else 'invoke_native'
                with self.providers(self.namespace):
                    result = self.namespace[name](*args, **kwargs)
            else:
                result = owner(self, args, kwargs)
        except BaseException as error:
            outcome = {'error': self.error(error)}
        else:
            outcome = {'returned': self.snapshot(result)}
        return {'name': self.case['name'], 'events': self.events, 'outcome': outcome,
                'closed': self.closed, 'transport': self.transport}


def observe_case(case, owner=None):
    return Fixture(case).observe(owner)


def public_observation(record):
    # The explicit new private wire is separately verified, never claimed
    # byte-equal to old public wire. No business event/outcome is normalized.
    return {key: value for key, value in record.items() if key != 'transport'}
