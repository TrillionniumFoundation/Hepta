"""In-process HIA scheduling; only selected foreign object effects are hosted.

This byte-image constructor is not source/cold admission. The ordinary selector
performs that admission before creating an immutable private RX mapping. No
child process, authoring module, dynamic compiler or host scheduler is used.
"""
from __future__ import annotations
import ctypes
from hashlib import sha256
import mmap
import struct

from .hia_core_lowering_native import LoweringSession, FRAME, MAGIC, _decode_pool

ENTRY = 176
WORK = 1118208
OUTPUT = 1 << 20
EVENT = struct.Struct('<8Q')
RPC = int.from_bytes(b'HIAIPC01', 'little')


def _protect(address, size, protection):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    libc.mprotect.restype = ctypes.c_int
    if libc.mprotect(address, size, protection):
        raise OSError(ctypes.get_errno(), 'native continuation page protection')


class InProcessContinuation:
    def __init__(self, raw, expected_sha256, *, pool_bytes):
        if (type(raw) is not bytes or not ENTRY < len(raw) <= 64 << 20
                or type(expected_sha256) is not str
                or sha256(raw).hexdigest() != expected_sha256):
            raise ValueError('native in-process container identity differs')
        if type(pool_bytes) is not int or not 64 <= pool_bytes <= OUTPUT:
            raise ValueError('native in-process pool extent differs')
        header = bytearray(ENTRY)
        header[:8] = b'HIAINP01'
        struct.pack_into('<2Q', header, 8, 1, ENTRY)
        struct.pack_into('<2Q', header, 96, len(raw), len(raw))
        if raw[:ENTRY] != header:
            raise ValueError('native in-process container header differs')
        mapping = mmap.mmap(-1, len(raw), prot=mmap.PROT_READ | mmap.PROT_WRITE)
        try:
            mapping.write(raw)
            address = ctypes.addressof(ctypes.c_char.from_buffer(mapping))
            _protect(address, len(raw), mmap.PROT_READ | mmap.PROT_EXEC)
            self._entry = ctypes.CFUNCTYPE(ctypes.c_uint64,
                *([ctypes.c_void_p, ctypes.c_uint64] * 3))(address + ENTRY)
            self._mapping = mapping
            self.pool_bytes = pool_bytes
        except BaseException:
            mapping.close()
            raise

    def invoke(self, owner, name, arguments):
        mode = owner.modes[name]
        if len(arguments) != mode['arity']:
            raise RuntimeError('native lowering bound argument count differs')
        return self.run(LoweringSession(owner, mode['number'], arguments))

    def run(self, session):
        if session.finished or getattr(session, '_native_started', False):
            raise RuntimeError('native continuation session is already consumed')
        session._native_started = True
        source = None
        try:
            owner = session.owner
            if not 128 <= owner.output_bytes <= OUTPUT:
                raise ValueError('native in-process owner output extent differs')
            # One private, read-only input page between inaccessible pages.
            page = mmap.PAGESIZE
            source = mmap.mmap(-1, page * 3, prot=mmap.PROT_READ | mmap.PROT_WRITE)
            base = ctypes.addressof(ctypes.c_char.from_buffer(source))
            address = base + page
            _protect(base, page, 0)
            _protect(address + page, page, 0)
            arrays = [ctypes.create_string_buffer(n + 32) for n in (OUTPUT, WORK)]
            addresses = [ctypes.addressof(a) + 16 for a in arrays]
            for target, size in zip(addresses, (OUTPUT, WORK)):
                ctypes.memset(target - 16, 0xa7, 16)
                ctypes.memset(target + size, 0xa7, 16)

            def guards():
                if any(ctypes.string_at(target - 16, 16) != b'\xa7' * 16
                        or ctypes.string_at(target + size, 16) != b'\xa7' * 16
                        for target, size in zip(addresses, (OUTPUT, WORK))):
                    raise RuntimeError('native in-process buffer canary changed')

            def enter(packet):
                if type(packet) is not bytes or len(packet) != 128:
                    raise TypeError('exact native in-process input packet required')
                _protect(address, page, mmap.PROT_READ | mmap.PROT_WRITE)
                ctypes.memset(address, 0x6d, page)
                ctypes.memmove(address, packet, 128)
                _protect(address, page, mmap.PROT_READ)
                try:
                    returned = self._entry(address, 128, addresses[0], OUTPUT, addresses[1], WORK)
                finally:
                    guards()
                if (ctypes.string_at(address, 128) != packet
                        or ctypes.string_at(address + 128, page - 128) != b'\x6d' * (page - 128)):
                    raise RuntimeError('native in-process read-only input changed')
                return returned

            packet = session.initial
            seen_pool = False
            try:
                while True:
                    status = enter(packet)
                    if status not in (0, 1, 3):
                        raise RuntimeError('native in-process protocol refusal: ' + str(status))
                    header = EVENT.unpack(ctypes.string_at(addresses[1], EVENT.size))
                    if header[0] != RPC or header[1] != status or header[6:] != (0, 0):
                        raise RuntimeError('native in-process event identity differs')
                    if status == 3:
                        if seen_pool or header[2] != self.pool_bytes:
                            raise RuntimeError('native in-process literal extent differs')
                        pool = ctypes.string_at(addresses[0], header[2])
                        if _decode_pool(pool, len(owner.literals)) != owner.literals:
                            raise RuntimeError('native in-process literal values differ')
                        seen_pool = True
                        continue
                    if not seen_pool or not 128 <= header[2] <= owner.output_bytes:
                        raise RuntimeError('native in-process event extent differs')
                    body = ctypes.string_at(addresses[0], header[2])
                    words = FRAME.unpack_from(body)
                    if words[0] != MAGIC:
                        raise RuntimeError('native in-process output identity differs')
                    if status == 0:
                        if len(body) != 128 or words[2] != 0:
                            raise RuntimeError('native in-process return framing differs')
                        value = session.value(words[3])
                        session.native_observation = header
                        if enter(packet) != 16:
                            raise RuntimeError('closed native in-process phase was replayable')
                        return value
                    opcode, count, vector, results = words[2:6]
                    if (not 1 <= opcode <= 18 or count > 8 or results > 3
                            or len(body) != 128 + vector * 8):
                        raise RuntimeError('native in-process primitive framing differs')
                    session.status, session.pending = 1, True
                    session.request = (words, struct.unpack_from('<' + 'Q' * vector, body, 128))
                    packet = session.observe()
            finally:
                guards()
        finally:
            session._close()
            if source is not None:
                source.close()
