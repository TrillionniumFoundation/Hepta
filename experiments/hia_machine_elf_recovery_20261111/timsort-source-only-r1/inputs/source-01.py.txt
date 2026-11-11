"""Reconstructed static ELF foreign observer, not a new qualification.

The visible authoring history is the recovery input. Original r1 adapter SHA
8ead697ed2d9cdae85673d61b500a4762e47fb88a0d0bb95cd54147d88fc011c
and its actual 55/51 outcomes remain historical observations. This separately
identified revision must be regenerated and tested before active use.
"""
from __future__ import annotations
from collections import Counter
import ctypes
import mmap
import struct
import sys
from .hia_json_preflight_native import (
    NativeHiaJsonImage, _installed_json_image, _source_resource_path)
from .hia_machine_elf_sort_observation import observe_sort, close_sort_observation

SOURCE = _source_resource_path('examples/hia_bootstrap/machine_elf.hiaasm')
SCHEMA = 'hepta.hia.machine-elf-native.v1'
SELECTOR = 'HEPTA_HIA_MACHINE_ELF_MANIFEST'
MAGIC = int.from_bytes(b'HIAELF01', 'little')
ABI = 0xfffffffd
ERRORS = {
    1: 'unreviewed text section alignment',
    2: 'nonempty bounded immutable machine bytes required',
    3: 'invalid symbol or relocation inventory',
    4: 'invalid function symbol record',
    5: 'invalid ELF symbol name',
    6: 'duplicate or out-of-range function symbol',
    7: 'function symbol ranges overlap',
    8: 'only explicit PLT32 call relocations are supported',
    9: 'call relocation does not point to an E8 placeholder',
    10: 'duplicate or overlapping call relocations',
    11: 'ELF symbol inventory exceeds limit',
    12: 'ELF object exceeds byte budget',
}
KEYS = ('', 'name', 'offset', 'size', 'global', 'symbol', 'type', 'addend')
PHASE, SEQUENCE, PENDING = 8, 16, 24
REQUEST, A, B, C, D = 32, 40, 48, 56, 64
ACK, NEED, RESULT_SIZE, END = 72, 80, 88, 96
FACT = 512
FACT_BYTES = 56
WORD_MASK = (1 << 64) - 1

def _private_buffer(size):
    mapped = mmap.mmap(-1, size, prot=mmap.PROT_READ | mmap.PROT_WRITE)
    view = (ctypes.c_ubyte * size).from_buffer(mapped)
    return mapped, view

class ElfSession:
    """One-shot transport; HIA chooses each foreign operation and all policy."""
    def __init__(self, image, code, symbols, relocations, alignment):
        self.image = image
        self.arguments = (None, alignment, code, symbols, relocations)
        self.code = code
        self.objects = [None]
        self.identities = {}
        self.maps = ({}, {}, {})
        self.work_map, self.work = _private_buffer(4096)
        self.out_map, self.output = _private_buffer(64)
        self.finished = False
        self.pending = False
        self.calls = Counter()
        self._payload = b''

    def close(self):
        if self.work is None and self.output is None:
            return
        self.finished, self.pending = True, False
        close_sort_observation(self)
        self.arguments = self.code = None
        self.objects.clear()
        self.identities.clear()
        self.maps = ()
        self.work = self.output = None
        self.work_map.close()
        self.out_map.close()

    def word(self, at):
        return struct.unpack_from('<Q', self.work, at)[0]

    def put(self, at, value):
        struct.pack_into('<Q', self.work, at, value)

    def handle(self, value):
        identity = id(value)
        known = self.identities.get(identity)
        if known is not None:
            if self.objects[known] is not value:
                raise RuntimeError('foreign ELF object identity changed')
            return known
        result = len(self.objects)
        self.objects.append(value)
        self.identities[identity] = result
        return result

    def object(self, handle):
        if type(handle) is not int or not 1 <= handle < len(self.objects):
            raise RuntimeError('invalid native ELF foreign handle')
        return self.objects[handle]

    def atom(self, at):
        if not 0 <= at <= len(self.work) - 48:
            raise RuntimeError('native ELF atom outside its issued workspace')
        kind, value, flags, length, handle, payload = struct.unpack_from('<6Q', self.work, at)
        if handle:
            return self.object(handle)
        if kind in (1, 2):
            if flags & 2:
                raise RuntimeError('wide native atom lacks its foreign identity')
            return -value if flags & 1 else value
        if kind == 3:
            if payload != at + 48 or length > (len(self.work) - payload) // 4:
                raise RuntimeError('native ELF text atom outside workspace')
            return ''.join(chr(struct.unpack_from('<I', self.work, payload + i * 4)[0])
                           for i in range(length))
        raise RuntimeError('native ELF issued an unmaterializable atom')

    def _fact(self, value, payload, *, limit=193):
        typ = type(value)
        kind = 7
        if typ is int:
            kind = 1
        elif typ is bool:
            kind = 2
        elif typ is str:
            kind = 3
        elif typ is bytes:
            kind = 4
        elif typ is list:
            kind = 5
        elif typ is dict:
            kind = 6
        number = flags = length = count = 0
        at = len(payload)
        if typ is int:
            flags = int(value < 0)
            wide = value.bit_length() > 64
            flags |= 2 * int(wide)
            number = 0 if wide else abs(value)
        elif typ is bool:
            number = int(value)
        elif typ is str:
            length = len(value)
            observed = value[:limit]
            count = len(observed)
            payload.extend(observed.encode('utf-32-le', 'surrogatepass'))
        elif typ is bytes or typ is list or typ is dict:
            length = len(value)
        return (kind, number, flags, length, self.handle(value), at, count)

    def answer(self, values=(), *, payload=None, special=None, text_limit=193):
        if len(values) > 3:
            raise RuntimeError('native ELF observation exceeds three facts')
        raw = bytearray() if payload is None else bytearray(payload)
        facts = [self._fact(value, raw, limit=text_limit) for value in values]
        while len(facts) < 3:
            facts.append((0, 0, 0, 0, 0, 0, 0))
        if special is not None:
            facts[0] = special
        for index, fact in enumerate(facts):
            struct.pack_into('<7Q', self.work, FACT + index * FACT_BYTES, *fact)
        self._payload = bytes(raw)
        self.put(ACK, self.word(SEQUENCE))

    def _grow(self, output=False):
        required = self.word(NEED)
        old = self.output if output else self.work
        if not len(old) < required <= sys.maxsize:
            raise RuntimeError('invalid native ELF buffer growth request')
        size = max(required, len(old) * 2)
        mapped, fresh = _private_buffer(size)
        ctypes.memmove(fresh, old, len(old))
        if output:
            previous = self.out_map
            self.out_map, self.output = mapped, fresh
        else:
            previous = self.work_map
            self.work_map, self.work = mapped, fresh
        del old
        previous.close()

    def step(self):
        try:
            if self.finished or self.pending:
                raise RuntimeError('native ELF continuation is not ready for a step')
            while True:
                source = ctypes.c_char_p(self._payload)
                status = self.image._entry(source, len(self._payload),
                                           self.output, len(self.output),
                                           self.work, len(self.work))
                if status == 2:
                    self._grow()
                    continue
                if status == 3:
                    self._grow(True)
                    continue
                if status == 1:
                    self.pending = True
                    return 1
                if status == 0:
                    length = self.word(RESULT_SIZE)
                    if not 0 < length <= len(self.output):
                        raise RuntimeError('native ELF output length differs')
                    self.finished = True
                    return 0
                if status - 0x80000000 in ERRORS:
                    from .hia_machine_elf import MachineObjectError
                    raise MachineObjectError(ERRORS[status - 0x80000000])
                if status == 0x70000001:
                    raise struct.error('argument out of range')
                if status == 0x70000002:
                    raise struct.error('required argument is not an integer')
                raise RuntimeError('native ELF protocol refusal: ' + hex(status))
        except BaseException:
            self.finished, self.pending = True, False
            raise

    def observe(self):
        try:
            if self.finished or not self.pending:
                raise RuntimeError('native ELF foreign effect is not pending')
            self.pending = False
            op, a, b, c, d = struct.unpack_from('<5Q', self.work, REQUEST)
            self.calls[op] += 1
            self.image.calls[op] += 1
            if op == 1:
                self.answer((self.arguments[a],), text_limit=0)
            elif op == 2:
                self.answer((iter(self.object(a)),))
            elif op == 3:
                try:
                    value = next(self.object(a))
                except StopIteration:
                    self.answer()
                else:
                    self.answer((value,))
            elif op == 4:
                value = set(self.object(a))
                raw = bytearray()
                for index, key in enumerate(value):
                    if index == 4:
                        break
                    if type(key) is str:
                        observed = key[:8]
                        raw.extend(struct.pack('<QQQ', 3, len(key), len(observed)))
                        raw.extend(observed.encode('utf-32-le', 'surrogatepass'))
                    else:
                        raw.extend(struct.pack('<QQQ', 7, 0, 0))
                self.answer(payload=raw, special=(9, 0, 0, len(value), self.handle(value), 0, 0))
            elif op == 5:
                value = self.object(a)
                result = (value != {'name', 'offset', 'size', 'global'} if b == 0
                          else value != {'offset', 'symbol', 'type', 'addend'})
                self.answer((result,))
            elif op == 6:
                obj = self.object(a)
                if d:
                    values = (obj[KEYS[b]], obj[KEYS[c]], obj[KEYS[d]])
                elif c:
                    values = (obj[KEYS[b]], obj[KEYS[c]])
                else:
                    values = (obj[KEYS[b]],)
                self.answer(values)
            elif op == 7:
                self.answer((dict(self.object(a)),))
            elif op == 8:
                self.answer((bool(self.atom(a)),))
            elif op == 9:
                left, right = self.atom(a), self.atom(b)
                self.answer(((left + right) if c == 0 else (left - right),))
            elif op == 10:
                if c == 2:
                    left = (self.atom(self.word(a + 24)), self.atom(self.word(a + 32)))
                    right = (self.atom(self.word(b + 24)), self.atom(self.word(b + 32)))
                else:
                    left, right = self.atom(a), self.atom(b)
                if c == 1:
                    result = left > right
                elif c == 3:
                    result = left == right
                elif c == 4:
                    result = left != right
                else:
                    result = left < right
                self.answer((bool(result),))
            elif op == 11:
                self.maps[a][self.atom(b)] = c
                self.answer()
            elif op == 12:
                self.answer((self.maps[a][self.atom(b)],))
            elif op == 13:
                self.answer((self.code[self.atom(a)],))
            elif op == 14:
                value = self.code[self.atom(a):self.atom(b)]
                self.answer((value,), payload=value)
            elif op == 15:
                self.answer((self.code,), payload=self.code)
            elif op == 16:
                value = int.from_bytes(struct.pack('<Q', self.atom(a)), 'little')
                self.answer((value,))
            elif 17 <= op <= 28:
                observe_sort(self, op, a, b, c, d)
            else:
                raise RuntimeError('unknown native ELF foreign request')
        except BaseException:
            self.finished, self.pending = True, False
            raise

    def run(self):
        try:
            while self.step():
                self.observe()
            return ctypes.string_at(self.output, self.word(RESULT_SIZE))
        finally:
            self.close()

class NativeMachineElf(NativeHiaJsonImage):
    def __init__(self, image, expected_sha256):
        super().__init__(image, expected_sha256)
        self.calls = Counter()

    def write(self, code, symbols, relocations, *, text_alignment=16):
        return ElfSession(self, code, symbols, relocations, text_alignment).run()

def installed_machine_elf(manifest_path):
    return _installed_json_image(manifest_path, SOURCE, SCHEMA, NativeMachineElf)
