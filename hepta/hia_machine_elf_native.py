"""Explicit HIA ELF owner with fixed CPython foreign operations.

HIA owns validation, retained continuation/effect authority, stable Powersort,
layout and ELF bytes. The bridge retains actual objects and performs only the
issued physical operations. Selection is opt-in; development observations are
not complete source-cold or arbitrary-object equivalence qualifications.
"""
from __future__ import annotations
from collections import Counter
from functools import lru_cache
from hashlib import sha256
from itertools import count
import ctypes
import json
import mmap
from pathlib import Path
import struct
import sys
from .hia_json_preflight_native import (
    NativeHiaJsonImage, _source_resource_path)
from .hia_exception_delivery import ExceptionDelivery

SOURCE = _source_resource_path('examples/hia_bootstrap/machine_elf.hepta')
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
INIT_MAGIC = int.from_bytes(b'HIAELI02', 'little')
CLAIM_MAGIC = int.from_bytes(b'HIAELC02', 'little')
NONCE, CONSUME, DEAD = 680, 688, 696
FOREIGN_ERROR = 720
_RELEASED = object()
_NONCES = count(1)


def _new_nonce():
    value = next(_NONCES)
    if value > WORD_MASK:
        raise RuntimeError('native ELF instance namespace exhausted')
    return value

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
        self.nonce = _new_nonce()
        self._issued = None
        self._issued_header = None
        self._issued_spans = ()
        self._issued_objects = ()
        self._claimed_header = None
        self._in_operation = False
        self._unconfirmed_error = None
        self._cleanup_failures = ()
        self.maps = ({}, {}, {})
        self.work_map = self.out_map = None
        self.work = self.output = None
        self.finished = False
        self.pending = False
        self.calls = Counter()
        self._payload = struct.pack('<3Q', INIT_MAGIC, self.nonce,
                                    sys.version_info.major * 100 + sys.version_info.minor)
        try:
            self.work_map, self.work = _private_buffer(4096)
            self.out_map, self.output = _private_buffer(64)
        except BaseException:
            # A partial constructor already owns its first actual mapping.
            # Preserve the original allocation failure and opaque arguments;
            # any cleanup failure remains attached to this traceback owner.
            try:
                self.close(release=False)
            except BaseException:
                pass
            raise

    def close(self, *, release=True):
        self.finished, self.pending = True, False
        self._issued = self._issued_header = self._claimed_header = None
        self.work = self.output = None
        failures = []
        # Actual mmap objects remain rooted even if the first close or the
        # handoff between closes is interrupted. Explicit close can finish
        # only the still-open objects, never an fd number or replacement map.
        for mapped in (self.work_map, self.out_map):
            if mapped is not None:
                try:
                    if not mapped.closed:
                        mapped.close()
                except BaseException as error:
                    failures.append(error)
        self._cleanup_failures = tuple(failures)
        if release:
            self.arguments = self.code = None
            self._issued_spans = self._issued_objects = ()
            self.objects.clear()
            self.maps = ()
        if failures:
            raise failures[0]

    def word(self, at):
        return struct.unpack_from('<Q', self.work, at)[0]

    def put(self, at, value):
        struct.pack_into('<Q', self.work, at, value)

    def handle(self, value):
        # Every returned owner is distinct. Equal objects and repeated object
        # identities do not merge independently live expression-stack slots.
        result = len(self.objects)
        self.objects.append(value)
        return result

    def object(self, handle):
        if (type(handle) is not int or not 1 <= handle < len(self.objects)
                or self.objects[handle] is _RELEASED):
            raise RuntimeError('invalid native ELF foreign handle')
        return self.objects[handle]

    def take(self, handle):
        self.object(handle)
        value, self.objects[handle] = self.objects[handle], _RELEASED
        return value

    def _header(self):
        return (ctypes.string_at(self.work, 104) +
                ctypes.string_at(ctypes.addressof(self.work) + NONCE, 48))

    def _bytes(self, at, size):
        if type(at) is not int or type(size) is not int or not 0 <= at <= len(self.work) - size:
            raise RuntimeError('native ELF operand lies outside its workspace')
        return ctypes.string_at(ctypes.addressof(self.work) + at, size)

    def _capture_operands(self, op, a, b, c, d):
        spans, objects = [], []
        def bind(handle):
            objects.append(('handle', handle, self.object(handle)))
        def atom(at):
            head = self._bytes(at, 48)
            kind, value, flags, length, handle, payload = struct.unpack('<6Q', head)
            size = 48
            if kind == 3:
                # The HIA name table retains an opaque handle without copying
                # text into scratch (name_atom: count=0, payload=0). Ordinary
                # observed string atoms use bounded inline UTF-32 bytes.
                name_reference = flags == 0 and payload == 0 and handle != 0
                if flags > 193 or (payload != at + 48 and not name_reference):
                    raise RuntimeError('native ELF text operand is not bounded')
                size += flags * 4
            spans.append((at, self._bytes(at, size)))
            if handle:
                bind(handle)
        if op == 1:
            objects.append(('argument', a, self.arguments[a]))
        elif op in (2, 3, 4, 5, 6, 7):
            bind(a)
        elif op in (8, 13, 16):
            atom(a)
        elif op in (9, 14):
            atom(a)
            atom(b)
        elif op == 10:
            if c == 2:
                for node in (a, b):
                    spans.append((node, self._bytes(node, 64)))
                    atom(self.word(node + 24))
                    atom(self.word(node + 32))
            else:
                atom(a)
                atom(b)
        elif op in (11, 12):
            objects.append(('map', a, self.maps[a]))
            atom(b)
        elif op == 15:
            objects.append(('code', 0, self.code))
        else:
            raise RuntimeError('native ELF issued an unknown foreign operation')
        return tuple(spans), tuple(objects)

    def _check_operands(self):
        for at, raw in self._issued_spans:
            if self._bytes(at, len(raw)) != raw:
                raise RuntimeError('native ELF issued operand bytes changed')
        for kind, at, expected in self._issued_objects:
            if kind == 'handle':
                actual = self.object(at)
            elif kind == 'argument':
                actual = self.arguments[at]
            elif kind == 'map':
                actual = self.maps[at]
            else:
                actual = self.code
            if actual is not expected:
                raise RuntimeError('native ELF issued object binding changed')

    def _capture_request(self):
        if (self.word(PENDING) != 1 or self.word(NONCE) != self.nonce
                or self.word(DEAD) != 0 or self.word(SEQUENCE) == 0):
            raise RuntimeError('native ELF did not issue an exact live request')
        op, a, b, c, d = struct.unpack_from('<5Q', self.work, REQUEST)
        consume = self.word(CONSUME)
        if consume != (1 if op == 5 else 0):
            raise RuntimeError('native ELF issued an invalid owning-stack disposition')
        self._issued_header = self._header()
        self._issued_spans, self._issued_objects = self._capture_operands(op, a, b, c, d)
        self._issued = struct.pack('<9Q', CLAIM_MAGIC, self.nonce,
            self.word(SEQUENCE), op, a, b, c, d, consume)

    def _claim(self):
        request = self._issued
        header = self._issued_header
        if request is None or header is None:
            raise RuntimeError('native ELF has no unconsumed issued request')
        # Consume transport permission before entering HIA. A lost native
        # return never recreates a foreign invocation capability.
        self._issued = None
        self._issued_header = None
        source = ctypes.create_string_buffer(request, len(request))
        status = self.image._entry(source, len(request), self.output, len(self.output),
                                   self.work, len(self.work))
        expected = bytearray(header)
        struct.pack_into('<Q', expected, PENDING, 2)
        if type(status) is not int or status != 5 or self._header() != bytes(expected):
            raise RuntimeError('native ELF effect preclaim was not confirmed')
        self._claimed_header = bytes(expected)
        self._check_operands()

    def _enter_foreign(self):
        if self.finished or self._header() != self._claimed_header:
            raise RuntimeError('native ELF claimed frame changed before its foreign operation')
        self._check_operands()
        # This helper returns before the actual operator starts: none of its
        # temporary verification references survives an HIA-directed take.
        self._issued_spans = self._issued_objects = ()

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
        if self.finished or not self._in_operation or self._header() != self._claimed_header:
            raise RuntimeError('native ELF outcome has no exact claimed operation')
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
            if self.finished or self.pending or self._in_operation:
                raise RuntimeError('native ELF continuation is not ready for a step')
            while True:
                source = ctypes.c_char_p(self._payload)
                status = self.image._entry(source, len(self._payload),
                                           self.output, len(self.output),
                                           self.work, len(self.work))
                if type(status) is not int or not 0 <= status <= 0xffffffff:
                    raise RuntimeError('native ELF returned a non-ABI status')
                if status == 2:
                    self._grow()
                    continue
                if status == 3:
                    self._grow(True)
                    continue
                if status == 1:
                    self._capture_request()
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
            if self.finished or not self.pending or self._in_operation:
                raise RuntimeError('native ELF foreign effect is not pending')
            self.pending = False
            self._in_operation = True
            self._claim()
            op, a, b, c, d = struct.unpack_from('<5Q', self.work, REQUEST)
            self.calls[op] += 1
            self.image.calls[op] += 1
            self._enter_foreign()
            succeeded, observed = self._capture_foreign(op, a, b, c, d)
            try:
                if not succeeded:
                    self._confirm_foreign_error(observed)
                    self.image._exception_delivery.deliver(observed)
                    raise RuntimeError('native ELF exception delivery returned')
                # Packing/admission failures are outside the callback catcher.
                # They cannot manufacture a foreign-error acknowledgement for
                # an effect whose returned value was lost during transport.
                self._submit_foreign(op, observed)
            finally:
                observed = None
            self._claimed_header = None
        except BaseException:
            self.finished, self.pending = True, False
            raise
        finally:
            self._in_operation = False

    def _capture_foreign(self, op, a, b, c, d):
        try:
            return True, self._foreign(op, a, b, c, d)
        except BaseException as error:
            # Leave this handler before HIA-directed outcome admission or
            # reference release. This is a catcher, never a generator raise.
            return False, error

    def _foreign(self, op, a, b, c, d):
        if op == 1:
            return self.arguments[a]
        if op == 2:
            return iter(self.object(a))
        if op == 3:
            try:
                return True, next(self.object(a))
            except StopIteration:
                return False, None
        if op == 4:
            return set(self.object(a))
        if op == 5:
            if self.word(CONSUME) != 1:
                raise RuntimeError('native ELF did not authorize consuming the set operand')
            # HIA moves this owning slot onto the real interpreter stack.
            # No local variable keeps the temporary set after comparison.
            return (self.take(a) != {'name', 'offset', 'size', 'global'} if b == 0
                    else self.take(a) != {'offset', 'symbol', 'type', 'addend'})
        if op == 6:
            obj = self.object(a)
            if d:
                return obj[KEYS[b]], obj[KEYS[c]], obj[KEYS[d]]
            if c:
                return obj[KEYS[b]], obj[KEYS[c]]
            return (obj[KEYS[b]],)
        if op == 7:
            return dict(self.object(a))
        if op == 8:
            return bool(self.atom(a))
        if op == 9:
            return ((self.atom(a) + self.atom(b)) if c == 0
                    else (self.atom(a) - self.atom(b)))
        if op == 10:
            if c == 2:
                return bool((self.atom(self.word(a + 24)), self.atom(self.word(a + 32)))
                            < (self.atom(self.word(b + 24)), self.atom(self.word(b + 32))))
            # Keep the comparator result only on the original expression
            # stack: a truth conversion error releases it before caller catch.
            if c == 1:
                return bool(self.atom(a) > self.atom(b))
            if c == 3:
                return bool(self.atom(a) == self.atom(b))
            if c == 4:
                return bool(self.atom(a) != self.atom(b))
            return bool(self.atom(a) < self.atom(b))
        if op == 11:
            self.maps[a][self.atom(b)] = c
            return None
        if op == 12:
            return self.maps[a][self.atom(b)]
        if op == 13:
            return self.code[self.atom(a)]
        if op == 14:
            return self.code[self.atom(a):self.atom(b)]
        if op == 15:
            return self.code
        if op == 16:
            return int.from_bytes(struct.pack('<Q', self.atom(a)), 'little')
        raise RuntimeError('unknown native ELF foreign request')

    def _submit_foreign(self, op, value):
        if op == 1:
            self.answer((value,), text_limit=0)
        elif op == 3:
            self.answer((value[1],) if value[0] else ())
        elif op == 4:
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
        elif op == 6:
            self.answer(value)
        elif op == 11:
            self.answer()
        elif op in (14, 15):
            self.answer((value,), payload=value)
        else:
            self.answer((value,))

    def _confirm_foreign_error(self, error):
        if self.finished or not self._in_operation or self._header() != self._claimed_header:
            raise RuntimeError('native ELF foreign error has no exact claimed operation') from error
        self._unconfirmed_error = error
        self.put(FOREIGN_ERROR, 1)
        self.put(ACK, self.word(SEQUENCE))
        expected = bytearray(self._header())
        struct.pack_into('<Q', expected, PENDING, 0)
        struct.pack_into('<Q', expected, 104 + DEAD - NONCE, 1)
        result = self.image._entry(b'', 0, self.output, len(self.output), self.work, len(self.work))
        if type(result) is not int or result != 6 or self._header() != bytes(expected):
            raise RuntimeError('native ELF foreign-error outcome was not confirmed') from error
        self.finished, self.pending = True, False
        self._unconfirmed_error = None

    def run(self):
        completed = False
        try:
            while self.step():
                self.observe()
            result = ctypes.string_at(self.output, self.word(RESULT_SIZE))
            completed = True
            return result
        finally:
            # A traceback retains the original function's live locals. Keep
            # opaque owners attached to this terminal frame on failure too;
            # successful calls release even inside an ambient except handler.
            self.close(release=completed)

class NativeMachineElf(NativeHiaJsonImage):
    def __init__(self, image, expected_sha256):
        super().__init__(image, expected_sha256)
        self.calls = Counter()
        self._exception_delivery = ExceptionDelivery.from_hia(self)

    def write(self, code, symbols, relocations, *, text_alignment=16):
        return ElfSession(self, code, symbols, relocations, text_alignment).run()


def _unique_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate native ELF manifest field')
        result[key] = value
    return result


def _read_limit(path, limit):
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('native ELF executable selection exceeds its fixed profile')
    return raw


@lru_cache(maxsize=3)
def _mapped(image, image_sha, source_sha):
    selected = NativeMachineElf(image, image_sha)
    selected._bind_manifest_source(source_sha)
    return selected


def _admit_machine_elf(manifest_path):
    """Fresh source, manifest and image custody before every selection.

An already returned object retains its immutable mapping. A new selection,
including a warm-cache or pinned-worker hit, must still admit current bytes.
The worker bundle remains the only authority while its explicit scope exists.
"""
    from .hia_native_helpers import pinned_image
    pinned = pinned_image(manifest_path, SOURCE, SCHEMA, NativeMachineElf)
    path = Path(manifest_path).resolve(strict=True)
    raw = _read_limit(path, 16384)
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_pairs)
    if (type(value) is not dict or set(value) != {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            or value['schema'] != SCHEMA
            or any(type(value[k]) is not str or len(value[k]) != 64
                   or any(c not in '0123456789abcdef' for c in value[k])
                   for k in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid native ELF manifest')
    name = value['image_path']
    if (type(name) is not str or not name or name in {'.', '..'}
            or '\x00' in name or Path(name).name != name):
        raise ValueError('native ELF executable must be a sibling basename')
    source_bytes = SOURCE.read_bytes()
    if sha256(source_bytes).hexdigest() != value['source_sha256']:
        raise ValueError('native ELF source identity mismatch')
    image_path = path.parent / name
    image = _read_limit(image_path, 1 << 20)
    if not image or sha256(image).hexdigest() != value['image_sha256']:
        raise ValueError('native ELF executable identity mismatch')
    if pinned is None:
        selected = _mapped(image, value['image_sha256'], value['source_sha256'])
    else:
        if (type(pinned) is not NativeMachineElf
                or pinned.admitted_source_sha256 != value['source_sha256']
                or pinned.image_sha256 != value['image_sha256']):
            raise ValueError('native ELF inputs differ from the pinned worker bundle')
        selected = pinned
    if (path.read_bytes() != raw or SOURCE.read_bytes() != source_bytes
            or image_path.read_bytes() != image):
        raise ValueError('native ELF selection changed during admission')
    return selected, raw, source_bytes


def installed_machine_elf(manifest_path):
    return _admit_machine_elf(manifest_path)[0]
