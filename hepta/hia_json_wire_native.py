"""HIA-owned bounded JSON wire with a lazy, mechanical object observer.

The executable owns both traversals and every admission/output decision. Python
transports exact builtin type, identity, child, Unicode and integer magnitude
observations. It never serializes or recursively expands the input graph.
"""
from __future__ import annotations

import ctypes
import errno
import mmap
import struct
import sys
from typing import Protocol

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_program_tools import HIAEditRejected

SOURCE = _source_resource_path('examples/hia_bootstrap/json_wire.hiaasm')
SCHEMA = 'hepta.hia.json-wire-native.v1'
SELECTOR = 'HEPTA_HIA_JSON_WIRE_MANIFEST'
MAGIC = int.from_bytes(b'HIAWIR02', 'little')
CACHED_MAGIC = int.from_bytes(b'HIAWIR03', 'little')
KEY_CACHE_BYTES = 1024 * 160
MAXIMUM = 8 << 20
NONE, BOOL, INT, FLOAT, STRING, LIST, TUPLE, DICT, OPAQUE = range(9)
SUMMARY, CHILD, POINTS, LIMBS, DIGIT_LIMIT, FORMAT_FLOAT = range(1, 7)
ORDINARY_PROFILE = {
    'schema': 'hepta.hia.ordinary-json-wire-product-profile.v1',
    'selector': SELECTOR,
    'option_exact_types': ['NoneType', 'bool', 'int', 'float', 'str', 'bytes', 'tuple', 'frozenset'],
    'option_truth_owner': 'HIA_from_exact_type_and_magnitude_or_length_bits',
    'ordinary_renderer': 'None_or_exact_SelectedBinary64Renderer_after_source_admission',
    'budget_before_option_and_renderer_profile': True,
    'foreign_truth_hooks_and_mutable_option_objects': 'explicit_native_profile_refusal',
    'arbitrary_renderer_callbacks': 'explicit_native_profile_refusal',
    'unselected_owner': 'retained_reference',
    'entire_python_call_domain_replaced': False,
    'immutable_key_cache': 'HIAWIR03_only_for_fresh_stable_builtin_observer_without_renderer',
}

REASONS = {
    100: 'invalid JSON output byte budget',
    101: 'JSON input exceeds nesting depth before encoding',
    102: 'JSON input exceeds node/byte budget',
    103: 'JSON container exceeds queued-node/byte budget',
    104: 'cyclic JSON container',
    105: 'JSON integer exceeds byte budget',
    106: 'non-JSON in-process value',
    107: 'JSON object key collision after JSON conversion',
    108: 'JSON string exceeds byte budget before encoding',
    109: 'JSON key exceeds numeric byte budget',
    110: 'nonfinite JSON object key',
    111: 'nonfinite JSON number',
    112: 'invalid bounded JSON',
    113: 'unsupported JSON object key',
    114: 'JSON key exceeds byte budget',
    115: 'unpaired Unicode surrogate in UTF-8 JSON',
    116: 'JSON encoding exceeds byte budget',
    117: 'native JSON wire requires an immutable builtin ensure_ascii option',
    118: 'native JSON wire requires an immutable builtin sort_keys option',
    119: 'native ordinary JSON wire requires an admitted HIA binary64 renderer',
}


class SelectedBinary64Renderer:
    """A source-admitted HIA printer for the ordinary Agent wire selection.

    Construction retains the existing eager formatter-admission point. Exact
    type observation distinguishes this factory's printer from arbitrary
    Python callbacks; HIA makes the ordinary-profile admission decision.
    """
    __slots__ = ('_image',)

    def __init__(self, selected):
        from .hia_agent_binary64_format_native import installed_agent_binary64_format
        self._image = installed_agent_binary64_format(selected)

    def __call__(self, number):
        return self._image.render(number).decode('ascii')


class GraphObserver(Protocol):
    """Foreign observations requested individually by the HIA continuation.

    summary returns (kind,size,a,b). INT uses size=bit_length,a=negative;
    FLOAT uses a=IEEE64 bits; BOOL uses a=0/1; strings/containers use size=len.
    child(sequence,index,0) is an element; child(dict,index,0/1) is key/value.
    Codepoints retain isolated surrogates. Limbs are absolute-value little
    endian 32-bit words. Handles preserve identity and strong references.
    """
    def summary(self, handle: int) -> tuple[int, int, int, int]: ...
    def child(self, handle: int, index: int, part: int) -> int: ...
    def points(self, handle: int, start: int, count: int) -> tuple[int, ...]: ...
    def limbs(self, handle: int, start: int, count: int) -> tuple[int, ...]: ...


class ForeignGraphObserver:
    """Exact builtin transport. Registration does not inspect descendants."""
    def __init__(self):
        self._objects = {}
        self._identities = {}
        self._dict_cursors = {}
        self._magnitudes = {}

    def register(self, value):
        identity = id(value)
        old = self._identities.get(identity)
        if old is not None:
            return old
        handle = len(self._objects) + 1
        self._objects[handle] = value
        self._identities[identity] = handle
        return handle

    def value(self, handle):
        return self._objects[handle]

    def summary(self, handle):
        value = self.value(handle)
        kind = type(value)
        if value is None:
            return NONE, 0, 0, 0
        if kind is bool:
            return BOOL, 0, int(value), 0
        if kind is int:
            return INT, int.bit_length(value), int(value < 0), 0
        if kind is float:
            return FLOAT, 0, struct.unpack('<Q', struct.pack('<d', value))[0], 0
        if kind is str:
            return STRING, len(value), 0, 0
        if kind is list:
            return LIST, len(value), 0, 0
        if kind is tuple:
            return TUPLE, len(value), 0, 0
        if kind is dict:
            # A fresh observation starts a new traversal. Only requested pairs
            # are retained; no list(items), sorting or recursive transport.
            self._dict_cursors[handle] = (iter(value.items()), [])
            return DICT, len(value), 0, 0
        return OPAQUE, 0, 0, 0

    def child(self, handle, index, part):
        value = self.value(handle)
        if type(value) is dict:
            iterator, observed = self._dict_cursors[handle]
            while len(observed) <= index:
                observed.append(next(iterator))
            return self.register(observed[index][part])
        return self.register(value[index])

    def points(self, handle, start, count):
        value = self.value(handle)
        if (type(value) is str and type(start) is int and type(count) is int
                and 0 <= start <= len(value) and 0 <= count <= len(value) - start):
            # Convert only the window already requested by HIA. UTF-32LE with
            # surrogatepass is a mechanical codepoint representation, not JSON
            # admission or escaping. Keep the original indexing path for
            # subtypes and out-of-range direct observer calls.
            raw = value[start:start + count].encode('utf-32-le', 'surrogatepass')
            return struct.unpack('<' + 'I' * count, raw)
        return tuple(ord(value[index]) for index in range(start, start + count))

    def limbs(self, handle, start, count):
        value = self.value(handle)
        raw = self._magnitudes.get(handle)
        if raw is None:
            # Representation transport begins only after HIA asks for limbs.
            # No decimal conversion, numeric policy or graph preflight here.
            magnitude = abs(value)
            raw = int.to_bytes(magnitude, ((magnitude.bit_length() + 31) // 32) * 4, 'little')
            self._magnitudes[handle] = raw
        return struct.unpack_from('<' + 'I' * count, raw, start * 4)


_BUILTIN_OBSERVER_CLASS = ForeignGraphObserver
_BUILTIN_OBSERVER_METHODS = {
    name: (getattr(ForeignGraphObserver, name), getattr(ForeignGraphObserver, name).__code__)
    for name in ('__init__', 'register', 'value', 'summary', 'child', 'points', 'limbs')
}
_BUILTIN_DIGIT_LIMIT = sys.get_int_max_str_digits


def _immutable_key_capability(observer, renderer):
    """Observe a narrow, stable builtin transport capability; do not walk data.

    The ordinary entry creates this observer immediately before the session.
    Exact builtin strings cannot change after HIA admits their codepoints.
    Custom/virtual observers, replaced methods or instance fields, and every
    explicit renderer stay on the original uncached observation protocol.
    The capability assumes no asynchronous mutation of the interpreter's
    transport definitions during one synchronous session.
    """
    if (renderer is not None or ForeignGraphObserver is not _BUILTIN_OBSERVER_CLASS
            or type(observer) is not _BUILTIN_OBSERVER_CLASS
            or sys.get_int_max_str_digits is not _BUILTIN_DIGIT_LIMIT):
        return False
    methods = type.__getattribute__(_BUILTIN_OBSERVER_CLASS, '__dict__')
    if any(name in methods for name in ('__new__', '__getattribute__', '__getattr__')):
        return False
    for name, (method, code) in _BUILTIN_OBSERVER_METHODS.items():
        if methods.get(name) is not method or method.__code__ is not code:
            return False
    fields = object.__getattribute__(observer, '__dict__')
    # Check exact string keys before set/dict membership, so even an explicitly
    # supplied low-level instance cannot add a key with an equality/hash hook.
    keys = tuple(fields)
    if any(type(key) is not str for key in keys):
        return False
    expected = {'_objects', '_identities', '_dict_cursors', '_magnitudes'}
    if set(keys) != expected or any(type(fields[name]) is not dict for name in expected):
        return False
    return True


def buffer_sizes(maximum, *, key_cache=False):
    """Physical allocation mirrors the published ABI; HIA admits the budget."""
    physical = maximum if type(maximum) is int and 0 <= maximum <= MAXIMUM else 0
    budget = min(physical, 262144)
    slots = 2
    while slots < budget * 2:
        slots *= 2
    size = (32768 + (budget + 130) * 24 + budget * 64 + slots * 8
            + (physical + 64) * 2 + ((physical * 4 + 31) // 32) * 4 + 64 + 8192)
    if key_cache is True:
        size += KEY_CACHE_BYTES
    return physical, size


def _flag_fact(value):
    """Observe immutable builtin truth inputs without evaluating truthiness."""
    kind = type(value)
    if value is None:
        return 0, 0
    if kind is bool:
        return 1, int(value)
    if kind is int:
        return 2, int.bit_length(value)
    if kind is float:
        return 3, struct.unpack('<Q', struct.pack('<d', value))[0]
    if kind is str or kind is bytes or kind is tuple or kind is frozenset:
        return 4, len(value)
    return 5, 0


def _private_zeroed_buffer(size):
    """Keep the complete ABI extent without eagerly touching unused pages.

    The ctypes view retains an exported memoryview of the private mapping.
    That reference owns the mapping for the full buffer lifetime, including
    observers that raise and callers that retain a buffer after its session.
    No explicit close may run while such an export is still alive.
    """
    try:
        mapped = mmap.mmap(-1, size, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                           prot=mmap.PROT_READ | mmap.PROT_WRITE)
    except OSError as exc:
        if exc.errno == errno.ENOMEM:
            # Preserve the allocation-failure category of the old zeroed
            # ctypes allocation; it must not become an ordinary I/O rejection.
            raise MemoryError from None
        raise
    return (ctypes.c_char * size).from_buffer(mapped)


class WireSession:
    """Opaque HIA continuation plus protocol transport, independently testable."""
    def __init__(self, image, observer, root, maximum, *, ensure_ascii, sort_keys,
                 float_renderer=None, _renderer_profile=None, _builtin_keys=False):
        self.image, self.observer = image, observer
        self.float_renderer = float_renderer
        self.key_cache = _builtin_keys is True and _immutable_key_capability(observer, float_renderer)
        self._protocol_magic = CACHED_MAGIC if self.key_cache else MAGIC
        output_size, workspace_size = buffer_sizes(maximum, key_cache=self.key_cache)
        self.output_size = output_size
        self.output = _private_zeroed_buffer(max(1, output_size))
        self.workspace = _private_zeroed_buffer(workspace_size)
        if type(maximum) is int:
            kind, sign, bits = INT, int(maximum < 0), maximum.bit_length()
            low = abs(maximum) & ((1 << 64) - 1)
        else:
            kind, sign, bits, low = OPAQUE, 0, 0, 0
        # These are exact foreign type/value facts, not calls to __bool__.
        # HIA admits maximum before deciding either option or renderer profile.
        ascii_kind, ascii_value = _flag_fact(ensure_ascii)
        sort_kind, sort_value = _flag_fact(sort_keys)
        renderer_fact = int(float_renderer is not None) if _renderer_profile is None else _renderer_profile
        self.packet = struct.pack('<13Q', self._protocol_magic, 0, 0, root, kind, sign, bits, low,
                                  ascii_kind, ascii_value, sort_kind, sort_value, renderer_fact)
        if self.key_cache:
            self.packet += struct.pack('<Q', 1)
        self.finished = False

    def step(self, packet=None):
        if self.finished:
            raise RuntimeError('native JSON wire session is terminal')
        raw = self.packet if packet is None else packet
        # Exact bytes remain strongly referenced throughout this synchronous
        # call and ctypes transports their address as c_void_p. The verified
        # HIA parameter is readbuf; no input copy or writable view is needed.
        # Preserve the original conversion/length observations for other
        # explicitly supplied packet types, including bytes subclasses.
        source = raw if type(raw) is bytes else ctypes.create_string_buffer(raw, max(1, len(raw)))
        status = self.image._entry(source, len(raw), self.output, self.output_size,
                                   self.workspace, len(self.workspace))
        if status != 1:
            self.finished = True
        return status

    def observe(self):
        opcode, sequence = struct.unpack_from('<2Q', self.workspace, 8)
        handle, index, count, part = struct.unpack_from('<4Q', self.workspace, 200)
        a = b = c = d = 0
        payload = b''
        if opcode == SUMMARY:
            a, b, c, d = self.observer.summary(handle)
        elif opcode == CHILD:
            a = self.observer.child(handle, index, part)
        elif opcode == POINTS or opcode == LIMBS:
            method = self.observer.points if opcode == POINTS else self.observer.limbs
            values = method(handle, index, count)
            a = len(values)
            payload = struct.pack('<' + 'I' * a, *values)
        elif opcode == DIGIT_LIMIT:
            a = sys.get_int_max_str_digits()
        elif opcode == FORMAT_FLOAT:
            # The only supported callback profile is the existing selected
            # finite HIA binary64 printer, not an arbitrary JSON encoder hook.
            number = struct.unpack('<d', struct.pack('<Q', index))[0]
            rendered = self.float_renderer(number)
            payload = rendered.encode('ascii') if type(rendered) is str else rendered
            a = len(payload)
        else:
            raise RuntimeError('native JSON wire requested an unknown observation')
        self.packet = struct.pack('<7Q', self._protocol_magic, sequence, opcode, a, b, c, d) + payload
        return self.packet

    def run(self):
        try:
            while True:
                status = self.step()
                if status == 1:
                    self.observe()
                    continue
                if status == 2:
                    count, = struct.unpack_from('<Q', self.workspace, 112)
                    if count > self.output_size:
                        raise RuntimeError('native JSON wire returned an invalid extent')
                    return ctypes.string_at(self.output, count)
                if status in REASONS:
                    raise HIAEditRejected('E_HIA_EDIT: ' + REASONS[status])
                raise RuntimeError('native JSON wire continuation profile refused')
        except HIAEditRejected:
            raise
        except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
            raise HIAEditRejected('E_HIA_EDIT: invalid bounded JSON') from exc


class NativeJsonWire(NativeHiaJsonImage):
    def encode_observed(self, observer, root_handle, maximum=MAXIMUM, *, ensure_ascii=False,
                        sort_keys=True, float_renderer=None):
        return WireSession(self, observer, root_handle, maximum, ensure_ascii=ensure_ascii,
                           sort_keys=sort_keys, float_renderer=float_renderer).run()

    def encode(self, value, maximum=MAXIMUM, *, ensure_ascii=False, sort_keys=True, float_renderer=None):
        observer = ForeignGraphObserver()
        return self.encode_observed(observer, observer.register(value), maximum,
                                    ensure_ascii=ensure_ascii, sort_keys=sort_keys,
                                    float_renderer=float_renderer)

    def encode_ordinary(self, value, maximum, *, ensure_ascii=True, sort_keys=True, float_renderer=None):
        """Ordinary product profile; arbitrary renderer callbacks are explicit refusals."""
        observer = ForeignGraphObserver()
        profile = (0 if float_renderer is None else
                   1 if type(float_renderer) is SelectedBinary64Renderer else 2)
        return WireSession(self, observer, observer.register(value), maximum,
                           ensure_ascii=ensure_ascii, sort_keys=sort_keys,
                           float_renderer=float_renderer, _renderer_profile=profile,
                           _builtin_keys=True).run()


def installed_json_wire(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeJsonWire)
