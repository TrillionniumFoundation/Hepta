"""Explicit HIA worker control/report owner with native virtual graph output.

The Python boundary executes requested IO, calls, attributes and exact object
observations. Request admission remains independently selected; the unselected
request validator is an explicit retained foreign owner, not relabelled HIA.
"""
from __future__ import annotations

import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys

from .hia_json_preflight_native import (
    NativeHiaJsonImage, _load_manifest, _source_resource_path, _unique_manifest_pairs,
)
from .hia_json_wire_native import (
    ForeignGraphObserver, NativeJsonWire, SOURCE as WIRE_SOURCE, SCHEMA as WIRE_SCHEMA,
)

SOURCE = _source_resource_path('examples/hia_bootstrap/worker_report.hepta')
POLICY_SCHEMA = 'hepta.hia.worker-report-native.v1'
SCHEMA = 'hepta.hia.worker-report-bundle.v1'
SELECTOR = 'HEPTA_HIA_WORKER_REPORT_MANIFEST'
MAGIC = int.from_bytes(b'HIAWKR02', 'little')
HIGH = 1 << 63
NODE_BASE = 32768

# Raw exception descriptors avoid invoking user-defined __getattribute__ or
# __setattr__ while transporting the runtime's existing exception metadata.
_TRACEBACK = BaseException.__dict__['__traceback__']
_CONTEXT = BaseException.__dict__['__context__']


def _activation_state(exception):
    """Snapshot raw links a synthetic raise may change while breaking cycles.

    A previous foreign callback can connect the caller's active exception chain
    back to the exception being activated. CPython may cut that ambient link,
    so saving only the activated object's context would lose a real mutation.
    Identity traversal also bounds already cyclic chains without user hooks.
    """
    links, seen = [], set()
    current = sys.exception()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        context = _CONTEXT.__get__(current, BaseException)
        links.append((current, context))
        current = context
    if id(exception) not in seen:
        links.append((exception, _CONTEXT.__get__(exception, BaseException)))
    return _TRACEBACK.__get__(exception, BaseException), links


def _restore_activation(exception, state):
    traceback, links = state
    _TRACEBACK.__set__(exception, traceback)
    for current, context in links:
        _CONTEXT.__set__(current, context)


def _with_foreign_exception(exception, operation):
    """Execute one HIA-requested effect with its requested handled exception.

    Raising an existing object activates sys.exception() but would append an
    artificial traceback frame and may change an ambient context-chain link.
    Restore those raw fields before the actual effect. Leaving this except
    scope restores whatever handled exception the caller already had.
    """
    state = _activation_state(exception)
    try:
        raise exception
    except BaseException:
        _restore_activation(exception, state)
        return operation()


def _reraise_foreign(exception):
    """Propagate the observed foreign chain without replacing its context."""
    state = _activation_state(exception)
    try:
        raise exception
    except BaseException:
        _restore_activation(exception, state)
        raise


class WorkerGraphObserver:
    """Reads HIA-owned node descriptors and forwards original foreign handles."""
    def __init__(self, session):
        self.session = session
        self.foreign = ForeignGraphObserver()

    def register(self, value):
        handle = self.foreign.register(value)
        if handle >= HIGH:
            raise RuntimeError('worker foreign handle namespace exhausted')
        return handle

    def _node(self, handle):
        index = handle - HIGH
        count, = struct.unpack_from('<Q', self.session.workspace, 328)
        if not 0 < index < count:
            raise RuntimeError('invalid native worker virtual handle')
        return struct.unpack_from('<6Q', self.session.workspace, NODE_BASE + index * 48)

    def summary(self, handle):
        if handle < HIGH:
            return self.foreign.summary(handle)
        kind, size, subtype, a, b, c = self._node(handle)
        return kind, size, a if kind == 1 else 0, 0

    def child(self, handle, index, part):
        if handle < HIGH:
            return self.foreign.child(handle, index, part)
        kind, size, subtype, a, b, c = self._node(handle)
        if kind != 7 or index >= size or part not in (0, 1):
            raise RuntimeError('invalid native worker virtual dictionary observation')
        return struct.unpack_from('<Q', self.session.workspace, a + index * 16 + part * 8)[0]

    def points(self, handle, start, count):
        if handle < HIGH:
            return self.foreign.points(handle, start, count)
        kind, size, subtype, a, b, c = self._node(handle)
        if kind != 4 or start > size or count > size - start:
            raise RuntimeError('invalid native worker virtual string observation')
        if subtype == 0:
            return struct.unpack_from('<' + 'I' * count, self.session.workspace, a + start * 4)
        if subtype == 1:
            return self.points(a, b + start, count)
        if subtype == 2:
            first = min(count, max(0, c - start))
            left = self.points(a, start, first) if first else ()
            right = self.points(b, max(0, start - c), count - first) if first != count else ()
            return left + right
        raise RuntimeError('unknown native worker virtual string representation')

    def limbs(self, handle, start, count):
        if handle >= HIGH:
            raise RuntimeError('worker virtual arena contains no integer magnitude nodes')
        return self.foreign.limbs(handle, start, count)

    def value(self, handle):
        if handle < HIGH:
            return self.foreign.value(handle)
        kind, size, subtype, a, b, c = self._node(handle)
        if kind == 4:
            # Literal/slice representation transport for attribute names and
            # actual text IO. Virtual dictionaries are never materialized.
            return ''.join(chr(point) for at in range(0, size, 1024)
                           for point in self.points(handle, at, min(1024, size - at)))
        if kind == 1:
            return bool(a)
        if kind == 0:
            return None
        raise RuntimeError('native worker virtual graph cannot become a hosted container')


def _dict_primitives():
    """Raw CPython dictionary iteration/known-hash lookup, without comparison policy.

    Dict equality reuses stored key hashes rather than calling __hash__ again.
    The HIA walker requests each pair and decides how the corresponding values
    compare. These exported CPython primitives are a declared foreign ABI seam.
    """
    if sys.implementation.name != 'cpython':
        raise RuntimeError('native worker dictionary observations require CPython')
    next_item = getattr(ctypes.pythonapi, '_PyDict_Next', None)
    stored_hash = next_item is not None
    if next_item is None:
        # Newer CPython builds do not export the private hash-bearing variant.
        # Public PyDict_Next still avoids a Python iterator's mutation guard.
        next_item = ctypes.pythonapi.PyDict_Next
    next_item.argtypes = [ctypes.py_object, ctypes.POINTER(ctypes.c_ssize_t),
                          ctypes.POINTER(ctypes.py_object), ctypes.POINTER(ctypes.py_object)]
    if stored_hash:
        next_item.argtypes += [ctypes.POINTER(ctypes.c_ssize_t)]
    next_item.restype = ctypes.c_int
    lookup = ctypes.pythonapi._PyDict_GetItem_KnownHash
    lookup.argtypes = [ctypes.py_object, ctypes.py_object, ctypes.c_ssize_t]
    lookup.restype = ctypes.c_void_p
    return next_item, lookup, stored_hash


def _pure_builtin_key_hash(key):
    """A raw immutable builtin observation, never an arbitrary __hash__ call.

    This deliberately does not walk tuple/frozenset keys to inspect their
    descendants. Builds without stored-hash iteration retain an explicit
    unsupported foreign-key boundary rather than add observable hash hooks.
    """
    kind = type(key)
    if kind is str:
        return str.__hash__(key)
    if kind is bytes:
        return bytes.__hash__(key)
    if kind is int:
        return int.__hash__(key)
    if kind is float:
        return float.__hash__(key)
    if kind is bool:
        return bool.__hash__(key)
    if kind is type(None):
        return type(None).__hash__(key)
    raise RuntimeError('native worker runtime cannot observe the stored hash of this foreign dictionary key')


class WorkerSession:
    def __init__(self, owner, args, parser, identities, worker):
        self.owner, self.args, self.parser, self.worker = owner, args, parser, worker
        self.workspace = ctypes.create_string_buffer(262144)
        self.output = ctypes.create_string_buffer(8)
        self.observer = WorkerGraphObserver(self)
        reg = self.observer.register
        self.packet = struct.pack('<14Q', MAGIC, 0, 0, int(args.installation_manifest),
            int(args.request_json_stdin), reg(args.state_root), reg(args.artifact_root),
            reg(args.expected_worker_sha256), reg(args.expected_backend_sha256),
            reg(args.expected_catalog_sha256), reg(identities), reg(worker.VERSION), reg(None), 0)
        self.finished = False
        self._dict_next, self._dict_lookup, self._dict_stored_hash = _dict_primitives()

    def step(self, packet=None):
        if self.finished:
            raise RuntimeError('native worker continuation is terminal')
        raw = self.packet if packet is None else packet
        source = ctypes.create_string_buffer(raw, max(1, len(raw)))
        code = self.owner.policy._entry(source, len(raw), self.output, len(self.output),
                                        self.workspace, len(self.workspace))
        if code != 1:
            self.finished = True
        return code

    def observe(self):
        handled, = struct.unpack_from('<Q', self.workspace, 424)
        if handled:
            return _with_foreign_exception(self.observer.value(handled), self._observe)
        return self._observe()

    def _observe(self):
        opcode, sequence = struct.unpack_from('<2Q', self.workspace, 8)
        a, b, c, d = struct.unpack_from('<4Q', self.workspace, 200)
        reg, value = self.observer.register, self.observer.value
        x = y = z = t = 0
        payload = b''
        recovered = 0
        error = 0
        try:
            if opcode == 1:
                x, y, z, t = self.observer.summary(a)
            elif opcode == 2:
                x = self.observer.child(a, b, d)
            elif opcode in (3, 4):
                observe = self.observer.points if opcode == 3 else self.observer.limbs
                words = observe(a, b, c)
                x = len(words)
                payload = struct.pack('<' + 'I' * x, *words)
            elif opcode == 5:
                x = reg(value(a)[value(b)])
            elif opcode == 6:
                x = int(value(b) in value(a))
            elif opcode == 7:
                result = getattr(value(a), value(b), value(c)) if d else getattr(value(a), value(b))
                x = reg(result)
            elif opcode == 8:
                x = reg(value(a)())
            elif opcode == 9:
                x = reg(value(a)(value(b), value(c)))
            elif opcode == 10:
                from .hia_agent_service import HIAAgentService
                x = reg(HIAAgentService(value(a), artifact_roots=value(b)))
            elif opcode == 11:
                x = reg(self.worker.sys.stdin.buffer.read(a))
            elif opcode == 12:
                x = reg(self.worker.installation_manifest())
            elif opcode == 13:
                x = reg(self.worker.os.environ.get(value(a)))
            elif opcode == 14:
                from .hia_worker_request_native import installed_worker_request
                x = reg(installed_worker_request(value(a)))
            elif opcode == 15:
                def assigned(request):
                    nonlocal recovered
                    recovered = reg(request)
                x = reg(self.worker._reference_admission(value(a), value(b), assigned))
            elif opcode == 16:
                result = self.worker.AgentRejected(value(a), value(b), retry_action=value(c))
                if d:
                    raise result
                x = reg(result)
            elif opcode == 17:
                x = reg(self.worker.uuid.uuid4())
            elif opcode == 18:
                x = reg(str(value(a)))
            elif opcode == 19:
                x = reg(type(value(a)).__name__)
            elif opcode == 20:
                # HIA requests rich comparison only at an opaque leaf. The
                # complete manifest and builtin containers are never compared
                # here; their structure and builtin scalars belong to HIA.
                x = reg(value(a) != value(b) if c else value(a) == value(b))
            elif opcode == 21:
                x = int(bool(value(a)))
            elif opcode == 22:
                x = reg(self.parser.error(value(a)))
            elif opcode == 23:
                from .hia_agent_binary64_format_native import installed_agent_binary64_format
                x = reg(installed_agent_binary64_format(value(a)))
            elif opcode == 24:
                formatter = None
                if b:
                    image = value(b)
                    formatter = lambda number: image.render(number).decode('ascii')
                raw = self.owner.wire.encode_observed(self.observer, a, 8 * 1024 * 1024,
                    ensure_ascii=False, sort_keys=True, float_renderer=formatter)
                x = reg(raw)
            elif opcode == 25:
                x = reg(self.worker.sys.stdout.buffer.write(value(a) + value(b).encode('utf-8')))
            elif opcode == 26:
                x = reg(self.worker.sys.stderr.write(value(a)))
            elif opcode == 30:
                from .hia_worker_request_native import NativeRequestRejected
                try:
                    x = reg(value(a)(value(b), value(c)))
                except NativeRequestRejected as exc:
                    recovered = reg(exc.request)
                    raise
            elif opcode == 31:
                stored_hash = ctypes.c_ssize_t(c).value
                pointer = self._dict_lookup(value(a), value(b), stored_hash)
                x = int(bool(pointer))
                if pointer:
                    y = reg(ctypes.cast(pointer, ctypes.py_object).value)
            elif opcode == 32:
                x = reg(value(a)[:b])
            elif opcode == 33:
                x = reg(value(a) + value(b))
            elif opcode == 34:
                position = ctypes.c_ssize_t(b)
                key, item, stored_hash = ctypes.py_object(), ctypes.py_object(), ctypes.c_ssize_t()
                arguments = (value(a), ctypes.byref(position), ctypes.byref(key), ctypes.byref(item))
                x = int(self._dict_next(*arguments, ctypes.byref(stored_hash)) if self._dict_stored_hash
                        else self._dict_next(*arguments))
                if x:
                    key_value, item_value = key.value, item.value
                    if not self._dict_stored_hash:
                        stored_hash.value = _pure_builtin_key_hash(key_value)
                    y, z = reg(key_value), reg(item_value)
                t = position.value
                payload = struct.pack('<Q', stored_hash.value & ((1 << 64) - 1))
            elif opcode == 35:
                x = sys.getrecursionlimit()
            elif opcode == 36:
                grown = ctypes.create_string_buffer(a)
                ctypes.memmove(grown, self.workspace, len(self.workspace))
                self.workspace = grown
            elif opcode == 37:
                raise RecursionError('maximum recursion depth exceeded in comparison')
            else:
                raise RuntimeError('unknown native worker foreign instruction')
        except BaseException as exc:
            # Match exception classes from their real type, without invoking
            # an exception object's __class__/code/message/str properties.
            error = 1
            x = reg(exc)
            y = int(issubclass(type(exc), (ValueError, OSError, TypeError, OverflowError, RecursionError)))
            z, t, payload = recovered, 0, b''
        self.packet = struct.pack('<8Q', MAGIC, sequence, opcode, error, x, y, z, t) + payload
        return self.packet

    def run(self):
        while True:
            code = self.step()
            if code == 1:
                self.observe()
            elif code == 2:
                result, = struct.unpack_from('<Q', self.workspace, 192)
                if result not in (0, 2):
                    raise RuntimeError('invalid native worker exit code')
                return result
            elif code == 3:
                handle, = struct.unpack_from('<Q', self.workspace, 32)
                _reraise_foreign(self.observer.value(handle))
            else:
                raise RuntimeError('native worker continuation profile refused')


class NativeWorkerReport:
    def __init__(self, policy, wire):
        self.policy, self.wire = policy, wire

    def run(self, args, parser, identities, worker):
        return WorkerSession(self, args, parser, identities, worker).run()


def installed_worker_report(path):
    from .hia_native_helpers import pinned_bundle
    captured = pinned_bundle(path, SCHEMA, NativeWorkerReport)
    if captured is not None:
        return captured
    path = Path(path).resolve(strict=True)
    with path.open('rb') as handle:
        raw = handle.read(8193)
    if len(raw) > 8192:
        raise ValueError('native worker report bundle exceeds manifest extent')
    bundle = json.JSONDecoder(object_pairs_hook=_unique_manifest_pairs).decode(raw.decode('utf-8'))
    if type(bundle) is not dict or set(bundle) != {'schema', 'policy_manifest', 'policy_manifest_sha256',
                                                'wire_manifest', 'wire_manifest_sha256'} or bundle['schema'] != SCHEMA:
        raise ValueError('invalid native worker report bundle')
    children = {}
    for name in ('policy', 'wire'):
        target = bundle[name + '_manifest']
        expected = bundle[name + '_manifest_sha256']
        if (type(target) is not str or not target or Path(target).is_absolute() or '..' in Path(target).parts
                or type(expected) is not str or len(expected) != 64
                or any(c not in '0123456789abcdef' for c in expected)):
            raise ValueError('invalid native worker report child identity')
        child = (path.parent / target).resolve(strict=True)
        with child.open('rb') as handle:
            child_raw = handle.read(16385)
        if len(child_raw) > 16384 or sha256(child_raw).hexdigest() != expected:
            raise ValueError('native worker report child manifest identity mismatch')
        children[name] = (child, child_raw)
    sources = {'policy': SOURCE, 'wire': WIRE_SOURCE}
    source_hashes = {name: sha256(source.read_bytes()).hexdigest() for name, source in sources.items()}
    # Pass the exact bundle-bound manifest bytes to the shared immutable image
    # loader. Reopening a child through a second public loader would otherwise
    # permit loading different bytes from those named by the bundle.
    policy = _load_manifest(str(children['policy'][0]), children['policy'][1],
                            source_hashes['policy'], POLICY_SCHEMA, NativeHiaJsonImage)
    wire = _load_manifest(str(children['wire'][0]), children['wire'][1],
                          source_hashes['wire'], WIRE_SCHEMA, NativeJsonWire)
    if (path.read_bytes() != raw
            or any(child.read_bytes() != child_raw for child, child_raw in children.values())
            or any(sha256(source.read_bytes()).hexdigest() != source_hashes[name]
                   for name, source in sources.items())):
        raise ValueError('native worker report selection changed while loading')
    return NativeWorkerReport(policy, wire)
