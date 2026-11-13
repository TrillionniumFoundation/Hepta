"""Complete HIA-owned AgentStore construction and close control.

Explicit AgentStore selection retains this image for construction and close. The HIA
image owns all branches, sequencing, cleanup and exception decisions in the
original two bodies. CPython object/exception effects, filesystem operations,
SQLite and the four existing admitted subowners remain foreign providers.
"""
from __future__ import annotations
import builtins
from functools import lru_cache
import json
import stat
from hashlib import sha256
import os
from pathlib import Path
import struct

from .hia_json_preflight_native import _source_resource_path
from .hia_front_continuation import (
    ContinuationFrame, NativeContinuationImage, _Cell, _EMPTY,
    Issued, _read_word, _capture_with_handler)

SOURCE = _source_resource_path('examples/hia_bootstrap/store_lifecycle.hepta')
SCHEMA = 'hepta.hia.store-lifecycle-native.v1'
SELECTOR = 'HEPTA_HIA_STORE_LIFECYCLE_MANIFEST'
ARITIES = {'__init__': 2, 'close': 1}
_IMPORTS = {
    'hia_execution_budget': ('admitted_execution_budget', 'execution_budget_store'),
    'hia_request_journal_native': ('admitted_request_journal', 'request_journal_store'),
    'hia_artifact_namespace_native': ('admitted_artifact_namespace', 'artifact_namespace_store'),
    'hia_slot_ledger_continuation_native': ('admitted_slot_ledger', 'slot_ledger_store'),
}
_UNCONFIRMED_IMAGE_CLEANUP = []


class StoreLifecycleUnknown(RuntimeError):
    """An HIA or physical effect outcome is unconfirmed; no replay is granted."""


def _manifest_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate store-lifecycle manifest field')
        result[key] = value
    return result


def _regular_bytes(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
            raise ValueError('store-lifecycle input must be a bounded ordinary file')
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in fields):
        raise ValueError('store-lifecycle input changed while being read')
    return raw


@lru_cache(maxsize=3)
def _mapped_store_lifecycle(raw, expected):
    return NativeStoreLifecycleImage(raw, expected)


def installed_store_lifecycle(manifest_path, *, capture_identity=False):
    """Fresh admission; later execution retains this actual immutable mapping.

    An active worker bundle is authoritative. The cache shares only immutable
    executable bytes, never an admission decision or a mutable file snapshot.
    Each returned checker capability owns its exact source/manifest bytes.
    """
    from .hia_native_helpers import pinned_image
    selected = pinned_image(manifest_path, SOURCE, SCHEMA, NativeStoreLifecycleImage)
    path = Path(manifest_path).resolve(strict=True)
    raw = _regular_bytes(path, 16384)
    value = json.loads(raw, object_pairs_hook=_manifest_pairs)
    fields = {'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
    if (type(value) is not dict or set(value) != fields or value['schema'] != SCHEMA
            or any(type(value[key]) is not str or len(value[key]) != 64
                   or any(char not in '0123456789abcdef' for char in value[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid store-lifecycle manifest')
    name = value['image_path']
    if (type(name) is not str or not name or name in ('.', '..')
            or any(ord(char) < 32 for char in name) or Path(name).name != name):
        raise ValueError('store-lifecycle image must be a sibling basename')
    source_raw = _regular_bytes(SOURCE, 8 << 20)
    if sha256(source_raw).hexdigest() != value['source_sha256']:
        raise ValueError('store-lifecycle source identity mismatch')
    image_path = path.parent / name
    image_raw = _regular_bytes(image_path, 1 << 20)
    if sha256(image_raw).hexdigest() != value['image_sha256']:
        raise ValueError('store-lifecycle image identity mismatch')
    if selected is None:
        selected = _mapped_store_lifecycle(image_raw, value['image_sha256'])
    elif type(selected) is not NativeStoreLifecycleImage or selected.image_sha256 != value['image_sha256']:
        raise ValueError('store-lifecycle mapping differs from its pinned worker image')
    if (_regular_bytes(path, 16384) != raw or _regular_bytes(SOURCE, 8 << 20) != source_raw
            or _regular_bytes(image_path, 1 << 20) != image_raw):
        raise ValueError('store-lifecycle selection changed during admission')
    if capture_identity:
        from .hia_checker_identity import hold_native_owner
        return hold_native_owner(SELECTOR, selected, raw, source_raw)
    return selected


def admitted_store_lifecycle(*, capture_identity=False):
    selected = os.environ.get(SELECTOR)
    if not selected:
        return None
    return installed_store_lifecycle(selected, capture_identity=capture_identity)


def _match_exception(frame, slot):
    # This invokes the interpreter's real exception matching, not isinstance
    # (which has different metaclass behavior and accepts non-exception types).
    # No borrowed error or match type is saved in a transport named local.
    try:
        frame.image._delivery.deliver(frame.handled)
    except frame._get(slot) as delivered:
        if delivered is not frame.handled:
            frame._uncertain = True
            raise
        return 1
    except BaseException as delivered:
        if delivered is not frame.handled:
            frame._uncertain = True
            raise
        return 0
    frame._uncertain = True
    raise StoreLifecycleUnknown('store lifecycle exception delivery returned')


class StoreLifecycleFrame(ContinuationFrame):
    def _global(self, name):
        namespace = self.image.namespace
        if name in namespace:
            return namespace[name]
        if name in vars(builtins):
            return vars(builtins)[name]
        raise NameError("name '" + name + "' is not defined", name=name)

    def _move(self, slot):
        value = self._get(slot)
        self._clear(slot)
        return value

    def _load_named(self, slot, name, role):
        if type(slot) is not int or not 0 <= slot < len(self.values):
            raise StoreLifecycleUnknown('store lifecycle named slot is outside its frame')
        value = self.values[slot]
        if slot in self.cells:
            value = value.value
        if value is _EMPTY:
            return self.image.foreign.unbound(name, role)
        return value

    def _call(self, args, raw):
        if raw == (0, 251):
            if args:
                raise StoreLifecycleUnknown('lifecycle re-raise operands differ')
            raise
        if len(raw) < 2 or len(raw) != 2 + raw[1] or len(args) != 1 + raw[0] + raw[1]:
            raise StoreLifecycleUnknown('lifecycle ordinary-call ABI differs')
        key = (raw[0], tuple(self.image.literal(index) for index in raw[2:]))
        call = self.image.foreign.CALLS.get(key)
        if call is None:
            raise StoreLifecycleUnknown('lifecycle call shape is outside the original two bodies')
        return call(self, args)

    def _function(self, args, raw, vector):
        raise StoreLifecycleUnknown('lifecycle policy contains no nested function')

    def _effect(self):
        op, destinations, args, raw, vector = self._parts()
        if op == 14 and raw:
            if len(raw) != 2 or raw[0] != 1 or len(args) != 2 or destinations or vector:
                raise StoreLifecycleUnknown('lifecycle attribute-store representation differs')
            setattr(self._get(args[0]), self.image.literal(raw[1]), self._get(args[1]))
            return 0
        if op == 19:
            if len(raw) < 2 or len(destinations) != 1 or vector:
                raise StoreLifecycleUnknown('lifecycle import representation differs')
            if raw[0] == 0 and not args:
                module = self.image.literal(raw[1])
                names = tuple(self.image.literal(index) for index in raw[2:])
                if module not in _IMPORTS or names != _IMPORTS[module]:
                    raise StoreLifecycleUnknown('lifecycle import is outside its fixed ports')
                port = self.image._import_names.get((module, names))
                if port is None:
                    raise StoreLifecycleUnknown('lifecycle import group differs')
                self._set(destinations[0], port())
            elif raw[0] == 1 and len(raw) == 2 and len(args) == 1:
                name = self.image.literal(raw[1])
                port = self.image._import_from.get(name)
                if port is None:
                    raise StoreLifecycleUnknown('lifecycle imported field differs')
                self._set(destinations[0], port(self._get(args[0])))
            else:
                raise StoreLifecycleUnknown('lifecycle import phase differs')
            return 0
        if op == 15 and raw:
            if len(raw) != 2 or len(args) != 1 or len(destinations) != 1 or vector:
                raise StoreLifecycleUnknown('lifecycle named-load representation differs')
            self._set(destinations[0], self._load_named(args[0], self.image.literal(raw[0]), raw[1]))
            return 0
        if op == 21:
            if len(args) != 1 or destinations or raw or vector:
                raise StoreLifecycleUnknown('lifecycle exception matcher representation differs')
            return _match_exception(self, args[0])
        if op == 26:
            if raw != (1,) or len(destinations) != 1 or args or vector:
                raise StoreLifecycleUnknown('lifecycle handled-exception push differs')
            self._set(destinations[0], self.handled)
            self.handled = self.error
            self.error = None
            return 0
        if op == 27:
            if raw != (1,) or len(args) != 1 or destinations or vector:
                raise StoreLifecycleUnknown('lifecycle handled-exception restore differs')
            self.handled = self._move(args[0])
            return 0
        if op == 22:
            if raw != (1,) or len(destinations) != 1 or args or vector:
                raise StoreLifecycleUnknown('lifecycle current-exception load differs')
            self._set(destinations[0], self.handled)
            return 0
        return super()._effect()

    def service(self, issued):
        # Same issued-object/native-preclaim protocol as the frozen Plan
        # engine. The additional flag prevents a failing physical exception
        # mechanism from being acknowledged as a known foreign policy error.
        if (self.closed and not self._retiring) or issued is not self.pending or type(issued) is not Issued:
            raise StoreLifecycleUnknown('store lifecycle observation is not the issued permission')
        if type(issued.raw) is not bytes or issued.raw != self.frame_bytes or self.executed:
            raise StoreLifecycleUnknown('store lifecycle observation changed or was consumed')
        self.executed = True
        try:
            if self._invoke(2, op=_read_word(issued.raw, 32)) != 4:
                raise StoreLifecycleUnknown('store lifecycle observation claim refused')
            observed = _capture_with_handler(self)
            if self._uncertain:
                if not observed[0]:
                    raise observed[1]
                raise StoreLifecycleUnknown('store lifecycle physical effect lost its outcome')
            if observed[0]:
                self.reply = (observed[1], 0)
            else:
                self.error = observed[1]
                self.reply = (0, 1)
            observed = None
            self.completed = True
        except BaseException:
            self._uncertain = True
            self.close(release=False)
            raise


class NativeStoreLifecycleImage(NativeContinuationImage):
    def __init__(self, image, expected_sha256, namespace=None):
        try:
            super().__init__(image, expected_sha256)
            self._bind_namespace(namespace)
        except BaseException:
            self._entry = None
            for resource in (getattr(self, '_delivery', None), getattr(self, '_mapping', None)):
                if resource is not None:
                    try:
                        resource.close()
                    except BaseException:
                        _UNCONFIRMED_IMAGE_CLEANUP.append((self, resource))
            raise

    def _bind_namespace(self, namespace):
        # Fixed CPython representation ports are admitted only when an actual
        # native image is selected. Default service imports retain the public
        # package's Python 3.11 support and do not run a 3.12+ ABI template.
        from . import hia_store_lifecycle_foreign
        self.foreign = hia_store_lifecycle_foreign
        if sha256(self.table).hexdigest() != self.foreign.TABLE_SHA256:
            raise StoreLifecycleUnknown('complete request HIA policy table differs')
        from . import hia_agent_store
        if namespace is None:
            namespace = vars(hia_agent_store)
        if type(namespace) is not dict:
            raise TypeError('store lifecycle requires the actual store global namespace')
        self.namespace = namespace
        self._import_names, self._import_from = self.foreign.import_ports(namespace)
        self.modes = {name: (number, arity) for number, (name, arity) in enumerate(ARITIES.items(), 1)}
        self.layouts = {}
        if (self.function_count != 2 or type(self.foreign.FUNCTION_LAYOUT) is not tuple
                or len(self.foreign.FUNCTION_LAYOUT) != self.function_count):
            raise StoreLifecycleUnknown('complete store lifecycle function inventory differs')
        for expected, item in enumerate(self.foreign.FUNCTION_LAYOUT, 1):
            if (type(item) is not tuple or len(item) != 5 or item[0] != expected
                    or type(item[0]) is not int or item[1] != 'function'
                    or any(type(value) is not int or value < 0 for value in item[2:])):
                raise StoreLifecycleUnknown('store lifecycle lexical layout is not canonical')
            mode, kind, slots, arity, captures = item
            entry, actual_slots, info, metadata = self.function(mode)
            expected_info = arity | ((kind == 'generator') << 16) | (captures << 32)
            if slots != actual_slots or info != expected_info:
                raise StoreLifecycleUnknown('store lifecycle HIA lexical layout differs from the fixed bridge')
            self.layouts[mode] = item
        for mode, arity in self.modes.values():
            if self.function(mode)[2] != arity:
                raise StoreLifecycleUnknown('store lifecycle public method argument representation differs')

    def prepare(self, name, arguments, captures=(), *, witness=None):
        if type(name) is str:
            mode, arity = self.modes[name]
            if type(arguments) is not tuple or len(arguments) != arity or captures:
                raise StoreLifecycleUnknown('store lifecycle bound argument count differs')
        else:
            mode = name
        return StoreLifecycleFrame(self, mode, arguments, captures, witness=witness)

    def finish(self, frame):
        """Drive after the fixed facade has transferred its parameter owners."""
        completed = False
        try:
            if frame.drive() != 0:
                raise RuntimeError('native machine-plan public entry yielded')
            completed = True
            return frame.take()
        except BaseException:
            completed = False
            raise
        finally:
            frame.close(release=completed)


    def initialize(self, store, root):
        frame = self.prepare('__init__', (store, root))
        store = root = None
        return self.finish(frame)

    def close_store(self, store):
        frame = self.prepare('close', (store,))
        store = None
        return self.finish(frame)


class NativeStoreLifecycleOwner:
    """Per-Store held code; no reference back to the Store or Service.

    Close is intentionally repeatable with the original policy. It does not
    revoke the shared immutable image or recreate unknown frame permissions.
    """
    __slots__ = ('image', 'custody')

    def __init__(self, custody):
        from .hia_checker_identity import HeldNativeOwner, require_bound_checker_owner
        if type(custody) is not HeldNativeOwner:
            raise StoreLifecycleUnknown('store lifecycle requires an actual admitted capability')
        require_bound_checker_owner(SELECTOR, custody)
        if type(custody.image) is not NativeStoreLifecycleImage:
            raise StoreLifecycleUnknown('store lifecycle capability has another image type')
        self.image, self.custody = custody.image, custody

    def checker_owner(self):
        from .hia_checker_identity import require_bound_checker_owner
        require_bound_checker_owner(SELECTOR, self.custody)
        if self.image is not self.custody.image:
            raise StoreLifecycleUnknown('store lifecycle owner changed its held image')
        return self.custody

    def prepare(self, name, arguments):
        self.checker_owner()
        return self.image.prepare(name, arguments)

    def finish(self, frame):
        if frame.image is not self.image:
            raise StoreLifecycleUnknown('store lifecycle frame belongs to another image')
        return self.image.finish(frame)
