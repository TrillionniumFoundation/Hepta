"""Explicit full Slot control selection without probing user Store/image getters.

Non-data descriptors preserve ordinary instance/subclass overrides. Unselected
lookup returns the exact original descriptor binding; it adds no forwarding
frame to the original method. Selected v1/direct instance and class access retain the original HIA Python
bridge. Only an explicitly authorized live v5 capsule creates a captured C
callable. Both branches expose the original argument signature. The C route
never falls back after a stale authority, identity change or provider failure.
"""
from __future__ import annotations

from contextvars import ContextVar
from hashlib import sha256
import json
import os
from pathlib import Path
import threading
import types
from . import hia_native_helpers as _mechanical_authority

SELECTOR = 'HEPTA_HIA_SLOT_OPERATIONS_MANIFEST'
_OWNER = ContextVar('hia_slot_operations_owner', default=None)


class _ManifestOwner:
    __slots__ = ('image', 'path', 'manifest', 'source_path', 'source',
                 'image_path', 'image_bytes')

    def __init__(self, path, image=None):
        from .hia_slot_operations_native import installed_slot_operations, NativeSlotOperations, SOURCE
        from .hia_store_lifecycle_native import _regular_bytes
        from .hia_json_preflight_native import _unique_manifest_pairs
        selected = installed_slot_operations(path)
        self.path = Path(path).resolve(strict=True)
        self.manifest = _regular_bytes(self.path, 16384)
        value = json.loads(self.manifest, object_pairs_hook=_unique_manifest_pairs)
        self.source_path = SOURCE
        self.source = _regular_bytes(SOURCE, 8 << 20)
        self.image_path = self.path.parent / value['image_path']
        self.image_bytes = _regular_bytes(self.image_path, 1 << 20)
        if (sha256(self.source).hexdigest() != value['source_sha256']
                or sha256(self.image_bytes).hexdigest() != value['image_sha256']):
            raise ValueError('Slot control source changed during explicit binding')
        if image is not None and (type(image) is not NativeSlotOperations
                or image.image_sha256 != value['image_sha256']
                or image.admitted_source_sha256 != value['source_sha256']):
            raise ValueError('declared Slot controller differs from the admitted manifest')
        self.image = selected if image is None else image
        self.check()

    def check(self):
        from .hia_store_lifecycle_native import _regular_bytes
        from .hia_slot_operations_native import SlotOperationsUnknown
        if (_regular_bytes(self.path, 16384) != self.manifest
                or _regular_bytes(self.source_path, 8 << 20) != self.source
                or _regular_bytes(self.image_path, 1 << 20) != self.image_bytes):
            raise SlotOperationsUnknown('explicit Slot controller identity changed')
        # A currently installed administrator bundle remains authoritative.
        # Declaring a different mapped object does not extend that bundle.
        from .hia_native_helpers import pinned_image
        from .hia_slot_operations_native import SCHEMA, NativeSlotOperations
        pinned = pinned_image(str(self.path), self.source_path, SCHEMA, NativeSlotOperations)
        if pinned is not None and pinned is not self.image:
            raise SlotOperationsUnknown('Slot controller differs from the worker-pinned image')
        return self.image


class _LazyManifestOwner:
    """A captured route; admission occurs after original signature binding."""
    __slots__ = ('path', 'binding')

    def __init__(self, path):
        self.path, self.binding = path, None

    def check(self):
        binding = self.binding
        if binding is None:
            binding = _ManifestOwner(self.path)
            self.binding = binding
        return binding.check()


class SlotOperationsOwnerScope:
    """Explicit controller authority for original callers that clear env.

A scope grants no new helper to an old administrator bundle. A captured selected
method cannot reuse a closed or foreign-thread/PID scope. A direct manifest
method may run in a new thread as before: its actual Frame is created there.
    """
    __slots__ = ('binding', 'image', 'pid', 'thread', 'active', 'entered', 'token')

    def __init__(self, manifest_path, *, image=None):
        self.binding = _ManifestOwner(manifest_path, image)
        self.image = self.binding.image
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.active = self.entered = False
        self.token = None

    def check(self):
        from .hia_slot_operations_native import SlotOperationsUnknown
        if (not self.active or self.pid != os.getpid()
                or self.thread != threading.get_ident()):
            raise SlotOperationsUnknown('Slot controller scope is stale or transferred')
        self.binding.check()
        selected = os.environ.get(SELECTOR)
        if SELECTOR in os.environ and not selected:
            raise ValueError('Slot controller selector must not be empty')
        if selected is not None and Path(selected).resolve(strict=True) != self.binding.path:
            raise SlotOperationsUnknown('Slot controller selector conflicts with its explicit scope')
        return self.image

    def __enter__(self):
        if self.entered:
            raise RuntimeError('Slot controller scope cannot be reused')
        if self.pid != os.getpid() or self.thread != threading.get_ident():
            raise RuntimeError('Slot controller scope belongs to its creator')
        self.binding.check()
        self.entered = self.active = True
        self.token = _OWNER.set(self)
        try:
            self.check()
        except BaseException:
            self.active = False
            _OWNER.reset(self.token)
            self.token = None
            raise
        return self

    def __exit__(self, kind, error, traceback):
        self.active = False
        token, self.token = self.token, None
        if token is not None:
            _OWNER.reset(token)
        return False


def slot_operations_owner(manifest_path, *, image=None):
    return SlotOperationsOwnerScope(manifest_path, image=image)


def _selected_owner():
    # Route observation only. Do not map/attest/check a captured scope while
    # merely retrieving a method: Python must first bind the exact original
    # signature and evaluate caller arguments. The bridge then checks it.
    scope = _OWNER.get()
    if scope is not None:
        return scope
    if SELECTOR not in os.environ:
        return None
    return _LazyManifestOwner(os.environ[SELECTOR])



class _MechanicalOwner:
    """One captured C route; same digest in a later scope is not authority."""
    __slots__ = ("binding", "bridge", "pid", "thread")

    def __init__(self, binding, bridge):
        self.binding, self.bridge = binding, bridge
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self._check_bridge()

    def _check_bridge(self):
        if self.pid != os.getpid() or self.thread != threading.get_ident():
            raise ValueError("mechanical callable belongs to its creating process and thread")
        current = _mechanical_authority.selected_mechanical_bridge(
            "slot-mechanical", "hepta.slot.mechanical.cpython-gil-linux.v1")
        if current is not self.bridge:
            raise ValueError("mechanical callable belongs to its original v5 authority")
        return current

    def admit_runtime(self):
        self._check_bridge()
        from .hia_slot_mechanical import admit_runtime
        admit_runtime()
        self._check_bridge()

    def check(self):
        self._check_bridge()
        image = self.binding.check()
        self._check_bridge()
        return image

class _SlotControlMethod:
    """Intentionally non-data: Python's original override priority remains."""
    __slots__ = ('mode', 'name', 'references', 'is_static', 'qualname', 'module')

    def __init__(self, mode, name, references):
        original = references[name]
        function = original.__func__ if type(original) is staticmethod else original
        self.mode, self.name, self.references = mode, name, references
        self.is_static = type(original) is staticmethod
        self.qualname, self.module = function.__qualname__, function.__module__

    def __get__(self, instance, owner=None):
        binding = _selected_owner()
        if binding is None:
            return self.references[self.name].__get__(instance, owner)
        from .hia_slot_operations_native import SlotOperationsFrame
        bridge = _mechanical_authority.selected_mechanical_bridge(
            "slot-mechanical", "hepta.slot.mechanical.cpython-gil-linux.v1")
        if bridge is not None:
            from .hia_slot_operations_native import SlotOperationsUnknown
            from .hia_slot_mechanical import bind, CONTINUATIONS
            captured = _MechanicalOwner(binding, bridge)
            function = bind(CONTINUATIONS[self.mode], captured, SlotOperationsFrame,
                            SlotOperationsUnknown, self.mode, self.name,
                            self.qualname, self.module, admission=captured.admit_runtime)
            if self.is_static or instance is None:
                return function
            return function.__get__(instance, owner)
        template = _TEMPLATES[self.mode]
        # No closure, dynamic class, extra hidden argument, or cached user
        # receiver. The actual original signature binds before bridge code;
        # class calls and instance calls use the same new template code.
        namespace = {
            '__builtins__': __builtins__,
            '_slot_binding': binding,
            '_SlotFrame': SlotOperationsFrame,
        }
        function = types.FunctionType(template.__code__, namespace, self.name,
                                      template.__defaults__)
        function.__kwdefaults__ = template.__kwdefaults__
        function.__qualname__ = self.qualname
        function.__module__ = self.module
        function.__doc__ = 'Selected HIA Slot control bridge; source is the new template.'
        if self.is_static or instance is None:
            return function
        return function.__get__(instance, owner)


def install_slot_control_methods(cls):
    names = (
        '__init__', '_execute', '_call', 'snapshot', 'validate_u64', 'conditional',
        '_begin', 'admit_evaluation', 'admit_net_benefit', 'adopt', 'rollback',
        '_lease_value', 'acquire', 'lease', 'release',
    )
    if '_hia_slot_reference_methods' in vars(cls):
        raise RuntimeError('Slot controller dispatch was already installed')
    references = {name: vars(cls)[name] for name in names}
    cls._hia_slot_reference_methods = references
    for mode, name in enumerate(names, 1):
        setattr(cls, name, _SlotControlMethod(mode, name, references))
    return cls


def _bridge_1(self, store, image):
    controller = _slot_binding.check()
    frame = _SlotFrame(controller, 1, {"self": self, "store": store, "image": image})
    del self, store, image
    return frame.finish()

def _bridge_2(self, connection, statement, parameters=()):
    image = _slot_binding.check()
    frame = _SlotFrame(image, 2, {"self": self, "connection": connection, "statement": statement, "parameters": parameters})
    del self, connection, statement, parameters
    return frame.finish()

def _bridge_3(self, opcode, fields=(), *, labels=(), state=None, **values):
    image = _slot_binding.check()
    frame = _SlotFrame(image, 3, {"self": self, "opcode": opcode, "fields": fields, "labels": labels, "state": state, "values": values})
    del self, opcode, fields, labels, state, values
    return frame.finish()

def _bridge_4(self, slot):
    image = _slot_binding.check()
    frame = _SlotFrame(image, 4, {"self": self, "slot": slot})
    del self, slot
    return frame.finish()

def _bridge_5(self, value, label):
    image = _slot_binding.check()
    frame = _SlotFrame(image, 5, {"self": self, "value": value, "label": label})
    del self, value, label
    return frame.finish()

def _bridge_6(self, args, snapshot_reader):
    image = _slot_binding.check()
    frame = _SlotFrame(image, 6, {"self": self, "args": args, "snapshot_reader": snapshot_reader})
    del self, args, snapshot_reader
    return frame.finish()

def _bridge_7(self, epoch, target=None):
    image = _slot_binding.check()
    frame = _SlotFrame(image, 7, {"self": self, "epoch": epoch, "target": target})
    del self, epoch, target
    return frame.finish()

def _bridge_8(self, evaluation, objective):
    image = _slot_binding.check()
    frame = _SlotFrame(image, 8, {"self": self, "evaluation": evaluation, "objective": objective})
    del self, evaluation, objective
    return frame.finish()

def _bridge_9(self, objective):
    image = _slot_binding.check()
    frame = _SlotFrame(image, 9, {"self": self, "objective": objective})
    del self, objective
    return frame.finish()

def _bridge_10(self, args, snapshot, evaluation, abi, native):
    image = _slot_binding.check()
    frame = _SlotFrame(image, 10, {"self": self, "args": args, "snapshot": snapshot, "evaluation": evaluation, "abi": abi, "native": native})
    del self, args, snapshot, evaluation, abi, native
    return frame.finish()

def _bridge_11(self, args, snapshot, native):
    image = _slot_binding.check()
    frame = _SlotFrame(image, 11, {"self": self, "args": args, "snapshot": snapshot, "native": native})
    del self, args, snapshot, native
    return frame.finish()

def _bridge_12(fields):
    image = _slot_binding.check()
    frame = _SlotFrame(image, 12, {"fields": fields})
    del fields
    return frame.finish()

def _bridge_13(self, target_slot, snapshot_reader, native):
    image = _slot_binding.check()
    frame = _SlotFrame(image, 13, {"self": self, "target_slot": target_slot, "snapshot_reader": snapshot_reader, "native": native})
    del self, target_slot, snapshot_reader, native
    return frame.finish()

def _bridge_14(self, lease, *, release=False, connection=None):
    image = _slot_binding.check()
    frame = _SlotFrame(image, 14, {"self": self, "lease": lease, "release": release, "connection": connection})
    del self, lease, release, connection
    return frame.finish()

def _bridge_15(self, lease):
    image = _slot_binding.check()
    frame = _SlotFrame(image, 15, {"self": self, "lease": lease})
    del self, lease
    return frame.finish()

_TEMPLATES = {
    1: _bridge_1,
    2: _bridge_2,
    3: _bridge_3,
    4: _bridge_4,
    5: _bridge_5,
    6: _bridge_6,
    7: _bridge_7,
    8: _bridge_8,
    9: _bridge_9,
    10: _bridge_10,
    11: _bridge_11,
    12: _bridge_12,
    13: _bridge_13,
    14: _bridge_14,
    15: _bridge_15,
}
