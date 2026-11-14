"""HIA-owned service artifact-input policy with fixed object/effect ports.

Owns the six exact profile/Core/native/build-receipt input policies and their
held emission-selector route. The image performs all policy tests and loops.
Storage, Core checking, context/signature owners and hashing remain explicitly
declared subproviders. This does not claim a complete native runtime.
"""
from __future__ import annotations

import builtins
from contextvars import ContextVar
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import struct
import sys

from .hia_json_preflight_native import _source_resource_path
from .hia_machine_plan_control_native import (
    PlanFrame, NativeMachinePlanControl, _Cell, _EMPTY,
    Issued, _read_word, _capture_with_handler)

SOURCE = _source_resource_path('examples/hia_bootstrap/service_artifacts.hepta')
SCHEMA = 'hepta.hia.service-artifacts-native.v1'
SELECTOR = 'HEPTA_HIA_SERVICE_ARTIFACTS_MANIFEST'
ARITIES = {'_profile': 4, '_program': 3, '_signature_values': 3, '_native': 4, '_build_receipt': 5, '_build_inputs': 5}
_IMPORTS = {}
_ACTIVE = ContextVar('hia_service_artifacts_owner', default=None)
_UNCONFIRMED_IMAGE_CLEANUP = []
_WITH_UNKNOWN = {}


class ArtifactsUnknown(RuntimeError):
    """A native/effect handoff is unconfirmed; no permission is recreated."""


def _manifest_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate service-artifacts manifest field')
        result[key] = value
    return result


def _regular_bytes(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
            raise ValueError('service-artifacts input must be a bounded ordinary file')
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in fields):
        raise ValueError('service-artifacts input changed while being read')
    return raw


@lru_cache(maxsize=3)
def _mapped_artifacts(raw, expected):
    return NativeArtifactsImage(raw, expected)


def installed_artifacts(manifest_path, *, capture_identity=False):
    """Fresh admission; later execution retains this actual immutable mapping.

    An active worker bundle is authoritative. The cache shares only immutable
    executable bytes, never an admission decision or a mutable file snapshot.
    Each returned checker capability owns its exact source/manifest bytes.
    """
    from .hia_native_helpers import pinned_image
    selected = pinned_image(manifest_path, SOURCE, SCHEMA, NativeArtifactsImage)
    path = Path(manifest_path).resolve(strict=True)
    raw = _regular_bytes(path, 16384)
    value = json.loads(raw, object_pairs_hook=_manifest_pairs)
    fields = {'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
    if (type(value) is not dict or set(value) != fields or value['schema'] != SCHEMA
            or any(type(value[key]) is not str or len(value[key]) != 64
                   or any(char not in '0123456789abcdef' for char in value[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid service-artifacts manifest')
    name = value['image_path']
    if (type(name) is not str or not name or name in ('.', '..')
            or any(ord(char) < 32 for char in name) or Path(name).name != name):
        raise ValueError('service-artifacts image must be a sibling basename')
    source_raw = _regular_bytes(SOURCE, 8 << 20)
    if sha256(source_raw).hexdigest() != value['source_sha256']:
        raise ValueError('service-artifacts source identity mismatch')
    image_path = path.parent / name
    image_raw = _regular_bytes(image_path, 1 << 20)
    if sha256(image_raw).hexdigest() != value['image_sha256']:
        raise ValueError('service-artifacts image identity mismatch')
    if selected is None:
        selected = _mapped_artifacts(image_raw, value['image_sha256'])
    elif type(selected) is not NativeArtifactsImage or selected.image_sha256 != value['image_sha256']:
        raise ValueError('service-artifacts mapping differs from its pinned worker image')
    if (_regular_bytes(path, 16384) != raw or _regular_bytes(SOURCE, 8 << 20) != source_raw
            or _regular_bytes(image_path, 1 << 20) != image_raw):
        raise ValueError('service-artifacts selection changed during admission')
    if capture_identity:
        from .hia_checker_identity import hold_native_owner
        return hold_native_owner(SELECTOR, selected, raw, source_raw)
    return selected


def admitted_artifacts(*, capture_identity=False):
    selected = os.environ.get(SELECTOR)
    if not selected:
        return None
    return installed_artifacts(selected, capture_identity=capture_identity)


def _match_exception(frame, slot):
    # This invokes the interpreter's real exception matching, not isinstance
    # (which has different metaclass behavior and accepts non-exception types).
    # No borrowed error or match type is saved in a transport named local.
    try:
        frame.image._delivery.deliver(frame.error)
    except frame._get(slot) as delivered:
        if delivered is not frame.error:
            frame._uncertain = True
            raise
        return 1
    except BaseException as delivered:
        if delivered is not frame.error:
            frame._uncertain = True
            raise
        return 0
    frame._uncertain = True
    raise ArtifactsUnknown('artifacts exception delivery returned')


class ArtifactsFrame(PlanFrame):
    def __init__(self, *args, **kwargs):
        self._region_child = None
        self._region_value = _EMPTY
        self._region_returned = False
        super().__init__(*args, **kwargs)

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
            raise ArtifactsUnknown('artifacts named slot is outside its frame')
        value = self.values[slot]
        if slot in self.cells:
            value = value.value
        if value is _EMPTY:
            return self.image.foreign.unbound(name, role)
        return value

    def _call(self, args, raw):
        if raw == (0, 251):
            if args:
                raise ArtifactsUnknown('request re-raise operands differ')
            raise
        if raw == (0, 253):
            if len(args) != 2 or type(self._get(args[0])) is not dict:
                raise ArtifactsUnknown('artifacts dictionary-update ABI differs')
            return self.image.foreign.update_dict(self, args[0], args[1])
        if raw in ((0, 254), (1, 254)):
            if len(args) != 3 + raw[0] or type(self._get(args[1])) is not tuple:
                raise ArtifactsUnknown('artifacts mapping-prepare ABI differs')
            if raw[0] == 0:
                return self.image.foreign.merge_empty(self, *args)
            return self.image.foreign.merge_kind(self, *args)
        if raw == (0, 255):
            if len(args) != 3:
                raise ArtifactsUnknown('artifacts mapping-call ABI differs')
            return self.image.foreign.mapping_call(self, *args)
        if len(raw) < 2 or len(raw) != 2 + raw[1] or len(args) != 1 + raw[0] + raw[1]:
            raise ArtifactsUnknown('artifacts ordinary-call ABI differs')
        key = (raw[0], tuple(self.image.literal(index) for index in raw[2:]))
        call = self.image.foreign.CALLS.get(key)
        if call is None:
            raise ArtifactsUnknown('artifacts call shape is outside the fixed policy')
        return call(self, args)

    def _function(self, args, raw, vector):
        if len(raw) != 2:
            raise ArtifactsUnknown('artifacts closure representation differs')
        mode, generator = raw
        if generator not in (0, 1) or len(args) != generator:
            raise ArtifactsUnknown('artifacts closure entry representation differs')
        layout = self.image.layouts.get(mode)
        if layout is None or (layout[1] == 'generator') != bool(generator):
            raise ArtifactsUnknown('artifacts closure mode differs')
        captures = tuple(self.values[slot] for slot in vector)
        if len(captures) != layout[4] or any(type(cell) is not _Cell for cell in captures):
            raise ArtifactsUnknown('artifacts captured a non-cell or wrong closure')
        if generator:
            frame = ArtifactsFrame(self.image, mode, (self._get(args[0]),), captures,
                                    witness=self.witness)
            def native_generator():
                value = None
                try:
                    while True:
                        value = None
                        if frame.drive() == 0:
                            return
                        value = frame.take(yielded=True)
                        yield value
                finally:
                    value = None
            return native_generator()
        image, witness = self.image, self.witness
        def native_function(*arguments):
            frame = ArtifactsFrame(image, mode, arguments, captures, witness=witness)
            arguments = None
            return image.finish(frame)
        return native_function

    def _drive_region(self,mode,vector):
        captures=tuple(self.values[slot] for slot in vector)
        if any(type(cell) is not _Cell for cell in captures):
            raise ArtifactsUnknown('service-artifacts with region captured a non-cell')
        child=ArtifactsFrame(self.image,mode,(),captures,witness=self.witness)
        self._region_child=child
        captures=None
        child.handled=self.handled
        self._region_value=self.image.finish(child)
        if type(self._region_value) is not tuple or len(self._region_value)!=2:
            self._uncertain=True
            raise ArtifactsUnknown('service-artifacts region lacks its HIA terminal record')
        self._region_returned=True

    def _with_region(self,manager,mode,target,vector):
        if self._region_child is not None or self._region_value is not _EMPTY:
            self._uncertain=True
            raise ArtifactsUnknown('service-artifacts context-manager port is reentered')
        self._region_returned=False
        try:
            if target==65535:
                with self._move(manager):
                    self._drive_region(mode,vector)
            else:
                with self._move(manager) as entered:
                    self._set(target,entered)
                    entered=None
                    self._drive_region(mode,vector)
            child=self._region_child
            if (child is None or child._uncertain or not child.closed
                    or not child._terminal_taken or child.pending is not None):
                self._uncertain=True
                raise ArtifactsUnknown('context manager suppressed an unconfirmed HIA body')
            if self._region_returned:
                if child._status!=5 or not child._retired:
                    self._uncertain=True
                    raise ArtifactsUnknown('context manager returned a non-successful HIA body')
                return self._region_value,1
            if child._status!=3:
                self._uncertain=True
                raise ArtifactsUnknown('context manager has no confirmed suppressed exception')
            return None,0
        finally:
            child=self._region_child
            if self._uncertain or (child is not None and child._uncertain):
                self._uncertain=True
                _WITH_UNKNOWN[self.nonce]=self
            else:
                self._region_value=_EMPTY
                self._region_child=None


    def _effect(self):
        op, destinations, args, raw, vector = self._parts()
        if op == 15 and len(raw) == 3 and raw[0] == 2:
            if len(raw) != 3 or len(args) != 1 or destinations or vector:
                raise ArtifactsUnknown('artifacts named-delete representation differs')
            slot = args[0]
            if type(slot) is not int or not 0 <= slot < len(self.values):
                raise ArtifactsUnknown('artifacts named-delete slot is outside its frame')
            if ((self.values[slot].value if slot in self.cells else self.values[slot]) is _EMPTY):
                return self.image.foreign.unbound(self.image.literal(raw[1]), raw[2])
            self._clear(slot)
            return 0
        if op == 14 and raw:
            if len(raw) != 2 or raw[0] != 1 or len(args) != 2 or destinations or vector:
                raise ArtifactsUnknown('artifacts attribute-store representation differs')
            setattr(self._get(args[0]), self.image.literal(raw[1]), self._get(args[1]))
            return 0
        if op == 9 and len(raw) == 3 and raw[1] == 250:
            if len(args) != 1 or len(destinations) != 1:
                raise ArtifactsUnknown('artifacts with-region representation differs')
            result, flag = self._with_region(args[0], raw[0], raw[2], vector)
            self._set(destinations[0], (flag, result))
            result = None
            return 0
        if op == 13 and raw == (4,):
            if len(destinations) != 4 or len(args) != 1 or vector:
                raise ArtifactsUnknown('artifacts four-value unpack representation differs')
            first, second, third, fourth = self._get(args[0])
            self._set(destinations[0], first)
            self._set(destinations[1], second)
            self._set(destinations[2], third)
            self._set(destinations[3], fourth)
            first = second = third = fourth = None
            return 0
        if op == 19:
            if len(raw) < 2 or len(destinations) != 1 or vector:
                raise ArtifactsUnknown('artifacts import representation differs')
            if raw[0] == 0 and not args:
                module = self.image.literal(raw[1])
                names = tuple(self.image.literal(index) for index in raw[2:])
                if module not in _IMPORTS or any(name not in _IMPORTS[module] for name in names):
                    raise ArtifactsUnknown('artifacts import is outside fixed ports')
                port = self.image._import_names.get((module, names))
                if port is None:
                    raise ArtifactsUnknown('artifacts import group differs')
                self._set(destinations[0], port())
            elif raw[0] == 1 and len(raw) == 2 and len(args) == 1:
                name = self.image.literal(raw[1])
                port = self.image._import_from.get(name)
                if port is None:
                    raise ArtifactsUnknown('artifacts imported field differs')
                self._set(destinations[0], port(self._get(args[0])))
            else:
                raise ArtifactsUnknown('artifacts import phase differs')
            return 0
        if op == 15 and raw:
            if len(raw) != 2 or len(args) != 1 or len(destinations) != 1 or vector:
                raise ArtifactsUnknown('artifacts named-load representation differs')
            self._set(destinations[0], self._load_named(args[0], self.image.literal(raw[0]), raw[1]))
            return 0
        if op == 21:
            if len(args) != 1 or destinations or raw or vector:
                raise ArtifactsUnknown('artifacts exception matcher representation differs')
            return _match_exception(self, args[0])
        return super()._effect()

    def service(self, issued):
        # Same issued-object/native-preclaim protocol as the frozen Plan
        # engine. The additional flag prevents a failing physical exception
        # mechanism from being acknowledged as a known foreign policy error.
        if (self.closed and not self._retiring) or issued is not self.pending or type(issued) is not Issued:
            raise ArtifactsUnknown('artifacts observation is not the issued permission')
        if type(issued.raw) is not bytes or issued.raw != self.frame_bytes or self.executed:
            raise ArtifactsUnknown('artifacts observation changed or was consumed')
        self.executed = True
        try:
            if self._invoke(2, op=_read_word(issued.raw, 32)) != 4:
                raise ArtifactsUnknown('artifacts observation claim refused')
            observed = _capture_with_handler(self)
            if self._uncertain:
                if not observed[0]:
                    raise observed[1]
                raise ArtifactsUnknown('artifacts physical effect lost its outcome')
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


class NativeArtifactsImage(NativeMachinePlanControl):
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

    def literal(self, index):
        if type(index) is not int or not 0 <= index < self._literal_count:
            raise ArtifactsUnknown('artifacts scalar literal index differs')
        if index not in self._literals:
            at = struct.unpack_from('<I', self.table, self._literal_offsets + 4 * index)[0]
            kind, size = struct.unpack_from('<BQ', self.table, at)
            if kind in (5, 6):
                if at + 9 + size > len(self.table) or kind == 6 and size != 8:
                    raise ArtifactsUnknown('artifacts scalar literal extent differs')
                raw = self.table[at + 9:at + 9 + size]
                self._literals[index] = raw if kind == 5 else struct.unpack('<d', raw)[0]
        if index in self._literals:
            return self._literals[index]
        return super().literal(index)

    def _bind_namespace(self, namespace):
        # Fixed CPython representation ports are admitted only when an actual
        # native image is selected. Default service imports retain the public
        # package's Python 3.11 support and do not run a 3.12+ ABI template.
        from . import hia_service_artifacts_foreign
        self.foreign = hia_service_artifacts_foreign
        if sha256(self.table).hexdigest() != self.foreign.TABLE_SHA256:
            raise ArtifactsUnknown('complete request HIA policy table differs')
        from . import hia_agent_service
        if namespace is None:
            namespace = vars(hia_agent_service)
        if type(namespace) is not dict:
            raise TypeError('artifacts requires the actual service global namespace')
        self.namespace = namespace
        self._import_names, self._import_from = self.foreign.import_ports(namespace)
        self.modes = {name: (number, arity) for number, (name, arity) in enumerate(ARITIES.items(), 1)}
        self.layouts = {}
        if type(self.foreign.FUNCTION_LAYOUT) is not tuple or len(self.foreign.FUNCTION_LAYOUT) != self.function_count:
            raise ArtifactsUnknown('complete artifacts function inventory differs')
        for expected, item in enumerate(self.foreign.FUNCTION_LAYOUT, 1):
            if (type(item) is not tuple or len(item) != 5 or item[0] != expected
                    or type(item[0]) is not int or item[1] not in ('function', 'lambda', 'generator', 'with_region')
                    or any(type(value) is not int or value < 0 for value in item[2:])):
                raise ArtifactsUnknown('artifacts lexical layout is not canonical')
            mode, kind, slots, arity, captures = item
            entry, actual_slots, info, metadata = self.function(mode)
            expected_info = arity | ((kind == 'generator') << 16) | (captures << 32)
            if slots != actual_slots or info != expected_info:
                raise ArtifactsUnknown('artifacts HIA lexical layout differs from the fixed bridge')
            self.layouts[mode] = item
        for mode, arity in self.modes.values():
            if self.function(mode)[2] != arity:
                raise ArtifactsUnknown('artifacts public method argument representation differs')
    def prepare(self, name, arguments, captures=(), *, witness=None):
        if type(name) is str:
            mode, arity = self.modes[name]
            if type(arguments) is not tuple or len(arguments) != arity or captures:
                raise ArtifactsUnknown('artifacts bound argument count differs')
        else:
            mode = name
        return ArtifactsFrame(self, mode, arguments, captures, witness=witness)

    def run(self, name, *arguments):
        frame = self.prepare(name, arguments)
        arguments = None
        return self.finish(frame)


class NativeArtifactsService:
    """An immutable held image/custody scope; no Python reference to service."""
    def __init__(self, image, *, checker_custody=None):
        if type(image) is not NativeArtifactsImage:
            raise TypeError('artifacts service requires its actual admitted image')
        self.image, self.custody, self.closed = image, checker_custody, False

    def checker_owner(self):
        if self.custody is None:
            raise ArtifactsUnknown('artifacts owner lacks actual captured checker custody')
        return self.custody

    def prepare(self, name, arguments):
        if self.closed:
            raise ArtifactsUnknown('artifacts service is closed for new work')
        return self.image.prepare(name, arguments)

    def finish(self, frame):
        if self.closed:
            raise ArtifactsUnknown('artifacts service is closed for new work')
        token = _ACTIVE.set(self)
        try:
            return self.image.finish(frame)
        finally:
            _ACTIVE.reset(token)


def active_artifacts():
    return _ACTIVE.get()
