"""HIA-owned Agent verification coordination with fixed object/effect ports.

The image emits its complete immutable control program and chooses every
policy branch, object operation, once-only effect and retirement. Python holds
actual foreign objects; it does not import or interpret the policy authoring
source and never calls the seven retained reference bodies on this route.
Proof engines, proof-contract construction, storage, and native build/runtime
providers are separate declared dependencies, not claimed migrated here.
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
# A default import must not admit a selected-only CPython ABI. Keep the
# original mutable global binding: only its untouched initial sentinel loads.
_FOREIGN_NOT_LOADED = object()
_FOREIGN_MODULE_NAMESPACE = globals()
foreign = _FOREIGN_NOT_LOADED


def _load_foreign_ports():
    global foreign
    if _FOREIGN_MODULE_NAMESPACE.get('foreign') is _FOREIGN_NOT_LOADED:
        from . import hia_service_verification_foreign as foreign

SOURCE = _source_resource_path('examples/hia_bootstrap/service_verification.hiaasm')
SCHEMA = 'hepta.hia.service-verification-native.v1'
SELECTOR = 'HEPTA_HIA_SERVICE_VERIFICATION_MANIFEST'
ARITIES = {
    '_subject': 4, '_hia_verify': 2, '_verification': 5,
    '_replay_verification': 4, '_required_claims': 6,
    '_check_native_refinement_evidence': 6, '_native_refinement_binding': 5,
}
_ACTIVE = ContextVar('hia_service_verification_owner', default=None)
_UNCONFIRMED_IMAGE_CLEANUP = []


class VerificationUnknown(RuntimeError):
    """A native/effect handoff is unconfirmed; no permission is recreated."""


def _manifest_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate service-verification manifest field')
        result[key] = value
    return result


def _regular_bytes(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
            raise ValueError('service-verification input must be a bounded ordinary file')
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in fields):
        raise ValueError('service-verification input changed while being read')
    return raw


@lru_cache(maxsize=3)
def _mapped_verification(raw, expected):
    return NativeVerificationImage(raw, expected)


def installed_verification(manifest_path, *, capture_identity=False):
    """Fresh admission; later execution retains this actual immutable mapping.

    An active worker bundle is authoritative. The cache shares only immutable
    executable bytes, never an admission decision or a mutable file snapshot.
    Each returned checker capability owns its exact source/manifest bytes.
    """
    from .hia_native_helpers import pinned_image
    selected = pinned_image(manifest_path, SOURCE, SCHEMA, NativeVerificationImage)
    path = Path(manifest_path).resolve(strict=True)
    raw = _regular_bytes(path, 16384)
    value = json.loads(raw, object_pairs_hook=_manifest_pairs)
    fields = {'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
    if (type(value) is not dict or set(value) != fields or value['schema'] != SCHEMA
            or any(type(value[key]) is not str or len(value[key]) != 64
                   or any(char not in '0123456789abcdef' for char in value[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid service-verification manifest')
    name = value['image_path']
    if (type(name) is not str or not name or name in ('.', '..')
            or any(ord(char) < 32 for char in name) or Path(name).name != name):
        raise ValueError('service-verification image must be a sibling basename')
    source_raw = _regular_bytes(SOURCE, 8 << 20)
    if sha256(source_raw).hexdigest() != value['source_sha256']:
        raise ValueError('service-verification source identity mismatch')
    image_path = path.parent / name
    image_raw = _regular_bytes(image_path, 1 << 20)
    if sha256(image_raw).hexdigest() != value['image_sha256']:
        raise ValueError('service-verification image identity mismatch')
    if selected is None:
        selected = _mapped_verification(image_raw, value['image_sha256'])
    elif type(selected) is not NativeVerificationImage or selected.image_sha256 != value['image_sha256']:
        raise ValueError('service-verification mapping differs from its pinned worker image')
    if (_regular_bytes(path, 16384) != raw or _regular_bytes(SOURCE, 8 << 20) != source_raw
            or _regular_bytes(image_path, 1 << 20) != image_raw):
        raise ValueError('service-verification selection changed during admission')
    if capture_identity:
        from .hia_checker_identity import hold_native_owner
        return hold_native_owner(SELECTOR, selected, raw, source_raw)
    return selected


def admitted_verification(*, capture_identity=False):
    selected = os.environ.get(SELECTOR)
    if not selected:
        return None
    return installed_verification(selected, capture_identity=capture_identity)


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
    raise VerificationUnknown('verification exception delivery returned')


class VerificationFrame(PlanFrame):
    def _global(self, name):
        namespace = self.image.namespace
        if name in namespace:
            return namespace[name]
        if name in vars(builtins):
            return vars(builtins)[name]
        raise NameError("name '" + name + "' is not defined", name=name)

    def _move(self, slot):
        # Only a separately native-claimed CALL may reach this fixed move.
        # Original stack operands now belong to CPython's actual CALL stack,
        # so a callee error traceback cannot extend their lifetime via slots.
        value = self._get(slot)
        self._clear(slot)
        return value

    def _call(self, args, raw):
        if raw == (0, 253):
            if len(args) != 2 or type(self._get(args[0])) is not dict:
                raise VerificationUnknown('verification dictionary-update ABI differs')
            return foreign.update_dict(self, args[0], args[1])
        if raw in ((0, 254), (1, 254)):
            if len(args) != 3 + raw[0] or type(self._get(args[1])) is not tuple:
                raise VerificationUnknown('verification mapping-prepare ABI differs')
            if raw[0] == 0:
                return foreign.merge_empty(self, *args)
            return foreign.merge_kind(self, *args)
        if raw == (0, 255):
            if len(args) != 3:
                raise VerificationUnknown('verification mapping-call ABI differs')
            return foreign.mapping_call(self, *args)
        if len(raw) < 2 or len(raw) != 2 + raw[1] or len(args) != 1 + raw[0] + raw[1]:
            raise VerificationUnknown('verification ordinary-call ABI differs')
        key = (raw[0], tuple(self.image.literal(index) for index in raw[2:]))
        call = foreign.CALLS.get(key)
        if call is None:
            raise VerificationUnknown('verification call shape is outside the fixed policy')
        return call(self, args)

    def _function(self, args, raw, vector):
        mode, generator = raw
        if generator != 1 or len(args) != 1:
            raise VerificationUnknown('verification lazy-frame ABI differs')
        captures = tuple(self.values[slot] for slot in vector)
        if any(type(cell) is not _Cell for cell in captures):
            raise VerificationUnknown('verification captured a non-cell')
        frame = VerificationFrame(self.image, mode, (self._get(args[0]),), captures,
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

    def _effect(self):
        op, destinations, args, raw, vector = self._parts()
        if op == 13 and raw == (4,):
            if len(destinations) != 4 or len(args) != 1 or vector:
                raise VerificationUnknown('verification four-value unpack ABI differs')
            first, second, third, fourth = self._get(args[0])
            self._set(destinations[0], first)
            self._set(destinations[1], second)
            self._set(destinations[2], third)
            self._set(destinations[3], fourth)
            first = second = third = fourth = None
            return 0
        if op == 19:
            if len(raw) != 2 or args or vector or len(destinations) != 1:
                raise VerificationUnknown('verification import ABI differs')
            key = tuple(self.image.literal(i) for i in raw)
            if key == ('hia_program_native', 'validate_block_layout_plan'):
                from .hia_program_native import validate_block_layout_plan
                self._set(destinations[0], validate_block_layout_plan)
            elif key == ('hia_program_native', 'emit_program_machine'):
                from .hia_program_native import emit_program_machine
                self._set(destinations[0], emit_program_machine)
            elif key == ('hia_checker_identity', 'checker_native_selection'):
                from .hia_checker_identity import checker_native_selection
                self._set(destinations[0], checker_native_selection)
            elif key == ('hia_machine_plan', 'preservation_checks'):
                from .hia_machine_plan import preservation_checks
                self._set(destinations[0], preservation_checks)
            elif key == ('hia_safe_core_elf', 'bind_final_artifact'):
                from .hia_safe_core_elf import bind_final_artifact
                self._set(destinations[0], bind_final_artifact)
            else:
                raise VerificationUnknown('verification import is outside the fixed inventory')
            return 0
        if op == 21:
            if len(args) != 1 or destinations or raw or vector:
                raise VerificationUnknown('verification exception-match ABI differs')
            return _match_exception(self, args[0])
        return super()._effect()

    def service(self, issued):
        # Same issued-object/native-preclaim protocol as the frozen Plan
        # engine. The additional flag prevents a failing physical exception
        # mechanism from being acknowledged as a known foreign policy error.
        if (self.closed and not self._retiring) or issued is not self.pending or type(issued) is not Issued:
            raise VerificationUnknown('verification observation is not the issued permission')
        if type(issued.raw) is not bytes or issued.raw != self.frame_bytes or self.executed:
            raise VerificationUnknown('verification observation changed or was consumed')
        self.executed = True
        try:
            if self._invoke(2, op=_read_word(issued.raw, 32)) != 4:
                raise VerificationUnknown('verification observation claim refused')
            observed = _capture_with_handler(self)
            if self._uncertain:
                if not observed[0]:
                    raise observed[1]
                raise VerificationUnknown('verification physical effect lost its outcome')
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


class NativeVerificationImage(NativeMachinePlanControl):
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
        _load_foreign_ports()
        if namespace is None:
            from . import hia_agent_service
            namespace = vars(hia_agent_service)
        if type(namespace) is not dict:
            raise TypeError('verification requires the actual service global namespace')
        self.namespace = namespace
        self.modes = {name: (number, arity) for number, (name, arity) in enumerate(ARITIES.items(), 1)}
        if self.function_count != len(ARITIES) + 1:
            raise VerificationUnknown('complete verification function inventory differs')
        for mode, arity in self.modes.values():
            if self.function(mode)[2] != arity:
                raise VerificationUnknown('verification method argument ABI differs')
        if self.function(8)[2] & 0xffff != 1 or not self.function(8)[2] & (1 << 16):
            raise VerificationUnknown('verification lazy generator ABI differs')

    def prepare(self, name, arguments, captures=(), *, witness=None):
        mode, arity = self.modes[name]
        if type(arguments) is not tuple or len(arguments) != arity or captures:
            raise VerificationUnknown('verification bound argument count differs')
        return VerificationFrame(self, mode, arguments, witness=witness)

    def run(self, name, *arguments):
        frame = self.prepare(name, arguments)
        arguments = None
        return self.finish(frame)


class NativeVerificationService:
    """An immutable held image/custody scope; no Python reference to service."""
    def __init__(self, image, *, checker_custody=None):
        if type(image) is not NativeVerificationImage:
            raise TypeError('verification service requires its actual admitted image')
        self.image, self.custody, self.closed = image, checker_custody, False

    def checker_owner(self):
        if self.custody is None:
            raise VerificationUnknown('verification owner lacks actual captured checker custody')
        return self.custody

    def prepare(self, name, arguments):
        if self.closed:
            raise VerificationUnknown('verification service is closed for new work')
        return self.image.prepare(name, arguments)

    def finish(self, frame):
        if self.closed:
            raise VerificationUnknown('verification service is closed for new work')
        token = _ACTIVE.set(self)
        try:
            return self.image.finish(frame)
        finally:
            _ACTIVE.reset(token)


def active_verification():
    return _ACTIVE.get()
