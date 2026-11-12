"""HIA-owned proof-contract policy over fixed foreign object mechanisms.

The eight original functions and their eight lazy frames live in the native
HIA control program. Solver/checker identities and object/hash operations are
explicit foreign dependencies; none of the eight old policy bodies is called.
"""
from __future__ import annotations

import builtins
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path
import stat

from .hia_json_preflight_native import _source_resource_path
from .hia_machine_plan_control_native import (
    PlanFrame, NativeMachinePlanControl, _Cell, Issued, _read_word,
    _capture_with_handler)
# A default import must not admit a selected-only CPython ABI. Keep the
# original mutable global binding: only its untouched initial sentinel loads.
_FOREIGN_NOT_LOADED = object()
_FOREIGN_MODULE_NAMESPACE = globals()
foreign = _FOREIGN_NOT_LOADED


def _load_foreign_ports():
    global foreign
    if _FOREIGN_MODULE_NAMESPACE.get('foreign') is _FOREIGN_NOT_LOADED:
        from . import hia_proof_contract_foreign as foreign
from .hia_proof_contract_selection import proof_contract_scope

SOURCE = _source_resource_path('examples/hia_bootstrap/proof_contract.hiaasm')
SCHEMA = 'hepta.hia.proof-contract-native.v1'
SELECTOR = 'HEPTA_HIA_PROOF_CONTRACT_MANIFEST'
ARITIES = {'_item': 2, '_require': 2, '_safe_core_method': 3, 'proof_subject': 2,
           '_method': 4, 'proof_result': 8, 'assumptions_document': 1,
           'proof_contract_description': 0}
_UNCONFIRMED_IMAGE_CLEANUP = []


class ProofContractUnknown(RuntimeError):
    """A claimed effect has no confirmed outcome; it cannot be replayed."""


def _manifest_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate proof-contract manifest field')
        result[key] = value
    return result


def _regular_bytes(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
            raise ValueError('proof-contract input must be a bounded ordinary file')
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in fields):
        raise ValueError('proof-contract input changed while being read')
    return raw


@lru_cache(maxsize=3)
def _mapped_proof_contract(raw, expected):
    return NativeProofContractImage(raw, expected)


def installed_proof_contract(manifest_path, *, capture_identity=False):
    """Fresh admission; later execution retains this actual immutable mapping.

    An active worker bundle is authoritative. The cache shares only immutable
    executable bytes, never an admission decision or a mutable file snapshot.
    Each returned checker capability owns its exact source/manifest bytes.
    """
    from .hia_native_helpers import pinned_image
    selected = pinned_image(manifest_path, SOURCE, SCHEMA, NativeProofContractImage)
    path = Path(manifest_path).resolve(strict=True)
    raw = _regular_bytes(path, 16384)
    value = json.loads(raw, object_pairs_hook=_manifest_pairs)
    fields = {'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
    if (type(value) is not dict or set(value) != fields or value['schema'] != SCHEMA
            or any(type(value[key]) is not str or len(value[key]) != 64
                   or any(char not in '0123456789abcdef' for char in value[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid proof-contract manifest')
    name = value['image_path']
    if (type(name) is not str or not name or name in ('.', '..')
            or any(ord(char) < 32 for char in name) or Path(name).name != name):
        raise ValueError('proof-contract image must be a sibling basename')
    source_raw = _regular_bytes(SOURCE, 8 << 20)
    if sha256(source_raw).hexdigest() != value['source_sha256']:
        raise ValueError('proof-contract source identity mismatch')
    image_path = path.parent / name
    image_raw = _regular_bytes(image_path, 1 << 20)
    if sha256(image_raw).hexdigest() != value['image_sha256']:
        raise ValueError('proof-contract image identity mismatch')
    if selected is None:
        selected = _mapped_proof_contract(image_raw, value['image_sha256'])
    elif type(selected) is not NativeProofContractImage or selected.image_sha256 != value['image_sha256']:
        raise ValueError('proof-contract mapping differs from its pinned worker image')
    if (_regular_bytes(path, 16384) != raw or _regular_bytes(SOURCE, 8 << 20) != source_raw
            or _regular_bytes(image_path, 1 << 20) != image_raw):
        raise ValueError('proof-contract selection changed during admission')
    if capture_identity:
        from .hia_checker_identity import hold_native_owner
        return hold_native_owner(SELECTOR, selected, raw, source_raw)
    return selected


def admitted_proof_contract(*, capture_identity=False):
    selected = os.environ.get(SELECTOR)
    if not selected:
        return None
    return installed_proof_contract(selected, capture_identity=capture_identity)

def _match_exception(frame, slot):
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
    raise ProofContractUnknown('proof-contract exception delivery returned')


class ProofContractFrame(PlanFrame):
    def _global(self, name):
        if name in self.image.namespace:
            value = self.image.namespace[name]
            if name in self.image._helpers and value is self.image.public_entries[name]:
                return self.image._helpers[name]
            return value
        if name in vars(builtins):
            return vars(builtins)[name]
        raise NameError("name '" + name + "' is not defined", name=name)

    def _move(self, slot):
        value = self._get(slot)
        self._clear(slot)
        return value

    def _call(self, args, raw):
        if raw in ((0, 252), (1, 252)):
            if len(args) != 1:
                raise ProofContractUnknown('proof-contract format ABI differs')
            return (foreign.format_plain if raw[0] == 0 else foreign.format_02d)(self, args[0])
        if raw == (4, 251):
            if len(args) != 4:
                raise ProofContractUnknown('proof-contract string assembly ABI differs')
            return foreign.build_string(self, args)
        if raw == (0, 253):
            if len(args) != 2 or type(self._get(args[0])) is not dict:
                raise ProofContractUnknown('proof-contract dictionary-update ABI differs')
            return foreign.update_dict(self, args[0], args[1])
        if len(raw) < 2 or len(raw) != 2 + raw[1] or len(args) != 1 + raw[0] + raw[1]:
            raise ProofContractUnknown('proof-contract CALL ABI differs')
        key = (raw[0], tuple(self.image.literal(index) for index in raw[2:]))
        primitive = foreign.CALLS.get(key)
        if primitive is None:
            raise ProofContractUnknown('proof-contract CALL shape is outside its original inventory')
        return primitive(self, args)

    def _function(self, args, raw, vector):
        mode, generator = raw
        if generator != 1 or len(args) != 1:
            raise ProofContractUnknown('proof-contract lazy-frame ABI differs')
        captures = tuple(self.values[slot] for slot in vector)
        if any(type(cell) is not _Cell for cell in captures):
            raise ProofContractUnknown('proof-contract captured a non-cell')
        frame = ProofContractFrame(self.image, mode, (self._get(args[0]),), captures,
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
        if op == 19:
            if len(destinations) != 1 or vector:
                raise ProofContractUnknown('proof-contract import result ABI differs')
            if len(raw) == 2 and raw[0] == 0 and raw[1] in (0, 1) and not args:
                self._set(destinations[0], self.image._import_groups[raw[1]]())
            elif len(raw) == 2 and raw[0] == 1 and len(args) == 1:
                name = self.image.literal(raw[1])
                if name not in self.image._import_fields:
                    raise ProofContractUnknown('proof-contract imported field differs')
                self._set(destinations[0], self.image._import_fields[name](self._get(args[0])))
            elif raw == (2,) and not args:
                self._set(destinations[0], self.image._import_plain())
            else:
                raise ProofContractUnknown('proof-contract import operation differs')
            return 0
        if op == 21:
            if len(args) != 1 or destinations or raw or vector:
                raise ProofContractUnknown('proof-contract exception-match ABI differs')
            return _match_exception(self, args[0])
        return super()._effect()

    def service(self, issued):
        if (self.closed and not self._retiring) or issued is not self.pending or type(issued) is not Issued:
            raise ProofContractUnknown('proof-contract effect is not its issued permission')
        if type(issued.raw) is not bytes or issued.raw != self.frame_bytes or self.executed:
            raise ProofContractUnknown('proof-contract permission changed or was consumed')
        self.executed = True
        try:
            if self._invoke(2, op=_read_word(issued.raw, 32)) != 4:
                raise ProofContractUnknown('proof-contract native effect claim refused')
            observed = _capture_with_handler(self)
            if self._uncertain:
                if not observed[0]:
                    raise observed[1]
                raise ProofContractUnknown('proof-contract physical effect lost its outcome')
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


class NativeProofContractImage(NativeMachinePlanControl):
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
        from . import hia_proof_contract
        if namespace is None:
            namespace = vars(hia_proof_contract)
        if type(namespace) is not dict:
            raise TypeError('proof-contract requires its actual module namespace')
        self.namespace = namespace
        self.public_entries = vars(hia_proof_contract)['_NATIVE_PROOF_PUBLIC_ENTRIES']
        self.modes = {name: (number, arity) for number, (name, arity) in enumerate(ARITIES.items(), 1)}
        if self.function_count != 16:
            raise ProofContractUnknown('complete proof-contract function inventory differs')
        for mode, arity in self.modes.values():
            if self.function(mode)[2] != arity:
                raise ProofContractUnknown('proof-contract argument ABI differs')
        for mode in range(9, 17):
            if self.function(mode)[2] & 0xffff != 1 or not self.function(mode)[2] & (1 << 16):
                raise ProofContractUnknown('proof-contract lazy argument ABI differs')
        self._import_groups, self._import_plain, self._import_fields = foreign.import_ports(namespace)
        owner = self
        def item(identity, statement):
            frame = owner.prepare('_item', (identity, statement))
            identity = statement = None
            return owner.finish(frame)
        def require(condition, message):
            frame = owner.prepare('_require', (condition, message))
            condition = message = None
            return owner.finish(frame)
        def safe_core_method(status, subject, evidence):
            frame = owner.prepare('_safe_core_method', (status, subject, evidence))
            status = subject = evidence = None
            return owner.finish(frame)
        def subject(record, target_profile):
            frame = owner.prepare('proof_subject', (record, target_profile))
            record = target_profile = None
            return owner.finish(frame)
        def method(claim, status, subject, evidence):
            frame = owner.prepare('_method', (claim, status, subject, evidence))
            claim = status = subject = evidence = None
            return owner.finish(frame)
        def result(*, claim, status, domain, subject, profile, installation, evidence,
                   held_native_owners=()):
            frame = owner.prepare('proof_result',
                (claim, status, domain, subject, profile, installation, evidence, held_native_owners))
            claim = status = domain = subject = profile = installation = evidence = held_native_owners = None
            return owner.finish(frame)
        def assumptions(result):
            frame = owner.prepare('assumptions_document', (result,))
            result = None
            return owner.finish(frame)
        def description():
            frame = owner.prepare('proof_contract_description', ())
            return owner.finish(frame)
        self._helpers = dict(zip(ARITIES,
            (item, require, safe_core_method, subject, method, result, assumptions, description)))
        for name, function in self._helpers.items():
            function.__name__ = function.__qualname__ = name
            function.__module__ = namespace.get('__name__', __name__)

    def prepare(self, name, arguments, *, witness=None):
        mode, arity = self.modes[name]
        if type(arguments) is not tuple or len(arguments) != arity:
            raise ProofContractUnknown('proof-contract bound arguments differ')
        return ProofContractFrame(self, mode, arguments, witness=witness)

    def finish(self, frame):
        # A caller's already handled exception is not this frame's outcome.
        # Keep the return value solely on the interpreter return stack while
        # retiring a confirmed success; failed and unknown outcomes retain the
        # original traceback/liveness and no-replay obligations.
        completed = False
        try:
            if frame.drive() != 0:
                raise ProofContractUnknown('native proof-contract public entry yielded')
            completed = True
            return frame.take()
        except BaseException:
            completed = False
            raise
        finally:
            frame.close(release=completed)

    def run(self, name, *arguments):
        frame = self.prepare(name, arguments)
        arguments = None
        return self.finish(frame)


class NativeProofContractOwner:
    """One admitted image and its exact held checker identity, without service."""
    def __init__(self, image, *, checker_custody):
        from .hia_checker_identity import HeldNativeOwner
        if type(image) is not NativeProofContractImage:
            raise TypeError('proof-contract owner requires its actual admitted image')
        if (type(checker_custody) is not HeldNativeOwner
                or checker_custody.selector != SELECTOR or checker_custody.image is not image):
            raise TypeError('proof-contract custody belongs to a different mapping')
        self.image, self.custody, self.closed = image, checker_custody, False

    def checker_owner(self):
        return self.custody

    def bind_checker_owners(self, held):
        # Leave non-tuples and caller duplicates for the original checker to
        # reject in its original order. Only the exact same admitted capability
        # avoids adding a second entry; equal image bytes are not an admission.
        if type(held) is not tuple or any(binding is self.custody for binding in held):
            return held
        return held + (self.custody,)

    def prepare(self, name, arguments):
        if self.closed:
            raise ProofContractUnknown('proof-contract owner is closed for new work')
        return self.image.prepare(name, arguments)

    def finish(self, frame):
        if self.closed:
            raise ProofContractUnknown('proof-contract owner is closed for new work')
        if type(frame) is not ProofContractFrame or frame.image is not self.image:
            raise ProofContractUnknown('proof-contract continuation belongs to a different mapping')
        with proof_contract_scope(self):
            return self.image.finish(frame)
