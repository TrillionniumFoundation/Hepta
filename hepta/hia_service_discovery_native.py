"""Complete HIA control of service discovery and example construction.

HIA owns both methods' choices, sequencing and final acknowledgement. The
original opcode catalog, assembly/Core verifier and Store.profile are explicit
providers. No constructor, _profiles, SQL implementation or whole-stack native
closure is claimed. Selected routes never invoke the retained method bodies.
"""
from __future__ import annotations
import builtins
import ctypes
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import struct
import types
from .hia_emission_native import _global_value
from .hia_json_preflight_native import NativeHiaJsonImage, _source_resource_path, _unique_manifest_pairs
from .hia_native_delivery import DeliveryRecord
from .hia_store_lifecycle_native import _regular_bytes
from .hia_service_discovery_protocol import (
    SELECTOR, SCHEMA, SOURCE_NAME, REQUEST_MAGIC, RESULT_MAGIC, STATE_MAGIC,
    REQUEST_BYTES, OUTPUT_BYTES, STATE_BYTES, INITIALIZE, CLAIM, SUCCEEDED,
    RAISED, FINALIZE, ISSUED, CLAIMED, RETURNED, PROPAGATE,
    READY_RETURN, READY_PROPAGATE, DESCRIBE, EXAMPLES, PORT, PORTS,
    MODE_RANGES, ERROR_PORTS, LOCAL_NAMES)
SOURCE = _source_resource_path(SOURCE_NAME)
_REQUEST_REJECTIONS = (ValueError, TypeError, OSError, OverflowError,
                       RecursionError, sqlite3.Error)
_UNBOUND = object()
# These three private ABI classes are module-owned, not per-frame collectable
# ctypes type cycles. The real allocation and all guards remain unchanged.
_REQUEST_BUFFER_TYPE = ctypes.c_char * (REQUEST_BYTES + 16)
_OUTPUT_BUFFER_TYPE = ctypes.c_char * (OUTPUT_BYTES + 16)
_STATE_BUFFER_TYPE = ctypes.c_char * (STATE_BYTES + 16)

class _ReleaseProbe:
    __slots__ = ('events', 'name')
    def __init__(self, events, name):
        self.events, self.name = events, name
    def __del__(self):
        self.events.append(self.name)


def _frame_release_probe(events):
    first = _ReleaseProbe(events, 'first')
    last = _ReleaseProbe(events, 'last')


def _dict_release_probe(events):
    values = {'first': _ReleaseProbe(events, 'first'),
              'last': _ReleaseProbe(events, 'last')}


@lru_cache(maxsize=1)
def _storage_is_reversed():
    frame_events, dict_events = [], []
    _frame_release_probe(frame_events)
    _dict_release_probe(dict_events)
    admissible = (['first', 'last'], ['last', 'first'])
    if frame_events not in admissible or dict_events not in admissible:
        raise RuntimeError('runtime does not provide immediate local storage release')
    return frame_events != dict_events


class ServiceDiscoveryUnknown(RuntimeError):
    """The actual selected invocation has an unconfirmed delivery."""


class NativeServiceDiscovery(NativeHiaJsonImage):
    pass


@lru_cache(maxsize=3)
def _mapped_discovery(raw, digest, source_digest):
    image = NativeServiceDiscovery(raw, digest)
    image.admitted_source_sha256 = source_digest
    return image


def installed_service_discovery(manifest_path):
    if not manifest_path:
        raise ValueError('native service discovery selector must not be empty')
    from .hia_native_helpers import pinned_image
    selected = pinned_image(manifest_path, SOURCE, SCHEMA, NativeServiceDiscovery)
    path = Path(manifest_path).resolve(strict=True)
    raw = _regular_bytes(path, 16384)
    value = json.loads(raw, object_pairs_hook=_unique_manifest_pairs)
    if (type(value) is not dict or set(value) != {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            or value['schema'] != SCHEMA
            or any(type(value[key]) is not str or len(value[key]) != 64
                   or any(char not in '0123456789abcdef' for char in value[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid native service discovery manifest')
    name = value['image_path']
    if (type(name) is not str or not name or name in ('.', '..')
            or Path(name).name != name or any(ord(char) < 32 for char in name)):
        raise ValueError('native discovery image must be a sibling basename')
    source = _regular_bytes(SOURCE, 8 << 20)
    image_path = path.parent / name
    image_bytes = _regular_bytes(image_path, 1 << 20)
    if sha256(source).hexdigest() != value['source_sha256']:
        raise ValueError('native service discovery source identity mismatch')
    if sha256(image_bytes).hexdigest() != value['image_sha256']:
        raise ValueError('native service discovery image identity mismatch')
    if selected is None:
        selected = _mapped_discovery(image_bytes, value['image_sha256'], value['source_sha256'])
    elif type(selected) is not NativeServiceDiscovery or selected.image_sha256 != value['image_sha256']:
        raise ValueError('native discovery differs from the pinned worker image')
    if (_regular_bytes(path, 16384) != raw or _regular_bytes(SOURCE, 8 << 20) != source
            or _regular_bytes(image_path, 1 << 20) != image_bytes):
        raise ValueError('native service discovery selection changed during admission')
    selected.admitted_source_sha256 = value['source_sha256']
    return selected


def _checksum(words):
    value = 1469598103934665603
    for index, word in enumerate(words):
        if index != 10:
            value = (((value << 7) | (value >> 57)) & ((1 << 64) - 1)) ^ word
    return value


def _handoff(record, extent):
    record.enter_native()
    return extent


@dataclass(frozen=True)
class ServiceDiscoveryReceipt:
    port: int
    sequence: int
    phase: int
    failed: int


class ServiceDiscoveryFrame:
    def __init__(self, image, mode, service=None, arguments=None, *, namespace=None,
                 local_names=None, global_builtins=None, import_capsules=None):
        if type(image) is not NativeServiceDiscovery:
            raise TypeError('service discovery requires its admitted image')
        if type(mode) is not int or mode not in (DESCRIBE, EXAMPLES):
            raise ValueError('unknown service discovery mode')
        from . import hia_agent_service
        canonical_imports = hia_agent_service._SERVICE_DISCOVERY_IMPORTS
        if namespace is None:
            namespace = vars(hia_agent_service)
            if import_capsules is None:
                import_capsules = canonical_imports
            global_builtins = hia_agent_service._SERVICE_DISCOVERY_GLOBAL_BUILTINS[mode]
            if local_names is None:
                local_names = hia_agent_service._SERVICE_DISCOVERY_LOCAL_NAMES[mode]
        elif global_builtins is None:
            global_builtins = namespace.get('__builtins__', vars(builtins))
        if type(global_builtins) is types.ModuleType:
            global_builtins = vars(global_builtins)
        if import_capsules is None:
            # An explicit internal namespace must carry its actual captured
            # builtins. After a namespace __builtins__ rebind, supply a capsule
            # made with the original capture, just as with a real Python frame.
            import_capsules = {mode: types.FunctionType(
                canonical_imports[mode].__code__, namespace,
                canonical_imports[mode].__name__)}
        importer = import_capsules[mode]
        if (type(importer) is not types.FunctionType
                or importer.__globals__ is not namespace
                or importer.__builtins__ is not global_builtins
                or importer.__code__ is not canonical_imports[mode].__code__):
            raise ValueError('discovery import capsule differs from its captured namespace')
        self._import = importer
        names = tuple(LOCAL_NAMES[mode] if local_names is None else local_names)
        if names != LOCAL_NAMES[mode]:
            raise ValueError('original discovery local layout differs')
        self.image, self.mode = image, mode
        self.namespace, self.global_builtins = namespace, global_builtins
        self._retired_data = {}
        self.data = dict.fromkeys(names[::-1] if _storage_is_reversed() else names, _UNBOUND)
        if mode == DESCRIBE:
            self.data['self'], self.data['args'] = service, arguments
        self.result = None
        self.identity = struct.unpack('<2Q', os.urandom(16))
        self.buffer = ctypes.create_string_buffer(STATE_BYTES + 16)
        ctypes.memmove(ctypes.addressof(self.buffer) + STATE_BYTES, b'\xb7' * 16, 16)
        self.receipt = None
        self.fenced = self.finished = self.native_failed = self._entered = False
        self._pending_foreign = self._whole = None
        self._foreign_started = self._effect_started = False
        self._native_source = self._native_output = None
        self._delivery = DeliveryRecord(self)
        try:
            self.call(INITIALIZE)
        except BaseException:
            self._delivery.retire()
            raise

    def _global(self, name):
        return _global_value(self.namespace, self.global_builtins, name)


    def _check(self):
        record = self._delivery
        record.check(ServiceDiscoveryUnknown)
        whole = self._whole
        if whole is not None:
            whole.pending_resources.check_borrowed_resources()
        # The identity query/GC can itself run a real child.
        record.check(ServiceDiscoveryUnknown)


    def call(self, event, observation=0):
        record = self._delivery
        if self.fenced or self.finished or not record.current():
            raise ServiceDiscoveryUnknown('service discovery has no current invocation')
        self._check()
        native_confirmed = False
        try:
            previous = self.receipt
            port, sequence = (0, 0) if previous is None else (previous.port, previous.sequence)
            old_failed = 0 if previous is None else previous.failed
            raw = struct.pack('<16Q', REQUEST_MAGIC, event, sequence, port,
                              observation, self.mode, *self.identity, *([0] * 8))
            source = ctypes.create_string_buffer(raw + b'\xc9' * 16, REQUEST_BYTES + 16)
            output = ctypes.create_string_buffer(OUTPUT_BYTES + 16)
            ctypes.memmove(ctypes.addressof(output) + OUTPUT_BYTES, b'\xa5' * 16, 16)
            self._native_source, self._native_output = source, output
            code = self.image._entry(source, REQUEST_BYTES, output, OUTPUT_BYTES,
                                     self.buffer, _handoff(record, STATE_BYTES))
            if (code != OUTPUT_BYTES or source.raw != raw + b'\xc9' * 16
                    or output.raw[OUTPUT_BYTES:] != b'\xa5' * 16
                    or self.buffer.raw[STATE_BYTES:] != b'\xb7' * 16):
                raise ServiceDiscoveryUnknown('service discovery return is unconfirmed')
            words = struct.unpack('<12Q', output.raw[:OUTPUT_BYTES])
            state = struct.unpack('<24Q', self.buffer.raw[:STATE_BYTES])
            expected_sequence = 1 if event == INITIALIZE else sequence if event == CLAIM else sequence + 1
            expected_phases = {
                INITIALIZE:(ISSUED,), CLAIM:(CLAIMED,),
                SUCCEEDED:(ISSUED, READY_RETURN, READY_PROPAGATE),
                RAISED:(ISSUED, READY_PROPAGATE),
                FINALIZE:(RETURNED, PROPAGATE),
            }[event]
            failed = 1 if event == RAISED else old_failed
            low, high = MODE_RANGES[self.mode]
            active = words[4] in (ISSUED, CLAIMED)
            if (words[0] != RESULT_MAGIC or words[1] != 0
                    or words[2:7] != (state[3], state[4], state[5], state[2], state[12])
                    or state[:3] != (STATE_MAGIC, 1, self.mode)
                    or words[8:10] != self.identity or state[6:8] != self.identity
                    or words[7] != 0 or words[10:12] != (0, 0)
                    or state[8:10] != (0, 0) or state[11] != 0
                    or state[13:] != (0,) * 11 or state[10] != _checksum(state)
                    or words[3] != expected_sequence or words[4] not in expected_phases
                    or words[6] != failed
                    or (active and not low <= words[2] <= high)
                    or (active and int(words[2] in ERROR_PORTS) != failed)
                    or (not active and words[2] != 0)
                    or (words[4] in (RETURNED, READY_RETURN) and
                        (failed != 0 or state[8] != 0 or state[9] != 0))
                    or (words[4] in (PROPAGATE, READY_PROPAGATE) and failed != 1)
                    or (event == CLAIM and words[2] != port)
                    or (event == FINALIZE and (
                        previous.phase not in (READY_RETURN, READY_PROPAGATE)
                        or words[4] != (RETURNED if previous.phase == READY_RETURN else PROPAGATE)))):
                raise ServiceDiscoveryUnknown('service discovery receipt differs from complete state')
            receipt = ServiceDiscoveryReceipt(words[2], words[3], words[4], words[6])
            pending = None
            if event in (SUCCEEDED, RAISED):
                pending = self._pending_foreign
            elif event == FINALIZE:
                pending = self._whole
            if event in (SUCCEEDED, RAISED, FINALIZE):
                if pending is None:
                    raise ServiceDiscoveryUnknown('discovery has no matching foreign activation')
                pending.prepare_acknowledgement()
            self._check()
            record.confirmed()
            native_confirmed = True
            self.receipt = receipt
            self._native_source = self._native_output = None
            if pending is not None:
                pending.acknowledged()
                if event != FINALIZE:
                    self._pending_foreign = None
            self._check()
            if event == FINALIZE:
                record.confirmed(terminal=True)
            return receipt
        except BaseException as error:
            entered = record.native_pending
            lost = record.failed(error)
            pending = self._pending_foreign
            if pending is not None:
                pending.failed(error)
            if self._whole is not None:
                self._whole.failed(error)
            self.fenced = True
            self.native_failed = self.native_failed or lost or record.loss is not None
            if entered and not native_confirmed and isinstance(error, _REQUEST_REJECTIONS):
                raise ServiceDiscoveryUnknown('service discovery native delivery failed') from error
            raise


    def finish(self):
        # A denied same-Frame reentry must never execute the active owner's
        # cleanup/retire finally. Normal public recursion creates a new Frame.
        if self._entered:
            raise ServiceDiscoveryUnknown('service discovery frame cannot be reused')
        if not self._delivery.current():
            raise ServiceDiscoveryUnknown('service discovery frame cannot be transferred')
        self._entered = True
        try:
            self._check()
            whole = self._delivery.foreign(capture_resources=True, weak_registered_resources=True)
            self._whole = whole
            with self._delivery.foreign(observation=False):
                try:
                    with whole:
                        release_observation = self._drive()
                        # The original-local owner has now really returned.
                        # Its ordinary finalizers (or retained traceback frame)
                        # determine lifetime before the release is acknowledged.
                        if (self.receipt.phase != CLAIMED
                                or self.receipt.port not in (PORT['describe_release'],
                                                            PORT['examples_release'])):
                            raise ServiceDiscoveryUnknown('discovery release is not awaiting acknowledgement')
                        self.call(SUCCEEDED, release_observation)
                        if self.receipt.phase != READY_RETURN:
                            raise ServiceDiscoveryUnknown('discovery release has no return directive')
                except BaseException as error:
                    if (not self._foreign_started and self._delivery.loss is None
                            and not self._delivery.native_pending):
                        # This is a proven refusal before the first original
                        # foreign handoff, not a completed body outcome.
                        self._delivery.foreign_refused()
                    if (not self.native_failed and self._delivery.loss is None
                            and self.receipt.phase == READY_PROPAGATE):
                        self._finalize()
                        raise
                    whole.failed(error)
                    raise
                self._finalize()
                return self.__dict__.pop('result')
        except BaseException as error:
            self._delivery.failed(error)
            if self._pending_foreign is not None:
                self._pending_foreign.failed(error)
            if self._whole is not None:
                self._whole.failed(error)
            if self._delivery.loss is not None:
                self.fenced = self.native_failed = True
                self._delivery.propagate(error, ServiceDiscoveryUnknown, _REQUEST_REJECTIONS)
            raise
        finally:
            self._delivery.retire()


    def _effect_once(self):
        self._effect_started = False
        if self.receipt.phase != ISSUED:
            raise ServiceDiscoveryUnknown('discovery effect is not newly issued')
        self.call(CLAIM)
        activation = self._delivery.foreign(capture_resources=True, weak_registered_resources=True)
        self._pending_foreign = activation
        with activation:
            self._check()
            # Exact one-way handoff marker. No original lookup has run between
            # this point and effect(); a failure of the call itself is uncertain.
            self._foreign_started = self._effect_started = True
            return self.effect(self.receipt.port)


    def _finalize(self):
        previous = self.receipt.phase
        if previous not in (READY_RETURN, READY_PROPAGATE):
            raise ServiceDiscoveryUnknown('discovery has no HIA completion directive')
        self.call(FINALIZE)
        wanted = RETURNED if previous == READY_RETURN else PROPAGATE
        if self.receipt.phase != wanted:
            raise ServiceDiscoveryUnknown('discovery final receipt is unconfirmed')
        self.finished = True
        if wanted == PROPAGATE:
            # HIA has confirmed the method's exceptional terminal outcome.
            # The actual drive frame owns the original local storage; keeping
            # a second owner here would outlive that frame's consumer clearing.
            # Detach only: neither the dictionary nor any traceback is cleared.
            self.data = self._retired_data


    def _drive(self):
        # A single real frame owns the original method's local storage.
        # Provider tracebacks may retain it through f_back; no traceback or
        # storage is cleared to manufacture a release schedule.
        original_locals = self.data
        while True:
            try:
                observed = self._effect_once()
            except BaseException as error:
                if not self._effect_started:
                    raise
                if self.fenced or self.native_failed or self._delivery.loss is not None:
                    self._delivery.propagate(error, ServiceDiscoveryUnknown, _REQUEST_REJECTIONS)
                    raise
                self.call(RAISED)
                if self.receipt.phase != READY_PROPAGATE:
                    raise ServiceDiscoveryUnknown('discovery has no exception directive')
                raise
            if self.receipt.port in (PORT['describe_release'], PORT['examples_release']):
                return observed
            self.call(SUCCEEDED, observed)
            if self.receipt.phase != ISSUED:
                raise ServiceDiscoveryUnknown('discovery left its normal continuation')

    def effect(self, port):
        if (self.receipt is None or self.receipt.phase != CLAIMED
                or self.receipt.port != port or not 1 <= port <= len(PORTS)):
            raise ServiceDiscoveryUnknown('discovery has no matching effect claim')
        return getattr(self, '_port_' + PORTS[port - 1])()


    def _port_describe_import(self):
        d = self.data
        d['opcode_catalog'] = self._import(d['self'], d['args'])
        return 0

    def _port_describe_cursor(self):
        if "cursor" in self.data['args']:
            return 1
        return 0

    def _port_describe_reject_cursor(self):
        self._global('reject')("E_HIA_CURSOR", "discovery has no further page for this bounded manifest")
        return 0

    def _port_describe_backend_present(self):
        if "backend_profile" in self.data['args']:
            return 1
        return 0

    def _port_describe_backend_differs(self):
        d = self.data
        if d['args']["backend_profile"] != d['self'].profiles["backend"]["id"]:
            return 1
        return 0

    def _port_describe_reject_backend(self):
        self._global('reject')("E_HIA_PROFILE", "requested backend profile is unavailable")
        return 0

    def _port_describe_language_schema(self):
        d = self.data
        d['language_schema'] = d['args'].get("language_schema", "hepta.hia.program.v8")
        return 0

    def _port_describe_language(self):
        d = self.data
        d['language'] = d['opcode_catalog'](d['language_schema'])
        return 0

    def _port_describe_profile(self):
        d = self.data
        d['profile'], d['language_ref'] = d['self'].store.profile(
            d['language_schema'], d['language'])
        return 0

    def _port_describe_section(self):
        d = self.data
        d['section'] = d['args']["section"]
        return 0

    def _port_describe_resources(self):
        d = self.data
        # A complete ordinary dict literal is eagerly evaluated, then indexed.
        # Choosing only a requested section would remove original side effects.
        d['resources'] = {
            "manifest": [d['self'].manifest],
            "language": [d['self'].resources["schema_registry"],
                         d['self'].resources["assembly_grammar"],
                         d['self'].resources["core_language"], d['language_ref']],
            "backend": [d['self'].profile_artifacts["backend"],
                        d['self'].profile_artifacts["lowering"],
                        d['self'].profile_artifacts["target"],
                        d['self'].resources["byte_bootstrap_guide"],
                        d['self'].resources["self_hosting_core_guide"],
                        d['self'].resources["self_hosting_core_support"],
                        d['self'].profile_artifacts["validation"],
                        d['self'].resources["machine_validation_guide"],
                        d['self'].resources["proof_contract_guide"],
                        d['self'].resources["buffer_lifecycle_guide"]],
            "examples": [d['self'].resources["examples"]],
            "diagnostics": [d['self'].resources["diagnostics"]],
            "plans": [d['self'].profile_artifacts["plan"],
                      d['self'].resources["plan_schema"],
                      d['self'].resources["machine_plan_guide"],
                      d['self'].resources["macro_policy"],
                      d['self'].resources["macro_policy_guide"]],
        }[d['section']]
        return 0

    def _port_describe_result(self):
        d = self.data
        self.result = {"catalog_sha256": d['self'].catalog_sha256,
            "manifest": d['self'].manifest,
            "language_catalogs": [d['profile']],
            "backend_profiles": [d['self'].profiles["backend"]],
            "artifact_profiles": [d['self'].profiles["artifact"]],
            "resources": d['resources'], "next_cursor": None}
        return 0

    def _port_describe_release(self):
        self.data = self._retired_data
        return 0

    def _port_examples_import(self):
        self.data['assemble_program'], self.data['render_assembly'] = self._import()
        return 0

    def _port_examples_params(self):
        self.data['params'] = [{"name": "value", "type": "u8"}]
        return 0

    def _port_examples_document(self):
        d = self.data
        d['document'] = {"schema": "hepta.hia.program.v6", "module": "discovery_identity",
            "functions": [{"name": "identity", "params": d['params'], "returns": ["u8"], "effects": [],
                "entry": "entry", "blocks": [{"id": "entry", "params": d['params'], "ops": [],
                    "term": {"op": "ret", "values": ["value"]}}]}]}
        return 0

    def _port_examples_program(self):
        d = self.data
        d['program'] = self._global('verify_program')(d['document'])
        return 0

    def _port_examples_assembly(self):
        d = self.data
        d['assembly'] = d['render_assembly'](d['program'])
        return 0

    def _port_examples_roundtrip_differs(self):
        d = self.data
        if d['assemble_program'](d['assembly']).sha256 != d['program'].sha256:
            return 1
        return 0

    def _port_examples_raise_roundtrip(self):
        raise self._global('RuntimeError')("discovery example does not round-trip")

    def _port_examples_result(self):
        d = self.data
        self.result = {"schema": "hepta.hia.agent.examples.v1",
            "core": d['program'].as_dict(), "assembly": d['assembly'],
            "wrong_reference": "Returning an undefined value fails whole-program admission.",
            "workload": {"schema": "hepta.hia.agent.workload.v1", "cases": [
                {"function": "identity", "arguments": [23], "expected": {"status": "returned", "values": [23]}}],
                "warmup_iterations": 0, "repetitions": 1},
            "objective": {"schema": "hepta.hia.agent.objective.v1", "metric": "artifact_bytes",
                "required_claims": ["core_admission", "encoding_check"], "allow_unchanged": True,
                "min_improvement_ratio": 0.0},
            "cost_policy": {"schema": "hepta.hia.agent.cost-policy.v1", "external_costs": {
                "model_tokens": None, "model_wall_ns": None, "discovery_wall_ns": None},
                "external_costs_complete": False, "expected_invocations": "0"}}
        return 0

    def _port_examples_release(self):
        self.data = self._retired_data
        return 0
