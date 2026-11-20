"""HIA control for complete service rollback and adoption methods.

One image owns two complete original control graphs. Exact literal calls,
unpack and ordered value construction remain opaque host observations.
The outer service/journal retains the original transaction boundary. The
separate Slot Store/SQL provider and its multi-SQL causality are not replaced
or qualified merely by selecting this image.
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
from .hia_service_slot_protocol import (
    SELECTOR, SCHEMA, SOURCE_NAME, REQUEST_MAGIC, RESULT_MAGIC, STATE_MAGIC,
    REQUEST_BYTES, OUTPUT_BYTES, STATE_BYTES, INITIALIZE, CLAIM, SUCCEEDED,
    RAISED, FINALIZE, ISSUED, CLAIMED, READY_RETURN, READY_PROPAGATE,
    RETURNED, PROPAGATE, PORT, PORTS, ROLLBACK, ADOPT,
)

SOURCE = _source_resource_path(SOURCE_NAME)
_REQUEST_REJECTIONS = (ValueError, TypeError, OSError, OverflowError, RecursionError, sqlite3.Error)

# ctypes keeps its dynamically constructed array types in a weak cache. These
# three fixed ABI classes belong to the adapter, not to an invocation; retain
# them so destroying private buffers does not leave new type cycles for a
# caller's later GC. The buffers, user objects and per-call checks are unchanged.
_REQUEST_BUFFER_TYPE = ctypes.c_char * (REQUEST_BYTES + 16)
_OUTPUT_BUFFER_TYPE = ctypes.c_char * (OUTPUT_BYTES + 16)
_STATE_BUFFER_TYPE = ctypes.c_char * (STATE_BYTES + 16)


class _LocalReleaseProbe:
    """One fixed private type; no user object participates in the probe."""
    __slots__ = ('events', 'name')

    def __init__(self, events, name):
        self.events, self.name = events, name

    def __del__(self):
        self.events.append(self.name)


def _probe_frame_release(events):
    first = _LocalReleaseProbe(events, 'first')
    last = _LocalReleaseProbe(events, 'last')


def _probe_dict_release(events):
    values = {'first': _LocalReleaseProbe(events, 'first'),
              'last': _LocalReleaseProbe(events, 'last')}


@lru_cache(maxsize=2)
def _local_storage_order(mode):
    """Make an ordinary dict release the original frame's locals in order.

CPython 3.13 and 3.14 clear frame slots in opposite directions. Observe both
the running frame and dict mechanics instead of choosing a version threshold.
The fixed probe type stays alive, its two instances have no cycles, and the
cache contains only the fixed6 rollback or16 adoption local names. No exceptional-path cleanup is inserted:
the caller still controls the lifetime of its actual traceback.
    """
    frame_events, dict_events = [], []
    _probe_frame_release(frame_events)
    _probe_dict_release(dict_events)
    forward, reverse = ['first', 'last'], ['last', 'first']
    if frame_events not in (forward, reverse) or dict_events not in (forward, reverse):
        raise RuntimeError('runtime does not provide immediate ordered local custody')
    if mode == ROLLBACK:
        names = ('service', 'arguments', 'snapshot', 'current', 'artifact', 'receipt')
    else:
        names = ('service', 'arguments', 'context', 'evaluation', '_', 'objective',
                 '_data', 'metadata', '_program', '_baseline_data', 'baseline',
                 '_baseline_program', 'snapshot', 'abi', 'current', 'receipt')
    return names if frame_events == dict_events else names[::-1]


class ServiceSlotUnknown(RuntimeError):
    """An actual handler observation is unconfirmed; no terminal or replay."""


class NativeServiceSlot(NativeHiaJsonImage):
    pass


@lru_cache(maxsize=3)
def _mapped_service_slot(raw, digest, source_digest):
    image = NativeServiceSlot(raw, digest)
    image.admitted_source_sha256 = source_digest
    return image


def installed_service_slot(manifest_path):
    if not manifest_path:
        raise ValueError('native service slot selector must not be empty')
    from .hia_native_helpers import pinned_image
    selected = pinned_image(manifest_path, SOURCE, SCHEMA, NativeServiceSlot)
    path = Path(manifest_path).resolve(strict=True)
    raw = _regular_bytes(path, 16384)
    value = json.loads(raw, object_pairs_hook=_unique_manifest_pairs)
    if (type(value) is not dict or set(value) != {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            or value['schema'] != SCHEMA
            or any(type(value[key]) is not str or len(value[key]) != 64
                   or any(char not in '0123456789abcdef' for char in value[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid native service slot manifest')
    name = value['image_path']
    if (type(name) is not str or not name or name in ('.', '..')
            or Path(name).name != name or any(ord(char) < 32 for char in name)):
        raise ValueError('native service slot image must be a sibling basename')
    source = _regular_bytes(SOURCE, 8 << 20)
    image_path = path.parent / name
    image = _regular_bytes(image_path, 1 << 20)
    if sha256(source).hexdigest() != value['source_sha256']:
        raise ValueError('native service slot source identity mismatch')
    if sha256(image).hexdigest() != value['image_sha256']:
        raise ValueError('native service slot image identity mismatch')
    if selected is None:
        selected = _mapped_service_slot(image, value['image_sha256'], value['source_sha256'])
    elif type(selected) is not NativeServiceSlot or selected.image_sha256 != value['image_sha256']:
        raise ValueError('native service slot differs from pinned worker image')
    if (_regular_bytes(path, 16384) != raw or _regular_bytes(SOURCE, 8 << 20) != source
            or _regular_bytes(image_path, 1 << 20) != image):
        raise ValueError('native service slot selection changed during admission')
    selected.admitted_source_sha256 = value['source_sha256']
    return selected


def _handoff(record, extent):
    record.enter_native()
    return extent


def _checksum(words):
    value = 1469598103934665603
    for index, word in enumerate(words):
        if index != 10:
            value = (((value << 7) | (value >> 57)) & ((1 << 64) - 1)) ^ word
    return value


# Each helper is one original expression/ignored call. Method calls stay literal:
# no callee prebinding, receiver capture, old-handler dispatch, or SQL shortcut.
# Truth conversion is only a 0/1 observation; HIA chooses the business branch.
def _literal_rollback_validate_ledger_present(service):
    return 1 if service._slot_ledger is not None else 0


def _literal_rollback_ledger_validate(service, arguments):
    service._slot_ledger.validate_u64(arguments['retained_generation'], 'retained_generation')


def _literal_rollback_reference_validate(arguments, lookup):
    lookup('uint64')(arguments['retained_generation'], 'retained_generation')


def _literal_rollback_snapshot(service, arguments):
    return service._conditional_slot(arguments)


def _literal_rollback_ledger_present(service):
    return 1 if service._slot_ledger is not None else 0


def _literal_rollback_ledger_call(service, arguments, snapshot):
    return service._slot_ledger.rollback(arguments, snapshot, service._native)


def _literal_rollback_reference_call(service, arguments, snapshot):
    return service._reference_slot_rollback(arguments, snapshot)


def _literal_rollback_receipt(service, arguments, snapshot, current, artifact):
    return service.store.json({'schema': 'hepta.hia.agent.rollback.v1', 'context': arguments['context'],
        'target_slot': arguments['target_slot'], 'previous': snapshot['current'], 'current': current,
        'active_artifact': artifact, 'reason': arguments['reason'], 'future_calls_only': True,
        'past_effects_reversed': False, 'in_flight_versions_retained': True}, 'rollback-receipt')


def _literal_rollback_result(arguments, snapshot, current, artifact, receipt):
    return {'target_slot': arguments['target_slot'], 'previous': snapshot['current'], 'current': current,
        'active_artifact': artifact, 'rollback_receipt': receipt, 'future_calls_only': True,
        'past_effects_reversed': False}


def _literal_adopt_context(service, arguments):
    return service._context(arguments['context'])


def _literal_adopt_evaluation(service, arguments):
    return service.store.get_json(arguments['evaluation_receipt'], kind='evaluation-receipt')


def _literal_adopt_context_differs(evaluation, arguments):
    return 1 if evaluation['context'] != arguments['context'] else 0


def _literal_adopt_candidate_differs(evaluation, arguments):
    return 1 if evaluation['candidate_artifact'] != arguments['candidate_artifact'] else 0


def _literal_adopt_installation_differs(evaluation, service):
    return 1 if evaluation['installation'] != service.identities else 0


def _literal_adopt_reject_binding(lookup):
    lookup('reject')('E_HIA_RECEIPT_BINDING',
        'evaluation does not authorize this candidate/context', 'adoption')


def _literal_adopt_build_receipt(service, evaluation, arguments):
    service._build_receipt(evaluation['build_receipt'], arguments['context'], arguments['candidate_artifact'])


def _literal_adopt_objective(service, context, arguments, evaluation):
    return service._required_claims(context, arguments['candidate_artifact'],
        arguments['verification_receipts'], evaluation['baseline_core_sha256'])


def _literal_adopt_evaluation_ledger_present(service):
    return 1 if service._slot_ledger is not None else 0


def _literal_adopt_ledger_evaluation(service, evaluation, objective):
    service._slot_ledger.admit_evaluation(evaluation, objective)


def _literal_adopt_reference_evaluation(service, evaluation, objective):
    service._reference_adoption_evaluation(evaluation, objective)


def _literal_adopt_measurements(service, evaluation):
    service.store.get(evaluation['measurements'], kind='measurements')


def _literal_adopt_full_cost_ledger(service, evaluation):
    service.store.get(evaluation['full_cost_ledger'], kind='cost-ledger')


def _literal_adopt_net_ledger_present(service):
    return 1 if service._slot_ledger is not None else 0


def _literal_adopt_ledger_net(service, objective):
    service._slot_ledger.admit_net_benefit(objective)


def _literal_adopt_reference_net(service, objective):
    service._reference_adoption_net_benefit(objective)


def _literal_adopt_native_candidate(service, arguments):
    return service._native(arguments['candidate_artifact'], arguments['context'])


def _literal_adopt_native_baseline(service, evaluation, arguments):
    return service._native(evaluation['baseline_artifact'], arguments['context'])


def _literal_adopt_signatures_differ(metadata, baseline):
    return 1 if metadata['signatures'] != baseline['signatures'] else 0


def _literal_adopt_reject_abi(lookup):
    lookup('reject')('E_HIA_ABI', 'candidate and baseline are not ABI compatible', 'adoption')


def _literal_adopt_snapshot(service, arguments):
    return service._conditional_slot(arguments)


def _literal_adopt_abi(metadata, lookup):
    return lookup('digest')(metadata['signatures'])


def _literal_adopt_ledger_present(service):
    return 1 if service._slot_ledger is not None else 0


def _literal_adopt_ledger_call(service, arguments, snapshot, evaluation, abi):
    return service._slot_ledger.adopt(arguments, snapshot, evaluation, abi, service._native)


def _literal_adopt_reference_call(service, arguments, snapshot, evaluation, abi):
    return service._reference_slot_adopt(arguments, snapshot, evaluation, abi)


def _literal_adopt_receipt(service, arguments, snapshot, current, evaluation):
    return service.store.json({'schema': 'hepta.hia.agent.adoption.v1', 'context': arguments['context'],
        'target_slot': arguments['target_slot'], 'previous': snapshot['current'], 'current': current,
        'active_artifact': arguments['candidate_artifact'], 'retained_baseline': evaluation['baseline_artifact'],
        'evaluation_receipt': arguments['evaluation_receipt'], 'verification_receipts': arguments['verification_receipts'],
        'future_calls_only': True, 'in_flight_versions_retained': True,
        'consumer_api': 'acquire_slot -> invoke_lease -> release_slot'}, 'adoption-receipt')


def _literal_adopt_result(arguments, snapshot, current, receipt):
    return {'target_slot': arguments['target_slot'], 'previous': snapshot['current'], 'current': current,
        'active_artifact': arguments['candidate_artifact'], 'adoption_receipt': receipt,
        'future_calls_only': True}


@dataclass(frozen=True)
class ServiceSlotReceipt:
    port: int
    sequence: int
    phase: int
    mode: int
    failed: int


class ServiceSlotFrame:
    def __init__(self, image, mode, service, arguments, *, namespace=None):
        if type(image) is not NativeServiceSlot:
            raise TypeError('native service slot requires an admitted image')
        if type(mode) is not int or mode not in (ROLLBACK, ADOPT):
            raise ValueError('native service slot mode must be rollback or adoption')
        from . import hia_agent_service
        if namespace is None:
            namespace = vars(hia_agent_service)
            global_builtins = (hia_agent_service._SERVICE_SLOT_ROLLBACK_GLOBAL_BUILTINS
                               if mode == ROLLBACK else hia_agent_service._SERVICE_SLOT_ADOPT_GLOBAL_BUILTINS)
        else:
            global_builtins = namespace.get('__builtins__', vars(builtins))
            if type(global_builtins) is types.ModuleType:
                global_builtins = vars(global_builtins)
        self.image, self.mode = image, mode
        self.namespace, self.global_builtins = namespace, global_builtins
        # These are the original handler's complete local slots. Preallocate
        # their storage order before any provider; later assignments replace
        # slots without moving them. A builtin dict supplies the destruction
        # mechanism, including when the caller releases an error traceback.
        self.data = dict.fromkeys(_local_storage_order(mode))
        self._retired_data = {}
        self.data['service'], self.data['arguments'] = service, arguments
        self.result = None
        self.identity = struct.unpack('<2Q', os.urandom(16))
        self.buffer = ctypes.create_string_buffer(STATE_BYTES + 16)
        ctypes.memmove(ctypes.addressof(self.buffer) + STATE_BYTES, b'\xb7' * 16, 16)
        self.receipt = None
        self.fenced = self.finished = self.native_failed = self._entered = False
        self._pending_foreign = self._whole = None
        self._foreign_started = self._effect_started = False
        # DeliveryRecord already owns this full frame while unknown. A second
        # owner-specific lock/registry would add no custody guarantee.
        self._delivery = DeliveryRecord(self)
        try:
            self.call(INITIALIZE)
        except BaseException:
            self._delivery.retire()
            raise

    @property
    def service(self):
        return self.data.get('service')

    @service.setter
    def service(self, value):
        self.data['service'] = value

    def _check(self):
        record = self._delivery
        record.check(ServiceSlotUnknown)
        whole = self._whole
        if whole is not None:
            whole.pending_resources.check_borrowed_resources()
        # The identity query or GC may itself perform a real child call.
        record.check(ServiceSlotUnknown)

    def call(self, event, observation=0):
        record = self._delivery
        if self.fenced or self.finished or not record.current():
            raise ServiceSlotUnknown('native service slot has no current invocation')
        self._check()
        native_confirmed = False
        try:
            previous = self.receipt
            port, sequence = (0, 0) if previous is None else (previous.port, previous.sequence)
            old_failed = 0 if previous is None else previous.failed
            raw = struct.pack('<10Q', REQUEST_MAGIC, event, sequence, port, observation,
                              self.mode, *self.identity, 0, 0)
            source = ctypes.create_string_buffer(raw + b'\xc9' * 16, REQUEST_BYTES + 16)
            output = ctypes.create_string_buffer(OUTPUT_BYTES + 16)
            ctypes.memmove(ctypes.addressof(output) + OUTPUT_BYTES, b'\xa5' * 16, 16)
            # Resolve the actual entry callable and all buffer arguments before
            # marking native handoff, at the final argument of the literal call.
            code = self.image._entry(source, REQUEST_BYTES, output, OUTPUT_BYTES,
                                     self.buffer, _handoff(record, STATE_BYTES))
            if (code != OUTPUT_BYTES or source.raw != raw + b'\xc9' * 16
                    or output.raw[OUTPUT_BYTES:] != b'\xa5' * 16
                    or self.buffer.raw[STATE_BYTES:] != b'\xb7' * 16):
                raise ServiceSlotUnknown('native service slot return is unconfirmed')
            words = struct.unpack('<12Q', output.raw[:OUTPUT_BYTES])
            state = struct.unpack('<16Q', self.buffer.raw[:STATE_BYTES])
            expected_sequence = 1 if event == INITIALIZE else sequence if event == CLAIM else sequence + 1
            expected_phases = {
                INITIALIZE: (ISSUED,), CLAIM: (CLAIMED,),
                SUCCEEDED: (ISSUED, READY_RETURN), RAISED: (READY_PROPAGATE,),
                FINALIZE: (RETURNED, PROPAGATE),
            }[event]
            failed = 1 if event == RAISED else old_failed
            active = words[4] in (ISSUED, CLAIMED)
            if (words[0] != RESULT_MAGIC or words[1] != 0
                    or words[2:7] != (state[3], state[4], state[5], state[2], state[12])
                    or state[:3] != (STATE_MAGIC, 1, self.mode)
                    or words[8:10] != self.identity or state[6:8] != self.identity
                    or words[7] != 0 or words[10:12] != (0, 0)
                    or state[8:10] != (0, 0) or state[11] != 0 or state[13:16] != (0, 0, 0)
                    or state[10] != _checksum(state)
                    or words[3] != expected_sequence or words[4] not in expected_phases
                    or words[6] != failed
                    or (words[4] in (READY_RETURN, RETURNED) and failed != 0)
                    or (words[4] in (READY_PROPAGATE, PROPAGATE) and failed != 1)
                    or (not active and words[2] != 0)
                    or (words[4] == READY_RETURN and port != PORT[
                        'rollback_release_locals' if self.mode == ROLLBACK else 'adopt_release_locals'])
                    or (active and not 1 <= words[2] <= len(PORTS))
                    or (active and (
                        (self.mode == ROLLBACK and words[2] > PORT['rollback_release_locals'])
                        or (self.mode == ADOPT and words[2] < PORT['adopt_context'])))
                    or (event == CLAIM and words[2] != port)
                    or (event == FINALIZE and (
                        previous.phase not in (READY_RETURN, READY_PROPAGATE)
                        or words[4] != (RETURNED if previous.phase == READY_RETURN else PROPAGATE)))):
                raise ServiceSlotUnknown('native service slot receipt differs from issued state')
            receipt = ServiceSlotReceipt(words[2], words[3], words[4], words[5], words[6])
            pending = None
            if event in (SUCCEEDED, RAISED):
                pending = self._pending_foreign
            elif event == FINALIZE:
                pending = self._whole
            if event in (SUCCEEDED, RAISED, FINALIZE):
                if pending is None:
                    raise ServiceSlotUnknown('native service slot has no matching foreign activation')
                pending.prepare_acknowledgement()
            self._check()
            record.confirmed()
            native_confirmed = True
            self.receipt = receipt
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
                raise ServiceSlotUnknown('native service slot observation failed') from error
            raise

    def finish(self):
        # Same-Frame reentry is refused outside the active owner's cleanup
        # region. A recursive public handler creates its own fresh Frame.
        if self._entered:
            raise ServiceSlotUnknown('native service slot frame cannot be reused')
        if not self._delivery.current():
            raise ServiceSlotUnknown('native service slot frame cannot be transferred')
        self._entered = True
        try:
            self._check()
            whole = self._delivery.foreign(capture_resources=True,
                                          weak_registered_resources=True)
            self._whole = whole
            with self._delivery.foreign(observation=False):
                try:
                    with whole:
                        self._drive()
                except BaseException as error:
                    if (not self._foreign_started and self._delivery.loss is None
                            and not self._delivery.native_pending):
                        # Safe refusal before any original effect. INIT was
                        # also outside this observed whole-method scope.
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
                self._delivery.propagate(error, ServiceSlotUnknown, _REQUEST_REJECTIONS)
            raise
        finally:
            self._delivery.retire()

    def _effect_once(self):
        self._effect_started = False
        if self.receipt.phase != ISSUED:
            raise ServiceSlotUnknown('native service slot effect is not newly issued')
        self.call(CLAIM)
        activation = self._delivery.foreign(capture_resources=True,
                                            weak_registered_resources=True)
        self._pending_foreign = activation
        with activation:
            self._check()
            self._foreign_started = self._effect_started = True
            return self.effect(self.receipt.port)

    def _finalize(self):
        previous = self.receipt.phase
        if previous not in (READY_RETURN, READY_PROPAGATE):
            raise ServiceSlotUnknown('native service slot has no HIA completion directive')
        self.call(FINALIZE)
        if self.receipt.phase != (RETURNED if previous == READY_RETURN else PROPAGATE):
            raise ServiceSlotUnknown('native service slot final receipt is unconfirmed')
        self.finished = True

    def _drive(self):
        while True:
            try:
                observed = self._effect_once()
            except BaseException as error:
                if self.fenced or self.native_failed or self._delivery.loss is not None:
                    self._delivery.propagate(error, ServiceSlotUnknown, _REQUEST_REJECTIONS)
                    raise
                if not self._effect_started:
                    # Preparation refused before the original expression. It
                    # is not a foreign outcome and receives no forged ACK.
                    raise
                self.call(RAISED)
                if self.receipt.phase != READY_PROPAGATE:
                    raise ServiceSlotUnknown('native service slot exception was not confirmed')
                # Preserve the same active exception through whole.__exit__
                # and the independent FINALIZE receipt. No data.clear or
                # traceback rewrite changes original local ownership.
                raise
            self.call(SUCCEEDED, observed)
            if self.receipt.phase == READY_RETURN:
                return
            if self.receipt.phase != ISSUED:
                raise ServiceSlotUnknown('native service slot left its normal continuation')

    def _global(self, name):
        return _global_value(self.namespace, self.global_builtins, name)

    def effect(self, port):
        if (self.receipt is None or self.receipt.phase != CLAIMED or self.receipt.port != port
                or not 1 <= port <= len(PORTS)):
            raise ServiceSlotUnknown('native service slot effect has no matching claim')
        name = PORTS[port - 1]
        d = self.data
        if name == 'rollback_validate_ledger_present':
            return _literal_rollback_validate_ledger_present(self.service)
        elif name == 'rollback_ledger_validate':
            _literal_rollback_ledger_validate(self.service, d['arguments'])
        elif name == 'rollback_reference_validate':
            _literal_rollback_reference_validate(d['arguments'], self._global)
        elif name == 'rollback_snapshot':
            d['snapshot'] = _literal_rollback_snapshot(self.service, d['arguments'])
        elif name == 'rollback_ledger_present':
            return _literal_rollback_ledger_present(self.service)
        elif name == 'rollback_ledger_call':
            d['current'], d['artifact'] = _literal_rollback_ledger_call(
                self.service, d['arguments'], d['snapshot'])
        elif name == 'rollback_reference_call':
            d['current'], d['artifact'] = _literal_rollback_reference_call(
                self.service, d['arguments'], d['snapshot'])
        elif name == 'rollback_receipt':
            d['receipt'] = _literal_rollback_receipt(
                self.service, d['arguments'], d['snapshot'], d['current'], d['artifact'])
        elif name == 'rollback_result':
            self.result = _literal_rollback_result(
                d['arguments'], d['snapshot'], d['current'], d['artifact'], d['receipt'])
        elif name == 'adopt_context':
            d['context'] = _literal_adopt_context(self.service, d['arguments'])
        elif name == 'adopt_evaluation':
            d['evaluation'], d['_'] = _literal_adopt_evaluation(self.service, d['arguments'])
        elif name == 'adopt_context_differs':
            return _literal_adopt_context_differs(d['evaluation'], d['arguments'])
        elif name == 'adopt_candidate_differs':
            return _literal_adopt_candidate_differs(d['evaluation'], d['arguments'])
        elif name == 'adopt_installation_differs':
            return _literal_adopt_installation_differs(d['evaluation'], self.service)
        elif name == 'adopt_reject_binding':
            _literal_adopt_reject_binding(self._global)
        elif name == 'adopt_build_receipt':
            _literal_adopt_build_receipt(self.service, d['evaluation'], d['arguments'])
        elif name == 'adopt_objective':
            d['objective'] = _literal_adopt_objective(
                self.service, d['context'], d['arguments'], d['evaluation'])
        elif name == 'adopt_evaluation_ledger_present':
            return _literal_adopt_evaluation_ledger_present(self.service)
        elif name == 'adopt_ledger_evaluation':
            _literal_adopt_ledger_evaluation(self.service, d['evaluation'], d['objective'])
        elif name == 'adopt_reference_evaluation':
            _literal_adopt_reference_evaluation(self.service, d['evaluation'], d['objective'])
        elif name == 'adopt_measurements':
            _literal_adopt_measurements(self.service, d['evaluation'])
        elif name == 'adopt_full_cost_ledger':
            _literal_adopt_full_cost_ledger(self.service, d['evaluation'])
        elif name == 'adopt_net_ledger_present':
            return _literal_adopt_net_ledger_present(self.service)
        elif name == 'adopt_ledger_net':
            _literal_adopt_ledger_net(self.service, d['objective'])
        elif name == 'adopt_reference_net':
            _literal_adopt_reference_net(self.service, d['objective'])
        elif name == 'adopt_native_candidate':
            d['_data'], d['metadata'], d['_program'] = _literal_adopt_native_candidate(
                self.service, d['arguments'])
        elif name == 'adopt_native_baseline':
            d['_baseline_data'], d['baseline'], d['_baseline_program'] = _literal_adopt_native_baseline(
                self.service, d['evaluation'], d['arguments'])
        elif name == 'adopt_signatures_differ':
            return _literal_adopt_signatures_differ(d['metadata'], d['baseline'])
        elif name == 'adopt_reject_abi':
            _literal_adopt_reject_abi(self._global)
        elif name == 'adopt_snapshot':
            d['snapshot'] = _literal_adopt_snapshot(self.service, d['arguments'])
        elif name == 'adopt_abi':
            d['abi'] = _literal_adopt_abi(d['metadata'], self._global)
        elif name == 'adopt_ledger_present':
            return _literal_adopt_ledger_present(self.service)
        elif name == 'adopt_ledger_call':
            d['current'] = _literal_adopt_ledger_call(
                self.service, d['arguments'], d['snapshot'], d['evaluation'], d['abi'])
        elif name == 'adopt_reference_call':
            d['current'] = _literal_adopt_reference_call(
                self.service, d['arguments'], d['snapshot'], d['evaluation'], d['abi'])
        elif name == 'adopt_receipt':
            d['receipt'] = _literal_adopt_receipt(
                self.service, d['arguments'], d['snapshot'], d['current'], d['evaluation'])
        elif name == 'adopt_result':
            self.result = _literal_adopt_result(
                d['arguments'], d['snapshot'], d['current'], d['receipt'])
        elif name in ('rollback_release_locals', 'adopt_release_locals'):
            # HIA issued the normal release after constructing the result.
            # Transfer frame ownership to the preallocated empty dict. Do not
            # clear an old dict still held by a handled provider traceback.
            # The local d releases naturally at this effect's return.
            self.data = self._retired_data
        return 0
