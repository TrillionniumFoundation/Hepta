"""HIA control for the complete Store transaction generator.

The image chooses lock entry, BEGIN, body suspension, COMMIT/ROLLBACK,
exception exit and suppression. Python supplies the real generator ABI and
the original opaque object/SQL operations. Each actual advance has fresh
native custody; a confirmed suspension is not tied to its creator thread.
"""
from __future__ import annotations

from builtins import BaseException as _BaseException
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import struct
import sys
import threading

from .hia_emission_native import _context_special, _global_value, _runtime_context_lookup_order
from .hia_json_preflight_native import NativeHiaJsonImage, _source_resource_path, _unique_manifest_pairs
from .hia_native_delivery import (
    DeliveryRecord, guarded, reserve_resource_observation, resource_scope,
)
from .hia_store_lifecycle_native import _regular_bytes
from .hia_store_transaction_protocol import (
    SELECTOR, SCHEMA, SOURCE_NAME, REQUEST_MAGIC, RESULT_MAGIC, STATE_MAGIC,
    REQUEST_BYTES, OUTPUT_BYTES, STATE_BYTES, INITIALIZE, CLAIM, SUCCEEDED,
    RAISED, BODY_RETURNED, BODY_RAISED, ISSUED, CLAIMED, RETURNED, PROPAGATE,
    BODY_WAIT, LEAVE_HANDLER, PORT, PORTS,
)

SOURCE = _source_resource_path(SOURCE_NAME)
_FRAME_CUSTODY = {}
_CUSTODY_LOCK = threading.Lock()
_CUSTODY_PID = os.getpid()
_REQUEST_REJECTIONS = (ValueError, TypeError, OSError, OverflowError, RecursionError, sqlite3.Error)


class StoreTransactionUnknown(RuntimeError):
    """An actual transaction observation is unconfirmed; do not replay it."""


def _after_fork_child():
    global _CUSTODY_LOCK, _CUSTODY_PID
    # Keep actual unknown resources. A healthy confirmed BODY_WAIT can still
    # be resumed under a fresh child-process invocation, just like the original
    # generator. No inherited native activation becomes a child activation.
    _CUSTODY_LOCK = threading.Lock()
    _CUSTODY_PID = os.getpid()


if hasattr(os, 'register_at_fork'):
    os.register_at_fork(after_in_child=_after_fork_child)


def _custody_lock():
    if os.getpid() != _CUSTODY_PID:
        raise StoreTransactionUnknown('native transaction custody has no child-process lock')
    return _CUSTODY_LOCK


class NativeStoreTransaction(NativeHiaJsonImage):
    pass


@lru_cache(maxsize=3)
def _mapped_transaction(raw, digest, source_digest):
    image = NativeStoreTransaction(raw, digest)
    image.admitted_source_sha256 = source_digest
    return image


def installed_store_transaction(manifest_path, *, _bound_image=None):
    if not manifest_path:
        raise ValueError('native Store transaction selector must not be empty')
    from .hia_native_helpers import pinned_image
    selected = pinned_image(manifest_path, SOURCE, SCHEMA, NativeStoreTransaction)
    path = Path(manifest_path).resolve(strict=True)
    raw = _regular_bytes(path, 16384)
    value = json.loads(raw, object_pairs_hook=_unique_manifest_pairs)
    if (type(value) is not dict or set(value) != {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            or value['schema'] != SCHEMA
            or any(type(value[key]) is not str or len(value[key]) != 64
                   or any(char not in '0123456789abcdef' for char in value[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid native Store transaction manifest')
    name = value['image_path']
    if (type(name) is not str or not name or name in ('.', '..')
            or Path(name).name != name or any(ord(char) < 32 for char in name)):
        raise ValueError('native Store transaction image must be a sibling basename')
    source = _regular_bytes(SOURCE, 8 << 20)
    image_path = path.parent / name
    image = _regular_bytes(image_path, 1 << 20)
    if sha256(source).hexdigest() != value['source_sha256']:
        raise ValueError('native Store transaction source identity mismatch')
    if sha256(image).hexdigest() != value['image_sha256']:
        raise ValueError('native Store transaction image identity mismatch')
    if _bound_image is not None:
        if selected is not None and selected is not _bound_image:
            raise ValueError('native transaction owner differs from pinned worker image')
        selected = _bound_image
    if selected is None:
        selected = _mapped_transaction(image, value['image_sha256'], value['source_sha256'])
    elif type(selected) is not NativeStoreTransaction or selected.image_sha256 != value['image_sha256']:
        raise ValueError('native Store transaction differs from pinned worker image')
    if (_regular_bytes(path, 16384) != raw or _regular_bytes(SOURCE, 8 << 20) != source
            or _regular_bytes(image_path, 1 << 20) != image):
        raise ValueError('native Store transaction selection changed during admission')
    return selected


class _TransactionOwnerBinding:
    """An explicit image selection for this live process/thread/context.

    This is a routing scope, not a new worker capability. Every selection still
    passes the original manifest/source/image admission and worker bundle
    checks. It does not keep any Store or alter an already-started transaction.
    """

    def __init__(self, manifest_path, image):
        from .hia_agent_store import _STORE_TRANSACTION_OWNER
        from .hia_native_helpers import native_helpers_identity
        self.variable = _STORE_TRANSACTION_OWNER
        self.pid = os.getpid()
        self.thread = threading.get_ident()
        self.active = False
        self.path = Path(manifest_path).resolve(strict=True)
        self.raw = _regular_bytes(self.path, 16384)
        self.worker_identity = native_helpers_identity()
        self.image = image
        selected = installed_store_transaction(str(self.path), _bound_image=image)
        if selected is not image:
            raise ValueError('native transaction owner requires its exact current image')
        if (_regular_bytes(self.path, 16384) != self.raw
                or native_helpers_identity() != self.worker_identity):
            raise ValueError('native transaction owner changed during reservation')
        self.manifest_sha256 = sha256(self.raw).hexdigest()

    def _check_active(self):
        if (not self.active or self.variable.get() is not self
                or os.getpid() != self.pid or threading.get_ident() != self.thread):
            raise ValueError('native transaction owner belongs to its live process, thread and context')

    def select(self):
        self._check_active()
        from .hia_native_helpers import native_helpers_identity
        selected_path = os.environ.get(SELECTOR)
        if selected_path is not None:
            if not selected_path:
                raise ValueError('native Store transaction selector must not be empty')
            if Path(selected_path).resolve(strict=True) != self.path:
                raise ValueError('native transaction selector differs from its explicit owner')
        if native_helpers_identity() != self.worker_identity:
            raise ValueError('native transaction worker authority differs from its explicit owner')
        if _regular_bytes(self.path, 16384) != self.raw:
            raise ValueError('native transaction owner manifest changed')
        selected = installed_store_transaction(str(self.path), _bound_image=self.image)
        if (selected is not self.image or _regular_bytes(self.path, 16384) != self.raw
                or native_helpers_identity() != self.worker_identity):
            raise ValueError('native transaction owner changed during selection')
        self._check_active()
        return selected


@contextmanager
def transaction_owner_scope(manifest_path, image):
    """Select an already-admitted exact image without altering caller env.

    Absence of a selector inside this explicit scope is permitted. An empty or
    conflicting selector is refused. Outside the scope the original lazy
    environment selection is unchanged. A copied context cannot reactivate a
    completed scope or authorize a different process/thread.
    """
    binding = _TransactionOwnerBinding(manifest_path, image)
    token = binding.variable.set(binding)
    binding.active = True
    try:
        binding.select()
        yield binding
    finally:
        binding.active = False
        binding.variable.reset(token)


def _checksum(words):
    value = 1469598103934665603
    for index, word in enumerate(words):
        if index != 10:
            value = (((value << 7) | (value >> 57)) & ((1 << 64) - 1)) ^ word
    return value


def _retain_current_error():
    """Keep a genuine handled-exception state for a later bare re-raise.

The transport primes this one-shot generator only in the actual handler after
HIA has chosen propagation. Its final advance occurs after HIA-authorized
operand release, outside that handler. No exception attributes are inspected
or rewritten; Python also supplies its ordinary StopIteration conversion.
    """
    try:
        raise
    except _BaseException:
        yield
        raise


@dataclass(frozen=True)
class TransactionReceipt:
    port: int
    sequence: int
    phase: int
    failed: int


class StoreTransactionFrame:
    """One logical generator, with separate actual-resume delivery records."""

    def __init__(self, image, store, *, namespace=None):
        if type(image) is not NativeStoreTransaction:
            raise TypeError('native Store transaction requires an admitted image')
        from . import hia_agent_store
        self.image, self.store = image, store
        self.namespace = vars(hia_agent_store) if namespace is None else namespace
        self.global_builtins = hia_agent_store._STORE_TRANSACTION_GLOBAL_BUILTINS
        self.context_lookup_order = _runtime_context_lookup_order()
        self.data = {}
        self.exception = None
        # Reserve the exception carrier before any lock/SQL effect. A later
        # propagation choice does not need to allocate a new generator.
        self._error_transfer = _retain_current_error()
        self._error_transfer_ready = False
        identity = struct.unpack('<2Q', os.urandom(16))
        self.identity = identity if identity != (0, 0) else (1, 0)
        self.buffer = ctypes.create_string_buffer(STATE_BYTES + 16)
        ctypes.memmove(ctypes.addressof(self.buffer) + STATE_BYTES, b'\xb7' * 16, 16)
        self.receipt = None
        self._delivery = self._ambient = self._resource_scope = None
        self.fenced = self.finished = self.native_failed = self.effect_started = False
        self._body_observation = reserve_resource_observation(self, store)
        try:
            with _custody_lock():
                # Grow before lock entry/BEGIN. No arbitrary active/unknown
                # count limits narrow the original Store/generator domain.
                _FRAME_CUSTODY[id(self)] = self
        except _BaseException:
            self._body_observation.retire()
            raise

    def _release(self):
        with _custody_lock():
            _FRAME_CUSTODY.pop(id(self), None)
        self._body_observation.retire()

    def _new_advance(self):
        if self.fenced or self.finished or self._delivery is not None:
            raise StoreTransactionUnknown('native Store transaction has no new advance')
        if self._resource_scope is not None:
            self._resource_scope.deactivate()
        scope = resource_scope(self.store, unknown=StoreTransactionUnknown)
        scope.__enter__()
        self._resource_scope = scope
        record = DeliveryRecord(self)
        self._delivery = record
        record.associate(self.store, unknown=StoreTransactionUnknown)
        ambient = record.foreign(observation=False)
        ambient.__enter__()
        self._ambient = ambient

    def _end_advance(self):
        ambient, record = self._ambient, self._delivery
        self._ambient = None
        try:
            if ambient is not None:
                ambient.__exit__(*sys.exc_info())
        finally:
            if record is not None:
                record.retire()
            self._delivery = None

    def call(self, event, observation=0):
        record = self._delivery
        if self.fenced or self.finished or record is None or not record.current():
            raise StoreTransactionUnknown('native Store transaction has no current advance')
        record.check(StoreTransactionUnknown)
        handed_off = False
        try:
            port, sequence = (0, 0) if self.receipt is None else (self.receipt.port, self.receipt.sequence)
            raw = struct.pack('<10Q', REQUEST_MAGIC, event, sequence, port, observation, 1, *self.identity, 0, 0)
            source = ctypes.create_string_buffer(raw + b'\xc9' * 16, REQUEST_BYTES + 16)
            output = ctypes.create_string_buffer(OUTPUT_BYTES + 16)
            ctypes.memmove(ctypes.addressof(output) + OUTPUT_BYTES, b'\xa5' * 16, 16)
            record.enter_native()
            handed_off = True
            code = self.image._entry(source, REQUEST_BYTES, output, OUTPUT_BYTES, self.buffer, STATE_BYTES)
            if (code != OUTPUT_BYTES or source.raw != raw + b'\xc9' * 16
                    or output.raw[OUTPUT_BYTES:] != b'\xa5' * 16
                    or self.buffer.raw[STATE_BYTES:] != b'\xb7' * 16):
                raise StoreTransactionUnknown('native Store transaction return is unconfirmed')
            words = struct.unpack('<12Q', output.raw[:OUTPUT_BYTES])
            state = struct.unpack('<16Q', self.buffer.raw[:STATE_BYTES])
            expected_sequence = 1 if event == INITIALIZE else sequence if event == CLAIM else sequence + 1
            expected_phases = ((ISSUED, RETURNED, PROPAGATE, BODY_WAIT, LEAVE_HANDLER) if event == SUCCEEDED
                               else (CLAIMED,) if event == CLAIM else (ISSUED, LEAVE_HANDLER) if event == RAISED
                               else (ISSUED,))
            if (words[0] != RESULT_MAGIC or words[1] != 0
                    or words[2:7] != (state[3], state[4], state[5], state[2], state[12])
                    or state[:3] != (STATE_MAGIC, 1, 1)
                    or words[8:10] != self.identity or state[6:8] != self.identity
                    or words[7] != 0 or words[10:12] != (0, 0)
                    or state[14:16] != (0, 0) or state[10] != _checksum(state)
                    or state[8] > 3 or state[9] > 3 or state[11] > 2 or state[12] > 1 or state[13] > 1
                    or words[3] != expected_sequence or words[4] not in expected_phases
                    or (words[4] == PROPAGATE and words[6] != 1)
                    or (words[6] != 0 and words[4] != PROPAGATE
                        and (words[4] not in (CLAIMED, LEAVE_HANDLER) or words[2] != PORT['terminal_release']))
                    or (words[4] in (RETURNED, PROPAGATE, BODY_WAIT) and words[2] != 0)
                    or (words[4] in (RETURNED, PROPAGATE) and port != PORT['terminal_release'])
                    or (words[4] in (ISSUED, CLAIMED, LEAVE_HANDLER) and not 1 <= words[2] <= len(PORTS))
                    or (words[4] == LEAVE_HANDLER and (words[2] != PORT['terminal_release']
                        or state[8] & 1 or state[13] != state[12]))
                    or (words[4] == BODY_WAIT and (state[8], state[9], state[11], state[12], state[13]) != (3, 3, 0, 0, 0))
                    or (event == CLAIM and words[2] != port)):
                raise StoreTransactionUnknown('native Store transaction receipt differs from issued state')
            self.receipt = TransactionReceipt(words[2], words[3], words[4], words[6])
            # BODY_WAIT ends this actual advance, not the transaction itself.
            record.confirmed(terminal=words[4] in (RETURNED, PROPAGATE, BODY_WAIT))
            return self.receipt
        except _BaseException as error:
            lost = record.failed(error)
            self.fenced = True
            self.native_failed = self.native_failed or lost
            # Safe preparation before the first native handoff has neither a
            # native nor a foreign observation obligation. Preserve its error
            # identity and let the outer driver release that unused custody.
            # A prior foreign ACK/body-result obligation is retained by its
            # own explicit record/token, without inventing a native entry.
            if handed_off and isinstance(error, Exception) and (
                    not isinstance(error, RuntimeError) or isinstance(error, _REQUEST_REJECTIONS)):
                raise StoreTransactionUnknown('native Store transaction observation failed') from error
            raise

    def _foreign_error(self, error):
        if self.native_failed or self._delivery.loss is not None:
            self.fenced = True
            self._delivery.propagate(error, StoreTransactionUnknown, _REQUEST_REJECTIONS)
            raise
        self.exception = sys.exc_info()
        self.call(RAISED)

    def _completed(self):
        if self.receipt.phase not in (RETURNED, PROPAGATE):
            raise StoreTransactionUnknown('native Store transaction did not confirm completion')
        self.finished = True
        self._release()

    def _exception_continuation(self):
        """Remain in the actual handler until HIA confirms leave or propagate."""
        while self.receipt.phase == ISSUED:
            self.call(CLAIM)
            self.effect_started = True
            try:
                with self._delivery.foreign():
                    observed = self.effect(self.receipt.port)
            except _BaseException as error:
                self._foreign_error(error)
                if self.receipt.phase == PROPAGATE:
                    self._completed()
                    raise
                self._exception_continuation()
                return
            self.call(SUCCEEDED, observed)
        if self.receipt.phase == LEAVE_HANDLER:
            if self.receipt.failed:
                if self._error_transfer_ready:
                    raise StoreTransactionUnknown('native transaction already captured its final error')
                next(self._error_transfer)
                self._error_transfer_ready = True
            return
        if self.receipt.phase == PROPAGATE:
            self._completed()
            raise
        raise StoreTransactionUnknown('native Store transaction has no exception continuation')

    def drive(self):
        while self.receipt.phase in (ISSUED, LEAVE_HANDLER):
            self.call(CLAIM)
            self.effect_started = True
            try:
                with self._delivery.foreign():
                    observed = self.effect(self.receipt.port)
            except _BaseException as error:
                self._foreign_error(error)
                if self.receipt.phase == PROPAGATE:
                    self._completed()
                    raise
                self._exception_continuation()
                self.exception = None
                # The next port runs only after leaving this real handler.
                continue
            self.call(SUCCEEDED, observed)
        if self.receipt.phase in (RETURNED, PROPAGATE):
            self._completed()
            if self.receipt.phase == PROPAGATE:
                if not self._error_transfer_ready:
                    raise StoreTransactionUnknown('native transaction has no captured propagation')
                next(self._error_transfer)
                raise StoreTransactionUnknown('native transaction error carrier returned')
        elif self.receipt.phase != BODY_WAIT:
            raise StoreTransactionUnknown('native Store transaction has no confirmed suspension')

    def start(self):
        self._new_advance()
        self.call(INITIALIZE)
        self.drive()
        return self.receipt.phase

    def suspend(self):
        if self.receipt.phase != BODY_WAIT:
            raise StoreTransactionUnknown('native Store transaction did not issue a body suspension')
        self._end_advance()

    def resume(self, event):
        # Reserve was made before BEGIN. Mark the real foreign return/throw
        # before allocating a new record, storing an exception tuple, or
        # preparing any continuation packet, including a legal new thread.
        self._body_observation.observed()
        if event == BODY_RAISED:
            self.exception = sys.exc_info()
        self._new_advance()
        self.call(event)
        self._body_observation.confirmed()

    def failed(self, error):
        self._body_observation.failed(error)
        record = self._delivery
        if record is not None:
            record.failed(error)
            if record.loss is not None:
                self.fenced = self.native_failed = True
                record.propagate(error, StoreTransactionUnknown, _REQUEST_REJECTIONS)
        if self._body_observation.loss is not None:
            self.fenced = self.native_failed = True
        if not self.effect_started and not self.native_failed:
            self._release()

    def finish_advance(self):
        try:
            self._end_advance()
        finally:
            if self._resource_scope is not None:
                self._resource_scope.deactivate()

    def effect(self, port):
        """One original object/SQL operation; no host transaction policy."""
        if not 1 <= port <= len(PORTS):
            raise StoreTransactionUnknown('native Store transaction issued an unknown port')
        name = PORTS[port - 1]
        d = self.data
        if name == 'lock_lookup':
            d['manager'] = self.store.lock
            d['lookup'] = iter(self.context_lookup_order)
        elif name == 'context_lookup_next':
            return next(d['lookup'], 0)
        elif name == 'context_lookup_enter':
            d['enter'] = _context_special(d['manager'], '__enter__')
        elif name == 'context_lookup_exit':
            d['exit'] = _context_special(d['manager'], '__exit__')
        elif name == 'lock_enter':
            del d['lookup'], d['manager']
            # Consume the captured callable in the actual CALL expression.
            # Its release precedes POP_TOP of the enter result, as with does.
            d.pop('enter')()
        elif name == 'begin':
            self.store.db.execute(guarded('BEGIN IMMEDIATE'))
        elif name == 'body_exception_match':
            matcher = _global_value(self.namespace, self.global_builtins, 'BaseException')
            try:
                raise
            except matcher:
                return 1
            except _BaseException:
                return 0
        elif name == 'rollback':
            self.store.db.execute(guarded('ROLLBACK'))
        elif name == 'commit':
            self.store.db.execute(guarded('COMMIT'))
        elif name == 'lock_exit_normal':
            d.pop('exit')(None, None, None)
        elif name == 'lock_exit_exception':
            d['exit_outcome'] = d['exit'](*self.exception)
        elif name == 'lock_exit_truth':
            return int(bool(d.pop('exit_outcome')))
        elif name == 'terminal_release':
            self.exception = None
            d.clear()
        return 0


def store_transaction_context(image, store, *, namespace=None):
    """Use the identical single raw generator as the actual public route."""
    from .hia_agent_store import _store_transaction_context
    return _store_transaction_context(store, image, namespace=namespace)
