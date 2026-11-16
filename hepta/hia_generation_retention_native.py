"""Retained HIA generation references and one-close lease cells.

The HIA block is the reference-count and retirement-handoff authority. Python
keeps locks, opaque object custody, allocation and the original resource effects.
Neither public generation numbers nor selection epochs enter this ABI. The
reference count grows as canonical magnitude bytes instead of wrapping at a
machine integer boundary. A selected native invocation is never retried after
an uncertain return, and its foreign objects remain strongly quarantined.
"""
from __future__ import annotations

import ctypes
import os
import struct
import threading

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/generation_retention.hepta')
SCHEMA = 'hepta.hia.generation-retention-native.v1'
SELECTOR = 'HEPTA_HIA_GENERATION_RETENTION_MANIFEST'
REQUEST_MAGIC = int.from_bytes(b'HIAGRQ01', 'little')
STATE_MAGIC = int.from_bytes(b'HIAGST01', 'little')
LEASE_MAGIC = int.from_bytes(b'HIAGLS01', 'little')
NEED_CAPACITY = 4294967288
_QUERY_FLAGS = (0, 1, 4, 15, 29)
_QUARANTINED = {}


class NativeGenerationFailure(RuntimeError):
    """The selected retained owner cannot authorize further resource effects."""


def _identity():
    value = struct.unpack('<2Q', os.urandom(16))
    if value == (0, 0):
        raise NativeGenerationFailure('native generation instance identity unavailable')
    return value


def _error(error):
    return {'type': type(error).__name__, 'message': str(error)[:1024]}


def generation_quarantine_snapshot():
    """Read-only diagnostics; these observations never restore effect rights."""
    return [state.diagnostic() for state in tuple(_QUARANTINED.copy().values())]


def _admit_new_custody():
    if _QUARANTINED:
        raise NativeGenerationFailure('native generation custody is quarantined; new native owners require process retirement')


class NativeGenerationImage(NativeHiaJsonImage):
    def owner(self, runtime, *, initial_capacity=1):
        _admit_new_custody()
        return GenerationRetention(self, runtime, initial_capacity=initial_capacity)


def installed_generation_retention(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeGenerationImage)


def selected_generation_retention():
    """Called once before a new runtime creates any filesystem resources."""
    _admit_new_custody()
    path = os.environ[SELECTOR]
    if not path:
        raise ValueError('generation retention selector must not be empty')
    return installed_generation_retention(path)


class LeaseCell:
    """Foreign object custody and the native-owned 64-byte lease cell."""
    def __init__(self, owner, lease):
        self.owner = owner
        self.lease = lease
        self.identity = _identity()
        self.buffer = ctypes.create_string_buffer(64)

    @property
    def closed(self):
        return self.owner.lease_status(self) == 2

    def require_open(self):
        self.owner.require_healthy()
        return self.owner.lease_status(self) == 1


class GenerationRetention:
    """One generation block, retained across every original runtime operation.

    The live-cell table is custody, not a reference-count implementation. It is
    never counted to reconstruct or overwrite HIA state. Growth retains prior
    buffer allocations so an existing alias cannot become a dangling pointer.
    The task nonce binds exactly one original NativeRetirement holder in HIA.
    """
    def __init__(self, image, runtime, *, initial_capacity=1):
        if type(initial_capacity) is not int or initial_capacity < 1:
            raise ValueError('generation reference capacity must be positive')
        self.image = image
        self._runtime = runtime
        self._generation = None
        self._creator_pid = os.getpid()
        self._lock = threading.RLock()
        self._owner = _identity()
        self._task_identity = _identity()
        self._buffer = ctypes.create_string_buffer(64 + initial_capacity)
        self._previous_buffers = []
        self._cells = {}
        self._allocation_error = None
        self._allocation_cell = None
        self._task = None
        self._fenced = None
        self._last_observation = None
        self._transition(0)

    def bind(self, generation):
        if self._generation is not None and self._generation is not generation:
            raise NativeGenerationFailure('generation resource custody cannot be rebound')
        self._generation = generation

    def _check_process(self):
        if os.getpid() != self._creator_pid:
            raise NativeGenerationFailure('native generation owner belongs to its creator process')

    def require_healthy(self):
        self._check_process()
        if self._fenced is not None:
            raise NativeGenerationFailure('native generation state is fenced; no transition or effect retry permitted')

    def fence(self, error):
        # This also roots a just-activated lease whose Python return delivery
        # was interrupted. No destructor or recovery API releases this custody.
        if self._fenced is None:
            self._fenced = _error(error)
        _QUARANTINED[(self._creator_pid, self._owner)] = self

    def _invoke(self, event, cell=None, token=(0, 0)):
        raw = struct.pack('<8Q', REQUEST_MAGIC, event, *self._owner, *token, 0, 0)
        source = ctypes.create_string_buffer(raw, 64)
        output = ctypes.create_string_buffer(64) if cell is None else cell.buffer
        before_state, before_cell = self._buffer.raw, output.raw
        returned = self.image._entry(source, 64, output, 64, self._buffer, len(self._buffer))
        if source.raw != raw:
            raise NativeGenerationFailure('native generation changed its immutable request')
        allowed = {0: (0,), 1: (0, NEED_CAPACITY), 2: (0, 1), 3: (0,),
                   4: (0, 1), 5: _QUERY_FLAGS, 6: (1, 2)}[event]
        if type(returned) is not int or returned not in allowed:
            raise NativeGenerationFailure('invalid native generation transition receipt: ' + str(returned))
        if event in (5, 6) or returned == NEED_CAPACITY:
            if self._buffer.raw != before_state or output.raw != before_cell:
                raise NativeGenerationFailure('native generation changed state during read or capacity refusal')
        elif event in (0, 3, 4) and output.raw != before_cell:
            raise NativeGenerationFailure('native generation changed an unrelated lease cell')
        return returned

    def _observe(self):
        flags = self._invoke(5)
        raw = self._buffer.raw
        words = struct.unpack('<8Q', raw[:64])
        if (words[0] != STATE_MAGIC or words[1:3] != self._owner
                or words[4] > len(raw) - 64 or words[3] != flags & 3):
            raise NativeGenerationFailure('native generation receipt does not bind its retained block')
        result = {'references': int.from_bytes(raw[64:64 + words[4]], 'little'),
                  'retired': bool(flags & 1), 'claimed': bool(flags & 2),
                  'retirement_ready': bool(flags & 8), 'collectible': bool(flags & 16)}
        self._last_observation = result
        return result

    def observe(self):
        """Query native bytes even after fencing, without resuming mutation."""
        self._check_process()
        with self._lock:
            try:
                return dict(self._observe())
            except BaseException as error:
                self.fence(error)
                raise

    def _transition(self, event, cell=None, token=(0, 0)):
        self._check_process()
        with self._lock:
            self.require_healthy()
            try:
                returned = self._invoke(event, cell, token)
                if returned == NEED_CAPACITY:
                    # A complete, verified no-write receipt permits the caller
                    # to allocate storage without risking a repeated mutation.
                    return returned
                observation = self._observe()
                if event in (1, 2):
                    status = self._invoke(6, cell, token)
                    if status != (1 if event == 1 else 2):
                        raise NativeGenerationFailure('native generation receipt does not bind its lease cell')
                if event == 0 and observation != {
                        'references': 0, 'retired': False, 'claimed': False,
                        'retirement_ready': False, 'collectible': False}:
                    raise NativeGenerationFailure('native generation did not initialize fresh state')
                if event == 3 and not observation['retired']:
                    raise NativeGenerationFailure('native generation did not attest retirement')
                if event == 4:
                    self._check_task_claim(token, observation)
                return returned
            except BaseException as error:
                self.fence(error)
                raise

    def new_cell(self, lease):
        self.require_healthy()
        return LeaseCell(self, lease)

    def acquire(self, cell):
        self._check_process()
        with self._lock:
            self.require_healthy()
            self._allocation_error = None
            self._allocation_cell = None
            try:
                if cell.owner is not self:
                    # The native owner check still binds any supplied cell;
                    # foreign Python custody must not be silently transferred.
                    raise NativeGenerationFailure('lease cell belongs to another native custodian')
                prior = self._cells.get(cell.identity)
                if prior is not None and prior is not cell:
                    raise NativeGenerationFailure('lease identity collides with retained custody')
                try:
                    self._cells[cell.identity] = cell
                except MemoryError as error:
                    # Even an insertion that completed before raising has not
                    # entered HIA. Restore only the new custody registration.
                    if prior is None:
                        self._cells.pop(cell.identity, None)
                    self._allocation_error = error
                    self._allocation_cell = cell
                    raise
                while self._transition(1, cell, cell.identity) == NEED_CAPACITY:
                    # No native invocation is pending in this allocation block.
                    # The original block and cell remain untouched if memory
                    # allocation fails; no active lease has been delivered.
                    previous = self._buffer
                    try:
                        expanded = ctypes.create_string_buffer(64 + (len(previous) - 64) * 2)
                        ctypes.memmove(expanded, previous, len(previous))
                        self._previous_buffers.append(previous)
                    except MemoryError as error:
                        self._cells.pop(cell.identity, None)
                        self._allocation_error = error
                        self._allocation_cell = cell
                        raise
                    self._buffer = expanded
            except BaseException as error:
                if self._allocation_error is not error or self._allocation_cell is not cell:
                    self.fence(error)
                raise

    def acquire_failed(self, error, cell):
        """Finish caller return handling, preserving a proven no-write failure.

        This one-use transport receipt is only issued for failed custody
        insertion before HIA, or failed allocation after NEED_CAPACITY. It
        contains no reference count or lifecycle policy. All other interrupted
        returns retain the original quarantine behavior.
        """
        self._check_process()
        with self._lock:
            no_transition = (self._allocation_error is error and self._allocation_cell is cell
                             and cell.owner is self)
            self._allocation_error = None
            self._allocation_cell = None
            if not no_transition:
                self.fence(error)

    def close(self, cell):
        self._check_process()
        with self._lock:
            self.require_healthy()
            try:
                self._transition(2, cell, cell.identity)
                self._cells.pop(cell.identity, None)
            except BaseException as error:
                self.fence(error)
                raise

    def lease_status(self, cell):
        self._check_process()
        with self._lock:
            try:
                return self._invoke(6, cell, cell.identity)
            except BaseException as error:
                self.fence(error)
                raise

    def retire(self):
        self._transition(3)

    def retirement_ready(self):
        self.require_healthy()
        return self.observe()['retirement_ready']

    def retain_task(self, task):
        """Strongly retain the original effect owner before table registration."""
        self.require_healthy()
        with self._lock:
            if self._task is not None and self._task is not task:
                raise NativeGenerationFailure('generation retirement custody cannot be rebound')
            self._task = task
            task._generation_retention = self

    def _check_task_claim(self, token, observation):
        if (not observation['claimed'] or not observation['retirement_ready']
                or struct.unpack_from('<2Q', self._buffer, 48) != token):
            raise NativeGenerationFailure('native retirement claim does not bind its original effect owner')

    def claim_registered_task(self, task):
        """Claim once; a delivered claim is recovered with a read-only query."""
        self._check_process()
        with self._lock:
            self.require_healthy()
            if self._task is not task or self._runtime._cleanup_pending.get(task.generation) is not task:
                raise NativeGenerationFailure('native retirement requires its registered original effect owner')
            observation = self.observe()
            if observation['claimed']:
                self._check_task_claim(self._task_identity, observation)
            else:
                self._transition(4, token=self._task_identity)

    def require_claimed_task(self, task):
        self._check_process()
        with self._lock:
            self.require_healthy()
            if self._task is not task:
                raise NativeGenerationFailure('native retirement effect owner differs from retained custody')
            self._check_task_claim(self._task_identity, self.observe())

    def diagnostic(self):
        result = {'creator_pid': self._creator_pid, 'effects_permitted': False,
                  'native_policy_error': None if self._fenced is None else dict(self._fenced)}
        if os.getpid() != self._creator_pid:
            result['status'] = 'foreign_process_quarantine'
            return result
        try:
            result['observation'] = self.observe()
            result['observation_is_last_attested'] = False
        except BaseException as error:
            result['observation'] = self._last_observation
            result['observation_is_last_attested'] = True
            result['query_error'] = _error(error)
        generation = self._generation
        if generation is not None:
            result['generation_custody'] = {
                'generation': generation.info.generation, 'native_descriptor': generation.fd,
                'library_held': generation.library is not None,
                'function_references': len(generation.functions)}
        result['retirement_task_held'] = self._task is not None
        return result
