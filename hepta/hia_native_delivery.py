"""Call-local custody for uncertain native delivery across owner boundaries.

Only an adapter's actual native handoff or undelivered observation can publish
loss. Exception classes, image identity and an administrator selection scope
are not evidence of loss or ancestry. This module grants no effect/replay
authority and implements no HIA business policy.
"""
from __future__ import annotations

from contextvars import ContextVar
import os
import threading


class NativeDeliveryUnknown(RuntimeError):
    """A real causal native delivery is unconfirmed; no ordinary terminal."""


_ACTIVE = ContextVar('hia_native_delivery_foreign_call', default=None)
_CUSTODY = {}
_CUSTODY_LOCK = threading.Lock()
_CUSTODY_PID = os.getpid()


def _after_fork_child():
    global _CUSTODY_LOCK, _CUSTODY_PID
    # Retain inherited records and their actual resources. Their original PID
    # never changes, so neither inherited contexts nor tokens become active
    # child-process ancestry. Only the representation lock is replaced.
    _CUSTODY_LOCK = threading.Lock()
    _CUSTODY_PID = os.getpid()


if hasattr(os, 'register_at_fork'):
    os.register_at_fork(after_in_child=_after_fork_child)


def _custody_lock():
    if os.getpid() != _CUSTODY_PID:
        raise NativeDeliveryUnknown('delivery custody belongs to its creator process')
    return _CUSTODY_LOCK


def _live(scope, pid, thread):
    return (type(scope) is ForeignCall and scope.active
            and scope.record.pid == pid and scope.record.thread == thread
            and not scope.record.retired and not scope.record.terminal)


def _active_scope():
    scope = _ACTIVE.get()
    pid, thread = os.getpid(), threading.get_ident()
    while type(scope) is ForeignCall:
        if _live(scope, pid, thread):
            return scope
        scope = scope.previous
    return None


class DeliveryRecord:
    """One actual invocation, reserved before any new external effect.

An owner with a longer lifetime creates a fresh record for each invocation.
The first loss roots its origin through every live causal ancestor. Successful
records are removed; unknown records have explicit process-lifetime custody.
"""
    __slots__ = ('owner', 'pid', 'thread', 'parent', 'native_pending',
                 'observation_pending', 'terminal', 'retired', 'loss', 'error')

    def __init__(self, owner):
        self.owner = owner
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.parent = _active_scope()
        self.native_pending = self.observation_pending = False
        self.terminal = self.retired = False
        self.loss = self.error = None
        if self.parent is not None:
            self.parent.record.check()
        # No fixed active/unknown quota. Failure to reserve happens before the
        # invocation can start an external effect or native handoff.
        with _custody_lock():
            _CUSTODY[id(self)] = self

    def current(self):
        return self.pid == os.getpid() and self.thread == threading.get_ident()

    def check(self, unknown=NativeDeliveryUnknown):
        if not self.current():
            raise unknown('native delivery record cannot be inherited or transferred')
        # A frame may have been prepared before this call. Follow the actual
        # active invocation chain, never an old construction-time relationship.
        scope = _ACTIVE.get()
        while self.loss is None and type(scope) is ForeignCall:
            if _live(scope, self.pid, self.thread) and scope.record.loss is not None:
                self.loss = scope.record.loss
                break
            scope = scope.previous
        if self.loss is not None:
            raise unknown('causal native delivery is unconfirmed; no terminal or replay') from self.loss.error

    def enter_native(self):
        self.check()
        if self.retired or self.terminal:
            raise NativeDeliveryUnknown('native delivery invocation already completed')
        # Set only immediately before the actual native call, after safe input
        # validation. An interrupted handoff cannot be proved not to execute.
        self.native_pending = True

    def confirmed(self, *, terminal=False):
        """Called only after every required receipt/state/guard is verified."""
        self.native_pending = self.observation_pending = False
        if terminal:
            self.terminal = True

    def observed(self):
        """A completed foreign return/error still needs its original ACK."""
        if self.current() and not self.retired and not self.terminal:
            self.observation_pending = True

    def foreign_refused(self):
        """The original provider/input refusal occurred before native entry.

This is not a native ACK or terminal. It only discharges a foreign preparation
obligation whose ordinary failure the existing owner already handles. A real
causal loss, if present, remains sticky.
        """
        self.observation_pending = False

    def publish(self, error):
        if not self.current() or self.retired or self.terminal:
            return False
        if self.loss is None:
            self.error = error
            self.loss = self
        origin = self.loss
        scope = _ACTIVE.get()
        while type(scope) is ForeignCall:
            if _live(scope, self.pid, self.thread):
                parent = scope.record
                if parent.loss is None:
                    parent.loss = origin
            scope = scope.previous
        return True

    def failed(self, error):
        """No loss for a safe pre-entry or post-confirmed-terminal error."""
        if self.loss is not None:
            return True
        if self.native_pending or self.observation_pending:
            return self.publish(error)
        return False

    def propagate(self, error, unknown, rejections):
        """Classify an already recorded loss, never infer loss from a class.

The caller uses a bare raise afterwards. Only the original request-rejection
families need normalization, so a replacement domain error cannot hide a real
loss. Foreign MemoryError, RuntimeError and process-control identities remain
unchanged. Each transport keeps its separate original native-entry classifier.
        """
        if self.loss is not None and isinstance(error, rejections):
            raise unknown('causal native delivery is unconfirmed') from error

    def retire(self):
        if not self.current() or self.loss is not None:
            return
        if self.native_pending or self.observation_pending:
            return
        with _custody_lock():
            if _CUSTODY.get(id(self)) is self:
                del _CUSTODY[id(self)]
        self.retired = True
        self.owner = self.parent = None

    def foreign(self, *, observation=True):
        return ForeignCall(self, observation=observation)


class ForeignCall:
    """One activation; a completed token is never reused for a later effect."""
    __slots__ = ('record', 'observation', 'active', 'token', 'entered', 'previous')

    def __init__(self, record, *, observation=True):
        self.record, self.observation = record, observation
        self.active = False
        self.token = None
        self.entered = False
        self.previous = None

    def __enter__(self):
        self.record.check()
        if self.entered:
            raise NativeDeliveryUnknown('foreign activation token cannot be reused')
        if self.record.retired or self.record.terminal:
            raise NativeDeliveryUnknown('foreign activation belongs to a completed invocation')
        self.entered = True
        self.previous = _ACTIVE.get()
        self.token = _ACTIVE.set(self)
        self.active = True
        return self

    def __exit__(self, kind, error, traceback):
        if self.observation:
            # This precedes exception storage/packet allocation in the driver.
            # An ordinary provider exception remains confirmable via event 3.
            self.record.observed()
        self.active = False
        try:
            _ACTIVE.reset(self.token)
        except BaseException as reset_error:
            self.record.publish(reset_error)
            raise
        return False


class NativeCall:
    """A pure/helper native invocation with explicit handoff/receipt cutpoints."""
    def __init__(self, owner):
        self.record = DeliveryRecord(owner)

    def __enter__(self):
        return self.record

    def __exit__(self, kind, error, traceback):
        if error is not None:
            self.record.failed(error)
        self.record.retire()
        return False


def current_record():
    scope = _active_scope()
    return None if scope is None else scope.record


def check_current():
    record = current_record()
    if record is not None:
        record.check()


def delivery_lost():
    record = current_record()
    return record is not None and record.loss is not None


def guarded(value):
    """Check after original argument evaluation, before the literal effect."""
    check_current()
    return value


def custody_snapshot():
    """Read-only transport observations; they confer no effect authority."""
    with _custody_lock():
        return tuple({'pid': record.pid, 'thread': record.thread,
                      'lost': record.loss is not None,
                      'native_pending': record.native_pending,
                      'observation_pending': record.observation_pending,
                      'terminal': record.terminal, 'retired': record.retired}
                     for record in _CUSTODY.values())
