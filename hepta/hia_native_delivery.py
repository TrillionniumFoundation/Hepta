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
import weakref


class NativeDeliveryUnknown(RuntimeError):
    """A real causal native delivery is unconfirmed; no ordinary terminal."""


_ACTIVE = ContextVar('hia_native_delivery_foreign_call', default=None)
_CUSTODY = {}
_CUSTODY_LOCK = threading.Lock()
_CUSTODY_PID = os.getpid()
_RESOURCE_ACTIVE = ContextVar('hia_native_delivery_resource_scope', default=None)
_RESOURCE_LIFETIMES = {}
_RESOURCE_OBSERVATIONS = {}
_RESOURCE_SERIAL = 0


class _ResourceLifetime:
    __slots__ = ('pid', 'serial')

    def __init__(self, serial):
        self.pid, self.serial = os.getpid(), serial


def _resource_token(resource):
    selected = _RESOURCE_LIFETIMES.get(id(resource))
    return selected[1] if selected is not None and selected[0]() is resource else None


def _resource_loss(resource):
    # Unknown records retain the actual object, preventing object-id reuse.
    # Reinitializing the SAME object cannot launder an earlier actual loss.
    with _custody_lock():
        for record in _CUSTODY.values():
            if record.loss is not None and any(item[0] is resource for item in record.resources):
                return record.loss
        for observation in _RESOURCE_OBSERVATIONS.values():
            if observation.loss is not None and observation.resource is resource:
                return observation.loss
    return None


def check_resource_retirement(resource, *, unknown=NativeDeliveryUnknown):
    """Refuse this exact resource's actual retained loss, not a global flag.

No resource attributes, equality, hashes or filesystem paths are consulted.
A healthy resource gains no new thread/fork restriction. Existing owner guards
retain their separate policy and precedence.
    """
    loss = _resource_loss(resource)
    if loss is not None:
        raise unknown('resource has unconfirmed native delivery; it cannot be retired') from loss.error


def bind_resource_lifetime(resource, *, unknown=NativeDeliveryUnknown):
    """Reserve a construction generation without retaining a healthy owner."""
    global _RESOURCE_SERIAL
    check_resource_retirement(resource, unknown=unknown)
    with _custody_lock():
        _RESOURCE_SERIAL += 1
        token = _ResourceLifetime(_RESOURCE_SERIAL)
    key = id(resource)

    def released(reference):
        with _custody_lock():
            selected = _RESOURCE_LIFETIMES.get(key)
            if selected is not None and selected[0] is reference:
                del _RESOURCE_LIFETIMES[key]

    try:
        reference = weakref.ref(resource, released)
    except TypeError:
        # Non-weakrefable DB/lock objects need no global strong registry. Their
        # exact objects are retained only by explicit invocation associations.
        return token
    with _custody_lock():
        _RESOURCE_LIFETIMES[key] = (reference, token)
    return token


def _resource_bindings():
    pid, thread = os.getpid(), threading.get_ident()
    resources = []
    scope = _RESOURCE_ACTIVE.get()
    while type(scope) is ResourceScope:
        if scope.active and scope.pid == pid and scope.thread == thread:
            for item in scope.resources:
                if not any(previous[0] is item[0] for previous in resources):
                    resources.append(item)
        scope = scope.previous
    # Inherit only explicit associations of real live ancestors. Never inspect
    # arbitrary owners to guess a Store, connection or lock relationship.
    scope = _ACTIVE.get()
    while type(scope) is ForeignCall:
        if _live(scope, pid, thread):
            for item in scope.record.resources:
                if not any(previous[0] is item[0] for previous in resources):
                    resources.append(item)
        scope = scope.previous
    return resources


class ResourceScope:
    """Explicit resource scope, separate from native causal activation.

A Python generator may resume in a different Context/thread. deactivate()
does not reset another Context's token or change this activation's creator.
Inactive leftovers carry no resources and never form active ancestry.
    """
    __slots__ = ('resources', 'pid', 'thread', 'previous', 'active', 'entered', 'unknown')

    def __init__(self, resource, unknown):
        self.resources = [(resource, _resource_token(resource))]
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.previous = None
        self.active = self.entered = False
        self.unknown = unknown

    def __enter__(self):
        if self.entered:
            raise self.unknown('resource scope activation cannot be reused')
        if self.pid != os.getpid() or self.thread != threading.get_ident():
            raise self.unknown('a resource scope must be activated in its creator context')
        for resource, _ in self.resources:
            check_resource_retirement(resource, unknown=self.unknown)
        previous = _RESOURCE_ACTIVE.get()
        while type(previous) is ResourceScope and not previous.active:
            previous = previous.previous
        self.previous = previous
        _RESOURCE_ACTIVE.set(self)
        self.entered = self.active = True
        return self

    def deactivate(self):
        self.active = False
        if _RESOURCE_ACTIVE.get() is self:
            previous = self.previous
            while type(previous) is ResourceScope and not previous.active:
                previous = previous.previous
            _RESOURCE_ACTIVE.set(previous)
        # Releasing user objects outside the custody lock avoids running their
        # foreign finalizers while the representation lock is held.
        self.resources.clear()

    def __exit__(self, kind, error, traceback):
        self.deactivate()
        return False


def resource_scope(resource, *, unknown=NativeDeliveryUnknown):
    return ResourceScope(resource, unknown)


class ResourceObservation:
    """Pre-reserved delivery of a foreign result across a suspended yield.

This is not a native handoff or a recycled NativeCall. A fresh actual advance
still owns its own creator-bound DeliveryRecord. The token may be marked by a
legal cross-Context/thread resume without changing any native record's creator.
    """
    __slots__ = ('owner', 'resource', 'token', 'reserved_pid', 'reserved_thread',
                 'pending', 'retired', 'loss', 'error')

    def __init__(self, owner, resource):
        check_resource_retirement(resource)
        self.owner, self.resource, self.token = owner, resource, _resource_token(resource)
        self.reserved_pid, self.reserved_thread = os.getpid(), threading.get_ident()
        self.pending = self.retired = False
        self.loss = self.error = None
        with _custody_lock():
            _RESOURCE_OBSERVATIONS[id(self)] = self

    def observed(self):
        if self.retired or self.loss is not None:
            raise NativeDeliveryUnknown('foreign resource observation cannot be resumed')
        # This assignment precedes allocation of a fresh native advance record
        # or storage/packing of the foreign result being delivered.
        self.pending = True

    def confirmed(self):
        if self.loss is not None:
            raise NativeDeliveryUnknown('foreign resource observation is unconfirmed') from self.error
        if self.retired or not self.pending:
            raise NativeDeliveryUnknown('foreign resource observation was not pending')
        self.pending = False
        self.retire()

    def failed(self, error):
        if self.retired or not self.pending:
            return False
        if self.loss is None:
            self.error, self.loss = error, self
        # Only the current real activation chain is notified. No native
        # ancestry is inferred from where the suspended body originally ran.
        pid, thread = os.getpid(), threading.get_ident()
        scope = _ACTIVE.get()
        while type(scope) is ForeignCall:
            if _live(scope, pid, thread) and scope.record.loss is None:
                scope.record.loss = self
            scope = scope.previous
        return True

    def retire(self):
        if self.loss is not None or self.pending:
            return
        with _custody_lock():
            if _RESOURCE_OBSERVATIONS.get(id(self)) is self:
                del _RESOURCE_OBSERVATIONS[id(self)]
        self.retired = True
        self.owner = self.resource = self.token = None


def reserve_resource_observation(owner, resource):
    return ResourceObservation(owner, resource)


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
                 'observation_pending', 'terminal', 'retired', 'loss', 'error', 'resources')

    def __init__(self, owner):
        self.owner = owner
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.parent = _active_scope()
        self.native_pending = self.observation_pending = False
        self.terminal = self.retired = False
        self.loss = self.error = None
        self.resources = _resource_bindings()
        if self.parent is not None:
            self.parent.record.check()
        # No fixed active/unknown quota. Failure to reserve happens before the
        # invocation can start an external effect or native handoff.
        with _custody_lock():
            _CUSTODY[id(self)] = self
        for resource, _ in self.resources:
            loss = _resource_loss(resource)
            if loss is not None:
                self.loss = loss
                self.publish(loss.error)
                self.check()

    def associate(self, resource, *, unknown=NativeDeliveryUnknown):
        """Associate an already obtained object without extra user lookup."""
        self.check(unknown)
        if self.retired or self.terminal:
            raise unknown('native delivery invocation already completed')
        if not any(item[0] is resource for item in self.resources):
            self.resources.append((resource, _resource_token(resource)))
        loss = _resource_loss(resource)
        if loss is not None:
            self.loss = loss
            self.publish(loss.error)
            self.check(unknown)
        return resource

    def current(self):
        return self.pid == os.getpid() and self.thread == threading.get_ident()

    def check(self, unknown=NativeDeliveryUnknown):
        if not self.current():
            raise unknown('native delivery record cannot be inherited or transferred')
        # A bound resource can acquire a real loss in another Context/thread
        # after this invocation was created. Recheck the exact object at each
        # guard; this is resource evidence, not cross-thread native ancestry.
        for resource, _ in self.resources:
            if self.loss is None:
                origin = _resource_loss(resource)
                if origin is not None:
                    self.loss = origin
                    self.publish(origin.error)
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
        self.resources.clear()

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
