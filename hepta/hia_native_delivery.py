"""Call-local custody for uncertain native delivery across owner boundaries.

Only an adapter's actual native handoff or undelivered observation can publish
loss. Exception classes, image identity and an administrator selection scope
are not evidence of loss or ancestry. This module grants no effect/replay
authority and implements no HIA business policy.
"""
from __future__ import annotations

from contextvars import ContextVar
import os
import sys
import threading
import weakref


class NativeDeliveryUnknown(RuntimeError):
    """A real causal native delivery is unconfirmed; no ordinary terminal."""


_ACTIVE = ContextVar('hia_native_delivery_foreign_call', default=None)
_PENDING_RESOURCE_CAPTURE = ContextVar('hia_native_delivery_pending_resources', default=None)
_CUSTODY = {}
_CUSTODY_LOCK = threading.RLock()
_CUSTODY_PID = os.getpid()
_RESOURCE_ACTIVE = ContextVar('hia_native_delivery_resource_scope', default=None)
_RESOURCE_LIFETIMES = {}
_RESOURCE_OBSERVATIONS = {}
_RESOURCE_SERIAL = 0

# A terminal observation is deliberately not a DeliveryRecord/ForeignCall.
# It grants no effect, resource, replay, close, or terminal authority. In
# particular its sticky fact cannot prevent the worker's original finally
# from attempting close. Only the existing real loss/retirement cutpoints
# below notify this current-request observer.
_REQUEST_DELIVERY = ContextVar('hia_native_delivery_request_terminal', default=None)


class RequestDeliveryObservation:
    """Read-only facts for one synchronous request terminal boundary.

    A copied or inherited Context does not revive an ended observation, nor
    transfer its PID/thread. Fresh requests do not inherit a previous loss.
    No registry is scanned when entering or reading this observation.
    """
    __slots__ = ('pid', 'thread', 'previous', 'active', 'entered', 'origin',
                 'primary_error', 'cleanup_error')

    def __init__(self):
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.previous = None
        self.active = self.entered = False
        self.origin = self.primary_error = self.cleanup_error = None

    def __enter__(self):
        if self.entered or self.pid != os.getpid() or self.thread != threading.get_ident():
            raise RuntimeError('request delivery observation cannot be reused or transferred')
        self.entered = True
        self.previous = _REQUEST_DELIVERY.get()
        _REQUEST_DELIVERY.set(self)
        self.active = True
        return self

    def __exit__(self, kind, error, traceback):
        self.active = False
        # Do not reset a ContextVar token created in another Context. A copied
        # Context may retain this inactive node; it cannot receive new facts.
        if _REQUEST_DELIVERY.get() is self:
            _REQUEST_DELIVERY.set(self.previous)
        if self.origin is None:
            self.primary_error = self.cleanup_error = None
        return False


def _current_request_observation():
    observation = _REQUEST_DELIVERY.get()
    if (type(observation) is RequestDeliveryObservation and observation.active
            and observation.pid == os.getpid()
            and observation.thread == threading.get_ident()):
        return observation
    return None


def _observe_request_loss(origin):
    # Called only after real delivery loss exists, or at an exact resource's
    # actual refusal. Retaining that origin adds no healthy resource lifetime.
    observation = _REQUEST_DELIVERY.get()
    pid, thread = os.getpid(), threading.get_ident()
    while type(observation) is RequestDeliveryObservation:
        if (observation.active and observation.pid == pid
                and observation.thread == thread and observation.origin is None):
            observation.origin = origin
        observation = observation.previous


def note_request_failure(error, *, cleanup=False):
    """Retain the actual request/close exception, without classifying it."""
    observation = _current_request_observation()
    if observation is not None:
        if cleanup:
            if observation.cleanup_error is None:
                observation.cleanup_error = error
        elif observation.primary_error is None:
            observation.primary_error = error


def release_healthy_request_failures():
    observation = _current_request_observation()
    if observation is not None and observation.origin is None:
        observation.primary_error = observation.cleanup_error = None


def guard_request_output(value):
    """Check actual request facts after argument evaluation, before stdio."""
    observation = _current_request_observation()
    if observation is not None and observation.origin is not None:
        raise NativeDeliveryUnknown(
            'request has unconfirmed native delivery; no complete worker report'
        ) from observation.origin.error
    return value



class _ResourceLifetime:
    __slots__ = ('pid', 'serial')

    def __init__(self, serial):
        self.pid, self.serial = os.getpid(), serial


def _resource_token(resource):
    selected = _RESOURCE_LIFETIMES.get(id(resource))
    return selected[1] if selected is not None and selected[0]() is resource else None


def _registered_resource_identity(resource):
    """Borrow an existing generation; never register or inspect user fields."""
    key = id(resource)
    with _custody_lock():
        selected = _RESOURCE_LIFETIMES.get(key)
        if selected is not None and selected[0]() is resource:
            return selected[0], selected[1], key
    return None


def _registered_resource_loss(registration):
    """Read already-recorded loss for an exact borrowed generation.

    No healthy target is freshly acquired. A weakref is dereferenced only
    after a lossy record already strongly retains an object with the same
    numeric identity; the exact weakref/token and object identity must all
    agree. Weak pending observations compare only their reserved identities.
    """
    if registration is None:
        return None
    reference, token, key = registration
    with _custody_lock():
        selected = _RESOURCE_LIFETIMES.get(key)
        if (selected is None or selected[0] is not reference
                or selected[1] is not token):
            return None
        for record in _CUSTODY.values():
            if record.loss is not None:
                for resource, unused_token in record.resources:
                    if id(resource) == key and reference() is resource:
                        return record.loss
        for observation in _RESOURCE_OBSERVATIONS.values():
            origin = observation.loss
            if origin is None:
                holder = observation.owner
                if (type(holder) is not _PendingForeignResources or holder.record.loss is None
                        or not holder.pending_observation(observation)):
                    continue
                origin = holder.record.loss
            resource = observation.resource
            strong_match = (resource is not None and id(resource) == key
                            and reference() is resource)
            weak_match = (type(observation) is _WeakResourceObservation
                          and observation.reference is reference
                          and observation.token is token)
            if strong_match or weak_match:
                return origin
    return None


def _resource_loss(resource):
    # Unknown records retain the actual object, preventing object-id reuse.
    # Reinitializing the SAME object cannot launder an earlier actual loss.
    with _custody_lock():
        for record in _CUSTODY.values():
            if record.loss is not None and any(item[0] is resource for item in record.resources):
                return record.loss
        for observation in _RESOURCE_OBSERVATIONS.values():
            if (observation.resource is resource
                    or (type(observation) is _WeakResourceObservation
                        and observation.matches(resource))):
                if observation.loss is not None:
                    return observation.loss
                holder = observation.owner
                if (type(holder) is _PendingForeignResources and holder.record.loss is not None
                        and holder.pending_observation(observation)):
                    # A pre-reserved occurrence survives interrupted per-slot
                    # bookkeeping. This uses a real parent loss and explicit
                    # resource fact, not an exception class or owner layout.
                    return holder.record.loss
    return None


def check_resource_retirement(resource, *, unknown=NativeDeliveryUnknown):
    """Refuse this exact resource's actual retained loss, not a global flag.

No resource attributes, equality, hashes or filesystem paths are consulted.
A healthy resource gains no new thread/fork restriction. Existing owner guards
retain their separate policy and precedence.
    """
    loss = _resource_loss(resource)
    if loss is not None:
        _observe_request_loss(loss)
        if sys.exception() is not None:
            # Keep the active handler/finally exception in the diagnostic chain.
            # Explicitly chaining the earlier raw loss would hide that context.
            # The retained loss and resource refusal do not change.
            raise unknown('resource has unconfirmed native delivery; it cannot be retired')
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
    __slots__ = ('resources', 'pid', 'thread', 'previous', 'active', 'entered', 'unknown',
                 '_pending_parents', '_return_fact')

    def __init__(self, resource, unknown):
        self.resources = [(resource, _resource_token(resource))]
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.previous = None
        self.active = self.entered = False
        self.unknown = unknown
        self._pending_parents = ()
        self._return_fact = None

    def __enter__(self):
        if self.entered:
            raise self.unknown('resource scope activation cannot be reused')
        if self.pid != os.getpid() or self.thread != threading.get_ident():
            raise self.unknown('a resource scope must be activated in its creator context')
        for resource, _ in self.resources:
            check_resource_retirement(resource, unknown=self.unknown)
        # Only an explicitly opted-in real foreign activation reserves these
        # references. The scope alone is not evidence of a native handoff or
        # completed provider outcome; its return below supplies that fact.
        if _PENDING_RESOURCE_CAPTURE.get() is not None:
            fact = _PendingUseFact('resource', self.pid, self.thread)
            self._pending_parents = _prepare_pending_resources(self.resources, fact=fact)
            if self._pending_parents:
                self._return_fact = fact
        previous = _RESOURCE_ACTIVE.get()
        while type(previous) is ResourceScope and not previous.active:
            previous = previous.previous
        self.previous = previous
        _RESOURCE_ACTIVE.set(self)
        self.entered = self.active = True
        if self._pending_parents:
            try:
                current = current_record()
                if current is not None:
                    current.check(self.unknown)
            except BaseException:
                self.deactivate()
                raise
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
        self._pending_parents = ()
        self._return_fact = None

    def __exit__(self, kind, error, traceback):
        fact = self._return_fact
        if fact is not None:
            # This pre-reserved flag precedes every identity query, iterator
            # allocation, finalizer and deactivation after the provider body.
            # Failure below cannot turn an actual return back into pre-entry.
            fact.occurred = True
        try:
            if fact is not None:
                fact.capture = _PENDING_RESOURCE_CAPTURE.get()
                fact.qualified = (self.pid == os.getpid() and self.thread == threading.get_ident())
        finally:
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
        _observe_request_loss(self.loss)
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


class _WeakResourceObservation(ResourceObservation):
    """Pre-reserved registered identity with no healthy strong resource ref.

    This constructor deliberately does not call ResourceObservation.__init__.
    The existing strong observation remains unchanged for every old caller.
    A weak observation is globally visible before effects, so interruption
    during loss promotion cannot hide its already-occurred parent's loss.
    """
    __slots__ = ('reference', 'key', 'registration')

    def __init__(self, owner, registration):
        reference, token, key = registration
        self.owner, self.resource, self.token = owner, None, token
        self.reference, self.key = reference, key
        self.registration = registration
        self.reserved_pid, self.reserved_thread = os.getpid(), threading.get_ident()
        self.pending = self.retired = False
        self.loss = self.error = None
        with _custody_lock():
            _RESOURCE_OBSERVATIONS[id(self)] = self

    def matches(self, resource):
        if self.retired or self.reference is None:
            return False
        selected = _RESOURCE_LIFETIMES.get(self.key)
        return (selected is not None and selected[0] is self.reference
                and selected[1] is self.token and self.reference() is resource)

    def failed(self, error):
        if not ResourceObservation.failed(self, error):
            return False
        # This slot and registry entry predate the provider. The promotion
        # creates no list/dict/tuple/observation or replacement lifetime.
        # All queries are of internal identity records, not user attributes.
        with _custody_lock():
            selected = _RESOURCE_LIFETIMES.get(self.key)
            if (selected is not None and selected[0] is self.reference
                    and selected[1] is self.token):
                resource = self.reference()
                if resource is not None:
                    self.resource = resource
        return True

    def retire(self):
        # Healthy ACK cleanup never dereferences the borrowed resource.
        ResourceObservation.retire(self)
        if self.retired:
            self.reference = self.key = self.registration = None


def reserve_resource_observation(owner, resource):
    return ResourceObservation(owner, resource)


class _PendingUseFact:
    """Pre-reserved occurrence fact, separate from native causal ancestry."""
    __slots__ = ('kind', 'pid', 'thread', 'occurred', 'qualified', 'capture')

    def __init__(self, kind, pid, thread):
        self.kind, self.pid, self.thread = kind, pid, thread
        self.occurred = False
        self.qualified = True if kind in ('native', 'borrow') else None
        self.capture = None

    def pending_for(self, activation_id):
        if not self.occurred or self.qualified is False:
            return False
        if self.kind in ('native', 'borrow'):
            return True
        if self.qualified is None:
            # Return occurred but its identity observation failed. Preserve
            # this explicit resource outcome; do not invent a child native
            # record, cross-thread ancestor or effect from an exception type.
            return True
        scope = self.capture
        while type(scope) is ForeignCall:
            if id(scope) == activation_id:
                return True
            scope = scope.previous
        return False


class _PendingResource:
    __slots__ = ('observation', 'facts', 'pending')

    def __init__(self, observation):
        self.observation = observation
        self.facts = []
        self.pending = False

    def pending_for(self, activation_id):
        return any(fact.pending_for(activation_id) for fact in self.facts)


class _PendingForeignResources:
    """Resources of one opted-in parent's not-yet-ACKed foreign outcome.

Reserve before the child's actual handoff/provider body. Association by itself
does not arm a pending observation. Healthy references exist only through the
matching parent ACK; an actual loss uses the existing resource-observation
registry and retains them. No service getter, equality, hash or object layout
is consulted, and no second resource registry or fixed quota is introduced.
    """
    __slots__ = ('record', 'activation_id', 'entries', 'closed', 'completed',
                 'retirement_iterator', 'retiring_entry', 'ack_ready',
                 'weak_registered', 'has_borrowed_resources')

    def __init__(self, record, activation_id, *, weak_registered=False):
        self.record, self.activation_id = record, activation_id
        self.weak_registered = weak_registered
        self.has_borrowed_resources = False
        self.entries = []
        self.closed = self.completed = False
        self.ack_ready = False
        # The actual list iterator is reserved before the provider can run.
        # It sees later appends but allocates no new classification generator
        # when an already-confirmed ACK retires its resources.
        self.retirement_iterator = iter(self.entries)
        self.retiring_entry = None

    def reserve(self, resource, fact):
        if self.weak_registered:
            registration = _registered_resource_identity(resource)
            if registration is None:
                # This opt-in policy has no guessed association for an opaque
                # unregistered/non-weakrefable resource. Causal loss still
                # propagates through the actual DeliveryRecord chain.
                return None
            origin = _resource_loss(resource)
            if origin is not None:
                if self.record.loss is None:
                    self.record.loss = origin
                    self.record.publish(origin.error)
                self.record.check()
            return self.reserve_borrow(registration, fact)
        for entry in self.entries:
            if entry is not None and entry.observation.resource is resource:
                if not any(previous is fact for previous in entry.facts):
                    entry.facts.append(fact)
                return entry
        record = self.record
        origin = _resource_loss(resource)
        if origin is not None:
            if record.loss is None:
                record.loss = origin
                record.publish(origin.error)
            record.check()
        # Reserve list capacity before global observation registration. An
        # allocation failure cannot leave an unowned registered observation.
        slot = len(self.entries)
        self.entries.append(None)
        observation = None
        try:
            observation = reserve_resource_observation(self, resource)
            entry = _PendingResource(observation)
            entry.facts.append(fact)
            # Allocation/weakref callbacks can re-enter an actual ancestor.
            # Its independently appended entries must not change this slot.
            self.entries[slot] = entry
            return entry
        except BaseException:
            self.entries[slot] = None
            if observation is not None:
                observation.retire()
            raise

    def reserve_borrow(self, registration, fact):
        """A direct-call weak fact, independent of this holder's old policy."""
        reference, token, key = registration
        for entry in self.entries:
            if (entry is not None and type(entry.observation) is _WeakResourceObservation
                    and entry.observation.reference is reference
                    and entry.observation.token is token):
                if not any(previous is fact for previous in entry.facts):
                    entry.facts.append(fact)
                return entry
        self.record.check()
        slot = len(self.entries)
        self.entries.append(None)
        observation = None
        try:
            observation = _WeakResourceObservation(self, registration)
            entry = _PendingResource(observation)
            entry.facts.append(fact)
            self.entries[slot] = entry
            self.has_borrowed_resources = True
            return entry
        except BaseException:
            self.entries[slot] = None
            if observation is not None:
                observation.retire()
            raise

    def returned(self, activation):
        if (self.closed or self.completed or id(activation) != self.activation_id
                or activation.record is not self.record
                or not self.record.current() or not activation.active):
            raise NativeDeliveryUnknown('pending foreign resources already completed')
        for entry in self.entries:
            if entry is None:
                continue
            if entry.pending_for(self.activation_id):
                entry.pending = True
                # A retained, already lost observation stays pending. Repeating
                # its marker during unwind must not replace the original loss.
                if (entry.observation.retired or not entry.observation.pending
                        or entry.observation.loss is None):
                    entry.observation.observed()
            else:
                # A safe failure before the prepared child handoff has no
                # pending resource outcome, even if its exception is caught.
                entry.observation.retire()
        self.closed = True

    def pending_observation(self, observation):
        if self.completed:
            # This activation already has its complete ACK. A later
            # actual loss during cleanup cannot re-arm its old facts.
            return False
        for entry in self.entries:
            if entry is not None and entry.observation is observation:
                return entry.pending_for(self.activation_id)
        return False

    def check_borrowed_resources(self):
        """Recheck explicit weak facts against real cross-context loss."""
        for entry in self.entries:
            if (entry is not None and type(entry.observation) is _WeakResourceObservation
                    and entry.pending_for(self.activation_id)):
                origin = _registered_resource_loss(entry.observation.registration)
                if origin is not None:
                    if self.record.loss is None:
                        self.record.loss = origin
                        self.record.publish(origin.error)
                    self.record.check()

    def prepare_acknowledgement(self, activation):
        record = self.record
        if (not self.closed or self.completed or id(activation) != self.activation_id
                or activation.record is not record or activation.active
                or not record.current()):
            raise NativeDeliveryUnknown('pending foreign resources have no matching ACK activation')
        if self.has_borrowed_resources:
            self.check_borrowed_resources()
        record.check()
        self.ack_ready = True

    def acknowledged(self):
        if (not self.ack_ready or self.completed or self.record.native_pending
                or self.record.observation_pending):
            raise NativeDeliveryUnknown('pending foreign resources have no confirmed ACK')
        # This is the adapter's exact, already-validated ACK cutpoint. A later
        # ordinary retirement/finalizer error must not retroactively convert
        # that acknowledged foreign result into delivery loss.
        self.completed = True
        self.retire_acknowledged()

    def retire_acknowledged(self):
        """Resume only confirmed custody cleanup; never a provider or ACK.

The selected entry remains explicit if its retirement raises. Classification
was completed before the ACK, and retry does not inspect fact/identity again.
No native operation, resource close or application effect is repeated.
        """
        if not self.completed:
            return
        while True:
            entry = self.retiring_entry
            if entry is None:
                try:
                    entry = next(self.retirement_iterator)
                except StopIteration:
                    self.entries.clear()
                    return
                if entry is None:
                    continue
                self.retiring_entry = entry
            # The full ACK already confirms this activation. A later ordinary
            # bookkeeping error must leave a resumable confirmed retirement,
            # not re-arm an observation or overwrite sticky actual loss.
            entry.observation.pending = False
            entry.observation.retire()
            self.retiring_entry = None

    def failed(self, error):
        if self.completed:
            self.retire_acknowledged()
            return
        if not self.record.current():
            return
        for entry in self.entries:
            if entry is None:
                continue
            if entry.pending_for(self.activation_id):
                entry.pending = True
                if not entry.observation.retired and not entry.observation.pending:
                    entry.observation.observed()
                entry.observation.failed(error)
            else:
                entry.observation.retire()


def _prepare_pending_resources(resources, *, fact, native_record=None):
    """Reserve links only to actual live opted-in ancestors, before effects."""
    scope = _PENDING_RESOURCE_CAPTURE.get()
    if not resources or scope is None:
        return ()
    links = []
    pid, thread = os.getpid(), threading.get_ident()
    while type(scope) is ForeignCall:
        if (_live(scope, pid, thread) and scope.record is not native_record
                and scope.pending_resources is not None):
            holder = scope.pending_resources
            for resource, _ in resources:
                entry = holder.reserve(resource, fact)
                if entry is not None:
                    links.append((scope, holder, entry))
        scope = scope.previous
    return links


def _prepare_borrowed_resources(activation, registration, fact):
    """Reserve separate weak slots in this exact live capture ancestry."""
    scope = activation
    pid, thread = os.getpid(), threading.get_ident()
    while type(scope) is ForeignCall:
        if _live(scope, pid, thread) and scope.pending_resources is not None:
            scope.pending_resources.reserve_borrow(registration, fact)
        scope = scope.previous


def _after_fork_child():
    global _CUSTODY_LOCK, _CUSTODY_PID
    # Retain inherited records and their actual resources. Their original PID
    # never changes, so neither inherited contexts nor tokens become active
    # child-process ancestry. Only the representation lock is replaced.
    _CUSTODY_LOCK = threading.RLock()
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
            _observe_request_loss(self.loss)
            raise unknown('causal native delivery is unconfirmed; no terminal or replay') from self.loss.error

    def enter_native(self):
        self.check()
        if self.retired or self.terminal:
            raise NativeDeliveryUnknown('native delivery invocation already completed')
        # An opted-in parent can learn only resources explicitly associated
        # with this actual child. Reserve before setting the handoff flag; a
        # preparation failure is safe and does not arm a resource observation.
        fact = None
        if self.resources and _PENDING_RESOURCE_CAPTURE.get() is not None:
            fact = _PendingUseFact('native', self.pid, self.thread)
            _prepare_pending_resources(self.resources, fact=fact, native_record=self)
            # Allocation/GC during reservation can run a real child and
            # publish loss in this actual active chain. Recheck after all
            # preparation, before the handoff flag and before _entry.
            self.check()
        # Set only immediately before the actual native call, after safe input
        # validation. An interrupted handoff cannot be proved not to execute.
        self.native_pending = True
        if fact is not None:
            # No identity call or iteration can fail after the handoff flag
            # but before the linked resource occurrence is recorded.
            fact.occurred = True

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
        _observe_request_loss(origin)
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

    def foreign(self, *, observation=True, capture_resources=False, weak_registered_resources=False):
        return ForeignCall(self, observation=observation, capture_resources=capture_resources,
                           weak_registered_resources=weak_registered_resources)


class ForeignCall:
    """One activation; a completed token is never reused for a later effect."""
    __slots__ = ('record', 'observation', 'active', 'token', 'entered', 'previous',
                 'pending_resources', 'capture_token', '_borrow_prepared',
                 '_borrow_armed', '_borrow_fact', '_borrow_registration')

    def __init__(self, record, *, observation=True, capture_resources=False,
                 weak_registered_resources=False):
        if (type(weak_registered_resources) is not bool
                or (weak_registered_resources and not capture_resources)):
            raise ValueError('weak registered capture requires an explicit capture activation')
        if type(capture_resources) is not bool or (capture_resources and not observation):
            raise ValueError('pending resource capture requires an observed foreign activation')
        self.record, self.observation = record, observation
        self.active = False
        self.token = None
        self.entered = False
        self.previous = None
        self.pending_resources = (_PendingForeignResources(record, id(self),
            weak_registered=weak_registered_resources) if capture_resources else None)
        self.capture_token = None
        self._borrow_prepared = self._borrow_armed = False
        self._borrow_fact = None
        self._borrow_registration = None

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
        if self.pending_resources is not None:
            try:
                self.capture_token = _PENDING_RESOURCE_CAPTURE.set(self)
                self.record.check()
            except BaseException:
                self.active = False
                try:
                    if self.capture_token is not None:
                        _PENDING_RESOURCE_CAPTURE.reset(self.capture_token)
                finally:
                    _ACTIVE.reset(self.token)
                raise
        return self

    def __exit__(self, kind, error, traceback):
        if self.observation:
            # This precedes exception storage/packet allocation in the driver.
            # An ordinary provider exception remains confirmable via event 3.
            self.record.observed()
        try:
            if self.pending_resources is not None:
                self.pending_resources.returned(self)
        except BaseException as bookkeeping_error:
            # The foreign outcome has already been observed. Losing the
            # pre-reserved custody handoff is transport loss, not an ordinary
            # provider exception that the adapter may ACK as event 3.
            self.record.failed(bookkeeping_error)
            if self.pending_resources is not None:
                self.pending_resources.failed(bookkeeping_error)
            raise
        finally:
            self.active = False
            try:
                try:
                    if self.capture_token is not None:
                        _PENDING_RESOURCE_CAPTURE.reset(self.capture_token)
                finally:
                    _ACTIVE.reset(self.token)
            except BaseException as reset_error:
                self.record.publish(reset_error)
                raise
        return False

    def borrow_registered_resource(self, resource):
        """Return the original receiver, with only an exact weak identity tap.

        Used at one literal SQL receiver point. Instrumentation callables are
        bound before entering that expression. No getter is duplicated and no
        strong user object is stored in the fact, holder, links or closure.
        """
        if (self.pending_resources is None or not self.active
                or _active_scope() is not self or self._borrow_prepared):
            raise NativeDeliveryUnknown('resource borrow has no unique current activation')
        self.record.check()
        registration = _registered_resource_identity(resource)
        if registration is not None:
            origin = _resource_loss(resource)
            if origin is not None:
                if self.record.loss is None:
                    self.record.loss = origin
                    self.record.publish(origin.error)
                self.record.check()
            fact = _PendingUseFact('borrow', self.record.pid, self.record.thread)
            _prepare_borrowed_resources(self, registration, fact)
            self._borrow_fact = fact
            self._borrow_registration = registration
        self._borrow_prepared = True
        # All weak slots and links are reserved. Allocation/GC during that
        # preparation can have run an actual child, or another Context can
        # have published a loss for this exact registered generation. Check
        # both before returning the receiver to the original .db lookup.
        self.record.check()
        origin = _registered_resource_loss(self._borrow_registration)
        if origin is not None and self.record.loss is None:
            self.record.loss = origin
            self.record.publish(origin.error)
        # The identity query itself can allocate/run GC. A child loss need
        # not concern this borrowed resource to invalidate the live chain.
        self.record.check()
        return resource

    def resource_call_arguments(self, value):
        """Original tuple unchanged; mark only this prepared call attempt."""
        if (not self.active or _active_scope() is not self
                or not self._borrow_prepared or self._borrow_armed):
            raise NativeDeliveryUnknown('resource call has no unique prepared activation')
        self.record.check()
        origin = _registered_resource_loss(self._borrow_registration)
        if origin is not None and self.record.loss is None:
            self.record.loss = origin
            self.record.publish(origin.error)
        # This is the final preparation boundary before the original SQL
        # call. Reject a real child loss even if the resource query returned
        # None while its own allocation/GC ran that child.
        self.record.check()
        self._borrow_armed = True
        fact = self._borrow_fact
        if fact is not None:
            fact.occurred = True
        return value

    def acknowledged(self):
        """Adapter-only, after validating this activation's complete ACK."""
        if self.pending_resources is None:
            raise NativeDeliveryUnknown('foreign activation did not reserve pending resources')
        self.pending_resources.acknowledged()

    def prepare_acknowledgement(self):
        """Validate the exact activation before recording native confirmation."""
        if self.pending_resources is None:
            raise NativeDeliveryUnknown('foreign activation did not reserve pending resources')
        self.pending_resources.prepare_acknowledgement(self)

    def failed(self, error):
        if self.pending_resources is not None:
            self.pending_resources.failed(error)

    def recover_acknowledged_resources(self):
        """Mechanical recovery after a confirmed ACK's cleanup exception."""
        if self.pending_resources is not None:
            self.pending_resources.retire_acknowledged()


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
