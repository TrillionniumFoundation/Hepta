"""Operation-long, explicit custody for the complete Slot SQL controller.

This module adds a bounded-per-observation (growable in number) API over the
existing delivery registry. It does not change ForeignCall, ResourceScope,
resource tokens, locks, native ancestry, or any Read/TX/Store primitive.
Only an actual original SQL argument handoff arms its pre-reserved fact.
A per-port ACK never acknowledges the whole operation's earlier SQL facts.
"""
from __future__ import annotations

from contextvars import ContextVar
import os
import threading

from .hia_native_delivery import (
    NativeDeliveryUnknown, ForeignCall, _PendingForeignResources, _PendingUseFact,
    _registered_resource_identity, _registered_resource_loss,
    _prepare_borrowed_resources, _active_scope,
    _live,
)

_ACTIVE_SERIES = ContextVar('hia_slot_operation_series', default=None)


class _Use:
    __slots__ = ('fact', 'previous')

    def __init__(self, fact, previous):
        self.fact, self.previous = fact, previous


class _SeriesLink:
    __slots__ = ('series', 'previous')

    def __init__(self, series, previous):
        self.series, self.previous = series, previous


def _actually_active(series, pid, thread):
    if (type(series) is not OperationSeries or not series.active
            or series.record.pid != pid or series.record.thread != thread
            or series.record.retired or series.record.terminal):
        return False
    # A copied/stale series ContextVar alone grants no actual causal ancestry.
    scope = _active_scope()
    while type(scope) is ForeignCall:
        if _live(scope, pid, thread) and scope.record is series.record:
            return True
        scope = scope.previous
    return False



def _check_registration(record, registration):
    """Reject a real same-generation loss even before this fact is armed."""
    record.check()
    origin = _registered_resource_loss(registration)
    if origin is not None and record.loss is None:
        record.loss = origin
        record.publish(origin.error)
    # The identity query may allocate/run GC. This last check covers an
    # actual child loss concerning any resource, not only this registration.
    record.check()


class SqlAttempt:
    """A fresh final-argument cutpoint; never reset or reused for another SQL."""
    __slots__ = ('series', 'fact', 'links', 'borrowed', 'used', 'registration')

    def __init__(self, series):
        series.check()
        self.series = series
        self.fact = _PendingUseFact('borrow', series.record.pid, series.record.thread)
        self.links = None
        self.borrowed = self.used = False
        self.registration = None
        pid, thread = os.getpid(), threading.get_ident()
        current = _ACTIVE_SERIES.get()
        while type(current) is OperationSeries:
            if _actually_active(current, pid, thread):
                # Every real ancestor owns an independent slot before SQL.
                # Nodes contain no Store or DB reference.
                use = _Use(self.fact, current.uses)
                link = _SeriesLink(current, self.links)
                current.uses = use
                self.links = link
            current = current.previous
        if not any_series(self.links, series):
            raise NativeDeliveryUnknown('SQL attempt has no actual operation scope')
        series.check()

    def borrow_store(self, resource):
        """Value-preserving tap at the original single self.store lookup."""
        if self.borrowed or self.used:
            raise NativeDeliveryUnknown('SQL resource observation was reused')
        self.borrowed = True
        registration = _registered_resource_identity(resource)
        self.registration = registration
        if registration is not None:
            node = self.links
            while node is not None:
                node.series.holder.reserve_borrow(registration, self.fact)
                node = node.previous
            # Each actual opted-in outer foreign activation separately retains
            # its own weak fact until its own original ACK.
            activation = _active_scope()
            _prepare_borrowed_resources(activation, registration, self.fact)
        _check_registration(self.series.record, registration)
        self.series.check()
        return resource

    def arguments(self, value):
        """Run only after the original callee and all SQL arguments exist."""
        if not self.borrowed or self.used:
            raise NativeDeliveryUnknown('SQL attempt has no fresh prepared resource fact')
        node = self.links
        while node is not None:
            node.series.check()
            node = node.previous
        _check_registration(self.series.record, self.registration)
        self.series.check()
        # One existing boolean is the handoff cutpoint. No iterator, identity
        # call, allocation, user lookup or replay occurs after it.
        self.used = True
        self.fact.occurred = True
        return value


def any_series(node, target):
    while node is not None:
        if node.series is target:
            return True
        node = node.previous
    return False


class OperationSeries:
    """One full original method invocation, including nested dynamic methods."""
    __slots__ = ('record', 'holder', 'uses', 'previous', 'token', 'active',
                 'entered', 'ready')

    def __init__(self, record):
        self.record = record
        self.holder = _PendingForeignResources(record, id(self), weak_registered=True)
        self.uses = self.previous = self.token = None
        self.active = self.entered = self.ready = False

    def __enter__(self):
        if self.entered:
            raise NativeDeliveryUnknown('operation series cannot be entered twice')
        self.record.check()
        self.previous = _ACTIVE_SERIES.get()
        self.token = _ACTIVE_SERIES.set(self)
        self.entered = self.active = True
        try:
            self.record.check()
        except BaseException:
            self.active = False
            _ACTIVE_SERIES.reset(self.token)
            self.token = None
            raise
        return self

    def __exit__(self, kind, error, traceback):
        self.active = False
        token, self.token = self.token, None
        if token is not None:
            _ACTIVE_SERIES.reset(token)
        # No SQL, rollback, close, native ACK or provider retry is performed.
        return False

    def check(self):
        self.record.check()
        self.holder.check_borrowed_resources()
        self.record.check()

    def prepare_sql(self):
        if not self.active or self.ready or self.holder.completed:
            raise NativeDeliveryUnknown('operation series is not accepting new SQL')
        return SqlAttempt(self)

    def has_observation(self):
        use = self.uses
        while use is not None:
            if use.fact.occurred:
                return True
            use = use.previous
        return False

    def prepare_completion(self):
        """HIA has issued READY_RETURN/READY_PROPAGATE, not its final receipt."""
        if not self.active or self.ready or self.holder.completed:
            raise NativeDeliveryUnknown('operation has no new completion request')
        self.check()
        try:
            self.holder.returned(self)
        finally:
            # Even bookkeeping failure cannot leave an activated stale scope.
            self.active = False
        self.holder.prepare_acknowledgement(self)
        self.ready = True
        self.record.check()

    def confirmed(self):
        """Only after the complete FINALIZE receipt and record.confirmed()."""
        if not self.ready:
            raise NativeDeliveryUnknown('operation has no prepared final receipt')
        self.holder.acknowledged()
        self.uses = None

    def failed(self, error):
        if self.holder.completed:
            # Confirmed cleanup may resume; never re-arm an acknowledged SQL.
            self.holder.retire_acknowledged()
            self.uses = None
            return
        if not self.record.current():
            return
        if self.has_observation():
            # This is a real undelivered operation outcome after a declared
            # SQL handoff, not inference from an exception class or status.
            self.record.publish(error)
        self.holder.failed(error)
