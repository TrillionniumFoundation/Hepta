"""Version 1 custody for an explicitly captured native budget connection.

The budget object owns a distinct SQLite connection. A Store association is
not an association for that connection. This module adds no budget policy,
SQL, native entry, selector, replay right or administrator-bundle authority.

An actual live capture/operation opts the real provider into resource custody.
Once registered, that object's native operations keep the same lifetime.
Ordinary constructors outside those explicit scopes retain their old policy.
Every participating operation series reserves its own weak return fact before
the provider body; a child's ACK cannot discharge its parent's fact.
"""
from __future__ import annotations

import os
import threading

from .hia_native_delivery import (
    NativeDeliveryUnknown, DeliveryRecord, ForeignCall, ResourceScope,
    bind_resource_lifetime, check_resource_retirement, current_record,
    _PENDING_RESOURCE_CAPTURE, _registered_resource_identity, _live,
)
from .hia_slot_operation_series import (
    _ACTIVE_SERIES, OperationSeries, _actually_active, _Use, _SeriesLink,
    _check_registration,
)

API = 'hepta.hia.budget-resource-custody.v1'


class _InactiveBudgetScope:
    __slots__ = ()

    def __enter__(self):
        return self

    def __exit__(self, kind, error, traceback):
        return False


_INACTIVE = _InactiveBudgetScope()


def _has_live_capture(pid, thread):
    scope = _PENDING_RESOURCE_CAPTURE.get()
    while type(scope) is ForeignCall:
        if _live(scope, pid, thread) and scope.pending_resources is not None:
            return True
        scope = scope.previous
    series = _ACTIVE_SERIES.get()
    while type(series) is OperationSeries:
        if _actually_active(series, pid, thread):
            return True
        series = series.previous
    return False


class _BudgetReturnFactV1:
    """A returned provider body, never a claim that a native entry occurred."""
    __slots__ = ('occurred', 'qualified', 'series_ids')

    def __init__(self):
        self.occurred = False
        self.qualified = None
        self.series_ids = ()

    def pending_for(self, activation_id):
        return (self.occurred and self.qualified is not False
                and activation_id in self.series_ids)


class _BudgetScopeV1:
    __slots__ = ('scope', 'registration', 'fact', 'links', 'record',
                 'pid', 'thread', 'entered', 'active', 'provider_record')

    def __init__(self, resource, registration, pid, thread, provider_record):
        self.pid, self.thread = pid, thread
        self.entered = self.active = False
        self.record = current_record()
        self.provider_record = provider_record
        self.registration = registration
        self.scope = ResourceScope(resource, NativeDeliveryUnknown)
        self.fact = _BudgetReturnFactV1()
        self.links = None
        current = _ACTIVE_SERIES.get()
        identifiers = []
        while type(current) is OperationSeries:
            if _actually_active(current, pid, thread):
                # Allocate before publishing either linked-list pointer.
                # reserve_borrow can allocate/reenter; a nested append must
                # not be overwritten by a stale current.uses snapshot.
                use = _Use(self.fact, None)
                link = _SeriesLink(current, None)
                current.holder.reserve_borrow(registration, self.fact)
                use.previous = current.uses
                current.uses = use
                link.previous = self.links
                self.links = link
                identifiers.append(id(current))
            current = current.previous
        self.fact.series_ids = tuple(identifiers)
        if provider_record is not None:
            provider_record.associate(resource)
        self._check_prepared()

    def _check_prepared(self):
        if self.pid != os.getpid() or self.thread != threading.get_ident():
            raise NativeDeliveryUnknown('budget scope preparation changed its creator')
        if current_record() is not self.record:
            raise NativeDeliveryUnknown('budget scope has no original live activation')
        if self.record is not None:
            self.record.check()
        if self.provider_record is not None:
            self.provider_record.check()
        node = self.links
        while node is not None:
            if not _actually_active(node.series, self.pid, self.thread):
                raise NativeDeliveryUnknown('budget scope lost an actual operation ancestor')
            node.series.check()
            node = node.previous
        # The only strong reference here is the already prepared resource
        # scope. No user getter/hash/equality or DB inference is performed.
        resource = self.scope.resources[0][0]
        selected = _registered_resource_identity(resource)
        original = self.registration
        if (selected is None or selected[0] is not original[0]
                or selected[1] is not original[1] or selected[2] != original[2]):
            raise NativeDeliveryUnknown('budget resource lifetime changed during preparation')
        check_resource_retirement(resource)
        if self.record is not None:
            _check_registration(self.record, original)
            self.record.check()

    def __enter__(self):
        if self.entered:
            raise NativeDeliveryUnknown('budget resource scope cannot be reused')
        self.entered = True
        try:
            self._check_prepared()
            self.scope.__enter__()
            # ResourceScope preparation may allocate/run finalizers. This is
            # still before the original provider body and any of its SQL.
            self._check_prepared()
        except BaseException:
            # Do not call __exit__: no provider outcome has occurred.
            self.scope.deactivate()
            raise
        self.active = True
        return self

    def __exit__(self, kind, error, traceback):
        if not self.active:
            raise NativeDeliveryUnknown('budget resource scope was not active')
        # This pre-reserved fact precedes identity queries and deactivation.
        # If bookkeeping itself fails, the actual returned outcome remains
        # visible to each earlier operation holder; it is not a native entry.
        self.fact.occurred = True
        try:
            self.fact.qualified = (
                self.pid == os.getpid()
                and self.thread == threading.get_ident()
                and current_record() is self.record)
        finally:
            try:
                self.scope.__exit__(kind, error, traceback)
            finally:
                self.active = False
                self.links = self.registration = self.record = self.provider_record = None
        return False


def budget_resource_scope_v1(resource, *, record=None):
    """Real budget-provider entry; never a test-side registration shortcut.

    A newly observed object is registered only under actual live opt-in
    capture/series ancestry. Existing registered budget objects retain that
    lifetime for later standalone native operations. No healthy registration
    is renewed, and an earlier real loss cannot be laundered by reinitializing
    the same object. The original provider's SQL and error handling remain in
    its own executing method.
    """
    if record is not None and type(record) is not DeliveryRecord:
        raise TypeError('budget resource scope requires its actual delivery record')
    pid, thread = os.getpid(), threading.get_ident()
    registration = _registered_resource_identity(resource)
    if registration is None:
        if not _has_live_capture(pid, thread):
            return _INACTIVE
        bind_resource_lifetime(resource)
        registration = _registered_resource_identity(resource)
        if registration is None:
            raise NativeDeliveryUnknown('budget resource does not expose a weak lifetime')
    return _BudgetScopeV1(resource, registration, pid, thread, record)
