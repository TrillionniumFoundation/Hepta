"""Actual budget-B connection/ACK controls. No test-side resource registration.

Each case owns a fresh process. Native fault wrappers call the original entry
before losing its return. Original SQLite/close/provider bodies execute; no
loss field, receipt, resource association or parent check is fabricated.
"""
from __future__ import annotations
import argparse
import contextvars
import ctypes
import json
import os
from pathlib import Path
import signal
import sqlite3
import struct
import sys
import threading
import time
import types

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
from tests import hia_service_bootstrap_support as support
from tests.hia_service_bootstrap_controls import SELECTORS as BOOTSTRAP_SELECTORS
from tests.hia_service_bootstrap_controls import manifest_pins, clean_environment

SELECTORS = {**BOOTSTRAP_SELECTORS,
             'operations': 'HEPTA_HIA_SLOT_OPERATIONS_MANIFEST'}
CASE_IDS = (
    'constructor-confirmed', 'constructor-ACK-loss',
    'constructor-late-FINALIZE-loss', 'constructor-open-refusal',
    'constructor-admission-cleanup', 'close-confirmed-repeat',
    'close-ACK-loss', 'ordinary-error-confirmed',
    'child-loss-swallowed', 'child-loss-replaced',
    'standalone-opted-child-loss', 'healthy-other-budget',
    'series-confirmed', 'series-inner-confirmed-outer-loss',
    'series-child-loss-swallowed', 'series-already-closed-outer-loss',
    'preparation-finalizer-child-loss', 'return-identity-error-outer-loss',
    'unknown-reinitialize-refused', 'unknown-new-Context-close',
    'unknown-thread-close', 'unknown-fork-close',
)


def need(value, text):
    if value is not True:
        raise AssertionError(text)


def outcome(call):
    try:
        return call(), None
    except BaseException as error:
        return None, error


def error_record(error):
    if error is None:
        return None
    return {'type': type(error).__name__, 'text': str(error)}


def contains_error(error, expected):
    pending, seen = [error], set()
    while pending:
        current = pending.pop()
        if current is expected:
            return True
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        pending.extend((current.__cause__, current.__context__))
    return False


class Provider:
    def __init__(self, context, action):
        self.context, self.action = context, action

    def check_profile(self, ref, expected):
        record = self.context.delivery.current_record()
        self.context.bootstrap_frame = record.owner
        self.action()
        return ref


class ProfileService:
    profiles = {'test': 'profile'}
    def __init__(self, provider):
        self.store = provider


class Finalizer:
    def __init__(self, context, callback):
        self.context, self.callback = context, callback

    def __del__(self):
        context = self.context
        try:
            self.callback()
        except BaseException as error:
            context.finalizer_errors.append(error_record(error))
        else:
            context.finalizer_returns.append(True)


class Case:
    def __init__(self, manifests, directory, name, report):
        from hepta import hia_native_delivery as delivery
        from hepta import hia_service_bootstrap_native as bootstrap
        from hepta import hia_candidate_budget_native as candidate
        from hepta import hia_execution_budget_native as execution
        from hepta import hia_slot_operations_native as operations
        from hepta import hia_slot_ledger_native as ledger
        from hepta import hia_agent_service as api, hia_agent_store as store_api
        self.delivery, self.bootstrap, self.candidate = delivery, bootstrap, candidate
        self.execution, self.operations, self.ledger = execution, operations, ledger
        self.api, self.store_api = api, store_api
        self.manifests, self.directory, self.name, self.report = manifests, Path(directory), name, report
        self.bootstrap_image = bootstrap.installed_service_bootstrap(manifests['bootstrap'])
        self.candidate_image, source = candidate.selected_candidate_budget()
        self.admission = (self.candidate_image, source)
        self.ledger_image = ledger.selected_slot_ledger()
        self.operations_image = operations.installed_slot_operations(manifests['operations'])
        self.bootstrap_entry = self.bootstrap_image._entry
        self.candidate_entry = self.candidate_image._entry
        self.operations_entry = self.operations_image._entry
        self.bootstrap_frame = self.series_outer = self.series_inner = None
        self.owner_fault = ValueError('actual enclosing native receipt return lost')
        self.child_fault = ValueError('actual candidate COMMIT receipt return lost')
        self.ordinary_fault = MemoryError('ordinary provider after confirmed budget operation')
        self.replacement = RuntimeError('provider replacement after actual budget loss')
        self.owner_loss = self.child_loss = False
        self.owner_loss_event = bootstrap.SUCCEEDED
        self.swallowed = []
        self.finalizer_errors, self.finalizer_returns = [], []
        self.entries, self.traces, self.owners = [], {}, []
        self.budgets, self.stores = [], []
        self.report.update({'case': name, 'entries': self.entries, 'SQL': self.traces,
                            'swallowed': self.swallowed, 'validated': False,
                            'manual_resource_registration': False,
                            'loss_fields_written': False,
                            'parent_check_bypassed': False})
        self.bootstrap_image._entry = self.observe_bootstrap
        self.candidate_image._entry = self.observe_candidate
        self.operations_image._entry = self.observe_operations

    def entry(self, owner, words, code, source, size, output, capacity, state, extent):
        record = self.delivery.current_record()
        row = {'owner': owner, 'event': words[1], 'code': code,
               'actual_entry_returned': True,
               'record': None if record is None else id(record),
               'frame': None if record is None else id(record.owner),
               'request_bytes': size, 'output_bytes': capacity, 'state_bytes': extent,
               'request': ctypes.string_at(source, size).hex(),
               'output': ctypes.string_at(output, capacity).hex(),
               'state': ctypes.string_at(state, extent).hex()}
        if owner in ('bootstrap', 'operations'):
            row.update(port=words[3], mode=words[5])
        self.entries.append(row)
        return record

    def observe_bootstrap(self, source, size, output, capacity, state, extent):
        code = self.bootstrap_entry(source, size, output, capacity, state, extent)
        words = struct.unpack('<16Q', ctypes.string_at(source, size))
        record = self.entry('bootstrap', words, code, source, size, output, capacity, state, extent)
        if (self.owner_loss and record is not None and record.owner is self.bootstrap_frame
                and words[1] == self.owner_loss_event
                and (words[1] == self.bootstrap.FINALIZE
                     or words[3] == self.bootstrap.PORT['profile_result'])):
            raise self.owner_fault
        return code

    def observe_candidate(self, source, size, output, capacity, state, extent):
        code = self.candidate_entry(source, size, output, capacity, state, extent)
        words = struct.unpack('<12Q', ctypes.string_at(source, 96))
        self.entry('candidate', words, code, source, size, output, capacity, state, extent)
        if self.child_loss and words[1] == 4:
            raise self.child_fault
        return code

    def observe_operations(self, source, size, output, capacity, state, extent):
        code = self.operations_entry(source, size, output, capacity, state, extent)
        words = struct.unpack('<16Q', ctypes.string_at(source, size))
        record = self.entry('operations', words, code, source, size, output, capacity, state, extent)
        if (self.owner_loss and record is not None and record.owner is self.series_outer
                and words[1] == self.operations.FINALIZE):
            raise self.owner_fault
        return code

    def store(self, label):
        value = self.store_api.AgentStore(self.directory / label)
        self.stores.append(value)
        trace = []
        self.traces['Store-' + label] = trace
        value.db.set_trace_callback(trace.append)
        return value

    def budget(self, store, label):
        value = self.candidate.NativeCandidateBudgetStore(store, self.admission)
        self.budgets.append(value)
        trace = []
        self.traces['Budget-' + label] = trace
        value.db.set_trace_callback(trace.append)
        need(value.db is not store.db, 'budget did not own a distinct SQLite connection')
        self.report.setdefault('connections', []).append({
            'label': label, 'budget': id(value), 'connection': id(value.db),
            'Store_connection': id(store.db), 'distinct': True})
        return value

    def context(self, store, label):
        name = 'budget-resource-' + label
        store.db.execute('INSERT INTO contexts VALUES (?,?,?,?,?)',
                         (name, 'a' * 64, '{}', '1', 0))
        return name

    def profile(self, action):
        service = ProfileService(Provider(self, action))
        return self.api.HIAAgentService._profile(service, 'value', 'test')

    def create_bound(self, store, label):
        slot = []
        result = self.profile(lambda: slot.append(self.budget(store, label)))
        need(result == 'value', 'confirmed bootstrap provider result differs')
        value = slot[0]
        need(self.delivery._registered_resource_identity(value) is not None,
             'actual budget provider did not register its opted-in lifetime')
        return value

    def alive(self, budget):
        return budget.db.execute('SELECT 1').fetchone()[0] == 1

    def closed(self, budget):
        _, error = outcome(lambda: budget.db.execute('SELECT 1'))
        return type(error) is sqlite3.ProgrammingError

    def rejected_close(self, budget, *, already_closed=False):
        was = budget.closed
        _, error = outcome(budget.close)
        need(isinstance(error, self.delivery.NativeDeliveryUnknown),
             'actual public budget close did not reject retained loss')
        need(budget.closed is was and was is already_closed,
             'refused close changed the original closed state')
        need(self.closed(budget) if already_closed else self.alive(budget),
             'refused close changed actual SQLite liveness')
        self.report.setdefault('close_refusals', []).append({
            'budget': id(budget), 'closed_before': was, 'closed_after': budget.closed,
            'actual_connection_open': not already_closed, 'error': error_record(error)})
        return error

    def restore(self):
        self.bootstrap_image._entry = self.bootstrap_entry
        self.candidate_image._entry = self.candidate_entry
        self.operations_image._entry = self.operations_entry
        # Unknown resources remain owned until this fresh process exits.
        cleanup = []
        for budget in reversed(self.budgets):
            _, error = outcome(budget.close)
            cleanup.append({'owner': 'budget', 'error': error_record(error),
                            'closed': budget.closed})
            if error is not None and not isinstance(error, self.delivery.NativeDeliveryUnknown):
                raise error
        for store in reversed(self.stores):
            _, error = outcome(store.close)
            cleanup.append({'owner': 'Store', 'error': error_record(error)})
            if error is not None and not isinstance(error, self.delivery.NativeDeliveryUnknown):
                raise error
        self.report['cleanup'] = cleanup
        self.report['custody_after'] = self.delivery.custody_snapshot()
        self.report['unknown_resources_not_manually_closed'] = True


def construction_and_close(c):
    store = c.store('A')
    if c.name in ('constructor-confirmed', 'constructor-ACK-loss',
                  'constructor-late-FINALIZE-loss'):
        values = []
        c.owner_loss = c.name != 'constructor-confirmed'
        if c.name == 'constructor-late-FINALIZE-loss':
            c.owner_loss_event = c.bootstrap.FINALIZE
        value, error = outcome(lambda: c.profile(lambda: values.append(c.budget(store, 'B'))))
        need(len(values) == 1, 'actual B constructor did not return exactly once')
        budget = values[0]
        need(c.alive(budget), 'new B connection is not actually live')
        if c.owner_loss:
            need(contains_error(error, c.owner_fault), 'actual parent lost-return identity missing')
            c.rejected_close(budget)
        else:
            need(error is None and value == 'value', 'confirmed constructor parent failed')
            budget.close()
            need(budget.closed is True and c.closed(budget), 'healthy B close did not close SQLite')
        c.report['outcome'] = error_record(error)
        return

    if c.name in ('constructor-open-refusal', 'constructor-admission-cleanup'):
        owner = object.__new__(c.candidate.NativeCandidateBudgetStore)
        connections = []
        original_connect = c.execution.sqlite3.connect
        original_check = c.execution.NativeExecutionBudgetStore.check
        requested = MemoryError('original budget sqlite open refused')
        checks = []
        def connect(*args, **kwargs):
            if c.name == 'constructor-open-refusal':
                raise requested
            value = original_connect(*args, **kwargs)
            connections.append(value)
            return value
        def check(value):
            if value is owner:
                checks.append(True)
                if len(checks) == 2:
                    raise requested
            return original_check(value)
        c.execution.sqlite3.connect = connect
        c.execution.NativeExecutionBudgetStore.check = check
        try:
            _, error = outcome(lambda: c.profile(
                lambda: c.candidate.NativeCandidateBudgetStore.__init__(owner, store, c.admission)))
        finally:
            c.execution.sqlite3.connect = original_connect
            c.execution.NativeExecutionBudgetStore.check = original_check
        need(error is requested, 'confirmed ordinary constructor failure changed identity')
        need(c.delivery._resource_loss(owner) is None, 'confirmed refusal invented B UNKNOWN')
        need(len(connections) == int(c.name == 'constructor-admission-cleanup'),
             'constructor reached the wrong real SQLite connection count')
        for connection in connections:
            _, failure = outcome(lambda: connection.execute('SELECT 1'))
            need(type(failure) is sqlite3.ProgrammingError,
                 'original admission cleanup did not actually close SQLite')
        c.report.update({'constructor_error_identity': True,
                         'opened_connections': len(connections),
                         'original_admission_cleanup_closed': len(connections)})
        return

    budget = c.create_bound(store, 'B')
    if c.name == 'close-confirmed-repeat':
        first_connection = budget.db
        budget.close()
        need(budget.closed is True and c.closed(budget), 'first public close did not close SQLite')
        budget.close()
        need(budget.db is first_connection and budget.closed is True and c.closed(budget),
             'healthy repeated close reopened or replaced the original connection')
        c.report['healthy_repeat_same_closed_connection'] = True
    elif c.name == 'close-ACK-loss':
        c.owner_loss = True
        _, error = outcome(lambda: c.profile(budget.close))
        need(contains_error(error, c.owner_fault), 'close actual parent return was not lost')
        need(budget.closed is True and c.closed(budget), 'lost ACK erased the real close effect')
        c.rejected_close(budget, already_closed=True)
    elif c.name == 'ordinary-error-confirmed':
        context = c.context(store, 'ordinary')
        def provider():
            need(budget.consume(context, 3) == 1, 'actual candidate operation did not complete')
            raise c.ordinary_fault
        _, error = outcome(lambda: c.profile(provider))
        need(error is c.ordinary_fault, 'ordinary provider failure identity changed')
        need(c.delivery._resource_loss(budget) is None, 'confirmed ordinary error invented loss')
        budget.close()
        need(budget.closed is True and c.closed(budget), 'ordinary confirmed failure fenced healthy B')
        c.report['ordinary_error_identity_preserved'] = True
    else:
        raise AssertionError('wrong construction/close case')


def actual_child_loss(c):
    store = c.store('A')
    budget = c.create_bound(store, 'B')
    context = c.context(store, 'loss')
    other = c.create_bound(store, 'healthy-other') if c.name == 'healthy-other-budget' else None
    c.child_loss = True
    def consume():
        try:
            return budget.consume(context, 3)
        except BaseException as error:
            need(contains_error(error, c.child_fault), 'native loss lacks its actual fault chain')
            c.swallowed.append(error_record(error))
            if c.name == 'child-loss-replaced':
                raise c.replacement
            if c.name == 'child-loss-swallowed':
                return None
            raise
    if c.name == 'standalone-opted-child-loss':
        _, error = outcome(consume)
    else:
        _, error = outcome(lambda: c.profile(consume))
    need(error is not None, 'actual child loss reached an ordinary success')
    if c.name == 'child-loss-replaced':
        need(error is c.replacement, 'foreign RuntimeError replacement identity changed')
    c.rejected_close(budget)
    need(store.db.execute('SELECT attempts FROM contexts WHERE id=?', (context,)).fetchone()[0] == 1,
         'actual committed attempt was refunded or repeated')
    need(sum(row['owner'] == 'candidate' and row['event'] == 4 for row in c.entries) == 1,
         'actual candidate COMMIT receipt was retried')
    if other is not None:
        need(c.delivery._resource_loss(other) is None, 'unrelated healthy B inherited another B loss')
        other.close()
        need(other.closed is True and c.closed(other), 'healthy other B did not really close')
        c.report['different_B_close_confirmed'] = True
    c.report['outcome'] = error_record(error)


def nested_series(c, *, identity_failure=False):
    from hepta.hia_slot_operations_selection import slot_operations_owner
    from hepta import hia_budget_resource_custody as custody
    store = c.store('A')
    budget = c.budget(store, 'B')
    context = c.context(store, 'series')
    # Construction was outside any opt-in parent; the real first operation
    # below must register B itself, not this fixture.
    need(c.delivery._registered_resource_identity(budget) is None,
         'fixture unexpectedly registered B before a real operation')
    callback_state = {'outer': 0, 'inner': 0}
    c.owner_loss = c.name in ('series-inner-confirmed-outer-loss',
                             'series-already-closed-outer-loss',
                             'return-identity-error-outer-loss')
    c.child_loss = c.name == 'series-child-loss-swallowed'
    identity_error = MemoryError('actual budget scope returned identity query failed')
    original_exit = custody._BudgetScopeV1.__exit__
    original_os = custody.os
    identity_hits = []
    class FailedIdentity:
        @staticmethod
        def getpid():
            identity_hits.append(True)
            raise identity_error
    def interrupted_exit(scope, kind, error, traceback):
        if identity_failure and scope.scope.resources and scope.scope.resources[0][0] is budget:
            custody.os = FailedIdentity
            try:
                return original_exit(scope, kind, error, traceback)
            finally:
                custody.os = original_os
        return original_exit(scope, kind, error, traceback)
    with slot_operations_owner(c.manifests['operations'], image=c.operations_image):
        outer = c.ledger.NativeSlotLedgerStore(store, c.ledger_image)
        inner = c.ledger.NativeSlotLedgerStore(store, c.ledger_image)
        outer_execute, inner_execute = outer._execute, inner._execute
        def inner_provider(connection, statement, parameters=()):
            callback_state['inner'] += 1
            c.series_inner = c.delivery.current_record().owner
            if c.name == 'series-already-closed-outer-loss':
                budget.close()
            else:
                try:
                    budget.consume(context, 3)
                except BaseException as error:
                    if identity_failure:
                        need(error is identity_error, 'return identity failure object changed')
                    else:
                        need(c.child_loss and contains_error(error, c.child_fault),
                             'unexpected nested budget provider failure')
                    c.swallowed.append(error_record(error))
            return inner_execute(connection, statement, parameters)
        def outer_provider(connection, statement, parameters=()):
            callback_state['outer'] += 1
            c.series_outer = c.delivery.current_record().owner
            inner.snapshot('inner-missing')
            return outer_execute(connection, statement, parameters)
        inner._execute, outer._execute = inner_provider, outer_provider
        custody._BudgetScopeV1.__exit__ = interrupted_exit
        try:
            result, error = outcome(lambda: outer.snapshot('outer-missing'))
        finally:
            custody._BudgetScopeV1.__exit__ = original_exit
            custody.os = original_os
    need(callback_state == {'outer': 1, 'inner': 1}, 'nested actual public methods did not both run')
    if c.name == 'series-confirmed':
        need(error is None and result['current'] == {'generation': '0', 'epoch': '0'},
             'confirmed nested public Slot result differs')
        need(c.delivery._resource_loss(budget) is None, 'confirmed parent did not retire its B fact')
        budget.close()
        need(budget.closed is True and c.closed(budget), 'confirmed nested B did not close')
    else:
        need(error is not None, 'real nested loss reached ordinary terminal')
        if c.owner_loss:
            need(contains_error(error, c.owner_fault), 'outer actual FINALIZE loss identity missing')
            inner_finals = [row for row in c.entries if row['owner'] == 'operations'
                            and row['event'] == c.operations.FINALIZE
                            and row['frame'] == id(c.series_inner)]
            need(len(inner_finals) == 1, 'inner operation did not reach its own actual FINALIZE')
        c.rejected_close(budget, already_closed=c.name == 'series-already-closed-outer-loss')
    if identity_failure:
        need(len(identity_hits) == 1 and len(c.swallowed) == 1,
             'actual return-identity cutpoint was not reached exactly once')
        c.report['return_identity_query_failed_after_body'] = True
    c.report.update({'series_callbacks': callback_state, 'outcome': error_record(error),
                     'child_finalization_does_not_confirm_parent': True})


def preparation_finalizer(c):
    from hepta import hia_budget_resource_custody as custody
    store = c.store('A')
    budget = c.create_bound(store, 'B')
    peer = c.create_bound(store, 'C')
    context = c.context(store, 'preparation-B')
    peer_context = c.context(store, 'preparation-C')
    before_b = list(c.traces['Budget-B'])
    checks = []
    original = custody._BudgetScopeV1._check_prepared
    def actual_loss():
        c.child_loss = True
        _, error = outcome(lambda: peer.consume(peer_context, 3))
        need(contains_error(error, c.child_fault), 'finalizer did not lose an actual Native return')
        c.swallowed.append(error_record(error))
    held = [Finalizer(c, actual_loss)]
    def check(scope):
        if scope.scope.resources and scope.scope.resources[0][0] is budget:
            checks.append(True)
            # init guard, entry guard, then the guard after ResourceScope
            # preparation. No gc.collect or allocator warmup is introduced.
            if len(checks) == 3:
                item = held.pop()
                del item
        return original(scope)
    custody._BudgetScopeV1._check_prepared = check
    try:
        _, error = outcome(lambda: c.profile(lambda: budget.consume(context, 3)))
    finally:
        custody._BudgetScopeV1._check_prepared = original
    need(error is not None and held == [], 'preparation finalizer boundary did not reject')
    need(c.finalizer_errors == [] and c.finalizer_returns == [True]
         and len(c.swallowed) == 1, 'real finalizer child loss was hidden or not reached')
    need(c.traces['Budget-B'] == before_b, 'new B SQL began after preparation child loss')
    c.rejected_close(peer)
    # The real C NativeCall inherits the already active explicit B ResourceScope.
    # This reports actual association, not a claim that B SQL occurred.
    retained = [record for record in c.delivery._CUSTODY.values()
                if record.loss is not None and any(item[0] is budget for item in record.resources)]
    need(bool(retained), 'actual preparation child did not carry the live B association')
    c.rejected_close(budget)
    c.report.update({'preparation_original_B_SQL_started': False,
                     'actual_child_inherited_live_B_resource_scope': True,
                     'finalizer_errors': c.finalizer_errors,
                     'finalizer_returns': c.finalizer_returns,
                     'outcome': error_record(error)})


def creator_and_reuse(c):
    store = c.store('A')
    budget = c.create_bound(store, 'B')
    context = c.context(store, 'creator')
    c.child_loss = True
    _, first_error = outcome(lambda: c.profile(lambda: budget.consume(context, 3)))
    need(first_error is not None, 'creator fixture did not establish actual Native loss')
    c.rejected_close(budget)
    if c.name == 'unknown-reinitialize-refused':
        before = {key: list(value) for key, value in c.traces.items()}
        original_connection = budget.db
        _, error = outcome(lambda: c.candidate.NativeCandidateBudgetStore.__init__(
            budget, store, c.admission))
        need(isinstance(error, c.delivery.NativeDeliveryUnknown),
             'same-object constructor laundered its retained loss')
        need(budget.db is original_connection and c.traces == before,
             'reinitialization reached original lookup/SQL or replaced B')
        c.report['no_SQL_or_rebinding_on_reinitialize'] = True
    elif c.name == 'unknown-new-Context-close':
        _, error = outcome(lambda: contextvars.Context().run(budget.close))
        need(isinstance(error, c.delivery.NativeDeliveryUnknown) and not budget.closed,
             'fresh Context laundered B retirement')
        c.report['fresh_Context_close_refused'] = True
    elif c.name == 'unknown-thread-close':
        rows = []
        def worker():
            _, error = outcome(budget.close)
            rows.append({'pid': os.getpid(), 'thread': threading.get_ident(),
                         'error': error_record(error),
                         'unknown': isinstance(error, c.delivery.NativeDeliveryUnknown)})
        thread = threading.Thread(target=worker)
        thread.start(); thread.join(10)
        need(not thread.is_alive() and len(rows) == 1 and rows[0]['unknown'] is True
             and not budget.closed, 'other-thread retirement did not reject actual B loss')
        c.report['thread'] = rows
    elif c.name == 'unknown-fork-close':
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            try:
                _, error = outcome(budget.close)
                row = {'pid': os.getpid(), 'error': error_record(error),
                       'code': getattr(error, 'code', None), 'closed': budget.closed}
                os.write(write_fd, support.canonical(row))
            finally:
                os.close(write_fd)
            os._exit(0)
        os.close(write_fd)
        reaped = False; status = None; expired = False
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                done, status = os.waitpid(pid, os.WNOHANG)
                if done == pid:
                    reaped = True
                    break
                time.sleep(0.01)
            if not reaped:
                expired = True
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0); reaped = True
            raw = os.read(read_fd, 8192)
        finally:
            os.close(read_fd)
            if not reaped:
                try:os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:pass
                os.waitpid(pid, 0)
        row = support.parse(raw)
        need(not expired and os.waitstatus_to_exitcode(status) == 0,
             'owned fork did not terminate naturally within its original control bound')
        need(row['code'] == 'E_HIA_BUDGET_NATIVE_CUSTODY'
             and row['closed'] is False and not budget.closed,
             'original PID rejection did not precede RLock/resource retirement')
        c.report['fork'] = {'pid': pid, 'reaped': reaped, 'timed_out': expired, 'result': row}
    else:
        raise AssertionError('unknown creator case')
    c.rejected_close(budget)


def execute_case(c):
    if c.name in CASE_IDS[:8]:
        construction_and_close(c)
    elif c.name in CASE_IDS[8:12]:
        actual_child_loss(c)
    elif c.name in CASE_IDS[12:16]:
        nested_series(c)
    elif c.name == 'preparation-finalizer-child-loss':
        preparation_finalizer(c)
    elif c.name == 'return-identity-error-outer-loss':
        nested_series(c, identity_failure=True)
    else:
        creator_and_reuse(c)
    c.report['validated'] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--authority', type=Path, required=True)
    parser.add_argument('--authority-sha256', required=True)
    parser.add_argument('--authority-bytes', type=int, required=True)
    parser.add_argument('--case', choices=CASE_IDS, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    raw, authority, authority_pin = support.capture_json(args.authority, {
        'bytes': args.authority_bytes, 'sha256': args.authority_sha256})
    manifest_path = Path(authority['manifest_list_path'])
    manifest_raw, manifests, manifest_pin = support.capture_json(
        manifest_path, authority['manifest_list'])
    need(set(manifests) == set(SELECTORS), 'actual seven-image authority is incomplete')
    before = support.source_snapshot()
    need(support.same(before, authority['source_before']), 'authority source differs before execution')
    pins = manifest_pins(manifests)
    need(support.same(pins, authority['images']), 'authority manifest/image identity differs')
    bundle_path = Path(authority['bundle_path'])
    bundle_raw = bundle_path.read_bytes()
    need(support.same(support.bytes_pin(bundle_raw), authority['bundle']),
         'actual administrator bundle bytes differ')
    previous = dict(os.environ)
    environment = clean_environment()
    os.environ.clear()
    os.environ.update(environment)
    report = {'schema': 'hepta.hia.budget-resource-control.v1', **support.child_identity(),
              'status': 'HOLD', 'case': args.case, 'authority': authority_pin,
              'source_before': before, 'images_before': pins,
              'scope': authority['scope'], 'whole_native_stack_qualified': False}
    c = None
    try:
        from hepta.hia_native_helpers import native_helpers_scope
        with native_helpers_scope(str(bundle_path), expected_sha256=authority['bundle']['sha256']):
            c = Case(manifests, args.output / 'state', args.case, report)
            c.directory.mkdir(mode=0o700)
            try:
                execute_case(c)
            finally:
                c.restore()
        report['source_after'] = support.source_snapshot()
        report['images_after'] = manifest_pins(manifests)
        need(support.same(before, report['source_after'])
             and support.same(pins, report['images_after']),
             'actual source or seven-image identity changed')
        support.exact_reread(args.authority, raw)
        support.exact_reread(manifest_path, manifest_raw)
        support.exact_reread(bundle_path, bundle_raw)
        need(report['validated'] is True, 'case did not finish its full assertions')
        report['status'] = 'PASS_CONTROL_ONLY'
        return 0
    finally:
        os.environ.clear(); os.environ.update(previous)
        support.write_json(args.output / 'report.json', report)


if __name__ == '__main__':
    raise SystemExit(main())
