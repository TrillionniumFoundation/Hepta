"""Focused actual-native/SQLite Slot operation-series controls.

These new controls are independent of the immutable 248 original observations
and 7,574 unexecuted derived inputs. Every loss is a saved actual native entry
whose complete return is then deliberately withheld. No loss field is assigned.
Run only as an owned child after the current two images have been built/admitted.
"""
from __future__ import annotations
import argparse
import contextvars
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys
import threading
import traceback

CASES = (
    'prefix-before-next-sql', 'prefix-after-third-sql', 'prefix-finalize',
    'ordinary-rejection',
    'prior-loss-context', 'prior-loss-thread',
    'loss-between-borrow-and-call-context', 'loss-between-borrow-and-call-thread',
    'same-frame-reentry',
)


def require(value, message):
    if not value:
        raise AssertionError(message)


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')


def write(path, value):
    path.write_bytes(canonical(value) + b'\n')


def capture(call):
    try:
        value = call()
    except BaseException as error:
        return False, error
    return True, value


def error_value(error):
    return {'type': type(error).__module__ + '.' + type(error).__qualname__,
            'message': str(error),
            'cause_type': None if error.__cause__ is None else
                type(error.__cause__).__module__ + '.' + type(error.__cause__).__qualname__}


def external_context(kind, call):
    """No copied ForeignCall ancestry; a fresh actual activation owns work."""
    if kind == 'context':
        return contextvars.Context().run(call)
    values = []
    def target():
        values.append(capture(call))
    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(5)
    require(not thread.is_alive(), 'owned finite resource thread did not finish within 5 seconds')
    require(len(values) == 1, 'thread did not deliver exactly one outcome')
    ok, value = values[0]
    if not ok:
        raise value
    return value


class Database:
    """Explicit test provider forwarding every successful SQL to real SQLite."""
    def __init__(self, real, events, label):
        self.real, self.events, self.label = real, events, label
        self.lookup_hook = self.call_hook = None

    def __getattribute__(self, name):
        if name == 'execute':
            events = object.__getattribute__(self, 'events')
            events.append({'event': 'execute.lookup', 'store': object.__getattribute__(self, 'label')})
            hook = object.__getattribute__(self, 'lookup_hook')
            if hook is not None:
                object.__setattr__(self, 'lookup_hook', None)
                hook()
        return object.__getattribute__(self, name)

    def execute(self, statement, parameters=()):
        self.events.append({'event': 'execute.call', 'store': self.label,
                            'statement': statement, 'parameters': list(parameters)})
        hook, self.call_hook = self.call_hook, None
        if hook is not None:
            hook(statement, parameters)
        result = self.real.execute(statement, parameters)
        self.events.append({'event': 'execute.returned', 'store': self.label,
                            'statement': statement})
        return result

    def close(self):
        self.events.append({'event': 'db.close', 'store': self.label})
        return self.real.close()

    def __getattr__(self, name):
        return getattr(self.real, name)


class Controls:
    def __init__(self, root, controller_manifest, decision_manifest):
        import ctypes
        from hepta.hia_agent_store import AgentStore
        from hepta.hia_native_delivery import (
            NativeDeliveryUnknown, check_resource_retirement, current_record,
        )
        from hepta.hia_slot_ledger_native import NativeSlotLedgerStore, selected_slot_ledger
        from hepta.hia_slot_operations_native import (
            installed_slot_operations, SlotOperationsFrame, SlotOperationsUnknown,
        )
        from hepta.hia_slot_operations_protocol import PORT, CLAIM, SUCCEEDED, FINALIZE
        from hepta.hia_slot_operations_selection import slot_operations_owner
        self.ctypes = ctypes
        self.NativeDeliveryUnknown, self.SlotOperationsUnknown = NativeDeliveryUnknown, SlotOperationsUnknown
        self.Frame, self.Ledger = SlotOperationsFrame, NativeSlotLedgerStore
        self.retirement, self.current_record = check_resource_retirement, current_record
        self.scope_factory, self.PORT = slot_operations_owner, PORT
        self.CLAIM, self.SUCCEEDED, self.FINALIZE = CLAIM, SUCCEEDED, FINALIZE
        self.root, self.events, self.entries, self.sql = root, [], [], []
        self.losses, self.retained_calls, self.checks = [], [], []
        self.fault = None
        self.controller_manifest = str(controller_manifest.resolve(strict=True))
        os.environ['HEPTA_HIA_SLOT_OPERATIONS_MANIFEST'] = self.controller_manifest
        os.environ['HEPTA_HIA_SLOT_LEDGER_MANIFEST'] = str(decision_manifest.resolve(strict=True))
        self.controller = installed_slot_operations(self.controller_manifest)
        self.decision = selected_slot_ledger()
        require(self.decision is not None, 'actual decision image was not selected')
        self.original_entry = self.controller._entry
        self.references = NativeSlotLedgerStore._hia_slot_reference_methods
        self.saved_references = dict(self.references)

        def poison(*args, **kwargs):
            self.retained_calls.append('retained')
            raise AssertionError('selected Slot control called a retained original method')
        for name, method in self.saved_references.items():
            self.references[name] = staticmethod(poison) if type(method) is staticmethod else poison

        events = self.events
        class Store(AgentStore):
            def __getattribute__(store, name):
                if name == 'db':
                    try:
                        label = object.__getattribute__(store, '_control_label')
                        enabled = object.__getattribute__(store, '_control_watch')
                    except AttributeError:
                        enabled = False
                    if enabled:
                        events.append({'event': 'store.db', 'store': label})
                return super().__getattribute__(name)
        self.Store = Store

        def entry(source, source_size, output, output_size, state, state_size):
            raw = ctypes.string_at(source, source_size)
            values = struct.unpack('<16Q', raw)
            event, port, mode = values[1], values[3], values[5]
            # Log the exact saved entry first; a fixture can never count its
            # own injected exception as an actual image transition.
            returned = self.original_entry(source, source_size, output, output_size, state, state_size)
            observed = {'ordinal': len(self.entries), 'event': event, 'port': port,
                        'mode': mode, 'native_return': returned, 'request_hex': raw.hex(),
                        'output_hex': ctypes.string_at(output, output_size).hex(),
                        'state_hex': ctypes.string_at(state, state_size).hex()}
            self.entries.append(observed)
            wanted = self.fault
            if wanted is not None and (mode, event, port) == wanted:
                self.fault = None
                require(returned == 96, 'saved native entry did not return its complete receipt')
                header = struct.unpack('<12Q', bytes.fromhex(observed['output_hex']))
                require(header[1] == 0 and header[5] == mode, 'saved native entry refused this valid control input')
                observed['deliberately_withheld_return_before_adapter_validation'] = True
                self.losses.append(dict(observed))
                return 0
            return returned
        self.controller._entry = entry

    def close_fixture(self):
        self.controller._entry = self.original_entry
        self.references.clear()
        self.references.update(self.saved_references)

    def store(self, label):
        store = self.Store(self.root / label)
        object.__setattr__(store, '_control_label', label)
        object.__setattr__(store, '_control_watch', False)
        real = object.__getattribute__(store, 'db')
        real.set_trace_callback(lambda statement: self.sql.append({'store': label, 'statement': statement}))
        proxy = Database(real, self.events, label)
        store.db = proxy
        object.__setattr__(store, '_control_watch', True)
        driver = self.Ledger(store, self.decision)
        return store, proxy, driver

    def scope(self):
        return self.scope_factory(self.controller_manifest, image=self.controller)

    def public_execute(self, driver, db, statement):
        # The explicit class form must select the same new controller as the
        # ordinary instance form. The original signatures/argument order stay.
        return self.Ledger._execute(driver, db, statement, ())

    def healthy(self, label='healthy-generation'):
        store, db, driver = self.store(label)
        before = len(self.sql)
        cursor = self.public_execute(driver, db, 'SELECT 53')
        require(cursor.fetchone()[0] == 53, 'fresh registered Store did not execute normally')
        require(len(self.sql) == before + 1, 'healthy Store SQL was repeated or absent')
        self.retirement(store)
        store.close()
        self.checks.append({'check': 'fresh-generation-usable-and-close', 'store': label})

    def seed_loss(self, store, db, driver, statement='SELECT 7'):
        self.fault = (2, self.SUCCEEDED, self.PORT['execute_call'])
        before = len(self.losses)
        ok, error = capture(lambda: driver._execute(db, statement))
        require(not ok and type(error) is self.SlotOperationsUnknown, 'seed did not expose the actual controller loss')
        require(self.fault is None and len(self.losses) == before + 1, 'seed fault did not consume one real entry return')
        ok, refused = capture(lambda: self.retirement(store))
        require(not ok and type(refused) is self.NativeDeliveryUnknown, 'actual affected Store was not fenced')
        self.checks.append({'check': 'real-loss-seeded', 'error': error_value(error),
                            'retirement': error_value(refused)})
        return error

    def assert_fenced_close(self, store):
        before = len([e for e in self.events if e['event'] == 'db.close'])
        ok, error = capture(store.close)
        require(not ok and type(error) is self.NativeDeliveryUnknown, 'unknown Store close was not refused')
        require(len([e for e in self.events if e['event'] == 'db.close']) == before,
                'fenced Store reached the actual close provider')
        self.checks.append({'check': 'close-refused-with-no-db-close', 'error': error_value(error)})

    def prefix(self, case):
        from hepta.hia_agent_store import wire
        store, db, driver = self.store('prefix')
        db.real.execute('INSERT INTO slots VALUES (?,?,?,?,?)', ('s', 'ctx', '4', '9', 'abi'))
        artifact = {'id': 'artifact-a', 'sha256': 'a' * 64, 'uri': 'hepta:artifact-a'}
        db.real.execute('INSERT INTO versions VALUES (?,?,?)', ('s', '4', wire(artifact).decode()))
        self.events.clear()
        self.sql.clear()
        if case == 'ordinary-rejection':
            refusal = ValueError('declared ordinary second SQL refusal')
            def after_first(statement, parameters):
                # Hook consumed by the first call. Arm a fresh second-call
                # hook without changing or retrying the original SQL.
                def second(_statement, _parameters):
                    raise refusal
                db.call_hook = second
            db.call_hook = after_first
            ok, error = capture(lambda: driver.snapshot('s'))
            require(not ok and error is refusal, 'fully ACKed ordinary refusal changed its object')
            require(len(self.sql) == 1, 'ordinary refusal did not keep the exact one-SQL prefix')
            require(not self.losses, 'ordinary refusal was misreported as native loss')
            self.retirement(store)
            store.close()
            self.checks.append({'check': 'ordinary-error-fully-confirmed', 'error': error_value(error)})
            return
        goals = {
            'prefix-before-next-sql': (4, self.CLAIM, self.PORT['snapshot_version'], 1),
            'prefix-after-third-sql': (4, self.SUCCEEDED, self.PORT['snapshot_count'], 3),
            'prefix-finalize': (4, self.FINALIZE, 0, 3),
        }
        mode, event, port, count = goals[case]
        self.fault = mode, event, port
        ok, error = capture(lambda: driver.snapshot('s'))
        require(not ok and type(error) is self.SlotOperationsUnknown, 'prefix loss did not retain the native Unknown')
        require(self.fault is None and len(self.losses) == 1, 'prefix fault did not consume one actual return')
        require(len(self.sql) == count, 'SQL prefix differs or a later SQL was executed')
        completed_children = [entry for entry in self.entries
                              if entry['mode'] == 2 and entry['event'] == self.FINALIZE]
        require(len(completed_children) == count, 'earlier _execute children were not fully confirmed')
        require(len({entry['request_hex'] for entry in completed_children}) == count,
                'an already confirmed child final receipt was replayed')
        self.assert_fenced_close(store)
        self.healthy()
        self.checks.append({'check': 'earlier-SQL-facts-survive-individual-ACKs',
                            'sql_prefix': count, 'confirmed_execute_children': len(completed_children)})

    def prior_loss(self, kind):
        store, db, driver = self.store('prior')
        self.seed_loss(store, db, driver)
        self.events.clear()
        before_sql = len(self.sql)
        before_entries = len(self.entries)
        ok, error = capture(lambda: external_context(kind,
            lambda: self.public_execute(driver, db, 'SELECT 41')))
        require(not ok and type(error) is self.NativeDeliveryUnknown, 'same-generation pre-existing loss was not the exact guard refusal')
        require(len(self.sql) == before_sql, 'a first SQL ran on the fenced Store')
        require(not self.events, 'fenced Store reached .db or the execute lookup before refusal')
        require(len(self.entries) > before_entries, 'control did not enter its real fresh invocation before the original Store lookup')
        require(len(self.losses) == 1, 'guard created a second synthetic native loss')
        self.assert_fenced_close(store)
        self.healthy()
        self.checks.append({'check': 'same-generation-loss-pre-SQL', 'execution_context': kind,
                            'error': error_value(error), 'new_SQL': 0, 'new_provider_events': 0})

    def between_borrow_and_call(self, kind):
        store, db, driver = self.store('interleaved')
        captured = []
        before_sql = len(self.sql)
        def interleave():
            error = external_context(kind, lambda: self.seed_loss(store, db, driver, 'SELECT 97'))
            captured.append(error)
        db.lookup_hook = interleave
        ok, error = capture(lambda: self.public_execute(driver, db, 'SELECT 41'))
        require(not ok and type(error) is self.NativeDeliveryUnknown, 'last-argument guard did not find the new same-generation loss')
        require(len(captured) == 1 and type(captured[0]) is self.SlotOperationsUnknown,
                'independent context did not deliver its exact genuine loss')
        statements = [x['statement'] for x in self.sql[before_sql:]]
        require(statements == ['SELECT 97'], 'outer SQL was reached or child SQL was replayed')
        require(len(self.losses) == 1, 'interleaving did not withhold exactly one saved entry')
        self.assert_fenced_close(store)
        self.healthy()
        self.checks.append({'check': 'same-generation-loss-at-final-arguments',
                            'execution_context': kind, 'SQL': statements, 'error': error_value(error)})

    def reentry(self):
        store, db, driver = self.store('reentry')
        records = []
        def hook(statement, parameters):
            record = self.current_record()
            require(record is not None and type(record.owner) is self.Frame, 'provider has no actual current controller Frame')
            frame = record.owner
            state = (record.retired, record.terminal, record.native_pending, record.observation_pending,
                     frame.series.active, frame.series.holder.completed,
                     id(record.owner), id(frame._pending_foreign), id(frame.series))
            entry_count = len(self.entries)
            ok, error = capture(frame.finish)
            require(not ok and type(error) is self.SlotOperationsUnknown, 'same Frame was not rejected at its entry guard')
            after = (record.retired, record.terminal, record.native_pending, record.observation_pending,
                     frame.series.active, frame.series.holder.completed,
                     id(record.owner), id(frame._pending_foreign), id(frame.series))
            require(after == state and len(self.entries) == entry_count,
                    'caught re-entry changed active cleanup/pending state or entered native')
            require(driver.validate_u64(7, 'generation') == 7, 'legal fresh public-method recursion was incorrectly blocked')
            records.append({'before': state, 'after': after, 'reentry_error': error_value(error),
                            'reentry_native_entries': 0, 'fresh_recursion_entries': len(self.entries) - entry_count})
        db.call_hook = hook
        cursor = self.public_execute(driver, db, 'SELECT 61')
        require(cursor.fetchone()[0] == 61, 'outer SQL did not complete after the caught re-entry')
        require(len(records) == 1 and records[0]['fresh_recursion_entries'] > 0,
                're-entry or normal recursive control was not observed exactly once')
        require([v['statement'] for v in self.sql] == ['SELECT 61'], 'outer SQL was replayed')
        require(not self.losses, 'safe re-entry refusal manufactured native loss')
        self.retirement(store)
        store.close()
        self.checks.extend(records)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', choices=CASES, required=True)
    parser.add_argument('--controller-manifest', type=Path, required=True)
    parser.add_argument('--decision-manifest', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    for key in list(os.environ):
        if key.startswith(('HEPTA_HIA_', 'PYTHON')):
            del os.environ[key]
    retained_inputs = {}
    for name, manifest in [('controller', args.controller_manifest), ('decision', args.decision_manifest)]:
        raw = manifest.resolve(strict=True).read_bytes()
        value = json.loads(raw)
        image = manifest.resolve().parent / value['image_path']
        retained_inputs[name] = {'manifest_path': str(manifest.resolve()), 'manifest_sha256': sha256(raw).hexdigest(),
                                'image_path': str(image), 'image_sha256': sha256(image.read_bytes()).hexdigest()}
    controls = None
    error = None
    unraisable = []
    old_hook = sys.unraisablehook
    sys.unraisablehook = lambda arg: unraisable.append(error_value(arg.exc_value))
    try:
        controls = Controls(args.evidence / 'stores', args.controller_manifest, args.decision_manifest)
        with controls.scope():
            if args.case.startswith('prefix-') or args.case == 'ordinary-rejection':
                controls.prefix(args.case)
            elif args.case.startswith('prior-loss-'):
                controls.prior_loss(args.case.rsplit('-', 1)[1])
            elif args.case.startswith('loss-between-borrow-and-call-'):
                controls.between_borrow_and_call(args.case.rsplit('-', 1)[1])
            elif args.case == 'same-frame-reentry':
                controls.reentry()
            else:
                raise AssertionError('undeclared control')
        require(not controls.retained_calls, 'a retained original body was executed')
        require(controls.entries, 'no actual controller image entry was observed')
        require(not unraisable, 'a callback escaped as an unraisable error')
    except BaseException as caught:
        error = error_value(caught)
        (args.evidence / 'failure.traceback.txt').write_text(''.join(traceback.format_exception(caught)))
    finally:
        if controls is not None:
            controls.close_fixture()
        sys.unraisablehook = old_hook
    report = {'schema': 'hepta.slot-operations.focused-resource-control.v1',
              'status': 'PASS' if error is None else 'HOLD', 'id': args.case,
              'runtime': {'executable': sys.executable, 'version': sys.version, 'pid': os.getpid(),
                          'ppid': os.getppid(), 'pgid': os.getpgrp()},
              'inputs': retained_inputs, 'error': error, 'unraisable': unraisable,
              'actual_controller_entries': [] if controls is None else controls.entries,
              'actual_SQL': [] if controls is None else controls.sql,
              'provider_events': [] if controls is None else controls.events,
              'withheld_native_returns': [] if controls is None else controls.losses,
              'checks': [] if controls is None else controls.checks,
              'retained_original_calls': [] if controls is None else controls.retained_calls,
              'unknown_resources_kept_until_this_owned_child_exits': True,
              'guard_checks_hold_declared_fixture_references': True,
              'independent_weakref_only_lifetime_proof_claimed': False,
              'SQL_native_implementation_claimed': False,
              'original_248_or_derived_7574_replaced': False}
    write(args.evidence / 'report.json', report)
    return 0 if error is None else 1


if __name__ == '__main__':
    raise SystemExit(main())
