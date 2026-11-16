"""Focused actual-image checks for the proposed weak registered SQL boundary.

The independent frozen SQL observer separately owns original expression and
destructor expectations. These controls distinguish real handoff loss, exact
registered-resource facts, and ordinary foreign errors. A fixture Store is
explicitly registered; it is not presented as an arbitrary opaque DB owner.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from contextvars import Context
import ctypes
import gc
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import struct
import sys
import textwrap
from types import SimpleNamespace
from unittest.mock import patch
import weakref

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from hepta import hia_agent_service as api
from hepta import hia_native_delivery as delivery
from hepta import hia_service_read_native as read
from hepta import hia_service_context_native as context
from hepta import hia_service_artifact_native as artifact
from tests.hia_service_read_fixture import canonical

BODY = ROOT / 'tests/fixtures/hia_service_read_original_91bbd077/originals/_hia_read.py.txt'
BODY_SHA256 = 'b8c81da6c1bd879756e29ba9cc2f943af00deef35d5729928253d2ec395dcd80'


def caught(function):
    try:
        return function(), None
    except BaseException as error:
        return None, error


def original():
    raw = BODY.read_bytes()
    assert sha256(raw).hexdigest() == BODY_SHA256
    namespace = dict(vars(api))
    exec(compile(textwrap.dedent(raw.decode()), str(BODY), 'exec'), namespace)
    return namespace['_hia_read']


class Database:
    def __init__(self, events):
        self.events = events
        self.connection = sqlite3.connect(':memory:', isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute('CREATE TABLE cursors (id TEXT PRIMARY KEY, artifact_id TEXT, sha256 TEXT, offset INTEGER)')
        self.connection.execute('INSERT INTO cursors VALUES (?,?,?,?)', ('prior', 'input', 'a' * 64, 0))
        self.executions = []

    def __getattribute__(self, name):
        if name == 'execute':
            object.__getattribute__(self, 'events').append(['execute.lookup'])
        return object.__getattribute__(self, name)

    def execute(self, statement, parameters):
        self.events.append(['execute.before', statement, list(parameters)])
        answer = self.connection.execute(statement, parameters)
        self.executions.append([statement, list(parameters)])
        self.events.append(['execute.returned', statement])
        return answer


class RegisteredStore:
    def __init__(self, database, events, label):
        self._database, self.events, self.label = database, events, label
        delivery.bind_resource_lifetime(self)
        # This is an explicit real ResourceScope. Under a read activation it
        # must use that activation's weak policy from its birth, not create a
        # strong observation which is weakened only after this constructor.
        with delivery.resource_scope(self):
            events.append(['store.constructed', label])

    @property
    def db(self):
        self.events.append(['db.lookup', self.label])
        return self._database

    def get(self, reference):
        self.events.append(['get', self.label, reference['id']])
        return b'abcdef', {}

    def close(self):
        delivery.check_resource_retirement(self)
        self.events.append(['fixture.public-close', self.label])
        self._database.connection.close()

    def __del__(self):
        # No assertion in a destructor: every observation is checked by the
        # owning test outside an unraisable context.
        events = getattr(self, 'events', None)
        if events is not None:
            events.append(['store.deleted', getattr(self, 'label', 'partial')])


class Fixture:
    def __init__(self, *, cursor=False):
        self.events = []
        self.database = Database(self.events)
        self.store = RegisteredStore(self.database, self.events, 'persistent')
        self.service = SimpleNamespace(store=self.store)
        self.arguments = {'artifact': {'id': 'input', 'sha256': 'a' * 64}, 'max_bytes': 3}
        if cursor:
            self.arguments['cursor'] = 'prior'


def actual_peer_loss(image, error, *, resource=None):
    actual = image._entry
    entered = []
    def lost(*arguments):
        result = actual(*arguments)
        entered.append(result)
        raise error
    with delivery.NativeCall(('read-resource-control-explicit-association',)) as record:
        if resource is not None:
            record.associate(resource)
        with record.foreign(observation=False), patch.object(image, '_entry', lost):
            _, observed = caught(lambda: image.arithmetic(1, 3, 4))
        assert len(entered) == 1
        assert type(observed) is context.ServiceContextUnknown and observed.__cause__ is error
        assert record.loss is not None
        return record.loss


def gc_peer_loss(image, error, *, resource=None, fresh_context=False):
    observations = []
    class Reenter:
        def __del__(self):
            operation = lambda: actual_peer_loss(image, error, resource=resource)
            observations.append(caught(lambda: Context().run(operation) if fresh_context else operation()))
    probe = Reenter()
    probe.cycle = probe
    del probe
    gc.collect()
    assert len(observations) == 1 and observations[0][1] is None
    assert observations[0][0] is not None
    return observations[0][0]


def preparation(read_image, peer_image):
    rows = []
    for site in ('last-reservation', 'last-reservation-other-context',
                 'borrow-query', 'arguments-query'):
        fixture, fault = Fixture(cursor=True), ValueError('actual peer lost during ' + site)
        frame = read.ServiceReadFrame(read_image, fixture.service, fixture.arguments)
        fired, query_calls, loss = [], [], []
        reserve = delivery._PendingForeignResources.reserve_borrow
        query = delivery._registered_resource_loss
        def reservation(holder, registration, fact):
            result = reserve(holder, registration, fact)
            if (not fired and site.startswith('last-reservation')
                    and holder.record is frame._delivery and fact.kind == 'borrow'):
                fired.append(site)
                loss.append(gc_peer_loss(peer_image, fault,
                    resource=fixture.store if site.endswith('other-context') else None,
                    fresh_context=site.endswith('other-context')))
            return result
        def queried(registration):
            result = query(registration)
            scope = delivery._active_scope()
            if (scope is not None and scope.record is frame._delivery
                    and registration is not None and frame.receipt.port == read.PORT['cursor_select']):
                query_calls.append(result is None)
                wanted = 1 if site == 'borrow-query' else 2 if site == 'arguments-query' else 0
                if not fired and len(query_calls) == wanted:
                    assert result is None
                    fired.append(site)
                    loss.append(gc_peer_loss(peer_image, fault))
            return result
        with patch.object(delivery._PendingForeignResources, 'reserve_borrow', reservation), \
             patch.object(delivery, '_registered_resource_loss', queried):
            _, error = caught(frame.finish)
        assert fired == [site] and len(loss) == 1
        assert isinstance(error, RuntimeError) and frame._delivery.loss is loss[0]
        assert frame.fenced and frame.native_failed and fixture.database.executions == []
        assert not frame._pending_foreign._borrow_fact.occurred
        db_lookups = [event for event in fixture.events if event[0] == 'db.lookup']
        execute_lookups = [event for event in fixture.events if event[0] == 'execute.lookup']
        assert len(db_lookups) == len(execute_lookups) == (1 if site == 'arguments-query' else 0)
        rows.append({'site': site, 'actual_peer_loss': True, 'same_loss_origin': True,
            'events': fixture.events, 'SQL_called': False, 'direct_fact_armed': False,
            'original_db_lookup_count': len(db_lookups), 'original_execute_lookup_count': len(execute_lookups),
            'resource_or_causal_loss_distinguished': True})
    # A named RuntimeError without actual handoff loss remains a foreign
    # failure, including a partial but unarmed prepared weak observation.
    fixture = Fixture(cursor=True)
    frame = read.ServiceReadFrame(read_image, fixture.service, fixture.arguments)
    fault = delivery.NativeDeliveryUnknown('ordinary named failure during preparation')
    reserve = delivery._PendingForeignResources.reserve_borrow
    def ordinary(holder, registration, fact):
        result = reserve(holder, registration, fact)
        if holder.record is frame._delivery and fact.kind == 'borrow':
            raise fault
        return result
    with patch.object(delivery._PendingForeignResources, 'reserve_borrow', ordinary):
        _, error = caught(frame.finish)
    assert error is fault and frame.finished and frame.receipt.phase == read.PROPAGATE
    assert frame._delivery.loss is None and frame._delivery.retired
    assert not fixture.database.executions
    delivery.check_resource_retirement(fixture.store)
    fixture.store.close()
    rows.append({'site': 'ordinary-named-error', 'same_error_object': True,
        'confirmed_RAISED': True, 'resource_retirement_allowed': True, 'events': fixture.events})
    return rows


def sqlite_lost_ack(read_image):
    rows = []
    for name, cursor in (('cursor_select', True), ('cursor_insert', False)):
        for kind in (ValueError, MemoryError, KeyboardInterrupt):
            fixture, fault = Fixture(cursor=cursor), kind('SQL returned before read ACK loss')
            frame = read.ServiceReadFrame(read_image, fixture.service, fixture.arguments)
            actual, entries, fired = read_image._entry, [], []
            def lost(source, size, output, capacity, state, extent):
                packet = struct.unpack('<10Q', ctypes.string_at(source, size))
                result = actual(source, size, output, capacity, state, extent)
                entries.append([packet[1], packet[3], result])
                if not fired and (packet[1], packet[3]) == (read.SUCCEEDED, read.PORT[name]):
                    fired.append(True)
                    raise fault
                return result
            with patch.object(read_image, '_entry', lost):
                _, error = caught(frame.finish)
                before = len(entries), list(fixture.database.executions)
                _, repeated = caught(frame.finish)
            assert fired and frame._delivery.loss is not None and frame.native_failed
            if isinstance(fault, Exception):
                assert type(error) is read.ServiceReadUnknown and error.__cause__ is fault
            else:
                assert error is fault
            assert type(repeated) is read.ServiceReadUnknown
            assert before == (len(entries), fixture.database.executions)
            assert len(fixture.database.executions) == 1
            assert not any(event == read.RAISED for event, port, result in entries)
            _, retirement = caught(fixture.store.close)
            assert type(retirement) is delivery.NativeDeliveryUnknown
            assert not any(event[0] == 'fixture.public-close' for event in fixture.events)
            count = fixture.database.connection.execute('SELECT count(*) FROM cursors').fetchone()[0]
            assert count == (1 if cursor else 2)
            retained = [observation for observation in delivery._RESOURCE_OBSERVATIONS.values()
                        if type(observation) is delivery._WeakResourceObservation
                        and observation.resource is fixture.store and observation.loss is not None]
            assert retained
            registration = delivery._registered_resource_identity(fixture.store)
            _, renewal = caught(lambda: delivery.bind_resource_lifetime(fixture.store))
            assert type(renewal) is delivery.NativeDeliveryUnknown
            assert delivery._registered_resource_identity(fixture.store)[1] is registration[1]
            rows.append({'operation': name, 'fault': kind.__name__, 'entries': entries,
                'actual_SQLite_executions': fixture.database.executions,
                'cursor_row_count': count, 'exact_registered_Store_retirement_refused': True,
                'same_owner_retry_native_entries': 0, 'promoted_observation_count': len(retained),
                'lifetime_renewal_cannot_launder_already_recorded_loss': True,
                'independent_connection_close_claimed': False})
    return rows


def ephemeral(read_image):
    def observe(owner):
        events, refs = [], []
        database = Database(events)
        class Service:
            @property
            def store(self):
                item = RegisteredStore(database, events, 'temporary-' + str(len(refs) + 1))
                refs.append(weakref.ref(item))
                return item
        class Arguments(dict):
            def __getitem__(self, key):
                if key == 'cursor':
                    gc.collect()
                    events.append(['cursor.argument.temporary-store-alive', refs[-1]() is not None])
                return super().__getitem__(key)
        service = Service()
        arguments = Arguments(artifact={'id': 'input', 'sha256': 'a' * 64}, cursor='prior', max_bytes=3)
        result = owner(service, arguments)
        assert all(reference() is None for reference in refs)
        assert ['cursor.argument.temporary-store-alive', False] in events
        snapshot = {'events': events, 'result': result,
                    'executions': database.executions, 'all_temporary_stores_dead': True}
        database.connection.close()
        return snapshot
    expected = observe(original())
    actual = observe(lambda service, arguments: read.ServiceReadFrame(read_image, service, arguments).finish())
    assert canonical(expected) == canonical(actual)
    lost_rows = []
    for name, cursor in (('cursor_select', True), ('cursor_insert', False)):
        events, references = [], []
        database = Database(events)
        class Service:
            @property
            def store(self):
                item = RegisteredStore(database, events, 'dead-before-ACK-' + str(len(references)))
                references.append(weakref.ref(item))
                return item
        arguments = {'artifact': {'id': 'input', 'sha256': 'a' * 64}, 'max_bytes': 3}
        if cursor:
            arguments['cursor'] = 'prior'
        frame = read.ServiceReadFrame(read_image, Service(), arguments)
        entry, fired = read_image._entry, []
        fault = ValueError('SQL ACK lost after temporary Store already died')
        def lost(source, size, output, capacity, state, extent):
            packet = struct.unpack('<10Q', ctypes.string_at(source, size))
            result = entry(source, size, output, capacity, state, extent)
            if (packet[1], packet[3]) == (read.SUCCEEDED, read.PORT[name]):
                fired.append(all(reference() is None for reference in references))
                raise fault
            return result
        with patch.object(read_image, '_entry', lost):
            _, error = caught(frame.finish)
        assert fired == [True] and type(error) is read.ServiceReadUnknown and error.__cause__ is fault
        assert len(database.executions) == 1 and frame._delivery.loss is not None
        assert all(reference() is None for reference in references)
        holder = frame._pending_foreign.pending_resources
        weak_slots = [entry.observation for entry in holder.entries if entry is not None
                      and type(entry.observation) is delivery._WeakResourceObservation]
        assert weak_slots and all(observation.resource is None for observation in weak_slots)
        assert any(observation.loss is not None for observation in weak_slots)
        lost_rows.append({'operation': name, 'events': events,
            'actual_SQLite_executions': database.executions,
            'temporary_Stores_dead_before_actual_ACK_loss': True,
            'no_dead_target_resurrected_or_guessed': True,
            'unknown_read_owner_retained': not frame._delivery.retired,
            'independently_held_database_retirement_proved': False})
        # This diagnostic owns its independent connection and documents the
        # unsupported boundary. It is not the production public Store close.
        database.connection.close()
    return {'actual_resource_scope_constructors': True,
            'registered_healthy_temporary_observations_equal': True,
            'original': expected, 'candidate': actual,
            'actual_lost_ACK_after_original_Store_death': lost_rows,
            'all_temporary_DB_protocols_claimed': False}


def ancestors(read_image, artifact_image):
    rows = []
    for lose_parent in (False, True):
        fixture, children, after_child = Fixture(), [], []
        fault = ValueError('outer actual artifact ACK lost after complete read')
        def profile(*arguments):
            child = read.ServiceReadFrame(read_image, fixture.service, fixture.arguments)
            children.append(child)
            result = child.finish()
            assert child.finished and child._delivery.retired and result['next_cursor']
            assert delivery._resource_loss(fixture.store) is None
            holder = parent._pending_foreign.pending_resources
            pending = [entry for entry in holder.entries if entry is not None
                       and type(entry.observation) is delivery._WeakResourceObservation
                       and entry.observation.matches(fixture.store)]
            assert pending and all(entry.observation.resource is None for entry in pending)
            assert all(entry.pending_for(holder.activation_id) for entry in pending)
            after_child.append({'child_retired': True, 'parent_weak_slots': len(pending),
                                'healthy_resource_not_promoted': True})
        service = SimpleNamespace(_profile=profile,
            store=SimpleNamespace(put=lambda data, kind: {'id': 'outer-result', 'sha256': 'b' * 64}))
        arguments = {'artifact_profile': 'fixture-profile',
                     'source': {'kind': 'utf8', 'text': 'outer'}}
        parent = artifact.ServiceArtifactFrame(artifact_image, service, arguments)
        actual, entries = artifact_image._entry, []
        def observed(source, size, output, capacity, state, extent):
            packet = struct.unpack('<10Q', ctypes.string_at(source, size))
            result = actual(source, size, output, capacity, state, extent)
            entries.append([packet[1], packet[3], result])
            if lose_parent and (packet[1], packet[3]) == (artifact.SUCCEEDED, artifact.PORT['profile']):
                raise fault
            return result
        with patch.object(artifact_image, '_entry', observed):
            result, error = caught(parent.finish)
        assert len(children) == len(after_child) == 1
        if lose_parent:
            assert type(error) is artifact.ServiceArtifactUnknown and error.__cause__ is fault
            assert parent._delivery.loss is not None and children[0]._delivery.loss is None
            _, refused = caught(fixture.store.close)
            assert type(refused) is delivery.NativeDeliveryUnknown
            assert not any(event == artifact.RAISED for event, port, answer in entries)
        else:
            assert error is None and parent.finished and result['artifact']['id'] == 'outer-result'
            assert delivery._resource_loss(fixture.store) is None
            fixture.store.close()
        rows.append({'actual_parent_owner': 'service_artifact', 'lose_parent_ACK': lose_parent,
            'child': after_child[0], 'parent_entries': entries,
            'child_complete_ACK_not_reclassified': children[0]._delivery.loss is None,
            'parent_retirement_refused_only_after_actual_loss': lose_parent})
    # An independently established strong ancestor fact keeps its old policy.
    # The inner read's weak policy must not downgrade that separate fact.
    events, references = [], []
    database = Database(events)
    class Service:
        @property
        def store(self):
            item = RegisteredStore(database, events, 'outer-strong-' + str(len(references)))
            references.append(weakref.ref(item))
            return item
    checks = []
    def profile(*arguments):
        result = read.ServiceReadFrame(read_image, Service(), {
            'artifact': {'id': 'input', 'sha256': 'a' * 64}, 'max_bytes': 3}).finish()
        assert result['next_cursor'] and references and all(reference() is not None for reference in references)
        holder = parent._pending_foreign.pending_resources
        strong = [entry for entry in holder.entries if entry is not None
                  and type(entry.observation) is delivery.ResourceObservation]
        assert strong
        checks.append(len(strong))
    service = SimpleNamespace(_profile=profile,
        store=SimpleNamespace(put=lambda data, kind: {'id': 'outer-strong', 'sha256': 'c' * 64}))
    parent = artifact.ServiceArtifactFrame(artifact_image, service,
        {'artifact_profile': 'fixture-profile', 'source': {'kind': 'utf8', 'text': 'outer'}})
    parent.finish()
    assert checks and all(reference() is None for reference in references)
    database.connection.close()
    rows.append({'actual_parent_owner': 'service_artifact',
        'independent_strong_policy_preserved': True, 'strong_slots_before_parent_ACK': checks[0],
        'temporary_stores_released_after_parent_ACK': True, 'events': events})
    return rows


def generations(read_image):
    fixture = Fixture()
    frame = read.ServiceReadFrame(read_image, fixture.service, fixture.arguments)
    old_registration = delivery._registered_resource_identity(fixture.store)
    actual = read_image._entry
    fault, changed = ValueError('old-generation read ACK missing'), []
    def lost(source, size, output, capacity, state, extent):
        packet = struct.unpack('<10Q', ctypes.string_at(source, size))
        result = actual(source, size, output, capacity, state, extent)
        if (packet[1], packet[3]) == (read.SUCCEEDED, read.PORT['cursor_insert']):
            delivery.bind_resource_lifetime(fixture.store)
            changed.append(delivery._registered_resource_identity(fixture.store))
            raise fault
        return result
    with patch.object(read_image, '_entry', lost):
        _, error = caught(frame.finish)
    assert type(error) is read.ServiceReadUnknown and error.__cause__ is fault
    assert len(changed) == 1 and changed[0][1] is not old_registration[1]
    assert delivery._registered_resource_loss(old_registration) is None
    assert delivery._resource_loss(fixture.store) is None
    old = [observation for observation in delivery._RESOURCE_OBSERVATIONS.values()
           if type(observation) is delivery._WeakResourceObservation
           and observation.registration is not None and observation.registration[1] is old_registration[1]]
    assert old and all(observation.resource is None for observation in old)
    replacement = Fixture()
    fabricated_id = (old_registration[0], old_registration[1], id(replacement.store))
    assert delivery._registered_resource_loss(fabricated_id) is None
    replacement.store.close()
    fixture.store.close()
    return {'actual_old_generation_ACK_loss': True, 'new_generation_not_guessed': True,
        'lifetime_renewed_before_loss_became_known': True,
        'renewal_of_already_known_loss_covered_separately': True,
        'stale_registration_and_mismatched_numeric_id_rejected': True,
        'unconfirmed_old_generation_owner_retained': not frame._delivery.retired,
        'old_or_rebound_opaque_DB_custody_claimed': False,
        'actual_allocator_numeric_id_reuse_claimed': False}


def cleanup_boundaries(read_image, peer_image):
    rows = []
    # Memory failure before slot registration is a confirmable foreign failure.
    fixture = Fixture(cursor=True)
    frame = read.ServiceReadFrame(read_image, fixture.service, fixture.arguments)
    fault = MemoryError('weak slot preparation failed before SQL')
    initialize = delivery._WeakResourceObservation.__init__
    def refused(observation, holder, registration):
        if holder.record is frame._delivery:
            raise fault
        initialize(observation, holder, registration)
    with patch.object(delivery._WeakResourceObservation, '__init__', refused):
        _, error = caught(frame.finish)
    assert error is fault and frame._delivery.loss is None and frame._delivery.retired
    assert not fixture.database.executions
    fixture.store.close()
    rows.append({'boundary': 'pre-slot-MemoryError', 'same_error_object': True,
                 'SQL_effects': 0, 'confirmed_foreign': True})
    for mode in ('confirmed-cleanup-MemoryError', 'confirmed-cleanup-new-child-loss',
                 'loss-promotion-MemoryError'):
        fixture = Fixture()
        frame = read.ServiceReadFrame(read_image, fixture.service, fixture.arguments)
        native_fault = ValueError('actual INSERT ACK lost')
        cleanup_fault = MemoryError(mode)
        actual_entry, retire, failed = read_image._entry, delivery._WeakResourceObservation.retire, delivery._WeakResourceObservation.failed
        fired, before_promotion = [], []
        def entry(source, size, output, capacity, state, extent):
            packet = struct.unpack('<10Q', ctypes.string_at(source, size))
            result = actual_entry(source, size, output, capacity, state, extent)
            if mode == 'loss-promotion-MemoryError' and (packet[1], packet[3]) == (read.SUCCEEDED, read.PORT['cursor_insert']):
                raise native_fault
            return result
        def retirement(observation):
            holder = observation.owner
            if (not fired and holder is not None and holder.record is frame._delivery
                    and holder.completed and mode.startswith('confirmed-cleanup')):
                fired.append(mode)
                if mode.endswith('MemoryError'):
                    raise cleanup_fault
                actual_peer_loss(peer_image, ValueError('new child after the SQL ACK'))
            return retire(observation)
        def promotion(observation, error):
            holder = observation.owner
            if (not fired and holder is not None and holder.record is frame._delivery
                    and mode == 'loss-promotion-MemoryError'):
                fired.append(mode)
                # Establish the real existing loss flag first, then fail
                # before the pre-reserved weak slot is strongly promoted.
                delivery.ResourceObservation.failed(observation, error)
                _, refused = caught(lambda: delivery.check_resource_retirement(fixture.store))
                before_promotion.append({'resource_slot_empty': observation.resource is None,
                    'actual_loss_recorded': observation.loss is not None,
                    'retirement_already_refused': type(refused) is delivery.NativeDeliveryUnknown})
                raise cleanup_fault
            return failed(observation, error)
        with patch.object(read_image, '_entry', entry), \
             patch.object(delivery._WeakResourceObservation, 'retire', retirement), \
             patch.object(delivery._WeakResourceObservation, 'failed', promotion):
            _, error = caught(frame.finish)
        assert fired == [mode] and len(fixture.database.executions) == 1
        if mode == 'confirmed-cleanup-MemoryError':
            assert error is cleanup_fault and frame._delivery.loss is None and frame._delivery.retired
            fixture.store.close()
        elif mode == 'confirmed-cleanup-new-child-loss':
            assert isinstance(error, RuntimeError) and frame._delivery.loss is not None
            assert delivery._resource_loss(fixture.store) is None
            fixture.store.close()
        else:
            assert error is cleanup_fault and frame._delivery.loss is not None
            assert before_promotion == [{'resource_slot_empty': True,
                'actual_loss_recorded': True, 'retirement_already_refused': True}]
            _, refused_close = caught(fixture.store.close)
            assert type(refused_close) is delivery.NativeDeliveryUnknown
        rows.append({'boundary': mode, 'original_error_identity_checked': True,
            'actual_SQLite_executions': fixture.database.executions,
            'confirmed_SQL_fact_not_rearmed': mode.startswith('confirmed-cleanup'),
            'pre_reserved_loss_visible_before_promotion': before_promotion})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--context-manifest', type=Path, required=True)
    parser.add_argument('--artifact-manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    from tools.build_hia_service_read import INPUTS
    before = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in INPUTS}
    images = {'read': read.installed_service_read(str(args.manifest)),
        'context': context.installed_service_context(str(args.context_manifest)),
        'artifact': artifact.installed_service_artifact(str(args.artifact_manifest))}
    def forbidden(*arguments, **keywords):
        raise AssertionError('selected canonical read entered its retained body')
    rows = {}
    with ExitStack() as stack:
        stack.enter_context(patch.object(api, '_SERVICE_READ_REFERENCE', forbidden))
        stack.enter_context(patch.object(api.HIAAgentService, '_hia_read_reference', forbidden))
        cases = (
            ('registered_temporary_lifetime', lambda: ephemeral(images['read'])),
            ('preparation_boundaries', lambda: preparation(images['read'], images['context'])),
            ('actual_SQLite_lost_ACK', lambda: sqlite_lost_ack(images['read'])),
            ('actual_strong_ancestor_own_ACK', lambda: ancestors(images['read'], images['artifact'])),
            ('generation_identity', lambda: generations(images['read'])),
            ('MemoryError_and_confirmed_cleanup', lambda: cleanup_boundaries(images['read'], images['context'])),
        )
        for name, operation in cases:
            result = operation()
            rows[name] = result
            (args.output / (name + '.json')).write_bytes(canonical(result))
    after = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in INPUTS}
    assert before == after
    report = {'schema': 'hepta.hia.service-read-weak-resource-controls.v1', 'status': 'PASS',
        'groups': list(rows), 'source_before': before, 'source_after': after,
        'image_sha256': {key: image.image_sha256 for key, image in images.items()},
        'actual_SQLite_and_native_images': True, 'fixture_Store_explicit_registration': True,
        'ordinary_AgentStore_public_close_covered_here': False,
        'ordinary_AgentStore_public_close_separately_required_by_installed_worker': True,
        'unknown_records_retained': delivery.custody_snapshot(),
        'old_original_oracle_inputs_or_fields_changed': False,
        'opaque_dead_or_rebound_DB_custody_claimed': False,
        'all_input_equivalence_proved': False, 'whole_native_stack_qualified': False}
    (args.output / 'report.json').write_bytes(canonical(report))
    print(json.dumps({'status': report['status'], 'groups': report['groups']}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
