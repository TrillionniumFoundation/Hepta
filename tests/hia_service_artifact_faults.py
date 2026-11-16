"""Disposable actual-image controls; never clear custody or call old handler.

Static draft, not a receipt. Unknown records live until this process exits.
Actual loss comes from exercised entry/receipt boundaries, not field writes.
"""
from collections import Counter
from contextlib import ExitStack, suppress
import contextvars
import ctypes
import gc
from hashlib import sha256
import json
import os
from pathlib import Path
import select
import signal
import struct
import sys
import threading
from unittest.mock import patch
import weakref

CASE_IDS = (
    'parent-ACK-lost-after-confirmed-child', 'nested-parent-ACK-lost',
    'only-actual-other-Store-is-retained', 'unknown-resource-survives-fork',
    'child-loss-swallowed', 'child-loss-replaced', 'child-loss-with-suppression',
    'associate-only-does-not-arm', 'safe-child-preentry-does-not-arm',
    'healthy-ACK-releases-before-result', 'confirmed-ACK-retirement-MemoryError',
    'scope-return-identity-failure-confirmed', 'scope-return-identity-failure-lost',
    'actual-reentrant-child-loss-blocks-prepared-entry',
    'actual-reentrant-child-loss-blocks-resource-scope-body',
    'actual-reentrant-child-loss-blocks-foreign-body',
    'ordinary-provider-error-confirmed-after-child',
    'parent-preentry-MemoryError', 'parent-preentry-RuntimeError',
    'parent-preentry-KeyboardInterrupt', 'parent-preentry-SystemExit',
    'stale-Context-is-not-parent', 'copied-thread-is-not-parent', 'fork-is-not-parent',
)


def run(repository, parent_manifest, store_manifest, mode, directory):
    if mode not in CASE_IDS:
        raise ValueError('unfrozen resource control: ' + mode)
    sys.path.insert(0, str(repository))
    from hepta import hia_agent_service as service_api
    from hepta import hia_agent_store as store_api
    from hepta import hia_service_artifact_native as parent
    from hepta import hia_store_artifact_profile_native as child
    from hepta import hia_native_delivery as delivery

    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    for key in list(os.environ):
        if key.startswith('HEPTA_HIA_'):
            del os.environ[key]
    os.environ[parent.SELECTOR] = str(parent_manifest)
    scope_modes = ('scope-return-identity-failure-confirmed', 'scope-return-identity-failure-lost')
    original_store_provider = mode in (*scope_modes, 'actual-reentrant-child-loss-blocks-resource-scope-body')
    if not original_store_provider:
        os.environ[child.SELECTOR] = str(store_manifest)
    manifests = {str(path): path.read_bytes() for path in (parent_manifest, store_manifest)}
    images = {str(path): (path.parent / json.loads(raw)['image_path']).read_bytes()
              for path, raw in ((parent_manifest, manifests[str(parent_manifest)]),
                                (store_manifest, manifests[str(store_manifest)]))}
    image = parent.installed_service_artifact(str(parent_manifest))
    store_image = child.installed_store_artifact_profile(str(store_manifest))
    events, observations, controlled_errors = [], {}, {}
    counts = {'parent': Counter(), 'store': Counter()}
    initial_nonces = []
    original_parent_entry, original_store_entry = image._entry, store_image._entry
    controls = {'lose_parent_ack': False, 'lose_parent_raised': False,
                'lose_child_init': False, 'child_loss_consumed': False}

    def forbidden(*arguments, **keywords):
        raise AssertionError('selected owner invoked a retained original')

    service_api._NATIVE_SERVICE_ARTIFACT_REFERENCE = forbidden
    if not original_store_provider:
        for name in store_api._STORE_ARTIFACT_PROFILE_REFERENCES:
            store_api._STORE_ARTIFACT_PROFILE_REFERENCES[name] = forbidden
            setattr(store_api.AgentStore, '_' + name.lstrip('_') + '_reference', forbidden)

    def parent_entry(source, size, output, capacity, state, extent):
        packet = struct.unpack('<10Q', ctypes.string_at(source, size))
        result = original_parent_entry(source, size, output, capacity, state, extent)
        assert packet[0] == parent.REQUEST_MAGIC and result == parent.OUTPUT_BYTES
        counts['parent'][str(packet[1])] += 1
        nonce = tuple(packet[6:8])
        if packet[1] == 0:
            initial_nonces.append(nonce)
        if (controls['lose_parent_ack'] and packet[1] == parent.SUCCEEDED
                and packet[3] == parent.PORT['put'] and nonce == initial_nonces[0]):
            events.append('actual-parent-put-ACK-returned-then-lost')
            raise ValueError('actual parent put ACK is unavailable')
        if (controls['lose_parent_raised'] and packet[1] == parent.RAISED
                and packet[3] == parent.PORT['put'] and nonce == initial_nonces[0]):
            events.append('actual-parent-raised-ACK-returned-then-lost')
            raise ValueError('actual parent raised ACK is unavailable')
        return result

    def store_entry(source, size, output, capacity, state, extent):
        packet = struct.unpack('<10Q', ctypes.string_at(source, size))
        result = original_store_entry(source, size, output, capacity, state, extent)
        assert packet[0] == child.REQUEST_MAGIC and result == child.OUTPUT_BYTES
        counts['store'][str(packet[1])] += 1
        if controls['lose_child_init'] and packet[1] == 0 and not controls['child_loss_consumed']:
            controls['child_loss_consumed'] = True
            events.append('actual-Store-INIT-returned-then-lost')
            raise ValueError('actual Store child acknowledgement is unavailable')
        return result

    image._entry, store_image._entry = parent_entry, store_entry
    arguments = {'artifact_profile': 'opaque-profile',
                 'source': {'kind': 'utf8', 'text': 'actual artifact resource — 雪'}}

    class Service:
        def __init__(self, store, profile=None):
            self.store, self.profile = store, profile
        def _profile(self, reference, kind):
            events.append('profile')
            if self.profile is not None:
                self.profile()

    class Proxy:
        def __init__(self, operation):
            self.operation = operation
        def put(self, data, kind):
            events.append('proxy.put')
            return self.operation(data, kind)

    def invoke(service):
        return service_api.HIAAgentService._hia_artifact(service, arguments)

    def capture(operation):
        try:
            value = operation()
        except BaseException as error:
            return {'status': 'raised', 'class': type(error).__name__, 'message': str(error),
                    'controlled_identity': [name for name, item in controlled_errors.items() if error is item]}
        return {'status': 'returned', 'value': value}

    def new_store(name):
        return store_api.AgentStore(directory / name)

    def blocked(resource):
        try:
            delivery.check_resource_retirement(resource)
        except delivery.NativeDeliveryUnknown:
            return True
        return False

    def assert_close_blocked(resource):
        calls = []
        with patch.object(store_api, '_NATIVE_STORE_CLOSE_REFERENCE',
                          side_effect=lambda value: calls.append(value)):
            try:
                resource.close()
            except delivery.NativeDeliveryUnknown:
                pass
            else:
                raise AssertionError('actual unknown Store accepted close')
        assert not calls
        return {'guard_rejected': True, 'original_close_calls': len(calls)}

    def rows(store):
        return store.db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0]

    def fork_observe(operation):
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            try:
                raw = json.dumps(operation(), sort_keys=True).encode()
                os.write(write_fd, raw)
                os._exit(0)
            except BaseException:
                os._exit(74)
        os.close(write_fd)
        waited = False
        try:
            ready, _, _ = select.select([read_fd], [], [], 10)
            if not ready:
                raise AssertionError('fork observation exceeded 10 seconds')
            value = json.loads(os.read(read_fd, 65536))
            _, status = os.waitpid(pid, 0);waited = True
            assert os.waitstatus_to_exitcode(status) == 0
            return value
        finally:
            os.close(read_fd)
            if not waited:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(pid, 0)

    if mode in ('parent-ACK-lost-after-confirmed-child', 'nested-parent-ACK-lost',
                'only-actual-other-Store-is-retained', 'unknown-resource-survives-fork'):
        actual = new_store('actual')
        unrelated = new_store('unrelated')
        controls['lose_parent_ack'] = True
        if mode == 'nested-parent-ACK-lost':
            inner = Service(actual)
            outer = Service(Proxy(lambda data, kind: invoke(inner)['artifact']))
        elif mode == 'only-actual-other-Store-is-retained':
            outer = Service(Proxy(lambda data, kind: actual.put(data, kind)),
                            profile=lambda: unrelated.put(b'prior confirmed profile callback', 'input'))
        else:
            outer = Service(actual)
        result = capture(lambda: invoke(outer))
        assert result['status'] == 'raised' and result['class'] == 'ServiceArtifactUnknown', result
        assert controls['child_loss_consumed'] is False and counts['store']['0'] > 0
        assert rows(actual) == 1 and blocked(actual) and not blocked(unrelated)
        assert not child._FRAME_CUSTODY, 'confirmed Store child retained an unknown frame'
        retained = [value for value in delivery._RESOURCE_OBSERVATIONS.values()
                    if value.resource is actual]
        assert retained and all(value.pending and value.loss is not None for value in retained)
        assert all(value.resource is not unrelated for value in delivery._RESOURCE_OBSERVATIONS.values())
        observations.update(result=result, actual_artifact_rows=rows(actual),
            actual_close=assert_close_blocked(actual), unrelated_retirement_allowed=True,
            retained_actual_observations=len(retained),
            confirmed_child_frames_remaining=len(child._FRAME_CUSTODY))
        if mode == 'unknown-resource-survives-fork':
            def inherited():
                rejected = blocked(actual)
                fresh = delivery.DeliveryRecord(object())
                independent = fresh.current() and fresh.parent is None and fresh.loss is None
                fresh.retire()
                return {'exact_inherited_resource_still_rejected': rejected,
                        'fresh_record_has_no_inherited_native_ancestry': independent}
            observations['fork'] = fork_observe(inherited)
            assert all(observations['fork'].values())
        unrelated.close()

    elif mode in ('child-loss-swallowed', 'child-loss-replaced', 'child-loss-with-suppression'):
        actual = new_store('actual')
        controls['lose_child_init'] = True
        def put(data, kind):
            if mode == 'child-loss-with-suppression':
                with suppress(Exception):
                    actual.put(data, kind)
                return 'provider-suppressed-loss'
            try:
                actual.put(data, kind)
            except child.StoreArtifactProfileUnknown:
                if mode == 'child-loss-replaced':
                    raise ValueError('provider replaced child loss')
                return 'provider-swallowed-loss'
        result = capture(lambda: invoke(Service(Proxy(put))))
        assert result['status'] == 'raised' and result['class'] == 'ServiceArtifactUnknown', result
        assert controls['child_loss_consumed'] and counts['store']['0'] == 1
        assert blocked(actual) and rows(actual) == 0
        assert counts['parent']['2'] == 4 and counts['parent']['3'] == 0, counts
        observations.update(result=result, actual_close=assert_close_blocked(actual),
                            actual_artifact_rows=rows(actual))

    elif mode == 'associate-only-does-not-arm':
        actual = new_store('unused')
        controls['lose_parent_ack'] = True
        def put(data, kind):
            record = delivery.DeliveryRecord(object())
            try:
                record.associate(actual)
            finally:
                record.retire()
            return 'no-effect-no-entry'
        result = capture(lambda: invoke(Service(Proxy(put))))
        assert result['class'] == 'ServiceArtifactUnknown' and counts['store']['0'] == 0
        assert not blocked(actual) and not delivery._RESOURCE_OBSERVATIONS and rows(actual) == 0
        actual.close()
        observations.update(result=result, unused_resource_retirement_allowed=True)

    elif mode == 'safe-child-preentry-does-not-arm':
        actual = new_store('safe')
        fault = MemoryError('safe child packet preparation')
        original_struct = child.struct
        class Struct:
            def __getattr__(self, name):
                if name == 'pack':
                    def refuse(*values):
                        raise fault
                    return refuse
                return getattr(original_struct, name)
        caught = []
        def put(data, kind):
            with patch.object(child, 'struct', Struct()):
                try:
                    actual.put(data, kind)
                except child.StoreArtifactProfileUnknown as error:
                    assert error.__cause__ is fault
                    caught.append(True)
            return 'safe-refusal-was-caught'
        result = capture(lambda: invoke(Service(Proxy(put))))
        assert result['status'] == 'returned' and caught == [True]
        assert counts['store']['0'] == 0 and not blocked(actual)
        assert not delivery._RESOURCE_OBSERVATIONS and not delivery.custody_snapshot()
        actual.close()
        observations.update(result=result, original_Store_preentry_classifier_preserved=True,
                            unused_resource_retirement_allowed=True)

    elif mode in ('healthy-ACK-releases-before-result', 'confirmed-ACK-retirement-MemoryError'):
        refs, deleted, delete_errors, retire_calls = [], [], [], []
        collection_windows = []
        class TemporaryStore(store_api.AgentStore):
            def __del__(self):
                events.append('actual-Store.delete')
                deleted.append(True)
                try:
                    self.close()
                except BaseException as error:
                    delete_errors.append(type(error).__name__ + ': ' + str(error))
        class TemporaryService:
            def _profile(self, reference, kind):
                pass
            @property
            def store(self):
                value = TemporaryStore(directory / 'temporary')
                # Preserve the real pre-existing Store -> execution budget ->
                # Store cycle. Its collection is not synchronous refcounting.
                assert value.execution_budgets.store is value
                refs.append(weakref.ref(value))
                events.append('actual-Store.created')
                return value
        def collect_released_resource(stage):
            # The complete parent ACK must already have removed every new
            # custody observation before this test-only collection begins.
            # GC cannot make a registry-rooted resource appear collectible.
            assert not delivery._RESOURCE_OBSERVATIONS
            before = {'resource_alive': refs[0]() is not None,
                      'destructor_calls': list(deleted),
                      'registered_observations': len(delivery._RESOURCE_OBSERVATIONS)}
            collected = gc.collect()
            after = {'resource_alive': refs[0]() is not None,
                     'destructor_calls': list(deleted),
                     'registered_observations': len(delivery._RESOURCE_OBSERVATIONS)}
            collection_windows.append({'stage': stage, 'before': before,
                                       'collected': collected, 'after': after})
            assert deleted == [True] and refs[0]() is None and not delete_errors, delete_errors
        real_len = len
        def length(value):
            events.append('result.len-observation')
            collect_released_resource('after-parent-ACK-before-original-len')
            events.append('result.len')
            return real_len(value)
        original_retire = delivery.ResourceObservation.retire
        fault = MemoryError('confirmed custody retirement interrupted once')
        controlled_errors['healthy-ACK-retirement'] = fault
        def retiring(observation):
            if not observation.pending and not retire_calls:
                retire_calls.append(True)
                raise fault
            return original_retire(observation)
        with ExitStack() as stack:
            stack.enter_context(patch.object(service_api, 'len', length, create=True))
            if mode == 'confirmed-ACK-retirement-MemoryError':
                stack.enter_context(patch.object(delivery.ResourceObservation, 'retire', retiring))
            result = capture(lambda: invoke(TemporaryService()))
        if mode == 'confirmed-ACK-retirement-MemoryError':
            collect_released_resource('after-confirmed-ACK-retirement-refusal')
        assert deleted == [True] and refs[0]() is None and not delete_errors, delete_errors
        assert not delivery._RESOURCE_OBSERVATIONS and not delivery.custody_snapshot()
        if mode == 'healthy-ACK-releases-before-result':
            assert result['status'] == 'returned'
            assert events.index('actual-Store.delete') < events.index('result.len')
        else:
            assert result['class'] == 'MemoryError' and result['controlled_identity'] == ['healthy-ACK-retirement']
            assert retire_calls == [True] and 'result.len' not in events
        observations.update(result=result, healthy_resource_weakref_released=True,
                            registered_observations_after_return=len(delivery._RESOURCE_OBSERVATIONS),
                            mechanical_retirement_resumed=bool(retire_calls),
                            original_budget_back_reference_preserved=True,
                            test_only_collection_windows=collection_windows,
                            synchronous_Store_destruction_claimed=False)

    elif mode in scope_modes:
        actual = new_store('scope')
        original_put = store_api._STORE_ARTIFACT_PROFILE_REFERENCES['put']
        original_getpid = delivery.os.getpid
        armed = [False]
        fault = MemoryError('identity observation after actual resource provider return')
        controlled_errors['scope-identity'] = fault
        def provider(*values):
            result = original_put(*values)
            armed[0] = True
            return result
        def identity():
            if armed[0]:
                armed[0] = False
                raise fault
            return original_getpid()
        controls['lose_parent_raised'] = mode.endswith('-lost')
        with patch.dict(store_api._STORE_ARTIFACT_PROFILE_REFERENCES, {'put': provider}), \
             patch.object(delivery.os, 'getpid', identity):
            result = capture(lambda: invoke(Service(actual)))
        assert not armed[0] and rows(actual) == 1 and counts['store']['0'] == 0
        assert delivery._RESOURCE_ACTIVE.get() is None and delivery._PENDING_RESOURCE_CAPTURE.get() is None
        if controls['lose_parent_raised']:
            assert result['class'] == 'ServiceArtifactUnknown' and blocked(actual)
            observations['actual_close'] = assert_close_blocked(actual)
        else:
            assert result['class'] == 'MemoryError' and result['controlled_identity'] == ['scope-identity']
            assert not blocked(actual) and not delivery._RESOURCE_OBSERVATIONS
            actual.close()
        observations.update(result=result, actual_artifact_rows=1,
                            active_scope_cleared_after_identity_failure=True,
                            Store_provider_mode='original public resource-scoped provider; no Store native selection')

    elif mode in ('actual-reentrant-child-loss-blocks-prepared-entry',
                  'actual-reentrant-child-loss-blocks-resource-scope-body',
                  'actual-reentrant-child-loss-blocks-foreign-body'):
        actual, intervening = new_store('prepared'), new_store('intervening')
        original_reserve = delivery._PendingForeignResources.reserve
        entered, finalizers, caught_expected, callback_errors, body_calls = [], [], [], [], []
        class DuringReservation:
            def __init__(self):
                self.cycle = self
            def __del__(self):
                finalizers.append(True)
                controls['lose_child_init'] = True
                try:
                    with patch.dict(os.environ, {child.SELECTOR: str(store_manifest)}):
                        intervening.put(b'reentrant selected child', 'input')
                except child.StoreArtifactProfileUnknown:
                    caught_expected.append(True)
                    events.append('GC-finalizer-actual-child-loss-caught')
                except BaseException as error:
                    callback_errors.append({'class': type(error).__name__, 'message': str(error)})
        def collect_once():
            entered.append(True)
            temporary = DuringReservation()
            del temporary
            gc.collect()  # Fault control only; never product or original oracle.
            assert finalizers == [True] and caught_expected == [True] and not callback_errors, callback_errors
        def reserve(holder, resource, fact):
            if resource is actual and not entered:
                collect_once()
            return original_reserve(holder, resource, fact)
        original_capture = delivery._PENDING_RESOURCE_CAPTURE
        class Capture:
            def get(self):
                return original_capture.get()
            def set(self, value):
                token = original_capture.set(value)
                if not entered:
                    collect_once()
                return token
            def reset(self, token):
                return original_capture.reset(token)
        def forbidden_body(*values):
            body_calls.append(True)
            raise AssertionError('resource-scope body entered after actual child loss')
        with ExitStack() as stack:
            if mode == 'actual-reentrant-child-loss-blocks-foreign-body':
                stack.enter_context(patch.object(delivery, '_PENDING_RESOURCE_CAPTURE', Capture()))
            else:
                stack.enter_context(patch.object(delivery._PendingForeignResources, 'reserve', reserve))
            if mode == 'actual-reentrant-child-loss-blocks-resource-scope-body':
                stack.enter_context(patch.dict(store_api._STORE_ARTIFACT_PROFILE_REFERENCES, {'put': forbidden_body}))
            result = capture(lambda: invoke(Service(actual)))
        assert entered == [True] and controls['child_loss_consumed']
        assert result['status'] == 'raised'
        assert result['class'] == 'NativeDeliveryUnknown', result
        assert body_calls == []
        assert counts['store'] == Counter({'0': 1}), counts
        assert rows(actual) == rows(intervening) == 0 and blocked(intervening)
        if mode == 'actual-reentrant-child-loss-blocks-foreign-body':
            assert 'profile' not in events
            assert counts['parent'] == Counter({'0': 1, '1': 1})
        if mode != 'actual-reentrant-child-loss-blocks-prepared-entry':
            assert not blocked(actual)
        observations.update(result=result, prepared_native_entry_not_executed=True,
                            actual_GC_finalizer_calls=len(finalizers),
                            actual_GC_expected_child_exceptions=len(caught_expected),
                            GC_callback_errors=callback_errors,
                            guarded_resource_scope_body_calls=body_calls,
                            intervening_actual_native_entries=1,
                            intervening_close=assert_close_blocked(intervening))

    elif mode == 'ordinary-provider-error-confirmed-after-child':
        actual = new_store('ordinary')
        fault = MemoryError('ordinary provider after confirmed child')
        controlled_errors['ordinary-provider'] = fault
        def put(data, kind):
            actual.put(data, kind)
            raise fault
        result = capture(lambda: invoke(Service(Proxy(put))))
        assert result['class'] == 'MemoryError' and result['controlled_identity'] == ['ordinary-provider']
        assert counts['store']['0'] > 0 and rows(actual) == 1
        assert counts['parent']['3'] == 1 and not blocked(actual)
        assert not delivery._RESOURCE_OBSERVATIONS and not delivery.custody_snapshot()
        actual.close()
        observations.update(result=result, confirmed_ordinary_refusal_is_not_native_loss=True)

    elif mode.startswith('parent-preentry-'):
        kinds = {'MemoryError': MemoryError, 'RuntimeError': RuntimeError,
                 'KeyboardInterrupt': KeyboardInterrupt, 'SystemExit': SystemExit}
        kind = mode.removeprefix('parent-preentry-')
        fault = kinds[kind]('safe parent initialization refusal')
        controlled_errors['parent-preentry'] = fault
        original_struct = parent.struct
        class Struct:
            def __getattr__(self, name):
                if name == 'pack':
                    def refuse(*values):
                        raise fault
                    return refuse
                return getattr(original_struct, name)
        with patch.object(parent, 'struct', Struct()):
            result = capture(lambda: invoke(Service(Proxy(forbidden))))
        assert result['class'] == kind and result['controlled_identity'] == ['parent-preentry']
        assert not counts['parent'] and not counts['store'] and not events
        assert not delivery.custody_snapshot() and not delivery._RESOURCE_OBSERVATIONS
        observations.update(result=result, no_native_entry_or_foreign_effect=True)

    elif mode in ('stale-Context-is-not-parent', 'copied-thread-is-not-parent', 'fork-is-not-parent'):
        captured, facts = [], []
        class Resource:
            pass
        def independent():
            before = counts['parent'].copy()
            resource = Resource()
            delivery.bind_resource_lifetime(resource)
            with delivery.resource_scope(resource):
                frame = parent.ServiceArtifactFrame(image, Service(Proxy(lambda data, kind: 'independent')), arguments)
                facts.append({'parent_is_none': frame._delivery.parent is None,
                              'creator_is_current': frame._delivery.current()})
                value = frame.finish()
            assert value['artifact'] == 'independent'
            assert not blocked(resource)
            actual_events = dict(counts['parent'] - before)
            assert actual_events.get('0') == 1 and actual_events.get('1', 0) > 0
            return {'facts': facts, 'remaining_resources': len(delivery._RESOURCE_OBSERVATIONS),
                    'actual_native_entry_events': actual_events}
        def put(data, kind):
            context = contextvars.copy_context()
            if mode == 'stale-Context-is-not-parent':
                captured.append(context)
            elif mode == 'copied-thread-is-not-parent':
                outcomes = []
                thread = threading.Thread(target=lambda: outcomes.append(capture(lambda: context.run(independent))))
                thread.start();thread.join(10)
                assert not thread.is_alive() and len(outcomes) == 1, outcomes
                assert outcomes[0]['status'] == 'returned', outcomes
            else:
                value = fork_observe(independent)
                observations['fork'] = value
                assert value['remaining_resources'] == 0 and all(row['parent_is_none'] for row in value['facts'])
            return 'outer'
        result = capture(lambda: invoke(Service(Proxy(put))))
        assert result['status'] == 'returned', result
        if captured:
            captured[0].run(independent)
        assert all(row['parent_is_none'] and row['creator_is_current'] for row in facts), facts
        assert not delivery._RESOURCE_OBSERVATIONS and not delivery.custody_snapshot()
        observations.update(result=result, independent_actual_native_facts=facts,
                            no_stale_or_transferred_parent=True)
    else:
        raise ValueError('unknown resource control: ' + mode)

    assert delivery._ACTIVE.get() is None and delivery._PENDING_RESOURCE_CAPTURE.get() is None
    assert all(path.read_bytes() == manifests[str(path)] for path in (parent_manifest, store_manifest))
    assert all((path.parent / json.loads(manifests[str(path)])['image_path']).read_bytes() == images[str(path)]
               for path in (parent_manifest, store_manifest))
    report = {'mode': mode, 'status': 'PASS', 'events': events,
        'actual_native_entry_events': {key: dict(value) for key, value in counts.items()},
        'parent_frames_started': len(initial_nonces), 'observations': observations,
        'unknown_custody': delivery.custody_snapshot(),
        'retained_resource_observations': len(delivery._RESOURCE_OBSERVATIONS),
        'parent_original_poisoned': True, 'Store_original_poisoned': not original_store_provider,
        'manifest_sha256': {name: sha256(raw).hexdigest() for name, raw in manifests.items()},
        'images_sha256': {name: sha256(raw).hexdigest() for name, raw in images.items()},
        'unknown_records_retained_until_process_exit': True,
        'native_records_loss_fields_manually_written': False,
        'whole_native_stack_qualified': False}
    (directory / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    run(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], Path(sys.argv[5]))
