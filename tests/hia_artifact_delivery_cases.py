"""Disposable actual-image D5 controls; no retained native policy fallback."""
from contextlib import ExitStack, contextmanager
from contextvars import Context, copy_context
import ctypes
import gc
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import threading
from unittest.mock import patch
import weakref

from .hia_artifact_delivery_fixture import ROOT, encoded, clean_environment
from hepta import artifact_publication_native as api
from hepta import hia_artifact_delivery as bridge
from hepta import hia_artifact_delivery_protocol as protocol
from hepta import hia_native_delivery as delivery
from hepta.artifact_publication import PublicationRejected

NONCE = bytes(range(16))


def raised(operation):
    try:
        operation()
    except BaseException as error:
        return error
    raise AssertionError('expected operation to refuse')


def save(root, name, value):
    (root / (name + '.json')).write_bytes(encoded(value) + b'\n')


def _terminal(root, manifests):
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    from tests.test_hia_artifact_publication_native import observe
    raw = (ROOT / 'tests/fixtures/hia_artifact_delivery_terminal_cases.json').read_bytes()
    assert sha256(raw).hexdigest() == 'c883ffba7947f88d64acd37967b6f710416de4a3156e8885f25321291485aee3'
    image_bytes = (Path(manifests['artifact']).parent / 'policy.image.bin').read_bytes()
    image = NativeHiaJsonImage(image_bytes, sha256(image_bytes).hexdigest())
    rows = []
    lo, hi = struct.unpack('<2Q', NONCE)
    for case in json.loads(raw)['cases']:
        state = bytearray(4096)
        values = {0: 21, 8: case['operation'], 16: case['input_bytes'], 3000: 1,
            3008: case['facts'], 3016: case['phase'], 3024: case['exit_code'],
            3032: case['stdout_bytes'], 3040: lo, 3048: hi,
            3056: case['failure_phase'], 3064: case['cleanup_phase']}
        for at, value in values.items():
            struct.pack_into('<Q', state, at, value)
        expected = bytes(128) if case['policy_return'] == 16 else struct.pack('<16Q',
            int.from_bytes(b'HIAPDLV1', 'little'), 1, lo, hi, case['operation'], case['outcome'],
            case['exit_code'], case['phase'], case['input_bytes'], case['stdout_bytes'],
            case['facts'], case['failure_phase'], case['cleanup_phase'], 0, 0,
            int.from_bytes(b'HIAPEND1', 'little'))
        vm, vm_bytes = observe(b'', b'', bytes(state), range(128))
        source = ctypes.create_string_buffer(1)
        output = ctypes.create_string_buffer(b'P' * 17 + bytes(128) + b'S' * 23, 168)
        workspace = ctypes.create_string_buffer(b'W' * 19 + bytes(state) + b'T' * 29, 4144)
        result = image._entry(ctypes.addressof(source), 0, ctypes.addressof(output) + 17, 128,
                              ctypes.addressof(workspace) + 19, 4096)
        actual = output.raw[17:145]
        assert output.raw[:17] == b'P' * 17 and output.raw[145:] == b'S' * 23
        assert workspace.raw[:19] == b'W' * 19 and workspace.raw[-29:] == b'T' * 29
        assert workspace.raw[19:-29] == bytes(state)
        assert result == vm == case['policy_return'] and actual == vm_bytes == expected
        rows.append({'name': case['name'], 'native_return': result, 'VM_return': vm,
                     'expected_return': case['policy_return'], 'native_hex': actual.hex(),
                     'VM_hex': vm_bytes.hex(), 'expected_hex': expected.hex(), 'canaries_unchanged': True})
    assert len(rows) == 44
    return {'cases': rows, 'input_sha256': sha256(raw).hexdigest(),
            'policy_image_sha256': sha256(image_bytes).hexdigest(), 'VM_steps_limit': 2000000}


def _cli(root, manifests):
    built = Path(manifests['artifact']).parent
    rows = []
    operations = {'publish': 1, 'verify': 2, 'withdraw': 3, 'store-put': 4, 'store-get': 5, 'store-hash': 6}
    for payload in (b'\0', bytes(range(256)), NONCE + b'HIADCTL1\0private-looking-public-data'):
        for operation, code in operations.items():
            for private in (False, True):
                folder = root / str(len(rows)); folder.mkdir(mode=0o700)
                stage, destination, store = folder / 'stage', folder / 'destination', folder / 'store'
                store.mkdir(mode=0o700); stage.write_bytes(payload)
                digest = sha256(payload).hexdigest()
                if operation in ('verify', 'withdraw'):
                    os.link(stage, destination)
                if operation == 'store-get':
                    (store / digest).write_bytes(payload)
                data = b'' if operation in ('withdraw', 'store-get') else payload
                argv = [str(built / ('hia-artifact-private' if private else 'hia-artifact')), operation,
                    str(store if operation.startswith('store-') else stage),
                    digest if operation == 'store-get' else '-' if operation.startswith('store-') else str(destination)]
                wire = NONCE + data if private else data
                process = subprocess.run(argv, input=wire, capture_output=True, env={'PATH': ''}, timeout=30)
                row = {'operation': operation, 'private': private, 'argv': argv, 'env': {'PATH': ''},
                    'stdin_hex': wire.hex(), 'stdout_hex': process.stdout.hex(),
                    'stderr_hex': process.stderr.hex(), 'exit': process.returncode}
                rows.append(row); save(root, 'partial', rows)
                assert process.returncode == 0, row
                if private:
                    receipt = protocol.acknowledgement(process.stderr, NONCE, 0, process.stdout)
                    assert receipt.operation == code and receipt.outcome == protocol.RETURNED
                    row['ack'] = vars(receipt)
                else:
                    assert process.stderr == b''
                if operation == 'withdraw':
                    assert json.loads(process.stdout) == {'withdrawn': True} and not destination.exists()
                elif operation == 'store-get':
                    assert process.stdout == payload
                else:
                    assert json.loads(process.stdout) == {'sha256': digest, 'bytes': len(payload)}
    # The old four-argument public CLI never recognizes an operation control
    # marker. Its arbitrary input bytes above also remain ordinary payload.
    for operation in ('_delivery', 'HIADCTL1', 'store-control'):
        process = subprocess.run([str(built / 'hia-artifact'), operation, 'stage', 'destination'],
            input=NONCE, capture_output=True, env={'PATH': ''}, timeout=30)
        assert process.returncode == 16 and process.stdout == process.stderr == b''
        rows.append({'unknown_public_operation': operation, 'exit': process.returncode,
                     'stdin_hex': NONCE.hex(), 'stdout_hex': '', 'stderr_hex': ''})
    for extent in (0, 1, 8, 15):
        process = subprocess.run([str(built / 'hia-artifact-private'), 'store-hash', '-', '-'],
            input=NONCE[:extent], capture_output=True, env={'PATH': ''}, timeout=30)
        assert process.returncode == 16 and process.stdout == b''
        assert len(process.stderr) == 128
        actual_nonce = process.stderr[16:32]
        receipt = protocol.acknowledgement(process.stderr, actual_nonce, 16, b'')
        assert receipt.outcome == protocol.UNCONFIRMED and receipt.facts & protocol.PREFIX_COMPLETE == 0
        rows.append({'short_private_prefix': extent, 'exit': 16, 'stderr_hex': process.stderr.hex(),
                     'ack': vars(receipt), 'original_nonce_complete': False})
    from .hia_artifact_delivery_operation_oracle import actual_observations
    operation_observations = actual_observations(root, manifests['artifact'])
    return {'cases': rows, 'operation_objects': operation_observations,
            'actual_six_operations_public_and_private': True,
            'public_control_marker_added': False}


def _negative(root, manifests):
    trace = shutil.which('strace')
    assert trace is not None, 'original actual syscall refusal observations require strace'
    actual_run = subprocess.run
    rows = []
    class Resource:
        pass
    for position in (1, 2):
        folder = root / str(position); folder.mkdir(mode=0o700)
        store = folder / 'store'; store.mkdir(mode=0o700)
        payload = b'actual HIA fsync refusal ' + bytes([position])
        resource = Resource(); delivery.bind_resource_lifetime(resource)
        captured = []
        def injected(argv, **kwargs):
            assert argv[1] == 'store-put'
            command = [trace, '-o', str(folder / 'strace.log'), '-e',
                       'inject=fsync:error=EIO:when=' + str(position), *argv]
            result = actual_run(command, **kwargs)
            captured.append({'argv': command, 'input_hex': kwargs['input'].hex(),
                'stdout_hex': result.stdout.hex(), 'stderr_hex': result.stderr.hex(), 'exit': result.returncode})
            return result
        with delivery.resource_scope(resource), patch.object(api.subprocess, 'run', side_effect=injected):
            error = raised(lambda: api.invoke_artifact_store(manifests['artifact'], 'store-put', store, data=payload))
        assert type(error) is PublicationRejected and 'E_PUBLISH_IO' in str(error)
        delivery.check_resource_retirement(resource)
        assert len(captured) == 1
        native = captured[0]
        receipt = protocol.acknowledgement(bytes.fromhex(native['stderr_hex']),
            bytes.fromhex(native['input_hex'])[:16], native['exit'], bytes.fromhex(native['stdout_hex']))
        assert receipt.outcome == protocol.REFUSED and receipt.exit_code == 15
        contents = sorted(path.name for path in store.iterdir())
        digest = sha256(payload).hexdigest()
        assert contents == ([] if position == 1 else [digest])
        if position == 2:
            assert (store / digest).read_bytes() == payload
            assert receipt.facts & protocol.DIRECTORY_SYNC_REFUSED
        assert receipt.facts & protocol.TEMP_CLEANED
        rows.append({'fsync_position': position, 'native': native, 'ack': vars(receipt),
            'error_type': type(error).__name__, 'error_message': str(error),
            'residual_files': contents, 'resource_retirement_allowed': True})
    return {'cases': rows, 'real_file_and_directory_fsync_refusals': True,
            'allowed_immutable_content_residue_preserved': True}


def _loss(root, manifests):
    from hepta.hia_agent_store import AgentStore
    from hepta.hia_store_artifact_profile_native import SELECTOR as STORE
    modes = ('missing', 'truncated', 'extra', 'nonce', 'checksum', 'wrong-output',
             'OSError', 'ValueError', 'RuntimeError', 'MemoryError', 'KeyboardInterrupt', 'SystemExit')
    rows = []; actual_run = subprocess.run
    errors = {name: kind for name, kind in ((kind.__name__, kind) for kind in
        (OSError, ValueError, RuntimeError, MemoryError, KeyboardInterrupt, SystemExit))}
    for mode in modes:
        folder = root / mode; folder.mkdir()
        environment = dict(clean_environment(), **{STORE: manifests['store_artifact_profile'],
            'HEPTA_HIA_AGENT_ARTIFACT_STORE_MANIFEST': manifests['artifact']})
        fault = errors[mode]('actual artifact result lost') if mode in errors else None
        captured = []
        def lose(argv, **kwargs):
            result = actual_run(argv, **kwargs)
            captured.append({'operation': argv[1], 'exit': result.returncode,
                'input_hex': kwargs['input'].hex(), 'stdout_hex': result.stdout.hex(),
                'stderr_hex': result.stderr.hex()})
            if argv[1] != 'store-put':
                return result
            assert result.returncode == 0
            if fault is not None:
                raise fault
            stderr, stdout = result.stderr, result.stdout
            if mode == 'missing': stderr = b''
            elif mode == 'truncated': stderr = stderr[:-1]
            elif mode == 'extra': stderr += b'!'
            elif mode == 'nonce': stderr = stderr[:16] + bytes([stderr[16] ^ 1]) + stderr[17:]
            elif mode == 'checksum': stderr = stderr[:104] + bytes([stderr[104] ^ 1]) + stderr[105:]
            elif mode == 'wrong-output': stdout = b'?' * len(stdout)
            return subprocess.CompletedProcess(result.args, result.returncode, stdout, stderr)
        with patch.dict(os.environ, environment, clear=True):
            store = AgentStore(folder / 'state')
            count = store.db.execute('SELECT count(*) FROM artifacts').fetchone()[0]
            payload = ('actual retained artifact ' + mode).encode()
            with patch.object(api.subprocess, 'run', side_effect=lose):
                error = raised(lambda: store.put(payload, 'input'))
            if mode in ('RuntimeError', 'MemoryError', 'KeyboardInterrupt', 'SystemExit'):
                assert error is fault
            else:
                assert isinstance(error, RuntimeError), (mode, error)
            assert [item['operation'] for item in captured] == ['store-hash', 'store-put']
            assert (store.root / 'artifacts' / sha256(payload).hexdigest()).read_bytes() == payload
            assert store.db.execute('SELECT count(*) FROM artifacts').fetchone()[0] == count
            close_error = raised(store.close)
            assert isinstance(close_error, RuntimeError)
            assert store.db.execute('SELECT 1').fetchone()[0] == 1
            before = len(captured)
            with patch.object(api.subprocess, 'run', side_effect=lose):
                retry = raised(lambda: store.put(payload, 'input'))
            assert isinstance(retry, RuntimeError) and len(captured) == before
            reinit = folder / 'must-not-initialize'
            assert isinstance(raised(lambda: AgentStore.__init__(store, reinit)), RuntimeError)
            assert not reinit.exists()
            reference = weakref.ref(store)
            rows.append({'mode': mode, 'native': captured, 'error_type': type(error).__name__,
                'injected_identity_preserved': fault is not None and error is fault,
                'close_error_type': type(close_error).__name__, 'database_still_open': True,
                'artifact_row_count_unchanged': True, 'retry_native_calls': len(captured) - before,
                'same_object_reinitialization_refused': True})
            del store; gc.collect()
            assert reference() is not None
            rows[-1]['exact_Store_retained'] = True
            healthy = AgentStore(folder / 'healthy'); healthy.close()
            rows[-1]['unrelated_healthy_Store_closed'] = True
    return {'cases': rows, 'retained_custody_not_cleared': True,
            'source_Store_and_actual_provider_composition': True}


def _boundaries(root, manifests):
    from hepta.hia_agent_store import AgentStore
    rows = []; actual_run = subprocess.run
    class NamedUnknown(RuntimeError):
        pass
    NamedUnknown.__name__ = 'ArtifactDeliveryUnknown'
    for family in (OSError, ValueError, RuntimeError, MemoryError, KeyboardInterrupt, SystemExit, NamedUnknown):
        for position in ('before-handoff', 'after-confirmed-terminal'):
            folder = root / (family.__name__ + '-' + position); folder.mkdir()
            store = AgentStore(folder / 'state'); fault = family('ordinary foreign boundary')
            calls = []
            def counted(argv, **kwargs):
                result = actual_run(argv, **kwargs)
                calls.append({'operation': argv[1], 'exit': result.returncode, 'stderr_hex': result.stderr.hex()})
                return result
            class ForeignPath:
                def __fspath__(self):
                    raise fault
            confirmed = bridge.ArtifactInvocation.confirmed
            def after(invocation):
                confirmed(invocation)
                assert invocation.record.terminal and not invocation.record.native_pending
                raise fault
            with ExitStack() as stack:
                stack.enter_context(delivery.resource_scope(store))
                stack.enter_context(patch.object(api.subprocess, 'run', side_effect=counted))
                if position == 'after-confirmed-terminal':
                    stack.enter_context(patch.object(bridge.ArtifactInvocation, 'confirmed', after))
                error = raised(lambda: api.invoke_artifact_store(manifests['artifact'], 'store-hash',
                    ForeignPath() if position == 'before-handoff' else folder, data=b'foreign boundary'))
            assert error is fault
            assert len(calls) == (0 if position == 'before-handoff' else 1)
            delivery.check_resource_retirement(store); store.close()
            rows.append({'family': family.__name__, 'position': position, 'error_identity_preserved': True,
                         'native': calls, 'resource_closed': True})
    store = AgentStore(root / 'safe-custody'); fault = OSError('real memfd pre-entry refusal')
    with delivery.resource_scope(store), patch.object(api.os, 'memfd_create', side_effect=fault), \
            patch.object(api.subprocess, 'run', side_effect=AssertionError('unexpected child')):
        error = raised(lambda: api.invoke_artifact_store(manifests['artifact'], 'store-hash', root, data=b'x'))
    assert type(error) is PublicationRejected and error.__cause__ is fault
    delivery.check_resource_retirement(store); store.close()
    rows.append({'position': 'memfd-before-entry', 'error': str(error),
                 'original_cause_identity': True, 'native_calls': 0, 'resource_closed': True})
    return {'cases': rows, 'exception_name_never_evidence_of_loss': True,
            'post_terminal_foreign_not_reclassified': True}


def _lifetimes(root, manifests):
    class Resource:
        def __eq__(self, other):
            raise AssertionError('resource equality is not identity')
        def __hash__(self):
            raise AssertionError('resource hash was consulted')
    healthy = Resource(); delivery.bind_resource_lifetime(healthy)
    healthy_ref = weakref.ref(healthy); del healthy; gc.collect()
    assert healthy_ref() is None
    resource = Resource(); delivery.bind_resource_lifetime(resource)
    ancestor = delivery.DeliveryRecord(object()); ancestor.associate(resource)
    captured, errors = [], []
    actual_enter, actual_run = bridge.ArtifactInvocation.__enter__, subprocess.run
    def entered(invocation):
        result = actual_enter(invocation); captured.append(invocation.record); return result
    def lost(argv, **kwargs):
        result = actual_run(argv, **kwargs)
        assert result.returncode == 0 and len(result.stderr) == 128
        return subprocess.CompletedProcess(result.args, result.returncode, result.stdout, b'')
    def child():
        with delivery.resource_scope(resource):
            errors.append(raised(lambda: api.invoke_artifact_store(
                manifests['artifact'], 'store-hash', root, data=b'cross-thread explicit resource')))
    with ancestor.foreign(observation=False), patch.object(bridge.ArtifactInvocation, '__enter__', entered), \
            patch.object(api.subprocess, 'run', side_effect=lost):
        thread = threading.Thread(target=child); thread.start(); thread.join(20)
        assert not thread.is_alive() and len(errors) == len(captured) == 1
        assert ancestor.loss is None
        error = raised(ancestor.check)
        assert isinstance(error, delivery.NativeDeliveryUnknown)
        assert ancestor.loss is captured[0].loss
    assert isinstance(raised(lambda: delivery.check_resource_retirement(resource)), RuntimeError)
    unrelated = Resource(); delivery.check_resource_retirement(unrelated)
    scope = delivery.resource_scope(unrelated); first, second = Context(), Context()
    first.run(scope.__enter__); second.run(scope.deactivate)
    assert not scope.active and scope.resources == []
    def after_resume():
        record = delivery.DeliveryRecord(object())
        assert record.resources == []
        record.retire()
    first.run(after_resume)
    observation_resource = Resource(); delivery.bind_resource_lifetime(observation_resource)
    observation = delivery.reserve_resource_observation(object(), observation_resource)
    fault = MemoryError('resume record allocation failed after body observation')
    second.run(observation.observed); assert observation.failed(fault)
    retirement = raised(lambda: delivery.check_resource_retirement(observation_resource))
    assert retirement.__cause__ is fault
    observation.retire(); assert not observation.retired
    ordinary_resource = Resource()
    normal = delivery.reserve_resource_observation(object(), ordinary_resource)
    normal.observed(); normal.confirmed()
    assert normal.retired and normal.owner is normal.resource is None
    delivery.check_resource_retirement(ordinary_resource)
    return {'healthy_weak_owner_released': True, 'cross_thread_native_calls': 1,
        'cross_thread_no_invented_parent': True, 'explicit_resource_loss_observed_on_existing_record': True,
        'cross_context_deactivate_no_token_reset': True, 'stale_scope_inherits_no_resource': True,
        'pre_reserved_resume_observation_error_identity': True,
        'failed_observation_custody_retained': True, 'normal_observation_retired': True,
        'identity_only_resource_protocol': True}


def _reentrant(root, manifests):
    admitted = api._admitted_code(manifests['artifact'])
    public = protocol.public_executable(admitted)
    actual_run = subprocess.run; calls = []; lookups = []
    def inspected(argv, **kwargs):
        fd, = kwargs['pass_fds']
        sealed = os.pread(fd, len(admitted) + 1, 0)
        expected = public if len(calls) == 0 else admitted
        assert sealed == expected
        result = actual_run(argv, **kwargs)
        calls.append({'operation': argv[1], 'sealed_sha256': sha256(sealed).hexdigest(),
            'fixed_admitted_sha256': sha256(admitted).hexdigest(), 'input_hex': kwargs['input'].hex(),
            'stdout_hex': result.stdout.hex(), 'stderr_hex': result.stderr.hex(), 'exit': result.returncode})
        return result
    class Root:
        def __fspath__(self):
            lookups.append('root.__fspath__')
            assert bridge._CURRENT.get() is None
            result = api._execute_native(manifests['artifact'], 'withdraw', root / 'missing',
                                         root / 'nested-destination', b'')
            assert json.loads(result) == {'withdrawn': False}
            assert bridge._CURRENT.get() is None
            return str(root)
    with patch.object(api.subprocess, 'run', side_effect=inspected):
        receipt = api.invoke_artifact_store(manifests['artifact'], 'store-hash', Root(), data=b'outer')
    assert receipt == {'sha256': sha256(b'outer').hexdigest(), 'bytes': 5}
    assert lookups == ['root.__fspath__'] and len(calls) == 2
    assert len(bytes.fromhex(calls[0]['stderr_hex'])) == 0
    assert len(bytes.fromhex(calls[1]['stderr_hex'])) == 128
    assert bridge._CURRENT.get() is None
    def missing():
        with bridge.ArtifactInvocation('store-hash') as invocation:
            return api._execute_native(manifests['artifact'], 'store-hash', root, '-', b'x',
                                       _delivery_required=invocation)
    with patch.object(api.subprocess, 'run', side_effect=AssertionError('unarmed canonical child')):
        error = raised(missing)
    assert type(error) is bridge.ArtifactDeliveryUnknown
    assert bridge._CURRENT.get() is None
    return {'native': calls, 'root_lookups': lookups, 'outer_receipt': receipt,
            'direct_helper_did_not_consume_outer_token': True,
            'canonical_unarmed_refused_before_child': True, 'selector_token_restored': True}


def run_child(kind, directory, manifests_json):
    root, manifests = Path(directory), json.loads(manifests_json)
    owners = {'terminal': _terminal, 'cli': _cli, 'negative': _negative,
              'loss': _loss, 'boundaries': _boundaries, 'lifetimes': _lifetimes,
              'reentrant': _reentrant}
    if kind == 'installed':
        from .hia_artifact_delivery_installed import run
        observations = run(root, manifests)
    else:
        with ExitStack() as stack:
            if kind == 'loss':
                from hepta import hia_agent_store as store
                def forbidden(*args, **kwargs):
                    raise AssertionError('selected Store/provider loss route used retained Store body')
                for name in ('_put_reference', '_json_reference', '_ref_reference', '_get_reference',
                             '_get_json_reference', '_resolve_uri_reference', '_profile_reference',
                             '_check_profile_reference'):
                    stack.enter_context(patch.object(store.AgentStore, name, forbidden))
                stack.enter_context(patch.dict(store._STORE_ARTIFACT_PROFILE_REFERENCES,
                    {name: forbidden for name in store._STORE_ARTIFACT_PROFILE_REFERENCES}))
            observations = owners[kind](root, manifests)
    save(root, 'observations', {'schema': 'hepta.hia.artifact-delivery-child.v1',
        'status': 'PASS', 'kind': kind, 'observations': observations,
        'unknown_custody_not_cleared': True, 'whole_native_stack_qualified': False})
    print('D5 child ' + kind + ' PASS', flush=True)
    # The disposable process owns intentionally unconfirmed resources. Their
    # custody is never cleared to make teardown look successful.
    os._exit(0)
