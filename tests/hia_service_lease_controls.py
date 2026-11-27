"""Qualification wiring, separate from the four authored control graphs."""
from __future__ import annotations
from collections import Counter
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
PREFIX = 'HEPTA_HIA_SERVICE_LEASE'
COLD, DEV = PREFIX + '_COLD_REPORT', PREFIX + '_DEVELOPMENT_COMPILER'
EVIDENCE, SOURCE_EVIDENCE = PREFIX + '_EVIDENCE', PREFIX + '_SOURCE_EVIDENCE'
from tests.hia_slot_operations_qualification_support import (
    canonical, pin, read_json, write_json, product_snapshot, run_owned, successful_exit, clean_environment)


def invocation(variable, label):
    configured = os.environ.get(variable)
    base = Path(configured) if configured else Path(tempfile.mkdtemp(prefix='hia-service-lease-'))
    base.mkdir(parents=True, exist_ok=True)
    path = base / (label + '-' + str(os.getpid()) + '-' + str(time.time_ns()))
    path.mkdir(mode=0o700)
    return path


def source_paths():
    # Builder INPUTS is a source constant. Qualification executes the builder
    # only in its declared build gate; source-only original children do not.
    import ast
    source = (ROOT / 'tools/build_hia_service_lease.py').read_bytes()
    module = ast.parse(source)
    node = next(n for n in module.body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == 'INPUTS' for t in n.targets))
    return tuple(ast.literal_eval(node.value))


def freeze_source(path):
    files = product_snapshot(ROOT, source_paths())
    write_json(path, {'schema': 'hepta.service-lease.source-freeze.v1', 'files': files})
    return files, pin(path)['sha256']


def _observer_command(backend, output, freeze, digest, manifest=None):
    code = ('import runpy,sys;sys.path.insert(0,sys.argv.pop(1));'
            "runpy.run_module('tests.hia_service_lease_observer',run_name='__main__')")
    command = [sys.executable, '-I', '-B', '-c', code, str(ROOT),
               '--backend', backend, '--output', str(output),
               '--source-freeze', str(freeze), '--source-freeze-sha256', digest]
    if backend != 'original':
        command += ['--expected-frozen', str(output.parent / 'expected-frozen.json')]
    if manifest is not None:
        command += ['--manifest', str(manifest)]
    return command


def finite(root, backend, manifest=None):
    root = Path(root)
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    freeze = root / 'source-freeze.json'
    before, digest = freeze_source(freeze)
    deadline = time.monotonic() + 1800
    reports, captured_expected = {}, {}
    from tools.read_hia_service_lease import (
        _capture_raw, _raw_pin, _require_captured_unchanged, read_finite)
    try:
        for role in ('original-1', 'original-2', backend):
            actual_backend = 'original' if role.startswith('original-') else backend
            child = root / (role + '-observations')
            command = _observer_command(actual_backend, child, freeze, digest,
                                        manifest if actual_backend == 'native' else None)
            reports[role] = run_owned(command, cwd=ROOT, directory=root / (role + '-process'),
                timeout_seconds=180 if actual_backend == 'original' else 1800, deadline=deadline)
            if not successful_exit(reports[role]):
                write_json(root / 'supervision.json', reports)
                raise AssertionError('complete finite child failed: ' + role)
            if role == 'original-2':
                first = _capture_raw(root / 'original-1-observations/observations.json',
                                     captured_expected)
                second = _capture_raw(root / 'original-2-observations/observations.json',
                                      captured_expected)
                if first != second:
                    raise AssertionError('two independent original observations differ')
                seal = {'original_1': _raw_pin(first), 'original_2': _raw_pin(second),
                        'before_candidate': True, 'candidate_results_used': False}
                seal_raw = canonical(seal) + b'\n'
                write_json(root / 'expected-frozen.json', seal)
                _capture_raw(root / 'expected-frozen.json', captured_expected, _raw_pin(seal_raw))
                _require_captured_unchanged(captured_expected)
        _require_captured_unchanged(captured_expected)
    finally:
        write_json(root / 'supervision.json', reports)
        write_json(root / 'source-after.json', product_snapshot(ROOT, before))
    report = read_finite(root, ROOT, backend=backend)
    write_json(root / 'readback.json', report)
    if report['status'] != 'PASS':
        raise AssertionError('complete original/native observations differ; all raw rows retained')
    if product_snapshot(ROOT, before) != before:
        raise AssertionError('source changed through complete finite gate')
    return report


def build_images(root, *, companions=False):
    cold, dev = os.environ.get(COLD), os.environ.get(DEV)
    if bool(cold) == bool(dev):
        raise ValueError('choose matching cold report or explicit development compiler')
    if cold:
        from tools.hia_cold_compiler import compiler_from_cold_report
        compiler = compiler_from_cold_report(cold)
    else:
        compiler = Path(dev)
    from tools.build_hia_service_lease import build
    manifests = {'lease': build(Path(root) / 'lease-image', compiler, cold,
                               development=not bool(cold))}
    if companions:
        from tools.build_hia_store_artifact_profile import build as store_build
        from tools.build_hia_store_transaction import build as transaction_build
        manifests['store'] = store_build(Path(root) / 'store-image', compiler, cold,
                                        development=not bool(cold))
        manifests['transaction'] = transaction_build(Path(root) / 'transaction-image',
                                                     compiler, cold, development=not bool(cold))
        from tools.build_hia_slot_operations import build as operations_build
        manifests['operations'] = operations_build(Path(root) / 'operations-image',
            compiler, cold, development=not bool(cold))
        if cold:
            from tools.build_hia_slot_ledger import build as ledger_build
            manifests['ledger'] = ledger_build(Path(root) / 'ledger-image', compiler, Path(cold))
        else:
            from tools.qualify_hia_selfhost import compile_stage
            from tools.build_hia_source_build import _check_pack_output
            directory = Path(root) / 'ledger-image'
            directory.mkdir(mode=0o700)
            source_path = ROOT / 'examples/hia_bootstrap/slot_ledger.hepta'
            source, compiler_bytes = source_path.read_bytes(), compiler.read_bytes()
            image, receipt = compile_stage(directory, 'slot-ledger', compiler, source)
            full, raw = (directory / 'slot-ledger.output.bin').read_bytes(), image.read_bytes()
            if (_check_pack_output(receipt, full, artifact=compiler_bytes, source=source) != raw
                    or source_path.read_bytes() != source or compiler.read_bytes() != compiler_bytes):
                raise ValueError('original decision image construction custody differs')
            manifest = {'schema': 'hepta.hia.slot-ledger-native.v1',
                'source_sha256': sha256(source).hexdigest(), 'image_path': image.name,
                'image_sha256': sha256(raw).hexdigest(),
                'compiler_sha256': sha256(compiler_bytes).hexdigest()}
            manifests['ledger'] = directory / 'manifest.json'
            write_json(manifests['ledger'], manifest)
            write_json(directory / 'build.json', {'scope': 'EXPLICIT_DEVELOPMENT_COMPONENT',
                'native_compile_receipt': receipt, 'manifest': manifest,
                'cold_report_sha256': None})
    return manifests


def selected_environment(manifests):
    result = clean_environment()
    result['HEPTA_HIA_SERVICE_LEASE_MANIFEST'] = str(manifests['lease'])
    if 'store' in manifests:
        result['HEPTA_HIA_STORE_ARTIFACT_PROFILE_MANIFEST'] = str(manifests['store'])
    if 'transaction' in manifests:
        result['HEPTA_HIA_STORE_TRANSACTION_MANIFEST'] = str(manifests['transaction'])
    if 'operations' in manifests:
        result['HEPTA_HIA_SLOT_OPERATIONS_MANIFEST'] = str(manifests['operations'])
    if 'ledger' in manifests:
        result['HEPTA_HIA_SLOT_LEDGER_MANIFEST'] = str(manifests['ledger'])
    return result


class PlainCM:
    def __init__(self, events):
        self.events = events
    def __enter__(self):
        self.events.append('enter')
    def __exit__(self, typ, error, traceback):
        self.events.append(('exit', None if typ is None else typ.__name__))
        return False


class PlainStore:
    def __init__(self, events):
        self.events = events
    def transaction(self):
        self.events.append('transaction')
        return PlainCM(self.events)
    def put(self, data, kind, metadata):
        self.events.append(('put', data, kind, metadata))
        return {'id': 'published-buffer'}


class PlainLedger:
    def __init__(self, events):
        self.events = events
    def acquire(self, target, snapshot, native):
        self.events.append(('acquire', target))
        return {'id': 'lease', 'slot': target, 'generation': 3, 'artifact': {'id': 'native'}}
    def lease(self, value):
        self.events.append('lease')
        return dict(value)
    def release(self, value):
        self.events.append('release')
        return {'released': True, 'generation': value['generation'], 'artifact_retained': True}


class PlainService:
    def __init__(self):
        self.events = []
        self.store = PlainStore(self.events)
        self._slot_ledger = PlainLedger(self.events)
    def _slot_snapshot(self, target):
        return {'target': target}
    def _native(self, ref):
        return b'data', {'output_kind': 'shared', 'signatures': {'f': {'abi': False}}, 'context': {}}, None
    def _lease(self, lease):
        return dict(lease)
    def _context(self, ref):
        return {'budget': {'max_native_wall_ms': 25, 'max_memory_bytes': '1024'}}
    def _reference_slot_acquire(self, target):
        return self._slot_ledger.acquire(target, self._slot_snapshot, self._native)
    def _reference_slot_lease(self, value):
        return dict(value)
    def _reference_slot_release(self, value):
        return {'released': True, 'generation': value['generation'], 'artifact_retained': True}


LEASE_VALUE = {'id': 'lease', 'slot': 'slot', 'generation': 3, 'artifact': {'id': 'native'}}


def fake_runner(*args, **kwargs):
    return {'status': 'returned', 'report': {'observations': [{'status': 'returned', 'values': [9]}]},
            'captured_buffers': [], 'termination_confirmed': True}


def fake_validator(signature, arguments):
    return None


def raw_frame(image, mode=2, service=None):
    from hepta.hia_service_lease_native import ServiceLeaseFrame
    service = PlainService() if service is None else service
    arguments = ('slot',) if mode == 1 else (dict(LEASE_VALUE), 'f', []) if mode == 3 else (dict(LEASE_VALUE),)
    return ServiceLeaseFrame(image, mode, service, arguments,
                             import_ports=(lambda: fake_runner, lambda: fake_validator))


def public_controls(manifest):
    from hepta import hia_agent_service as api
    from hepta import hia_service_lease_native as native
    from hepta import hia_agent_runner, hia_agent_buffers
    previous = dict(os.environ)
    originals = {key: getattr(api, '_SERVICE_LEASE_' + key + '_REFERENCE')
                 for key in ('ACQUIRE', 'LEASE', 'INVOKE', 'RELEASE')}
    old_runner, old_validator = hia_agent_runner.run_native_batch, hia_agent_buffers.validate_arguments
    def forbidden(*args, **kwargs):
        raise AssertionError('selected lease public binding entered original body')
    image = native.installed_service_lease(str(manifest))
    actual_entry = image._entry
    counts = Counter()
    def counted(*args):
        result = actual_entry(*args)
        request = struct.unpack('<10Q', ctypes.string_at(args[0], args[1]))
        counts[str(request[5])] += 1
        return result
    image._entry = counted
    rows = []
    try:
        os.environ[native.SELECTOR] = str(manifest)
        for key in originals:
            setattr(api, '_SERVICE_LEASE_' + key + '_REFERENCE', forbidden)
        hia_agent_runner.run_native_batch, hia_agent_buffers.validate_arguments = fake_runner, fake_validator
        service = PlainService()
        value = api.HIAAgentService.acquire_slot(service, 'slot')
        rows.append(api.HIAAgentService._lease(service, value))
        rows.append(api.HIAAgentService.invoke_lease(service, value, 'f', []))
        rows.append(api.HIAAgentService.release_slot(service, value))
        if set(counts) != {'1', '2', '3', '4'} or rows[1]['values'] != [9]:
            raise AssertionError('four actual public modes were not executed')
        class Override(PlainService):
            def _lease(self, value):
                return {'override': True}
        obj = Override()
        before = sum(counts.values())
        if obj._lease(value) != {'override': True} or sum(counts.values()) != before:
            raise AssertionError('subclass provider override was bypassed')
        api.HIAAgentService._lease(obj, value)
        if sum(counts.values()) <= before:
            raise AssertionError('explicit canonical class call bypassed selected owner')
        bad_calls = [lambda f: f(), lambda f: f(service, 'x', 'extra'),
                     lambda f: f(service, target_slot='x', unknown=True)]
        binding = []
        for call in bad_calls:
            errors = []
            for function in (originals['ACQUIRE'], api.HIAAgentService.acquire_slot):
                try:
                    call(function)
                except TypeError as error:
                    errors.append((type(error).__name__, str(error)))
                else:
                    raise AssertionError('invalid original signature unexpectedly succeeded')
            if errors[0] != errors[1]:
                raise AssertionError(('public binding error differs', errors))
            binding.append(errors)
        return {'rows': rows, 'actual_mode_entry_counts': dict(counts),
                'binding_errors': binding, 'subclass_override_preserved': True,
                'explicit_class_call_selected': True, 'retained_poisoned': True}
    finally:
        image._entry = actual_entry
        for key, value in originals.items():
            setattr(api, '_SERVICE_LEASE_' + key + '_REFERENCE', value)
        hia_agent_runner.run_native_batch, hia_agent_buffers.validate_arguments = old_runner, old_validator
        os.environ.clear(); os.environ.update(previous)


def transport_controls(image):
    from hepta import hia_service_lease_native as native
    from hepta import hia_service_lease_protocol as p
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    from hepta.hia_program_runtime_prepared import prepare_runtime_program
    program = prepare_runtime_program(assemble_program(native.SOURCE.read_bytes()))
    comparisons = []
    def direct(words, state_bytes=None, *, sizes=(80, 96, 128)):
        raw = struct.pack('<10Q', *words)
        source = ctypes.create_string_buffer(raw + b'X' * 16)
        output = ctypes.create_string_buffer(b'\0' * 96 + b'Z' * 16, 112)
        state = ctypes.create_string_buffer((state_bytes or b'\0' * 128) + b'Y' * 16)
        snapshots = tuple(ctypes.string_at(value, size) for value, size in zip((source, output, state), sizes))
        code = image._entry(source, sizes[0], output, sizes[1], state, sizes[2])
        owners = [_Owner(index + 1, bytearray(raw)) for index, raw in enumerate(snapshots)]
        machine = _Machine(program, 4_000_000, 16 << 20, None, 128)
        model_code = machine.invoke(machine.functions['f0'],
            [_View(owner, index != 0) for index, owner in enumerate(owners)])[0]
        actual = tuple(ctypes.string_at(value, size) for value, size in zip((source, output, state), sizes))
        model = tuple(bytes(owner.data) for owner in owners)
        comparisons.append({'request': snapshots[0].hex(), 'sizes': list(sizes),
            'before': [value.hex() for value in snapshots],
            'actual_code': code, 'vm_code': model_code,
            'actual': [value.hex() for value in actual], 'vm': [value.hex() for value in model]})
        if code != model_code or actual != model:
            raise AssertionError('complete independent VM/native ABI buffers differ')
        if source.raw[:96] != raw + b'X' * 16 or state.raw[128:144] != b'Y' * 16 or output.raw[96:112] != b'Z' * 16:
            raise AssertionError('ABI crossed its original buffer extent')
        return code, output.raw[:96], state.raw[:128]
    request = [p.REQUEST_MAGIC, p.INITIALIZE, 0, 0, 0, p.LEASE, 31, 41, 0, 0]
    code, output, state = direct(request)
    if code != 96 or struct.unpack('<12Q', output)[1] != 0:
        raise AssertionError('actual initializer was not admitted')
    words = struct.unpack('<16Q', state)
    claim = [p.REQUEST_MAGIC, p.CLAIM, words[4], words[3], 0, p.LEASE, 31, 41, 0, 0]
    controls = []
    for name, changed in (
            ('request-magic', {0: 0}), ('request-reserved', {8: 1}),
            ('nonce', {6: 32}), ('mode', {5: p.INVOKE}), ('sequence', {2: words[4] + 1}),
            ('port', {3: words[3] + 1}), ('event', {1: p.FINALIZE}), ('observation', {4: 1})):
        candidate = claim.copy()
        for index, value in changed.items():
            candidate[index] = value
        returned, result, _ = direct(candidate, state)
        if returned == 96 and struct.unpack('<12Q', result)[1] == 0:
            raise AssertionError('invalid ABI identity was accepted: ' + name)
        controls.append(name)
    for dimension, sizes in enumerate(((79, 96, 128), (80, 95, 128), (80, 96, 127))):
        returned, _, _ = direct(request, sizes=sizes)
        if returned == 96:
            raise AssertionError('invalid ABI length was accepted')
        controls.append('length-' + str(dimension))
    for index in (0, 8, 40, 80, 88, 120):
        changed = bytearray(state)
        changed[index] ^= 1
        returned, result, _ = direct(claim, bytes(changed))
        if returned == 96 and struct.unpack('<12Q', result)[1] == 0:
            raise AssertionError('invalid retained state was accepted')
        controls.append('state-' + str(index))
    code, output, claimed = direct(claim, state)
    ack = [p.REQUEST_MAGIC, p.SUCCEEDED, words[4], words[3], 1, p.LEASE, 31, 41, 0, 0]
    code, output, advanced = direct(ack, claimed)
    code, output, _ = direct(ack, advanced)
    if code == 96 and struct.unpack('<12Q', output)[1] == 0:
        raise AssertionError('duplicate ACK replay was accepted')
    controls.append('ACK-replay')
    return {'controls': controls, 'actual_native_calls': True, 'provider_effects': 0,
            'full_buffer_VM_native_comparisons': comparisons,
            'fresh_machine_limits': [4_000_000, 16 << 20, 128]}


def transport_loss_controls(image):
    from hepta import hia_service_lease_native as native
    actual = image._entry
    results = []
    # Host preparation is before _handoff, with no original provider effect.
    real_pack, requested = native.struct.pack, MemoryError('before native handoff')
    def fail_pack(*args, **kwargs):
        raise requested
    native.struct.pack = fail_pack
    try:
        try:
            raw_frame(image)
        except MemoryError as error:
            if error is not requested:
                raise AssertionError('safe preparation changed original error identity')
        else:
            raise AssertionError('pre-entry allocation control did not fire')
        results.append('safe-pre-entry-original-MemoryError')
    finally:
        native.struct.pack = real_pack
    for label in ('lost-return', 'output', 'request', 'state-sentinel'):
        called = []
        def faulty(source, size, output, capacity, state, extent):
            code = actual(source, size, output, capacity, state, extent)
            called.append(code)
            if label == 'lost-return':
                raise ValueError('actual entry return lost')
            target, offset = ((output, 0) if label == 'output' else
                              (source, 0) if label == 'request' else (state, extent))
            address = ctypes.addressof(target) + offset
            ctypes.c_ubyte.from_address(address).value ^= 1
            return code
        image._entry = faulty
        try:
            try:
                raw_frame(image)
            except native.ServiceLeaseUnknown:
                pass
            else:
                raise AssertionError('unconfirmed native initialization was adopted')
            if called != [native.OUTPUT_BYTES]:
                raise AssertionError('loss was not after one actual entry')
            results.append(label)
        finally:
            image._entry = actual
    from hepta.hia_native_delivery import custody_snapshot
    for exception_type in (MemoryError, KeyboardInterrupt, SystemExit):
        requested = exception_type('actual entry loss preserves non-domain error identity')
        calls = []
        before_lost = sum(row['lost'] for row in custody_snapshot())
        def lost_non_domain(*arguments):
            code = actual(*arguments)
            calls.append(code)
            raise requested
        image._entry = lost_non_domain
        try:
            try:
                raw_frame(image)
            except BaseException as error:
                if error is not requested:
                    raise AssertionError('actual handoff normalized a non-domain original error')
            else:
                raise AssertionError('actual non-domain loss was adopted')
            if calls != [native.OUTPUT_BYTES] or sum(row['lost'] for row in custody_snapshot()) != before_lost + 1:
                raise AssertionError('native handoff was not retained independently of exception class')
            results.append('actual-return-' + exception_type.__name__)
        finally:
            image._entry = actual
    return {'controls': results, 'exception_class_was_not_loss_evidence': True}


def ownership_controls(image):
    import contextvars
    import select
    import signal
    import threading
    import time
    from hepta import hia_service_lease_native as native
    results = []
    frame = raw_frame(image)
    replies = []
    def other_thread():
        try:
            frame.finish()
        except BaseException as error:
            replies.append(type(error).__name__)
        else:
            replies.append('accepted')
    worker = threading.Thread(target=other_thread)
    worker.start(); worker.join(10)
    if worker.is_alive() or replies != ['ServiceLeaseUnknown']:
        raise AssertionError('creator thread refusal differs')
    if frame.finish() != LEASE_VALUE:
        raise AssertionError('failed transfer damaged the creator invocation')
    try:
        frame.finish()
    except native.ServiceLeaseUnknown:
        pass
    else:
        raise AssertionError('finished Frame was reused')
    results.extend(('thread-refusal-with-creator-continuation', 'stale-frame-refusal'))
    frame = raw_frame(image)
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            try:
                frame.finish()
            except native.ServiceLeaseUnknown:
                value = b'creator-refused'
            else:
                value = b'accepted'
            os.write(write_fd, value)
        finally:
            os._exit(0)
    os.close(write_fd)
    waited = False
    try:
        if not select.select([read_fd], [], [], 10)[0]:
            raise AssertionError('fork creator control exceeded its 10-second budget')
        value = os.read(read_fd, 128)
        _, status = os.waitpid(pid, 0)
        waited = True
        if status != 0 or value != b'creator-refused':
            raise AssertionError('fork creator refusal differs')
    finally:
        os.close(read_fd)
        if not waited:
            try: os.kill(pid, signal.SIGKILL)
            except ProcessLookupError: pass
            os.waitpid(pid, 0)
    if frame.finish() != LEASE_VALUE:
        raise AssertionError('child refusal changed parent ownership')
    results.append('fork-refusal-with-parent-continuation')
    holder, caught = {}, []
    class RecursiveLedger(PlainLedger):
        def lease(self, value):
            try:
                holder['frame'].finish()
            except native.ServiceLeaseUnknown:
                caught.append('refused')
            return dict(value)
    service = PlainService()
    service._slot_ledger = RecursiveLedger(service.events)
    frame = raw_frame(image, service=service)
    holder['frame'] = frame
    try:
        if frame.finish() != LEASE_VALUE or caught != ['refused'] or not frame.finished:
            raise AssertionError('same-Frame refusal retired its active invocation')
    finally:
        holder.clear()
    results.append('same-frame-reentry-refused-before-cleanup')
    # A fresh actual invocation in an unrelated Context does not invent an
    # active ancestor or add a new blanket Context transfer prohibition.
    fresh = raw_frame(image)
    if contextvars.Context().run(fresh.finish) != LEASE_VALUE:
        raise AssertionError('healthy same-thread Context advance was rejected')
    results.append('fresh-context-no-invented-parent')
    return {'controls': results}


def loader_controls(manifest, directory):
    from hepta import hia_service_lease_native as native
    from hepta.hia_native_helpers import native_helpers_scope
    directory = Path(directory)
    directory.mkdir()
    value = read_json(manifest)
    image = Path(manifest).parent / value['image_path']
    target = directory / value['image_path']
    target.write_bytes(image.read_bytes())
    controls = []
    for key in ('source_sha256', 'image_sha256', 'schema', 'image_path'):
        changed = dict(value)
        changed[key] = ('0' * 64 if key.endswith('sha256') else
                        '../outside.bin' if key == 'image_path' else 'wrong.schema')
        path = directory / (key + '.json')
        write_json(path, changed)
        try:
            native.installed_service_lease(str(path))
        except (ValueError, OSError):
            controls.append(key)
        else:
            raise AssertionError('manifest/source binding drift was accepted')
    for empty in ('', None):
        try:
            native.installed_service_lease(empty)
        except ValueError:
            controls.append('empty-' + repr(empty))
        else:
            raise AssertionError('empty explicit image was accepted')
    return {'controls': controls, 'source_file_modified': False}


def bundle_images(path, manifests):
    from hepta.hia_native_helpers import ABI, SCHEMA, TARGET
    names = {'lease': 'HEPTA_HIA_SERVICE_LEASE_MANIFEST',
             'store': 'HEPTA_HIA_STORE_ARTIFACT_PROFILE_MANIFEST',
             'transaction': 'HEPTA_HIA_STORE_TRANSACTION_MANIFEST',
             'ledger': 'HEPTA_HIA_SLOT_LEDGER_MANIFEST',
             'operations': 'HEPTA_HIA_SLOT_OPERATIONS_MANIFEST'}
    write_json(path, {'schema': SCHEMA, 'target': TARGET, 'abi': ABI, 'helpers': [
        {'selector': names[name], 'manifest_path': str(Path(manifest).resolve()),
         'manifest_sha256': pin(manifest)['sha256']}
        for name, manifest in manifests.items()]})
    return pin(path)['sha256']



def pinned_scope_controls(manifest, directory):
    import threading
    from hepta import hia_service_lease_native as native
    from hepta.hia_native_helpers import native_helpers_scope, native_helpers_identity
    directory = Path(directory)
    directory.mkdir()
    bundle = directory / 'bundle.json'
    digest = bundle_images(bundle, {'lease': manifest})
    copied = directory / 'undeclared'
    copied.mkdir()
    value = read_json(manifest)
    (copied / value['image_path']).write_bytes((Path(manifest).parent / value['image_path']).read_bytes())
    write_json(copied / 'manifest.json', value)
    previous = dict(os.environ)
    outcomes = []
    try:
        environment = clean_environment()
        os.environ.clear(); os.environ.update(environment)
        with native_helpers_scope(str(bundle), digest):
            image = native.installed_service_lease(str(manifest))
            if native.installed_service_lease(str(manifest)) is not image:
                raise AssertionError('worker route changed its exact admitted image')
            if native_helpers_identity()['native_helpers_sha256'] != digest:
                raise AssertionError('worker helper bundle differs')
            try:
                native.installed_service_lease(str(copied / 'manifest.json'))
            except ValueError:
                outcomes.append('undeclared-copy-refused')
            else:
                raise AssertionError('worker admitted an undeclared manifest')
            try:
                with native_helpers_scope(str(bundle), digest):
                    raise AssertionError('nested worker scope was entered')
            except ValueError:
                outcomes.append('nested-worker-refused')
            replies = []
            def foreign_thread():
                try:
                    native.installed_service_lease(str(manifest))
                except BaseException as error:
                    replies.append(type(error).__name__)
                else:
                    replies.append('accepted')
            thread = threading.Thread(target=foreign_thread)
            thread.start(); thread.join(10)
            if thread.is_alive() or replies != ['ValueError']:
                raise AssertionError('worker scope thread ownership differs')
            outcomes.append('worker-thread-refused')
            if raw_frame(image).finish() != LEASE_VALUE:
                raise AssertionError('negative scope control damaged its live owner')
        with native_helpers_scope():
            try:
                native.installed_service_lease(str(manifest))
            except ValueError:
                outcomes.append('unselected-worker-refused-executable')
            else:
                raise AssertionError('unselected worker acquired a new executable')
    finally:
        os.environ.clear(); os.environ.update(previous)
    return {'controls': outcomes, 'bundle_sha256': digest, 'exact_pinned_image': True}


def original_workflow(manifests, output):
    import unittest
    from hepta import hia_agent_service as api
    from hepta import hia_service_lease_native as native
    previous = dict(os.environ)
    aliases = {key: getattr(api, '_SERVICE_LEASE_' + key + '_REFERENCE')
               for key in ('ACQUIRE', 'LEASE', 'INVOKE', 'RELEASE')}
    image = native.installed_service_lease(str(manifests['lease']))
    entry, counts = image._entry, Counter()
    def counted(*args):
        code = entry(*args)
        words = struct.unpack('<10Q', ctypes.string_at(args[0], args[1]))
        counts[str(words[5])] += 1
        return code
    def forbidden(*args, **kwargs):
        raise AssertionError('original workflow used a retained lease method')
    image._entry = counted
    try:
        environment = selected_environment(manifests)
        os.environ.clear(); os.environ.update(environment)
        for key in aliases:
            setattr(api, '_SERVICE_LEASE_' + key + '_REFERENCE', forbidden)
        module = 'tests.test_hia_agent_native_lease_snapshot'
        suite = unittest.defaultTestLoader.loadTestsFromName(module)
        def flatten(suite):
            for test in suite:
                if isinstance(test, unittest.TestSuite):
                    yield from flatten(test)
                else:
                    yield test.id()
        ids = list(flatten(suite))
        expected = [module + '.LeaseSnapshotTests.test_caller_mutation_during_native_call_cannot_relabel_result_or_buffers']
        if ids != expected:
            raise AssertionError(('original complete workflow identity changed', ids))
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        report = {'planned': ids, 'run': result.testsRun,
            'failures': len(result.failures), 'errors': len(result.errors), 'skips': len(result.skipped),
            'actual_mode_entry_counts': dict(counts), 'retained_poisoned': True,
            'original_fixture_or_budget_changed': False}
        write_json(Path(output) / 'original-workflow.json', report)
        if (not result.wasSuccessful() or result.testsRun != len(ids) or result.skipped
                or set(counts) != {'1', '2', '3', '4'}):
            raise AssertionError('complete original lease workflow or actual routes failed')
        return report
    finally:
        image._entry = entry
        for key, value in aliases.items():
            setattr(api, '_SERVICE_LEASE_' + key + '_REFERENCE', value)
        os.environ.clear(); os.environ.update(previous)


def control_main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--action', choices=('public', 'transport', 'loss', 'ownership', 'loader', 'workflow', 'pinned'), required=True)
    parser.add_argument('--manifest-list', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    before = product_snapshot(ROOT, source_paths())
    manifests = read_json(args.manifest_list)
    captured = {name: pin(path) for name, path in manifests.items()}
    from hepta import hia_service_lease_native as native
    report = {'status': 'HOLD', 'action': args.action, 'source_before': before,
        'manifest_before': captured, 'runtime': sys.version, 'pid': os.getpid(), 'ppid': os.getppid()}
    try:
        image = native.installed_service_lease(str(manifests['lease']))
        if args.action == 'public':
            report['observation'] = public_controls(manifests['lease'])
        elif args.action == 'transport':
            report['observation'] = transport_controls(image)
        elif args.action == 'loss':
            report['observation'] = transport_loss_controls(image)
        elif args.action == 'ownership':
            report['observation'] = ownership_controls(image)
        elif args.action == 'loader':
            report['observation'] = loader_controls(manifests['lease'], args.output / 'drift')
        elif args.action == 'workflow':
            report['observation'] = original_workflow(manifests, args.output)
        else:
            report['observation'] = pinned_scope_controls(manifests['lease'], args.output / 'scope')
        report['source_after'] = product_snapshot(ROOT, before)
        report['manifest_after'] = {name: pin(path) for name, path in manifests.items()}
        if report['source_before'] != report['source_after'] or captured != report['manifest_after']:
            raise AssertionError('control source or image manifest drift')
        report['status'] = 'PASS'
        return 0
    finally:
        write_json(args.output / 'report.json', report)


if __name__ == '__main__':
    raise SystemExit(control_main())
