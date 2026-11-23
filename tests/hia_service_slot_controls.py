"""Test-only ownership and complete independent-original supervision."""
from __future__ import annotations
import ctypes
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
COLD = 'HEPTA_HIA_SERVICE_SLOT_COLD_REPORT'
DEV = 'HEPTA_HIA_SERVICE_SLOT_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_SERVICE_SLOT_EVIDENCE'
SOURCE_EVIDENCE = 'HEPTA_HIA_SERVICE_SLOT_SOURCE_EVIDENCE'
ORIGINALS = 'HEPTA_HIA_SERVICE_SLOT_ORIGINALS'
INPUTS = ROOT / 'tests/fixtures/hia_service_slot_observation_inputs_v1/inputs.json'
INPUT_SHA = '625d6fdb004b28e0f207f1fc22052dca55b28bacea09d9f3053674a78ee9d001'
VM_IDS = tuple(
    ['rollback.ledger.' + v + '.outer0' for v in ('00', '10', '01', '11')]
    + ['adopt.ledger.' + v + '.outer0' for v in
       ('000', '100', '010', '110', '001', '101', '011', '111')]
    + ['adopt.mismatch.' + field + '.truth.return' + flag + '.outer0'
       for field in ('context', 'abi') for flag in ('0', '1')]
    + ['adopt.receiver.detached.both.outer0',
       'rollback.unpack.rollback-unpack.iter.outer0',
       'adopt.descriptor.detached1.temporary1.outer0',
       'rollback.instance-override.detached1.temporary1.outer0'])

def encoded(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True,
                       separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')

def put(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream: stream.write(encoded(value))

def digest(path):
    value = sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(1 << 20), b''): value.update(chunk)
    return value.hexdigest()

def environment():
    return {k: v for k, v in os.environ.items()
            if k not in ('PYTHONHOME', 'PYTHONPATH') and not k.startswith('HEPTA_HIA_')}

def group_exists(pid):
    try: os.killpg(pid, 0)
    except ProcessLookupError: return False
    return True

def run_child(root, label, arguments, *, timeout, body=None, env=None, expected_code=0):
    directory = Path(root) / label; directory.mkdir(parents=True, exist_ok=False)
    command = [sys.executable, '-I', '-B', *map(str, arguments)]
    begin, stamp = time.monotonic(), time.time_ns()
    process = None; caught = None; timed_out = False; signals = []; cleanup = []
    with (directory / 'stdout.log').open('xb') as out, (directory / 'stderr.log').open('xb') as err:
        try:
            process = subprocess.Popen(command, cwd=ROOT, env=environment() if env is None else env,
                stdin=subprocess.PIPE if body is not None else subprocess.DEVNULL,
                stdout=out, stderr=err, start_new_session=True)
            put(directory / 'command.json', {
                'schema': 'hepta.hia.service-slot-child-command.v1',
                'command': command, 'cwd': str(ROOT), 'pid': process.pid, 'pgid': process.pid,
                'parent_pid': os.getpid(), 'started_time_ns': stamp,
                'timeout_seconds': timeout, 'cleanup_seconds': 3,
                'source_build_observations': os.environ.get('HEPTA_HIA_SOURCE_BUILD_OBSERVATIONS')})
            try: process.communicate(body, timeout=timeout)
            except subprocess.TimeoutExpired: timed_out = True
        except BaseException as error:
            caught = error
        finally:
            if process is not None:
                try:
                    if process.poll() is None or group_exists(process.pid):
                        try: os.killpg(process.pid, signal.SIGKILL); signals.append('SIGKILL')
                        except ProcessLookupError: pass
                    process.wait(timeout=3)
                except BaseException as error: cleanup.append(type(error).__name__ + ': ' + str(error))
    stdout = (directory / 'stdout.log').read_bytes()
    stderr = (directory / 'stderr.log').read_bytes()
    absent = process is not None and not group_exists(process.pid)
    good = (caught is None and process is not None and process.returncode == expected_code
            and absent and not timed_out and not signals and not cleanup)
    report = {'schema': 'hepta.hia.service-slot-child-result.v1',
        'status': 'PASS' if good else 'HOLD', 'command': command,
        'pid': None if process is None else process.pid,
        'returncode': None if process is None else process.returncode,
        'expected_returncode': expected_code, 'timeout': timed_out, 'signals': signals,
        'reaped': process is not None and process.returncode is not None,
        'owned_group_absent': absent, 'cleanup_errors': cleanup,
        'started_time_ns': stamp, 'finished_time_ns': time.time_ns(),
        'wall_seconds': time.monotonic() - begin, 'timeout_seconds': timeout,
        'stdout_sha256': sha256(stdout).hexdigest(), 'stderr_sha256': sha256(stderr).hexdigest(),
        'supervisor_error': None if caught is None else type(caught).__name__ + ': ' + str(caught)}
    put(directory / 'result.json', report)
    if caught is not None: raise caught
    if not good: raise AssertionError(encoded(report).decode() + stderr.decode('utf8', 'backslashreplace'))
    return stdout, stderr

def invocation(variable):
    value = os.environ.get(variable)
    if value == '': raise ValueError(variable + ' must not be empty')
    parent = Path(tempfile.mkdtemp(prefix='service-slot-')) if value is None else Path(value).absolute()
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix='invocation-' + str(os.getpid()) + '-', dir=parent))

def inputs():
    raw = INPUTS.read_bytes()
    if sha256(raw).hexdigest() != INPUT_SHA: raise ValueError('independent inputs changed')
    value = json.loads(raw)
    if len(value['cases']) != 348 or len(value['fault_basis']) != 13:
        raise ValueError('complete original input domain is required')
    return value

def originals(root):
    path = ROOT / 'tools/qualify_hia_service_slot_originals.py'
    spec = importlib.util.spec_from_file_location('service_slot_original_supervisor', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    supplied = os.environ.get(ORIGINALS)
    if supplied == '': raise ValueError('original authority must not be empty')
    destination = Path(supplied).resolve(strict=True) if supplied else Path(root) / 'originals'
    if supplied is None:
        run_child(root, 'original-command', [path, '--output', destination], timeout=1800)
    report_raw = (destination / 'original-bundle.json').read_bytes()
    report = module.read_originals(destination, report_raw=report_raw)
    put(Path(root) / 'original-authority.json', {
        'path': str(destination), 'sha256': sha256(report_raw).hexdigest(),
        'base_count': report['base_count'], 'fault_count': report['fault_count'],
        'runtime': report['runtime'], 'candidate_expectation_regenerated': False})
    return destination, report

def expected_rows(originals_path):
    rows = {}
    with (Path(originals_path) / 'base-first/observations.jsonl').open('rb') as stream:
        for raw in stream:
            value = json.loads(raw); rows[value['case']] = value
    if set(rows) != {v['id'] for v in inputs()['cases']}: raise ValueError('original IDs differ')
    return rows

def bundle(path, helpers):
    from hepta.hia_native_helpers import ABI, SCHEMA, TARGET
    put(path, {'schema': SCHEMA, 'target': TARGET, 'abi': ABI, 'helpers': [
        {'selector': selector, 'manifest_path': str(Path(manifest).resolve()),
         'manifest_sha256': digest(manifest)} for selector, manifest in helpers]})
    return digest(path)

def vm_call(program, raw, output, state):
    from hepta.hia_program_runtime import _Owner, _View
    from tests.hia_independent_vm import IndependentMachine
    owners = [_Owner(i + 1, bytearray(v)) for i, v in enumerate((raw, output, state))]
    machine = IndependentMachine(program, 2_000_000, 16 << 20, None, 128)
    result = machine.invoke(machine.functions['f0'], [_View(v, i != 0) for i, v in enumerate(owners)])
    if bytes(owners[0].data) != raw: raise AssertionError('VM changed immutable request')
    return result[0], bytes(owners[1].data), bytes(owners[2].data)

class VMEntry:
    # Holds only the program, never the image: no fixture closure cycle.
    def __init__(self, program): self.program, self.entries = program, 0
    def __call__(self, source, size, output, capacity, state, extent):
        code, result, retained = vm_call(self.program, ctypes.string_at(source, size),
            ctypes.string_at(output, capacity), ctypes.string_at(state, extent))
        ctypes.memmove(output, result, capacity); ctypes.memmove(state, retained, extent)
        self.entries += 1
        return code

def vm_image(program):
    from hepta.hia_service_slot_native import NativeServiceSlot
    image = object.__new__(NativeServiceSlot)
    image.image_sha256 = 'independent-vm-no-mapping'; image._entry = VMEntry(program)
    return image

def build_companions(root, compiler, cold):
    from tools.build_hia_service_slot import build
    from tools.build_hia_slot_operations import build as operations
    from tools.build_hia_store_artifact_profile import build as store
    from tools.build_hia_store_transaction import build as transaction
    from tools.build_hia_json_preflight import current_sources
    root, compiler = Path(root), Path(compiler)
    before, compiler_bytes = current_sources(), compiler.read_bytes()
    manifests = {}
    for name, builder in (('service', build), ('operations', operations),
                          ('store', store), ('transaction', transaction)):
        manifests[name] = builder(root / (name + '-build'), compiler, cold, development=cold is None)
    if cold is not None:
        from tools.build_hia_slot_ledger import build as ledger
        manifests['ledger'] = ledger(root / 'ledger-build', compiler, Path(cold))
    else:
        # The original decision builder has no DEV parameter. This separate
        # direct compile is explicitly diagnostic, with full output custody.
        from tools.qualify_hia_selfhost import compile_stage
        from tools.build_hia_source_build import _check_pack_output
        directory = root / 'ledger-build'; directory.mkdir(mode=0o700)
        source_path = ROOT / 'examples/hia_bootstrap/slot_ledger.hepta'
        source = source_path.read_bytes()
        image, receipt = compile_stage(directory, 'slot-ledger', compiler, source)
        full = (directory / 'slot-ledger.output.bin').read_bytes(); raw = image.read_bytes()
        if _check_pack_output(receipt, full, artifact=compiler_bytes, source=source) != raw:
            raise ValueError('decision companion complete output differs')
        value = {'schema': 'hepta.hia.slot-ledger-native.v1',
                 'source_sha256': sha256(source).hexdigest(), 'image_path': image.name,
                 'image_sha256': sha256(raw).hexdigest(),
                 'compiler_sha256': sha256(compiler_bytes).hexdigest()}
        manifests['ledger'] = directory / 'manifest.json'; put(manifests['ledger'], value)
        put(directory / 'build.json', {'scope': 'EXPLICIT_DEVELOPMENT_COMPONENT',
            'native_compile_receipt': receipt, 'manifest': value, 'source_manifest': before,
            'cold_report_sha256': None})
        if source_path.read_bytes() != source: raise ValueError('decision source changed')
    from hepta import hia_service_slot_native as service_native
    from hepta import hia_slot_operations_native as operations_native
    from hepta import hia_slot_ledger_native as ledger_native
    from hepta import hia_store_artifact_profile_native as store_native
    from hepta import hia_store_transaction_native as transaction_native
    helpers = [(module.SELECTOR, manifests[name]) for name, module in (
        ('service', service_native), ('operations', operations_native),
        ('ledger', ledger_native), ('store', store_native), ('transaction', transaction_native))]
    path = root / 'helpers.json'; pin = bundle(path, helpers)
    if current_sources() != before or compiler.read_bytes() != compiler_bytes:
        raise ValueError('same-attempt sources/compiler changed')
    put(root / 'companion-authority.json', {
        'schema': 'hepta.hia.service-slot-companions.v1',
        'scope': 'MATCHING_SOURCE_COLD_COMPONENT' if cold is not None else 'EXPLICIT_DEVELOPMENT_COMPONENT',
        'compiler': str(compiler), 'compiler_sha256': sha256(compiler_bytes).hexdigest(),
        'sources': before, 'manifests': {k: str(v) for k, v in manifests.items()},
        'manifest_sha256': {k: digest(v) for k, v in manifests.items()},
        'bundle': str(path), 'bundle_sha256': pin,
        'resource_or_SQL_equivalence_inferred_from_build': False})
    return manifests, path, pin

def selected_environment(manifests):
    result = environment()
    for key, path in manifests.items():
        selector = {'service': 'SERVICE_SLOT', 'operations': 'SLOT_OPERATIONS',
                    'ledger': 'SLOT_LEDGER', 'store': 'STORE_ARTIFACT_PROFILE',
                    'transaction': 'STORE_TRANSACTION'}[key]
        result['HEPTA_HIA_' + selector + '_MANIFEST'] = str(path)
    return result
