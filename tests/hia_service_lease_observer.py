"""Fresh-process lease observations. Expected rows are never produced by an owner."""
from __future__ import annotations
import argparse
from collections import Counter
import ctypes
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tests.hia_slot_operations_qualification_support import (
    pin, regular_bytes, read_json, write_json, canonical, product_snapshot, unique_pairs)
from tools.read_hia_service_lease import (
    _capture_raw, _raw_pin, _require_captured_unchanged)


class VMEntry:
    __slots__ = ('program', 'machine', 'owner', 'view', 'entries', 'events', 'modes')
    def __init__(self, program, machine, owner, view):
        self.program, self.machine, self.owner, self.view = program, machine, owner, view
        self.entries, self.events, self.modes = 0, Counter(), Counter()
    def __call__(self, source, size, output, capacity, state, extent):
        raw = ctypes.string_at(source, size)
        values = (raw, ctypes.string_at(output, capacity), ctypes.string_at(state, extent))
        owners = [self.owner(i + 1, bytearray(value)) for i, value in enumerate(values)]
        machine = self.machine(self.program, 4_000_000, 16 << 20, None, 128)
        code = machine.invoke(machine.functions['f0'],
            [self.view(owner, i != 0) for i, owner in enumerate(owners)])[0]
        if bytes(owners[0].data) != raw:
            raise AssertionError('VM changed immutable request')
        ctypes.memmove(output, bytes(owners[1].data), capacity)
        ctypes.memmove(state, bytes(owners[2].data), extent)
        words = struct.unpack('<10Q', raw)
        self.entries += 1
        self.events[str(words[1])] += 1
        self.modes[str(words[5])] += 1
        return code


class NativeEntry:
    __slots__ = ('entry', 'entries', 'events', 'modes')
    def __init__(self, entry):
        self.entry = entry
        self.entries, self.events, self.modes = 0, Counter(), Counter()
    def __call__(self, source, size, output, capacity, state, extent):
        code = self.entry(source, size, output, capacity, state, extent)
        words = struct.unpack('<10Q', ctypes.string_at(source, size))
        self.entries += 1
        self.events[str(words[1])] += 1
        self.modes[str(words[5])] += 1
        return code


def no_original(*args, **kwargs):
    raise AssertionError('selected lease owner invoked a retained complete method')


def public_factory(api, native, image, backend, selector):
    frame_type, loader = native.ServiceLeaseFrame, native.installed_service_lease
    names = {1: 'acquire_slot', 2: '_lease', 3: 'invoke_lease', 4: 'release_slot'}
    def factory(mode, namespace):
        def construct(image, selected_mode, service, arguments):
            return frame_type(image, selected_mode, service, arguments, namespace=namespace)
        def invoke(service, *arguments):
            call = {'self': service, 'callee': getattr(api.HIAAgentService, names[mode])}
            keys = ('target',) if mode == 1 else ('lease', 'name', 'arguments') if mode == 3 else ('lease',)
            call.update(zip(keys, arguments))
            del service, arguments
            previous = os.environ.get(native.SELECTOR)
            native.ServiceLeaseFrame = construct
            if backend == 'vm':
                native.installed_service_lease = lambda manifest: image
            os.environ[native.SELECTOR] = selector
            try:
                if mode == 1:
                    return call.pop('callee')(call.pop('self'), call.pop('target'))
                if mode in (2, 4):
                    return call.pop('callee')(call.pop('self'), call.pop('lease'))
                return call.pop('callee')(call.pop('self'), call.pop('lease'),
                    call.pop('name'), call.pop('arguments'))
            finally:
                native.ServiceLeaseFrame, native.installed_service_lease = frame_type, loader
                if previous is None:
                    os.environ.pop(native.SELECTOR, None)
                else:
                    os.environ[native.SELECTOR] = previous
        return invoke
    return factory



def unselected_factory(api, native):
    import types
    names = {1: ('ACQUIRE', 'acquire_slot'), 2: ('LEASE', '_lease'),
             3: ('INVOKE', 'invoke_lease'), 4: ('RELEASE', 'release_slot')}
    references = {mode: getattr(api, '_SERVICE_LEASE_' + pair[0] + '_REFERENCE')
                  for mode, pair in names.items()}
    def factory(mode, namespace):
        # Retain the actual product code object. Only the original global
        # provider namespace is injected; no code reset or recompilation.
        reference = types.FunctionType(references[mode].__code__, namespace)
        key, method = names[mode]
        alias = '_SERVICE_LEASE_' + key + '_REFERENCE'
        def invoke(service, *arguments):
            call = {'self': service, 'arguments': arguments,
                    'callee': getattr(api.HIAAgentService, method)}
            del service, arguments
            prior = getattr(api, alias)
            selector = os.environ.pop(native.SELECTOR, None)
            setattr(api, alias, reference)
            try:
                return call.pop('callee')(call.pop('self'), *call.pop('arguments'))
            finally:
                setattr(api, alias, prior)
                if selector is not None:
                    os.environ[native.SELECTOR] = selector
        return invoke
    return factory

def vm_image(native):
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    from hepta.hia_program_runtime_prepared import prepare_runtime_program
    program = prepare_runtime_program(assemble_program(native.SOURCE.read_bytes()))
    image = object.__new__(native.NativeServiceLease)
    image._entry = VMEntry(program, _Machine, _Owner, _View)
    image.admitted_source_sha256 = hashlib.sha256(native.SOURCE.read_bytes()).hexdigest()
    image.image_sha256 = '0' * 64
    return image


def audit_no_external(event, args):
    if (event in ('subprocess.Popen', 'os.system', 'os.posix_spawn', 'os.fork',
                  'os.forkpty', 'sqlite3.connect') or event.startswith('os.exec')):
        raise AssertionError('finite fake-provider child attempted external effect: ' + event)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend', choices=('original', 'unselected', 'vm', 'native'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-freeze', type=Path, required=True)
    parser.add_argument('--source-freeze-sha256', required=True)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--expected-frozen', type=Path)
    args = parser.parse_args(argv)
    output = args.output
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    captured_inputs = {}
    raw = _capture_raw(args.source_freeze, captured_inputs)
    if hashlib.sha256(raw).hexdigest() != args.source_freeze_sha256:
        raise ValueError('outer source freeze identity differs')
    freeze = json.loads(raw, object_pairs_hook=unique_pairs,
                        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    before = product_snapshot(ROOT, freeze['files'])
    if canonical(before) != canonical(freeze['files']):
        raise ValueError('complete component source differs before observation')
    expected_before = None
    if args.backend != 'original':
        if args.expected_frozen is None:
            raise ValueError('candidate needs a prior independent expected seal')
        expected_raw = _capture_raw(args.expected_frozen, captured_inputs)
        expected_before = _raw_pin(expected_raw)
        expected_seal = json.loads(expected_raw, object_pairs_hook=unique_pairs,
                                   parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
        if (expected_seal.get('before_candidate') is not True
                or expected_seal.get('candidate_results_used') is not False
                or expected_seal['original_1'] != expected_seal['original_2']):
            raise ValueError('independent expected observations were not sealed first')
    sys.addaudithook(audit_no_external)
    from tests import hia_service_lease_original_oracle as oracle
    cases = oracle.cases()
    input_path = oracle.FIXTURE / 'cases.json'
    input_pin = pin(input_path)
    factory, image, entry, manifest_before = oracle.original_factory, None, None, None
    if args.backend != 'original':
        from hepta import hia_service_lease_native as native
        from hepta import hia_agent_service as api
        if args.backend == 'unselected':
            factory = unselected_factory(api, native)
            native.NativeServiceLease.__init__ = no_original
        else:
            for name in ('ACQUIRE', 'LEASE', 'INVOKE', 'RELEASE'):
                setattr(api, '_SERVICE_LEASE_' + name + '_REFERENCE', no_original)
            if args.backend == 'vm':
                if args.manifest is not None:
                    raise ValueError('VM cannot claim a native image')
                image = vm_image(native)
                selector = 'independent-VM-component-injection'
            else:
                if args.manifest is None:
                    raise ValueError('native observer needs an actual admitted image')
                manifest_before = pin(args.manifest)
                selector = str(args.manifest.resolve(strict=True))
                image = native.installed_service_lease(selector)
                image._entry = NativeEntry(image._entry)
            entry = image._entry
            factory = public_factory(api, native, image, args.backend, selector)
    started, stopped, rows = [], [], []
    begin = time.monotonic()
    failure = None
    try:
        with (output / 'observations.jsonl').open('xb') as stream:
            for case in cases:
                started.append(case['id'])
                row = oracle.observe(case, factory=factory)
                stream.write(oracle.canonical(row))
                stream.flush()
                rows.append(row)
                stopped.append(case['id'])
    except BaseException as error:
        failure = {'type': type(error).__module__ + '.' + type(error).__qualname__,
                   'message': str(error)}
        raise
    finally:
        after = product_snapshot(ROOT, freeze['files'])
        write_json(output / 'observations.json', rows)
        report = {
            'schema': 'hepta.service-lease.finite-observations.v1',
            'backend': args.backend, 'runtime': sys.version,
            'executable': sys.executable, 'pid': os.getpid(), 'ppid': os.getppid(),
            'pgid': os.getpgid(0), 'planned': [case['id'] for case in cases],
            'started': started, 'stopped': stopped, 'failure': failure,
            'elapsed_seconds': time.monotonic() - begin,
            'source_before': before, 'source_after': after,
            'source_stable': canonical(before) == canonical(after),
            'expected_seal_before': expected_before,
            'expected_seal_after': None if args.expected_frozen is None else pin(args.expected_frozen),
            'input_before': input_pin, 'input_after': pin(input_path),
            'manifest_before': manifest_before,
            'manifest_after': None if args.manifest is None else pin(args.manifest),
            'observations': pin(output / 'observations.json'),
            'jsonl': pin(output / 'observations.jsonl'),
            'entries': 0 if entry is None else entry.entries,
            'events': {} if entry is None else dict(entry.events),
            'modes': {} if entry is None else dict(entry.modes),
            'originals_invoked_by_selected_route': False,
            'candidate_used_to_create_expected': False,
            'step_limit': 4_000_000, 'scratch_bytes': 16 << 20, 'call_depth': 128,
            'independent_vm_is_native_cold_qualification': False,
        }
        write_json(output / 'report.json', report)
    if before != after or input_pin != pin(input_path):
        raise AssertionError('finite observation inputs changed')
    if manifest_before is not None and manifest_before != pin(args.manifest):
        raise AssertionError('native manifest changed')
    if entry is not None and (entry.entries <= 0 or set(entry.modes) != {'1', '2', '3', '4'}):
        raise AssertionError('actual complete four-mode owner execution is absent')
    if len(started) != len(cases) or started != stopped:
        raise AssertionError('finite observations are incomplete')
    _require_captured_unchanged(captured_inputs)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
