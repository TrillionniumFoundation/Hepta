"""Execute the fixed development JSON-layout cases in a disposable native process."""
from __future__ import annotations
import argparse
import ctypes
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import threading
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys
import time
import traceback

def require(value, message):
    if not value:
        raise AssertionError(message)

def run_bridge_case(item, entry, *, bridge_module, image, image_sha256, fixtures):
    """Exercise the new byte transport while retaining actual HIA call records."""
    bridge = bridge_module.NativeJsonPretty(image, image_sha256)
    original_entry = bridge._entry
    calls = entry['native_invocations']
    lock = threading.Lock()
    barrier = None
    def traced(wire, size, output, capacity, workspace, workspace_bytes):
        require(type(wire) is bytes and size == len(wire), 'bridge input byte transport differs')
        require(workspace_bytes == bridge_module.WORKSPACE_BYTES == 161,
                'bridge workspace ABI differs')
        mode, = struct.unpack_from('<Q', workspace, 0)
        before = sha256(wire).hexdigest()
        address = hex(ctypes.addressof(workspace))
        if barrier is not None and mode == 0:
            barrier.wait(timeout=2)
        started = time.monotonic_ns()
        status = original_entry(wire, size, output, capacity, workspace, workspace_bytes)
        elapsed = time.monotonic_ns() - started
        require(sha256(wire).hexdigest() == before, 'bridge native input bytes changed')
        require(type(status) is int and 0 <= status <= 5, 'invalid bridge actual native status')
        record = {'mode': mode, 'source_bytes': size, 'source_sha256': before,
                  'output_capacity': capacity, 'workspace_bytes': workspace_bytes,
                  'workspace_address': address, 'actual_native_return': status,
                  'native_elapsed_ns': elapsed, 'source_unchanged': True,
                  'native_entry_executed': True, 'guard_regions_present': False}
        with lock:
            calls.append(record)
        return status
    bridge._entry = traced
    entry['scope'] = 'NEW_BYTE_TRANSPORT_NOT_ORIGINAL_CLI_OBJECT_DOMAIN'
    entry['installed_resource_or_manifest_admission_run'] = False
    entry['original37_guarded_native_cases_replaced'] = False
    def exact(wire, expected):
        output = bridge.format_admitted_compact(wire)
        require(type(output) is bytes and output == expected, 'bridge exact output differs')
        return {'input_bytes': len(wire), 'input_sha256': sha256(wire).hexdigest(),
                'output_bytes': len(output), 'output_sha256': sha256(output).hexdigest()}
    def refused(wire, wanted):
        try:
            bridge.format_admitted_compact(wire)
        except bridge_module.HiaJsonLayoutRefused as error:
            require(error.status == wanted, 'bridge actual refusal status differs')
            return {'actual_status': error.status, 'actual_error_offset': error.error_offset,
                    'failed_output_and_length_discarded': True}
        raise AssertionError('bridge unexpectedly admitted a refused input')
    try:
        which = item['bridge_case']
        if which == 'original_positive_layouts':
            chosen = [row for row in fixtures[:31] if row['kind'] == 'exact_layout']
            require(len(chosen) == 17, 'original positive bridge fixture denominator differs')
            entry['subcases'] = []
            for fixture in chosen:
                row = exact(fixture['wire'].encode(), fixture['expected'].encode())
                entry['subcases'].append({'id': fixture['name'], 'status': 'PASS', **row})
            require(len(calls) == 34 and all(row['actual_native_return'] == 0 for row in calls),
                    'actual bridge positive invocation denominator differs')
        elif which == 'expansion_above_8MiB':
            depth, scalars = item['depth'], item['scalars']
            require(depth == 64 and scalars == 65536, 'fixed bridge expansion descriptor differs')
            wire = b'[' * depth + b','.join([b'0'] * scalars) + b']' * depth
            expected = (b''.join(b'[\n' + b' ' * (2 * d) for d in range(1, depth + 1))
                + (b',\n' + b' ' * (2 * depth)).join([b'0'] * scalars)
                + b''.join(b'\n' + b' ' * (2 * (d - 1)) + b']'
                           for d in range(depth, 0, -1)))
            require(len(wire) == item['input_bytes'] == 131199
                    and sha256(wire).hexdigest() == item['input_sha256']
                    and len(expected) == item['output_bytes'] == 8593534
                    and sha256(expected).hexdigest() == item['output_sha256'],
                    'complete independent expansion bytes differ')
            entry.update(exact(wire, expected))
            require(len(calls) == 2 and all(row['actual_native_return'] == 0 for row in calls)
                    and calls[1]['output_capacity'] == 8593534 > (8 << 20),
                    'bridge imposed an extra output byte cap')
            entry['output_exceeds_8MiB_without_new_logical_cap'] = True
        elif which == 'refusal_before_output_allocation':
            bad = b'[' + b','.join([b'0'] * 1024)
            original_allocate = ctypes.create_string_buffer
            allocations = []
            def observed_allocate(value, *arguments):
                require(type(value) is int, 'bridge allocation used an unexpected initializer')
                allocations.append(value)
                return original_allocate(value, *arguments)
            ctypes.create_string_buffer = observed_allocate
            try:
                result = refused(bad, 2)
            finally:
                ctypes.create_string_buffer = original_allocate
            require(allocations and all(size <= 161 for size in allocations),
                    'bridge allocated an output from a failed measurement')
            require(len(calls) == 1 and calls[0]['mode'] == 0
                    and calls[0]['actual_native_return'] == 2,
                    'bridge refusal did not come from the actual HIA measurement')
            entry.update(result, allocation_sizes=allocations,
                         output_allocation_from_failed_length=False)
        elif which == 'repeated_refusal_and_success':
            entry['sequence'] = [refused(b'[', 2), exact(b'null', b'null'),
                refused(b'x' * ((8 << 20) + 1), 1),
                exact(b'{"a":1}', b'{\n  "a": 1\n}')]
            require([row['actual_native_return'] for row in calls] == [2, 0, 0, 1, 0, 0],
                    'same image repeated refusal/success sequence differs')
            entry['same_image_instance'] = True
        elif which == 'two_concurrent_private_workspaces':
            chosen = [next(row for row in fixtures[:31] if row['name'] == name)
                      for name in ('escaped_unicode', 'number_lexemes')]
            barrier = threading.Barrier(2)
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(exact, row['wire'].encode(), row['expected'].encode())
                           for row in chosen]
                entry['concurrent_outputs'] = [future.result() for future in futures]
            groups = {}
            for row in calls:
                groups.setdefault(row['workspace_address'], []).append(row)
            require(len(calls) == 4 and len(groups) == 2
                    and all(sorted(row['mode'] for row in group) == [0, 1]
                            and all(row['actual_native_return'] == 0 for row in group)
                            for group in groups.values()),
                    'concurrent bridge invocations shared or replaced a live workspace')
            entry['two_distinct_live_workspace_addresses'] = sorted(groups)
            entry['actual_native_calls_synchronized_after_workspace_allocation'] = True
        elif which == 'explicit_input_type':
            class BytesSubtype(bytes):
                def __len__(self):
                    raise AssertionError('subtype length hook must not run')
            rejected = [None, 'null', bytearray(b'null'), memoryview(b'null'),
                        BytesSubtype(b'null')]
            entry['refused_transport_types'] = []
            for value in rejected:
                try:
                    bridge.format_admitted_compact(value)
                except TypeError:
                    entry['refused_transport_types'].append(type(value).__name__)
                else:
                    raise AssertionError('new exact-byte ABI accepted a different type')
            require(not calls and len(entry['refused_transport_types']) == 5,
                    'foreign input transport reached the native byte entry')
            entry['scope'] = 'NEW_EXACT_BYTE_ABI_TYPE_CONTROL_NO_NATIVE_ENTRY'
        else:
            raise AssertionError('unknown fixed byte bridge development case')
        entry['native_entry_executed'] = bool(calls)
        entry['status'] = 'PASS'
    finally:
        bridge._entry = original_entry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--image-sha256', required=True)
    parser.add_argument('--cases', type=Path, required=True)
    parser.add_argument('--cases-sha256', required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--bridge', type=Path, required=True)
    parser.add_argument('--bridge-sha256', required=True)
    args = parser.parse_args()
    image = args.image.read_bytes()
    cases_raw = args.cases.read_bytes()
    require(sha256(image).hexdigest() == args.image_sha256, 'native image hash differs')
    require(sha256(cases_raw).hexdigest() == args.cases_sha256, 'fixed development cases differ')
    cases = json.loads(cases_raw)
    expected_ids = [item['name'] for item in cases]
    require(len(cases) == len(set(expected_ids)) == 43, 'fixed case denominator differs')
    sys.path.insert(0, str(args.source))
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    native = NativeHiaJsonImage(image, args.image_sha256)
    bridge_raw = args.bridge.read_bytes()
    require(sha256(bridge_raw).hexdigest() == args.bridge_sha256, 'new byte bridge source differs')
    bridge_name = 'hepta.hia_json_pretty_native'
    require(bridge_name not in sys.modules, 'new bridge module was already imported')
    spec = importlib.util.spec_from_file_location(bridge_name, args.bridge)
    require(spec is not None and spec.loader is not None, 'new bridge module loader unavailable')
    bridge_module = importlib.util.module_from_spec(spec)
    sys.modules[bridge_name] = bridge_module
    spec.loader.exec_module(bridge_module)
    report = {'schema': 'hia.json-pretty-native-cases.v1', 'status': 'HOLD',
              'scope': 'NEW_COMPONENT_DEVELOPMENT_NOT_ORIGINAL_CLI_CALLERS',
              'image_sha256': args.image_sha256, 'cases_sha256': args.cases_sha256,
              'bridge_source_sha256': args.bridge_sha256,
              'bridge_scope': 'NEW_BYTE_TRANSPORT_NOT_ORIGINAL_CLI',
              'installed_bridge_resource_qualified': False,
              'loaded_test_ids': expected_ids, 'executed_test_ids': [], 'tests': [],
              'failures': 0, 'errors': 0, 'skips': 0,
              'expectedFailures': 0, 'unexpectedSuccesses': 0,
              'cold_qualified': False, 'default_activation': False,
              'whole_native_delivery': False}
    started = time.monotonic_ns()
    try:
        for item in cases:
            name = item['name']
            report['executed_test_ids'].append(name)
            entry = {'id': name, 'status': 'HOLD'}
            report['tests'].append(entry)
            print('HIA_JSON_PRETTY_CASE_START_V1 ' + json.dumps({'id': name}), flush=True)
            shared_work = None
            invocations = []
            entry['native_invocations'] = invocations
            try:
                repetition = item.get('repeat_input')
                source_raw = (bytes([repetition['byte']]) * repetition['count'] if repetition
                              else item['wire'].encode('utf-8'))
                if item['kind'] == 'byte_bridge':
                    run_bridge_case(item, entry, bridge_module=bridge_module, image=image,
                                    image_sha256=args.image_sha256, fixtures=cases)
                    continue
                if 'repeat_json_string_bytes' in item:
                    count = item['repeat_json_string_bytes']
                    require(count == 8 << 20 and item['kind'] == 'exact_repeated_string',
                            'fixed exact-limit string descriptor differs')
                    source_raw = b'"' + b'x' * (count - 2) + b'"'
                    require(len(source_raw) == count
                            and sha256(source_raw).hexdigest() == item['expected_sha256'],
                            'complete exact-limit fixture bytes differ')
                def invoke(mode, capacity, workspace=161, *, reuse=False, source_bytes=None):
                    nonlocal shared_work
                    current_source = source_raw if source_bytes is None else source_bytes
                    source_guard = b'\xa5' * 16 + current_source + b'\xa5' * 16
                    source = ctypes.create_string_buffer(source_guard, len(source_guard))
                    output = ctypes.create_string_buffer(b'\xa5' * (capacity + 32), capacity + 32)
                    if reuse and shared_work is not None:
                        require(ctypes.sizeof(shared_work) == workspace + 32,
                                'same workspace extent changed across native calls')
                        work = shared_work
                    else:
                        fill = item.get('workspace_fill', 0)
                        require(type(fill) is int and 0 <= fill <= 255, 'invalid fixed workspace fill')
                        work_raw = b'\xa5' * 16 + bytes([fill]) * workspace + b'\xa5' * 16
                        work = ctypes.create_string_buffer(work_raw, len(work_raw))
                        if reuse:
                            shared_work = work
                    if workspace >= 8:
                        struct.pack_into('<Q', work, 16, mode)
                    entered = time.monotonic_ns()
                    result = native._entry(ctypes.addressof(source) + 16, len(current_source),
                                           ctypes.addressof(output) + 16, capacity,
                                           ctypes.addressof(work) + 16, workspace)
                    elapsed = time.monotonic_ns() - entered
                    observed_output, observed_work = output.raw, work.raw
                    require(source.raw == source_guard, 'native source or source guards changed')
                    require(observed_output[:16] == observed_output[-16:] == b'\xa5' * 16,
                            'native output guard changed')
                    require(observed_work[:16] == observed_work[-16:] == b'\xa5' * 16,
                            'native workspace guard changed')
                    require(type(result) is int and 0 <= result <= 5, 'invalid zero-extended native status')
                    invocations.append({'mode': mode, 'source_bytes': len(current_source),
                        'output_capacity': capacity, 'workspace_bytes': workspace,
                        'workspace_address': hex(ctypes.addressof(work) + 16),
                        'actual_native_return': result, 'native_elapsed_ns': elapsed,
                        'source_unchanged': True, 'all_guard_regions_preserved': True})
                    return result, observed_output[16:16 + capacity], observed_work[16:16 + workspace]
                def word(work, offset):
                    return struct.unpack_from('<Q', work, offset)[0]
                if item['kind'] in ('exact_layout', 'exact_repeated_string'):
                    expected = (source_raw if item['kind'] == 'exact_repeated_string'
                                else item['expected'].encode('utf-8'))
                    status, output, work = invoke(0, 0)
                    require(status == 0 and word(work, 8) == len(expected)
                            and word(work, 16) == word(work, 24) == 0, 'native measurement differs')
                    status, output, work = invoke(1, len(expected))
                    require(status == 0 and output == expected and word(work, 8) == len(expected)
                            and word(work, 16) == word(work, 24) == 0, 'exact native layout differs')
                    entry.update(output_bytes=len(output), output_sha256=sha256(output).hexdigest())
                elif item['kind'] == 'workspace_reuse_refusals':
                    expected = item['expected'].encode('utf-8')
                    require(source_raw == expected == b'null', 'fixed reuse fixture differs')
                    entry['reuse_trials'] = []
                    for reason, mode, rejected in (
                            ('invalid_mode', 13, source_raw),
                            ('over_original_wire_byte_cap', 1, b'x' * ((8 << 20) + 1))):
                        status, output, work = invoke(1, len(expected), reuse=True)
                        require(status == 0 and output == expected and word(work, 8) == len(expected)
                                and word(work, 16) == word(work, 24) == 0,
                                'valid call before workspace refusal differs')
                        before_address = invocations[-1]['workspace_address']
                        status, output, work = invoke(mode, len(expected), reuse=True,
                                                       source_bytes=rejected)
                        # Failure never admits either output or output length.
                        # Inspect only the status/diagnostic contract and guards.
                        require(status == 1 and word(work, 16) == 0 and word(work, 24) == 1,
                                'reused-workspace refusal differs')
                        require(invocations[-1]['workspace_address'] == before_address,
                                'workspace was copied instead of physically reused')
                        entry['reuse_trials'].append({'id': reason, 'status': 'PASS',
                            'actual_status': status, 'same_physical_workspace': True,
                            'failed_output_and_length_discarded': True})
                    require(len({row['workspace_address'] for row in invocations}) == 1,
                            'one workspace must survive all four calls')
                else:
                    status, output, work = invoke(item['mode'], item['output_bytes'],
                                                   item['workspace_bytes'])
                    require(status == item['expected_status'], 'native refusal status differs')
                    if len(work) >= 32:
                        require(word(work, 24) == status, 'native refusal diagnostic differs')
                        if 'expected_error_offset' in item:
                            require(word(work, 16) == item['expected_error_offset'],
                                    'native first-unwritten-byte error offset differs')
                            entry['observed_error_offset'] = word(work, 16)
                    entry.update(expected_status=item['expected_status'], observed_status=status)
                entry.update(status='PASS', input_bytes=len(source_raw),
                             input_sha256=sha256(source_raw).hexdigest())
            except BaseException as error:
                report['failures'] += 1
                entry['error'] = {'type': type(error).__name__, 'message': str(error),
                                  'traceback': traceback.format_exc()}
                raise
        forbidden = [name for name in sys.modules
                     if name in {'hepta.hia_agent_assembly', 'hepta.hia_program_native',
                                 'hepta.hia_machine', 'hepta.hia_machine_elf'}
                     or name.startswith('tools.generate_')]
        report['forbidden_host_compiler_modules_loaded'] = sorted(forbidden)
        require(not forbidden, 'host compiler entered native execution process')
        require(report['loaded_test_ids'] == report['executed_test_ids']
                and len(report['tests']) == 43
                and all(row['status'] == 'PASS' for row in report['tests']),
                'exact complete test denominator differs')
        require(args.image.read_bytes() == image and args.cases.read_bytes() == cases_raw
                and args.bridge.read_bytes() == bridge_raw,
                'native executable or fixtures changed')
        original_cases, bridge_cases = report['tests'][:37], report['tests'][37:]
        require(len(original_cases) == 37 and len(bridge_cases) == 6,
                'original and new bridge test populations differ')
        require(sum(len(row['native_invocations']) for row in original_cases) == 61
                and sum(len(row['native_invocations']) for row in bridge_cases) == 47,
                'actual native invocation population differs')
        report['original37_guarded_native_invocations'] = 61
        report['bridge6_actual_native_invocations'] = 47
        report['bridge6_include_one_host_type_admission_control'] = True
        report['status'] = 'NATIVE_JSON_LAYOUT_DEVELOPMENT_CASES_PASS'
    except BaseException as error:
        report['status'] = 'HOLD'
        report['errors'] += 1
        report['error'] = {'type': type(error).__name__, 'message': str(error),
                           'traceback': traceback.format_exc()}
        traceback.print_exc()
    finally:
        report['wall_elapsed_ns'] = time.monotonic_ns() - started
        raw = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()
        with args.report.open('xb') as stream:
            stream.write(raw)
        require(args.report.read_bytes() == raw, 'native case report readback differs')
    print(json.dumps({'status': report['status'], 'executed': len(report['executed_test_ids']),
                      'failed': report['failures'], 'errors': report['errors']}), flush=True)
    return 0 if report['status'] == 'NATIVE_JSON_LAYOUT_DEVELOPMENT_CASES_PASS' else 1

if __name__ == '__main__':
    raise SystemExit(main())
