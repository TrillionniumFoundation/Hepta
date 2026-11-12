"""Execute the fixed development JSON-layout cases in a disposable native process."""
from __future__ import annotations
import argparse
import ctypes
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

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--image-sha256', required=True)
    parser.add_argument('--cases', type=Path, required=True)
    parser.add_argument('--cases-sha256', required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    image = args.image.read_bytes()
    cases_raw = args.cases.read_bytes()
    require(sha256(image).hexdigest() == args.image_sha256, 'native image hash differs')
    require(sha256(cases_raw).hexdigest() == args.cases_sha256, 'fixed development cases differ')
    cases = json.loads(cases_raw)
    expected_ids = [item['name'] for item in cases]
    require(len(cases) == len(set(expected_ids)) == 37, 'fixed case denominator differs')
    sys.path.insert(0, str(args.source))
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    native = NativeHiaJsonImage(image, args.image_sha256)
    report = {'schema': 'hia.json-pretty-native-cases.v1', 'status': 'HOLD',
              'scope': 'NEW_COMPONENT_DEVELOPMENT_NOT_ORIGINAL_CLI_CALLERS',
              'image_sha256': args.image_sha256, 'cases_sha256': args.cases_sha256,
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
                and len(report['tests']) == 37
                and all(row['status'] == 'PASS' for row in report['tests']),
                'exact complete test denominator differs')
        require(args.image.read_bytes() == image and args.cases.read_bytes() == cases_raw,
                'native executable or fixtures changed')
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
