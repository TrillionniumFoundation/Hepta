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
    require(len(cases) == len(set(expected_ids)) == 31, 'fixed case denominator differs')
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
            try:
                repetition = item.get('repeat_input')
                source_raw = (bytes([repetition['byte']]) * repetition['count'] if repetition
                              else item['wire'].encode('utf-8'))
                def invoke(mode, capacity, workspace=161):
                    source_guard = b'\xa5' * 16 + source_raw + b'\xa5' * 16
                    source = ctypes.create_string_buffer(source_guard, len(source_guard))
                    output = ctypes.create_string_buffer(b'\xa5' * (capacity + 32), capacity + 32)
                    work_raw = b'\xa5' * 16 + bytes(workspace) + b'\xa5' * 16
                    work = ctypes.create_string_buffer(work_raw, len(work_raw))
                    if workspace >= 8:
                        struct.pack_into('<Q', work, 16, mode)
                    result = native._entry(ctypes.addressof(source) + 16, len(source_raw),
                                           ctypes.addressof(output) + 16, capacity,
                                           ctypes.addressof(work) + 16, workspace)
                    observed_output, observed_work = output.raw, work.raw
                    require(source.raw == source_guard, 'native source or source guards changed')
                    require(observed_output[:16] == observed_output[-16:] == b'\xa5' * 16,
                            'native output guard changed')
                    require(observed_work[:16] == observed_work[-16:] == b'\xa5' * 16,
                            'native workspace guard changed')
                    require(type(result) is int and 0 <= result <= 5, 'invalid zero-extended native status')
                    return result, observed_output[16:16 + capacity], observed_work[16:16 + workspace]
                def word(work, offset):
                    return struct.unpack_from('<Q', work, offset)[0]
                if item['kind'] == 'exact_layout':
                    expected = item['expected'].encode('utf-8')
                    status, output, work = invoke(0, 0)
                    require(status == 0 and word(work, 8) == len(expected)
                            and word(work, 16) == word(work, 24) == 0, 'native measurement differs')
                    status, output, work = invoke(1, len(expected))
                    require(status == 0 and output == expected and word(work, 8) == len(expected)
                            and word(work, 16) == word(work, 24) == 0, 'exact native layout differs')
                    entry.update(output_bytes=len(output), output_sha256=sha256(output).hexdigest())
                else:
                    status, output, work = invoke(item['mode'], item['output_bytes'],
                                                   item['workspace_bytes'])
                    require(status == item['expected_status'], 'native refusal status differs')
                    if len(work) >= 32:
                        require(word(work, 24) == status, 'native refusal diagnostic differs')
                    entry.update(expected_status=item['expected_status'], observed_status=status)
                entry.update(status='PASS', input_bytes=len(source_raw))
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
                and len(report['tests']) == 31
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
