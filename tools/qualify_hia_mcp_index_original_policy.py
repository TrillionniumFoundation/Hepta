"""Replay independent original Rust observations through the actual native image.

The reference contains fixture inputs and observations of original functions.
It has no native expected values. Compare every observable policy word and every
complete retained record; allocator indices and wall-clock fixture times are not
part of the cross-language policy ABI.
"""
from __future__ import annotations
import argparse
import ctypes
import gzip
from hashlib import sha256
import json
from pathlib import Path
import runpy
import struct

from hepta.hia_json_preflight_native import NativeHiaJsonImage


def qualify(image_path, construction_path, reference_path, author_path, output):
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    construction = json.loads(construction_path.read_text())
    image_bytes = image_path.read_bytes()
    assert sha256(image_bytes).hexdigest() == construction['native_image_sha256']
    assert sha256(author_path.read_bytes()).hexdigest() == construction['author_sha256']
    layout = runpy.run_path(str(author_path))['C']
    image = NativeHiaJsonImage(image_bytes, sha256(image_bytes).hexdigest())
    capacity = 32 << 20
    workspace = ctypes.create_string_buffer(capacity+64)
    address = ctypes.addressof(workspace)+32
    ctypes.memset(address-32, 0xa5, 32)
    ctypes.memset(address+capacity, 0xa5, 32)
    target = ctypes.create_string_buffer(544)
    report = {'schema': 'hepta.hia.original-index-policy-native-comparison.v1',
              'passed': False, 'observer_sha256': sha256(Path(__file__).read_bytes()).hexdigest(),
              'author_sha256': sha256(author_path.read_bytes()).hexdigest(),
              'native_image_sha256': sha256(image_bytes).hexdigest(),
              'construction_sha256': sha256(construction_path.read_bytes()).hexdigest(),
              'reference_sha256': sha256(reference_path.read_bytes()).hexdigest(),
              'observations': 0, 'native_calls': 0, 'complete_records': 0,
              'mismatches': [], 'whole_runtime_qualified': False,
              'disk_index_qualified': False, 'public_integration_qualified': False}
    raw_hash = sha256()
    raw_bytes = 0

    def native_call(op, args, data=b''):
        raw = struct.pack('<8Q', op, *(list(args)+[0]*(7-len(args))))+data
        source = ctypes.create_string_buffer(raw)
        ctypes.memset(target, 0xa7, 544)
        status = image._entry(source, len(raw), target, 544, address, capacity)
        assert status in (160, 544), (op, status)
        response = bytes(target.raw[:status])
        assert target.raw[status:] == b'\xa7'*(544-status)
        assert source.raw[:len(raw)] == raw
        assert ctypes.string_at(address-32, 32) == ctypes.string_at(address+capacity, 32) == b'\xa5'*32
        report['native_calls'] += 1
        return {'input_hex': raw.hex(), 'returncode': status, 'output_hex': response.hex()}, response

    try:
        with (output/'native-observations.jsonl.gz').open('wb') as physical:
            with gzip.GzipFile(fileobj=physical, mode='wb', mtime=0) as sink:
                with gzip.open(reference_path, 'rt') as reference:
                    for line in reference:
                        row = json.loads(line)
                        calls = []
                        answer = None
                        for action in row['actions']:
                            if 'fixture' in action:
                                call, answer = native_call(0, [])
                                calls.append(call)
                                packed = struct.pack('<12Q', *action['fixture'])
                                ctypes.memmove(address+layout['I_BASE'], packed, len(packed))
                                calls.append({'fixture_header_hex': packed.hex()})
                                answer = None
                            else:
                                call, answer = native_call(action['op'], action['args'], bytes.fromhex(action.get('data_hex', '')))
                                calls.append(call)
                        state_bytes = ctypes.string_at(address+layout['I_BASE'], 96)
                        actual_state = list(struct.unpack('<12Q', state_bytes))
                        problems = []
                        if 'state_words' in row and actual_state != row['state_words']:
                            problems.append({'kind': 'policy_state', 'expected': row['state_words'], 'actual': actual_state})
                        if row.get('status') is not None:
                            assert answer is not None
                            status, = struct.unpack('<Q', answer[:8])
                            if status != row['status']:
                                problems.append({'kind': 'operation_status', 'expected': row['status'], 'actual': status})
                        extra = row.get('extra') or {}
                        if 'entry_hex' in extra:
                            report['complete_records'] += 1
                            assert answer is not None
                            if answer[160:].hex() != extra['entry_hex']:
                                problems.append({'kind': 'complete_entry', 'expected': extra['entry_hex'], 'actual': answer[160:].hex()})
                        if 'claimed' in extra:
                            claim = struct.unpack('<2Q', ctypes.string_at(address+layout['I_BASE']+112, 16))
                            if list(claim) != [extra['claimed'], extra['generation']]:
                                problems.append({'kind': 'claim_custody', 'expected': [extra['claimed'], extra['generation']], 'actual': list(claim)})
                        if problems:
                            report['mismatches'].append({'case': row['case'], 'differences': problems})
                        observed = {'case': row['case'], 'calls': calls, 'state_hex': state_bytes.hex(), 'matched': not problems}
                        raw = (json.dumps(observed, separators=(',', ':'))+'\n').encode()
                        sink.write(raw);raw_hash.update(raw);raw_bytes += len(raw)
                        report['observations'] += 1
        report['passed'] = not report['mismatches']
        return report
    finally:
        report.update(raw_bytes=raw_bytes, raw_sha256=raw_hash.hexdigest())
        path = output/'native-observations.jsonl.gz'
        if path.exists():
            raw = path.read_bytes()
            report.update(compressed_bytes=len(raw), compressed_sha256=sha256(raw).hexdigest())
        (output/'qualification.json').write_text(json.dumps(report, indent=2)+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('image', 'construction', 'reference', 'author', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    report = qualify(args.image, args.construction, args.reference, args.author, args.output)
    print(json.dumps({key: report[key] for key in ('passed', 'observations', 'native_calls', 'complete_records', 'mismatches')}))
    if not report['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
