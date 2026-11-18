"""Compare the installed standalone HIA packet boundary to its reference."""
import argparse
import json
from pathlib import Path
import random
import struct
import subprocess

from hepta.hia_instruction_policy_native import transport
from tests.test_hia_nominal_json_native import (
    BAD_ABI, BAD_BUDGET, BAD_BYTES, BAD_DUPLICATE, BAD_INTEGER, BAD_JSON,
    HEADER, MAX_BYTES, REPLY_MAGIC, REQUEST_MAGIC, reference,
)


def check(executable, root):
    def exchange(header, raw, count, trailer):
        request = header + struct.pack('<Q', len(raw) if count is None else count) + raw + trailer
        result = subprocess.run([executable], input=request, capture_output=True, env={'PATH': ''},
                                timeout=20, check=False)
        assert not result.stderr
        return result.returncode, result.stdout

    def run(raw, digits=4300, wrapper=False, legacy=False, *, count=None, trailer=b''):
        header = HEADER.pack(REQUEST_MAGIC, digits, int(wrapper), int(legacy), 0, 0, 0, 0)
        return exchange(header, raw, count, trailer)

    def render(packet, *, reserved=0, count=None, trailer=b''):
        header = struct.pack('<8s7Q', b'HIAJTQ01', reserved, 0, 0, 0, 0, 0, 0)
        return exchange(header, packet, count, trailer)

    def compact(value):
        return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode()

    def node_count(value):
        if type(value) is list:
            return 1 + sum(map(node_count, value))
        if type(value) is dict:
            return 1 + len(value) + sum(map(node_count, value.values()))
        return 1

    def check_render(packet, value):
        expected = compact(value)
        observed = struct.pack('<8s7Q', b'HIAJTP01', len(expected), len(packet),
                               node_count(value), 0, 0, 0, 1) + expected
        assert render(packet) == (0, observed)

    def oracle(raw, digits=4300, wrapper=False, legacy=False):
        status, payload, nodes = reference(raw, digits=digits, wrapper=wrapper, legacy=legacy)
        if status:
            expected = 65, struct.pack('<8sQ', b'HIANJE01', status)
        else:
            custody = HEADER.pack(REPLY_MAGIC, len(payload), digits, int(wrapper), int(legacy),
                                  len(raw), nodes, 1)
            expected = 0, custody + payload
        assert run(raw, digits, wrapper, legacy) == expected

    profiles, documents, checks = set(), 0, 0
    roots = ('examples', 'experiments', 'formal', 'tests/fixtures')
    sources = sorted(path for folder in roots for path in (root / folder).rglob('*.hepta'))
    for path in sources:
        raw = path.read_bytes()
        if not raw.lstrip().startswith(b'{'):
            continue
        value = json.loads(raw)
        profiles.add(value['schema'])
        for wrapper, legacy in ((False, False), (True, False), (True, True)):
            oracle(raw, 4300, wrapper, legacy)
            status, reply = run(raw, 4300, wrapper, legacy)
            assert status == 0
            check_render(reply[64:], [value, legacy] if wrapper else value)
            checks += 1
        documents += 1
    assert {'hepta.hia.composite.v1', 'hepta.hia.composite.v2', 'hepta.hia.composite.v3'} <= profiles

    invalid = (
        (b'', BAD_JSON),
        (b'{"a":0,"\\u0061":1}', BAD_DUPLICATE),
        (b'{"a":0,"\\u0061":1}\xff', BAD_JSON),
        (b'1.5', BAD_JSON),
        (b'1' * 641, BAD_INTEGER),
        (b'[' * 129 + b'0' + b']' * 129, BAD_BUDGET),
    )
    for raw, status in invalid:
        assert run(raw, 640) == (65, struct.pack('<8sQ', b'HIANJE01', status))
        oracle(raw, 640)
    oracle(b'1' * 641, 0, True, True)
    oracle(b'{}' + b' ' * (MAX_BYTES - 2))
    assert run(b'', count=MAX_BYTES + 1) == (65, struct.pack('<8sQ', b'HIANJE01', BAD_BYTES))
    assert run(b'{}', 639) == (65, struct.pack('<8sQ', b'HIANJE01', BAD_ABI))
    assert run(b'{}', legacy=True) == (65, struct.pack('<8sQ', b'HIANJE01', BAD_ABI))
    assert run(b'{', count=2) == (64, b'')
    assert run(b'{}', trailer=b'\0') == (64, b'')
    # Include every escaped ASCII control and path/wide integer values used
    # in resolver commands, while retaining insertion order, not sorted keys.
    controls = ''.join(map(chr, range(32))) + '"\\/@éλ中🏺' + chr(127)
    values = [None, True, False, 0, -1, 2**256, '', [], {}, controls,
              {'op': 'origins', 'params': [[controls, 15]], 'returns': [6],
               'return_loans': [[controls, 'field']]},
              {'op': 'task_protocol', 'task': 12, 'functions': [['f', [7], [8]]]},
              {'op': 'resolve', 'ref': {'record': 'Example', 'args': [['u8'], 'u64']}}]
    rng = random.Random(2829)
    for _ in range(40):
        value = rng.choice(values[:13])
        for level in range(4):
            if rng.randrange(2):
                value = [bool(level), value, rng.randint(-1000, 1000)]
            else:
                value = {controls[:level]: value, 'x': [], 'é': rng.choice(values[:10])}
        values.append(value)
    depth = []
    for _ in range(129):
        depth = [depth]
    values.append(depth)
    for value in values:
        check_render(transport(value), value)
    output_limit = MAX_BYTES + 128
    large = 'a' * (output_limit - 2)
    check_render(transport(large), large)
    assert render(transport(large + 'a')) == (65, struct.pack('<8sQ', b'HIANJE01', BAD_BUDGET))

    def frame(kind, body):
        return struct.pack('<QQ', kind, len(body)) + body

    bad_packets = (b'', transport(None)[:-1], transport(0) + b'0', frame(7, b''),
                   frame(1, b'\x02'), frame(4, b'\xed\xa0\x80'),
                   frame(2, b'-0'), frame(2, b'01'), frame(2, b'+3'), frame(2, b'1x'),
                   frame(5, struct.pack('<Q', 1)),
                   frame(6, struct.pack('<Q', 1) + transport(2) + transport('v')))
    for packet in bad_packets:
        assert render(packet) == (65, struct.pack('<8sQ', b'HIANJE01', BAD_JSON))
    assert render(transport([depth])) == (65, struct.pack('<8sQ', b'HIANJE01', BAD_BUDGET))
    assert render(transport(0), reserved=1) == (65, struct.pack('<8sQ', b'HIANJE01', BAD_ABI))
    assert render(b'', count=(32 << 20) + 1) == (65, struct.pack('<8sQ', b'HIANJE01', BAD_BYTES))
    assert render(b'', count=1) == (64, b'')
    assert render(transport(0), trailer=b'1') == (64, b'')
    print(f'{checks} exact repository JSON round trips; '
          f'{len(values) + 1} additional rendering cases and {len(bad_packets) + 6} controls')
    print(f'{checks} exact repository packet cases across {documents} sources; '
          f'{len(invalid) + 7} exact byte, digit, budget and framing controls')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('executable', type=Path)
    args = parser.parse_args()
    check(args.executable, Path(__file__).resolve().parents[1])
