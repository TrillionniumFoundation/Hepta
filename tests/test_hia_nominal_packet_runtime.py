"""Compare the installed standalone HIA packet boundary to its reference."""
import argparse
import json
from pathlib import Path
import struct
import subprocess

from tests.test_hia_nominal_json_native import (
    BAD_ABI, BAD_BUDGET, BAD_BYTES, BAD_DUPLICATE, BAD_INTEGER, BAD_JSON,
    HEADER, MAX_BYTES, REPLY_MAGIC, REQUEST_MAGIC, reference,
)


def check(executable, root):
    def run(raw, digits=4300, wrapper=False, legacy=False, *, count=None, trailer=b''):
        request = HEADER.pack(REQUEST_MAGIC, digits, int(wrapper), int(legacy), 0, 0, 0, 0)
        request += struct.pack('<Q', len(raw) if count is None else count) + raw + trailer
        result = subprocess.run([executable], input=request, capture_output=True, env={'PATH': ''},
                                timeout=20, check=False)
        assert not result.stderr
        return result.returncode, result.stdout

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
        schema = json.loads(raw)['schema']
        profiles.add(schema)
        for wrapper, legacy in ((False, False), (True, False), (True, True)):
            oracle(raw, 4300, wrapper, legacy)
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
    print(f'{checks} exact repository packet cases across {documents} sources; '
          f'{len(invalid) + 7} exact byte, digit, budget and framing controls')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('executable', type=Path)
    args = parser.parse_args()
    check(args.executable, Path(__file__).resolve().parents[1])
