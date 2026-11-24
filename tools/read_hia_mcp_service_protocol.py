"""Independently read exact saved MCP process bytes under the frozen SDK profile.

The original execution report is preserved. This reader checks the current
frozen corpus, each full input and response capture, multiplicity, exit status
and reference/native identities. It separately reports wire-order differences.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
from tools.qualify_hia_mcp_service_protocol import (
    CASES_SHA256, FIXTURES, PROFILES_SHA256, REFERENCE_SHA256,
    compare_case, control_cases, framing_cases, messages_equal)
from tests.hia_mcp_stream_cases import cases as stream_cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.evidence.resolve()
    status_bytes = (root / 'status.json').read_bytes()
    status = json.loads(status_bytes)
    assert status['phase'] == 'completed'
    assert status['pins']['reference'] == REFERENCE_SHA256
    cases_bytes = (FIXTURES / 'hia_mcp_sdk_wire_cases.json').read_bytes()
    profiles_bytes = (FIXTURES / 'hia_mcp_sdk_wire_profiles.json').read_bytes()
    assert sha256(cases_bytes).hexdigest() == CASES_SHA256
    assert sha256(profiles_bytes).hexdigest() == PROFILES_SHA256
    profiles = json.loads(profiles_bytes)
    expected = [(c['name'], bytes.fromhex(c['hex']) + b'\n', None) for c in json.loads(cases_bytes)]
    expected.extend(framing_cases())
    expected.extend(('stream/' + name, raw, None) for name, raw in stream_cases())
    expected.extend(control_cases())
    raw_rows = (root / 'results.jsonl').read_bytes()
    rows = [json.loads(line) for line in raw_rows.splitlines()]
    assert len(rows) == len(expected) == status['count'] == status['expected_count']
    assert sorted(row['index'] for row in rows) == list(range(len(expected)))
    verdicts = []
    for row in sorted(rows, key=lambda value: value['index']):
        index = row['index']
        name, raw, ids = expected[index]
        directory = root / f'{index:04d}'
        assert row['name'] == name and row['expected_ids'] == ids
        assert (directory / 'input.bin').read_bytes() == raw
        assert row['input_sha256'] == sha256(raw).hexdigest()
        for side in ('reference', 'native'):
            original = (directory / (side + '.stdout')).read_bytes()
            messages = [json.loads(line) for line in original.splitlines()]
            assert messages == row[side]['messages']
            assert (directory / (side + '.stderr')).stat().st_size == row[side]['stderr_bytes']
        passed = compare_case(name, row['reference'], row['native'], profiles, ids)
        ordered = messages_equal(row['reference']['messages'], row['native']['messages'], profiles)
        verdicts.append({'index': index, 'name': name, 'passed': passed,
                         'ordered_response_match': ordered})
    report = {'schema': 'hepta.hia.mcp-protocol-independent-readback.v1',
              'passed': all(row['passed'] for row in verdicts), 'count': len(verdicts),
              'failed': sum(not row['passed'] for row in verdicts),
              'wire_order_differences': sum(not row['ordered_response_match'] for row in verdicts),
              'comparison': profiles['comparison'], 'pins': status['pins'],
              'original_execution_status_sha256': sha256(status_bytes).hexdigest(),
              'original_rows_sha256': sha256(raw_rows).hexdigest(),
              'original_ordered_verdict': status['passed'],
              'profiles_sha256': PROFILES_SHA256, 'cases': verdicts}
    with args.output.open('x') as output:
        output.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: value for key, value in report.items() if key != 'cases'}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
