"""Recheck every pinned original typed history error on the real native service."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
from tools.qualify_hia_mcp_request_history_public import Session, pin
from tools.qualify_hia_mcp_request_history import snapshot


def qualify(bundle, reference, output):
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    cases_path = reference/'params-cases-v2.jsonl'
    oracle_path = reference/'params-observations-v2.jsonl'
    assert pin(cases_path) == 'cd4f3e649b09482264c2f3d2a39ec650e48baf111c2555d6640fa257b527005c'
    assert pin(oracle_path) == 'b5e2c9efaa7bf1a8854205e20e872795d15f84a85edca5e743b96505d6d2d76a'
    expected = {row['id']: row for row in map(json.loads, oracle_path.read_bytes().splitlines())}
    rows = []
    report = {'schema': 'hepta.hia.metadata-parameter-regression.v1',
              'passed': False, 'scope': 'real native stdio original typed error objects',
              'service_sha256': pin(bundle/'hia-mcp-service'),
              'cases_sha256': pin(cases_path), 'oracle_sha256': pin(oracle_path),
              'whole_cold_qualified': False, 'checks': rows}
    session = Session(bundle, output/'stdio')
    try:
        before = snapshot(session.state)
        for item in map(json.loads, cases_path.read_bytes().splitlines()):
            baseline = expected[item['id']]
            if 'error' not in baseline:
                continue
            response = session.history(item['params_json'], item['id'])
            assert response.get('error') == baseline['error'], (item['id'], response, baseline)
            assert snapshot(session.state) == before
            rows.append({'case': item['id'], 'exact_original_error_equal': True, 'passed': True})
        large = reference.parent/'hia_usage_oracle/diagnostics.json'
        assert pin(large) == '8ee3539beb7f9987785a6ba86622f9feb7c030fecc9fc6a731c00d12d3a53d44'
        baseline = next(item for item in json.loads(large.read_text())['cases'] if item['id']=='ascii-over-1m')
        response = session.history(json.dumps({'limit': 'x'*1048577}), 'diagnostic-string-cap')
        error = response.get('error', {})
        message = error.get('message', '').encode()
        assert error.get('code') == baseline['code']
        assert len(message) == baseline['message_bytes']
        assert sha256(message).hexdigest() == baseline['message_sha256']
        assert snapshot(session.state) == before
        rows.append({'case': 'diagnostic-string-cap', 'exact_original_error_equal': True, 'passed': True})
        report.update(passed=True, passed_checks=len(rows))
        return report
    finally:
        session.close()
        (output/'qualification.json').write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('bundle', 'reference', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(qualify(args.bundle.resolve(), args.reference.resolve(), args.output.resolve())))


if __name__ == '__main__':
    main()
