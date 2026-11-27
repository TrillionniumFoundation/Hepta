"""Observe held HTTP credential ownership and session cache isolation."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path

from tools.qualify_hia_mcp_metadata_http import HTTP, encoded, events, pin, rpc
from tools.qualify_hia_mcp_request_history import snapshot, CURSOR
from tools.qualify_hia_mcp_request_archive import UNAVAILABLE


def qualify(bundle, output):
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    checks = []
    report = {'schema': 'hepta.hia.metadata-http-held-authority.v1', 'passed': False,
              'executable_sha256': pin(bundle/'hia-mcp-http'), 'checks': checks,
              'whole_cold_qualified': False, 'installed_worker_claimed': False}
    server = None

    def request(tool, arguments, ident):
        meta, raw = server.exchange(server.call(tool, arguments, ident), label=ident)
        assert meta['status'] == 200, (meta, raw[:256])
        value = rpc(raw)
        assert value['id'] == ident
        return value, raw

    def rows(tool, ident):
        value, raw = request(tool, {}, ident)
        assert value['result']['isError'] is False, value
        return json.loads(value['result']['content'][0]['text'])['requests'], raw

    def passed(name, **values):
        checks.append({'case': name, 'passed': True, **values})
        print('NATIVE_METADATA_HTTP_AUTHORITY_PASS', name, flush=True)

    try:
        server = HTTP(bundle, output/'first')
        server.initialize()
        value, _ = request('hia_describe', {'unexpected': True}, 'observe-held-owner')
        assert value['error']['code'] == -32602
        records = list((server.state/'request-audit').glob('*.json'))
        assert len(records) == 1, records
        record = json.loads(records[0].read_bytes())
        owner = sha256(b'hepta-runtime/private-operator-credential/v1\0'+server.token.encode()).hexdigest()
        assert record['owner'] == owner and record['tool_name'] == 'hia_describe', record
        before = snapshot(server.state)
        for tool in ('request_history', 'request_archive'):
            found, raw = rows(tool, 'held-'+tool)
            assert len(found) == 1 and found[0]['request_id'] == record['request_id'], found
            stream = events(raw)[1]['id'].split('/')[1]
        assert snapshot(server.state) == before
        passed('trusted-owner-derived-from-held-private-credential', owner=owner)

        previous_session = server.session
        server.initialize()
        assert server.session != previous_session
        meta, raw = server.exchange(method='GET', headers={'Last-Event-ID': '1/'+stream}, label='other-session-cache')
        assert meta['status'] == 200 and raw == b''
        found, _ = rows('request_history', 'same-credential-fresh-session')
        assert len(found) == 1 and found[0]['request_id'] == record['request_id']
        assert snapshot(server.state) == before
        passed('same-credential-metadata-resumes-with-separate-session-cache')

        state = server.state
        server.close()
        server = None
        server = HTTP(bundle, output/'restart-same-credential', state=state)
        server.initialize()
        for tool in ('request_history', 'request_archive'):
            found, _ = rows(tool, 'restart-'+tool)
            assert len(found) == 1 and found[0]['request_id'] == record['request_id']
        assert snapshot(server.state) == before
        passed('same-credential-restart-retains-held-metadata-authority')

        server.close()
        server = None
        server = HTTP(bundle, output/'different-credential', state=state,
                      token='hia-http-metadata-independent-fixture-token-20261127')
        server.initialize()
        for tool in ('request_history', 'request_archive'):
            found, _ = rows(tool, 'different-'+tool)
            assert found == []
            value, _ = request(tool, {'after_id': record['request_id']}, 'foreign-cursor-'+tool)
            assert value['result']['isError'] is True
            expected = CURSOR if tool == 'request_history' else UNAVAILABLE
            assert value['result']['content'] == [{'type': 'text', 'text': expected}]
        assert snapshot(server.state) == before
        passed('different-held-credential-cannot-project-records-or-cursors')
        report.update(passed=True, passed_checks=len(checks))
        return report
    finally:
        if server is not None:
            server.close()
        (output/'qualification.json').write_text(json.dumps(report, indent=2)+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = qualify(args.bundle.resolve(), args.output.resolve())
    print(json.dumps({'passed': report['passed'], 'checks': len(report['checks'])}))


if __name__ == '__main__':
    main()
