"""Compare real native stdio usage with the complete pinned Rust implementation."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import time

from tools.qualify_hia_mcp_request_archive_public import ArchiveSession, audit_child
from tools.qualify_hia_mcp_request_archive import DEADLINE
from tools.qualify_hia_mcp_request_history import snapshot


def pin(path):
    return sha256(path.read_bytes()).hexdigest()


class UsageSession(ArchiveSession):
    def usage(self, params='{}', label='usage', *, omit_arguments=False):
        if omit_arguments:
            self.connection.send({'jsonrpc': '2.0', 'id': label, 'method': 'tools/call',
                                  'params': {'name': 'usage_stats'}})
        else:
            raw = ('{"jsonrpc":"2.0","id":'+json.dumps(label)+
                   ',"method":"tools/call","params":{"name":"usage_stats","arguments":'+params+'}}\n').encode()
            self.connection.process.stdin.write(raw)
            self.connection.process.stdin.flush()
            (self.directory/(f'{self.sequence+1:03d}-'+label+'.input')).write_bytes(raw)
        response = self.connection.read()
        assert response.get('id') == label, response
        return self.record(label, response)


def compare(response, baseline, label):
    if 'text' in baseline or 'tool_error' in baseline:
        error = 'tool_error' in baseline
        text = baseline['tool_error'] if error else baseline['text']
        value = response.get('result', {})
        assert value.get('isError') is error, (label, response)
        assert value.get('content') == [{'type': 'text', 'text': text}], (label, response, baseline)
        if 'resultType' in value:
            assert value['resultType'] == 'complete'
        return 'tool_error' if error else 'success'
    assert response.get('error') == baseline['parameter_error'], (label, response, baseline)
    return 'parameter_error'


def qualify(bundle, original, extended, output):
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    checks = []
    report = {'schema': 'hepta.hia.usage-public-original-comparison.v1', 'passed': False,
              'scope': 'actual native stdio usage_stats', 'checks': checks,
              'original_source_ref': 'ae1c7ea593da45f7299c692a2acd44605c35be09',
              'service_sha256': pin(bundle/'hia-mcp-service'),
              'manifest_sha256': pin(bundle/'hia-controller.json'),
              'whole_cold_qualified': False, 'installed_worker_claimed': False, 'http_qualified': False,
              'live_registry_scope': 'original live registry excluded here; real native kernel-ticket control is separate',
              'query_budget_seconds': 3, 'references': {}}
    empty = None
    try:
        for family, cases_path, oracle_path in (
            ('original', original/'cases-v1.json', original/'observations-v2.json'),
            ('extended', extended/'extended-cases.json', extended/'extended-observations.json'),
        ):
            cases = json.loads(cases_path.read_bytes())
            oracle = json.loads(oracle_path.read_bytes())
            assert oracle.get('executable_sha256', oracle.get('reference_binary_sha256')) == '4148a73a93a8ae36a41837d86f56e18e5d86b21b7695b0e42ec3698c978b80af'
            report['references'][family] = {'cases_sha256': pin(cases_path), 'oracle_sha256': pin(oracle_path)}
            expected = {}
            for row in oracle['results']:
                values = {q['id']: q['result'] for q in row['observation']['queries']}
                if row['repeat'] == 0:
                    expected[row['case']] = values
                else:
                    assert expected[row['case']] == values, row['case']
            for index, case in enumerate(cases):
                queries = [q for q in case['queries'] if q['kind'] == 'usage']
                if not queries or case.get('active_ids'):
                    continue
                session = UsageSession(bundle, output/(family+f'-{index:03d}-'+case['id']))
                try:
                    owner = session.owner()
                    assert owner not in (case['owner'], 'b'*64, 'c'*64)
                    session.replace_archive(case, owner)
                    before = snapshot(session.state)
                    for query in queries:
                        baseline = expected[case['id']][query['id']]
                        response = session.usage(query['params_json'], query['id'])
                        kind = compare(response, baseline, (case['id'], query['id']))
                        assert snapshot(session.state) == before, (case['id'], query['id'])
                        checks.append({'case': case['id'], 'query': query['id'], 'kind': kind,
                                       'exact_original_text_equal': True, 'passed': True})
                        print('NATIVE_USAGE_PUBLIC_PASS', case['id'], query['id'], kind, flush=True)
                        if case['id'] == 'empty':
                            empty = baseline
                finally:
                    session.close()

        assert empty is not None
        session = UsageSession(bundle, output/'catalog-and-argument-defaults')
        try:
            session.connection.send({'jsonrpc': '2.0', 'id': 'catalog', 'method': 'tools/list', 'params': {}})
            response = session.record('catalog', session.connection.read())
            tools = response['result']['tools']
            selected = [tool for tool in tools if tool['name'] == 'usage_stats']
            assert len(tools) == 14 and len(selected) == 1
            schema = json.loads((extended/'usage-schema.json').read_bytes())
            schema.pop('$schema', None)
            assert selected[0]['inputSchema'] == schema, (selected[0]['inputSchema'], schema)
            assert selected[0]['annotations'] == {'readOnlyHint': True, 'destructiveHint': False,
                                                  'idempotentHint': True, 'openWorldHint': False}
            before = snapshot(session.state)
            compare(session.usage(label='omitted', omit_arguments=True), empty, 'omitted')
            compare(session.usage('null', 'null'), empty, 'null')
            assert snapshot(session.state) == before
            checks.append({'case': 'original-schema-and-null-or-omitted-arguments', 'passed': True})
        finally:
            session.close()

        session = UsageSession(bundle, output/'public-deadline-and-stale-response')
        child = audit_child(session)
        try:
            before = snapshot(session.state)
            os.kill(child, signal.SIGSTOP)
            wait = time.monotonic()+1
            while 'State:\tT' not in Path(f'/proc/{child}/status').read_text():
                assert time.monotonic() < wait
                time.sleep(0.005)
            started = time.monotonic()
            compare(session.usage(label='deadline'), {'tool_error': DEADLINE}, 'deadline')
            elapsed = time.monotonic()-started
            assert 2.5 <= elapsed < 4.5, elapsed
            assert snapshot(session.state) == before
            os.kill(child, signal.SIGCONT)
            compare(session.usage(label='fresh-after-stale'), empty, 'stale-generation')
            assert snapshot(session.state) == before
            checks.append({'case': 'absolute-three-second-deadline-and-stale-generation-drain',
                           'seconds': elapsed, 'passed': True})
        finally:
            os.kill(child, signal.SIGCONT)
            session.close()
        report.update(passed=True, passed_checks=len(checks))
        return report
    finally:
        (output/'qualification.json').write_text(json.dumps(report, indent=2)+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('bundle', 'original', 'extended', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(qualify(args.bundle.resolve(), args.original.resolve(), args.extended.resolve(), args.output.resolve())))


if __name__ == '__main__':
    main()
