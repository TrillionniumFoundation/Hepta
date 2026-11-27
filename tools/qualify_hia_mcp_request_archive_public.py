"""Compare the real native stdio archive tool with complete original Rust.

The controller contains actual seed-built native executables. The configured
Worker is a fixture; these controls claim neither installation nor HTTP parity.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import time

from tools.qualify_hia_mcp_request_history_public import Session, pin
from tools.qualify_hia_mcp_request_history import snapshot
from tools.qualify_hia_mcp_request_archive import seed_archive, UNAVAILABLE, DEADLINE
from tests.hia_request_audit_native_support import write_json


class ArchiveSession(Session):
    def archive(self, params='{}', label='archive', *, omit_arguments=False):
        if omit_arguments:
            self.connection.send({'jsonrpc':'2.0','id':label,'method':'tools/call',
                                  'params':{'name':'request_archive'}})
        else:
            raw=('{"jsonrpc":"2.0","id":'+json.dumps(label)+
                 ',"method":"tools/call","params":{"name":"request_archive","arguments":'+params+'}}\n').encode()
            self.connection.process.stdin.write(raw)
            self.connection.process.stdin.flush()
            (self.directory/(f'{self.sequence+1:03d}-'+label+'.input')).write_bytes(raw)
        response=self.connection.read()
        assert response.get('id')==label,response
        return self.record(label,response)

    def replace_archive(self, case, owner):
        # Only this freshly created observer scope is changed, while no request
        # is running. The production held namespace identities remain intact.
        hot=self.state/'request-audit'
        legacy=self.state/'request-archive-v11'
        for folder in (hot,legacy):
            paths=list(folder.glob('*.json'))
            assert len(paths)==1
            existing=json.loads(paths[0].read_text())
            assert existing['owner']==owner and existing['tool_name']=='hia_describe'
            paths[0].unlink()
        records=[json.loads(raw.replace('"owner":"'+case['owner']+'"',
                                       '"owner":"'+owner+'"')) for raw in case['records']]
        seed_archive(self.state,records,shard_after=case.get('shard_after'))
        wanted=set(case.get('hot_ids',[]))
        for row in records:
            if row['request_id'] in wanted:
                write_json(hot/(row['request_id']+'.json'),row)


def audit_child(session):
    pid=session.connection.process.pid
    found=[]
    for child in Path(f'/proc/{pid}/task/{pid}/children').read_text().split():
        path=Path('/proc')/child/'cmdline'
        if path.read_bytes()==b'hia-mcp-request-audit\0':
            found.append(int(child))
    assert len(found)==1,found
    return found[0]


def qualify(bundle,cases_path,oracle_path,output):
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    assert pin(cases_path)=='86feb3e773333491365c8d279c9ffad59da7ca236a162af0247a57a616d870c8'
    assert pin(oracle_path)=='ae4ce6424bffdac9ee4d88f7fbc5caf0e69fbec244afc27e07122d0deda8fe3d'
    oracle=json.loads(oracle_path.read_text())
    assert oracle['executable_sha256']=='4148a73a93a8ae36a41837d86f56e18e5d86b21b7695b0e42ec3698c978b80af'
    assert oracle['all_original_results_repeatable'] is True
    assert (oracle['cases'],oracle['queries'],oracle['repetitions'])==(11,46,2)
    cases=json.loads(cases_path.read_text())
    expected={r['case']:{q['id']:q['result'] for q in r['observation']['queries']}
              for r in oracle['results'] if r['repeat']==1}
    rows=[]
    report={'schema':'hepta.hia.request-archive-public-original-comparison.v1',
            'passed':False,'scope':'actual native stdio request_archive',
            'original_source_ref':'ae1c7ea593da45f7299c692a2acd44605c35be09',
            'cases_sha256':pin(cases_path),'oracle_sha256':pin(oracle_path),
            'service_sha256':pin(bundle/'hia-mcp-service'),'manifest_sha256':pin(bundle/'hia-controller.json'),
            'whole_cold_qualified':False,'installed_worker_claimed':False,'http_qualified':False,
            'usage_queries_excluded':True,'live_registry_exclusion':'actual native live kernel-ticket control is separate',
            'query_budget_seconds':3,'typed_diagnostic_decoded_string_limit':1048576,
            'over_limit_error_text_parity_claimed':False,'checks':rows}
    try:
        for index,case in enumerate(cases):
            queries=[q for q in case['queries'] if q['kind']=='archive']
            if not queries or case.get('active_ids'):
                continue
            session=ArchiveSession(bundle,output/(f'{index:03d}-'+case['id']))
            try:
                owner=session.owner()
                assert owner not in (case['owner'],'b'*64,'c'*64)
                session.replace_archive(case,owner)
                before=snapshot(session.state)
                for query in queries:
                    baseline=expected[case['id']][query['id']]
                    response=session.archive(query['params_json'],query['id'])
                    if 'text' in baseline:
                        value=response['result']
                        assert value['isError'] is False
                        assert value['content']==[{'type':'text','text':baseline['text']}],(case['id'],query['id'],response,baseline)
                        if 'resultType' in value:assert value['resultType']=='complete'
                        kind='success'
                    elif 'tool_error' in baseline:
                        value=response['result']
                        assert value['isError'] is True
                        assert value['content']==[{'type':'text','text':baseline['tool_error']}],(case['id'],query['id'],response,baseline)
                        kind='tool_error'
                    else:
                        assert response.get('error')==baseline['parameter_error'],(case['id'],query['id'],response,baseline)
                        kind='parameter_error'
                    assert snapshot(session.state)==before,(case['id'],query['id'],'query changed retained originals')
                    rows.append({'case':case['id'],'query':query['id'],'kind':kind,'exact_text_equal':True,'passed':True})
                    print('NATIVE_ARCHIVE_PUBLIC_PASS',case['id'],query['id'],kind,flush=True)
            finally:
                session.close()

        empty=expected['empty']['default']['text']
        discovery=ArchiveSession(bundle,output/'discovery')
        try:
            discovery.connection.send({'jsonrpc':'2.0','id':'catalog','method':'tools/list','params':{}})
            result=discovery.record('catalog',discovery.connection.read())
            tools=result['result']['tools']
            archive=[r for r in tools if r['name']=='request_archive']
            assert len(tools)==13 and len(archive)==1
            schema=json.loads((cases_path.parent.parent/'hia_request_history_oracle/oracle-params-schema.json').read_text())
            schema.pop('$schema',None)
            assert archive[0]['inputSchema']==schema
            assert archive[0]['annotations']=={'readOnlyHint':True,'destructiveHint':False,'idempotentHint':True,'openWorldHint':False}
            before=snapshot(discovery.state)
            for response in (discovery.archive(label='omitted',omit_arguments=True),discovery.archive('null','null-arguments')):
                assert response['result']['content']==[{'type':'text','text':empty}]
            assert snapshot(discovery.state)==before
            rows.append({'case':'catalog-original-schema-and-null-or-omitted-arguments','passed':True})
        finally:
            discovery.close()

        delayed=ArchiveSession(bundle,output/'deadline-and-old-response')
        child=audit_child(delayed)
        try:
            before=snapshot(delayed.state)
            os.kill(child,signal.SIGSTOP)
            limit=time.monotonic()+1
            while 'State:\tT' not in Path(f'/proc/{child}/status').read_text():
                assert time.monotonic()<limit
                time.sleep(0.005)
            started=time.monotonic()
            response=delayed.archive('{}','deadline')
            elapsed=time.monotonic()-started
            assert response['result']['isError'] is True and response['result']['content']==[{'type':'text','text':DEADLINE}],response
            assert 2.5<=elapsed<4.5,elapsed
            assert snapshot(delayed.state)==before
            os.kill(child,signal.SIGCONT)
            response=delayed.archive('{}','fresh-after-expired-response')
            assert response['result']['isError'] is False and response['result']['content']==[{'type':'text','text':empty}],response
            assert snapshot(delayed.state)==before
            rows.append({'case':'absolute-three-second-public-deadline-and-stale-response-drain','seconds':elapsed,'passed':True})
        finally:
            os.kill(child,signal.SIGCONT)
            delayed.close()

        first=ArchiveSession(bundle,output/'owner-first')
        try:
            owner=first.owner()
            case={'owner':owner,'records':[json.dumps({'request_id':'0'*63+'1','owner':owner,
                'tool_name':'host_list','state':'completed','accepted_unix_ms':7,'elapsed_ms':1},separators=(',',':'))]}
            first.replace_archive(case,owner)
            assert json.loads(first.archive()['result']['content'][0]['text'])['total']==1
        finally:
            first.close()
        second=ArchiveSession(bundle,output/'owner-second',state=first.state)
        try:
            before=snapshot(second.state)
            assert second.archive()['result']['content']==[{'type':'text','text':empty}]
            refused=second.archive(json.dumps({'after_id':'0'*63+'1'}),'old-owner-cursor')
            assert refused['result']['isError'] is True and refused['result']['content']==[{'type':'text','text':UNAVAILABLE}],refused
            assert snapshot(second.state)==before
            rows.append({'case':'fresh-stdio-owner-cannot-project-prior-retained-metadata','passed':True})
        finally:
            second.close()
        report.update(passed=True,original_archive_queries=sum('query' in r for r in rows),
                      additional_controls=sum('query' not in r for r in rows))
        return report
    finally:
        (output/'qualification.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,required=True)
    parser.add_argument('--cases',type=Path,required=True)
    parser.add_argument('--oracle',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=qualify(args.bundle.resolve(),args.cases.resolve(),args.oracle.resolve(),args.output.resolve())
    print(json.dumps({key:result[key] for key in ('passed','original_archive_queries','additional_controls')}))


if __name__=='__main__':
    main()
