"""Compare actual native stdio history responses with pinned original Rust.

The fixture uses a real native service and all real controller members. Its
Worker profile is only an explicit configuration fixture; no Worker installation
or full cold release is claimed and no valid Worker job is requested.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path

from tools.qualify_hia_mcp_service_config import fixture
from tools.qualify_hia_mcp_service_owner import Connection, INIT, READY
from tools.qualify_hia_mcp_request_history import snapshot, UNAVAILABLE, CURSOR

ROOT=Path(__file__).resolve().parents[1]


def pin(path):
    return sha256(path.read_bytes()).hexdigest()


class Session:
    def __init__(self,bundle,directory,*,state=None):
        self.bundle,self.directory=bundle,directory
        directory.mkdir(mode=0o700)
        self.state=directory/'state' if state is None else state
        manifest=bundle/'hia-controller.json'
        pins=json.loads(manifest.read_text())['files']
        config=fixture()['configuration']
        config['state_dir']=str(self.state)
        config['hia_worker']['catalog_sha256']=pins['HIA_AGENT_NATIVE_TOOL_CATALOG.json']
        # The retained service requires these profile capabilities at startup.
        # Only locally rejected HIA input is used to observe its trusted owner.
        host=config['hosts']['rog']
        host['ssh_target']='hia-history-test-unused-target'
        for key,role in [('entry','hia-job-entry'),('submit','hia-job-submit'),
                         ('observation','hia-job-observation'),('cancel','hia-job-cancel'),
                         ('launcher','hia-job-launch')]:
            host['native_jobs'][key]={'executable':str(bundle/role),'sha256':pins[role]}
        config_path=directory/'config.json'
        config_path.write_text(json.dumps(config,separators=(',',':')))
        config_path.chmod(0o600)
        argv=[str(bundle/'hia-mcp-service'),str(config_path),pin(config_path),str(manifest),pin(manifest)]
        env={k:v for k,v in os.environ.items() if not k.startswith('HEPTA_EFFECT_OWNER_')}
        env['PATH']=''
        self.connection=Connection(argv,env)
        self.sequence=0
        self.connection.send(INIT)
        initialized=self.connection.read()
        assert initialized['result']['protocolVersion']=='2025-11-25',initialized
        self.connection.send(READY)
        self.record('initialize',initialized)

    def record(self,label,response):
        self.sequence+=1
        (self.directory/(f'{self.sequence:03d}-'+label+'.json')).write_text(
            json.dumps(response,indent=2,sort_keys=True)+'\n')
        return response

    def history(self,params='{}',label='history',*,omit_arguments=False):
        if omit_arguments:
            data={'jsonrpc':'2.0','id':label,'method':'tools/call','params':{'name':'request_history'}}
            self.connection.send(data)
        else:
            raw=('{"jsonrpc":"2.0","id":'+json.dumps(label)+
                 ',"method":"tools/call","params":{"name":"request_history","arguments":'+params+'}}\n').encode()
            self.connection.process.stdin.write(raw)
            self.connection.process.stdin.flush()
            (self.directory/(f'{self.sequence+1:03d}-'+label+'.input')).write_bytes(raw)
        response=self.connection.read()
        assert response.get('id')==label,response
        return self.record(label,response)

    def owner(self):
        self.connection.send({'jsonrpc':'2.0','id':'owner-probe','method':'tools/call',
            'params':{'name':'hia_describe','arguments':{'unexpected':True}}})
        response=self.record('owner-probe',self.connection.read())
        assert response.get('error',{}).get('code')==-32602,response
        assert 'required field is absent' in response['error']['message'],response
        paths=list((self.state/'request-audit').glob('*.json'))
        assert len(paths)==1,paths
        row=json.loads(paths[0].read_text())
        assert row['tool_name']=='hia_describe' and row['state']=='failed',row
        assert len(row['owner'])==64 and all(c in '0123456789abcdef' for c in row['owner'])
        return row['owner']

    def replace_hot(self,case,owner):
        hot=self.state/'request-audit'
        for path in hot.glob('*.json'):
            path.unlink()
        for record in case['records']:
            raw=record['raw'].replace('"owner":"'+case['owner']+'"','"owner":"'+owner+'"')
            path=hot/record['name']
            descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600)
            try:
                assert os.write(descriptor,raw.encode())==len(raw.encode())
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def close(self):
        self.connection.close()


def qualify(bundle,cases_path,oracle_path,output):
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    oracle=json.loads(oracle_path.read_text())
    assert oracle['source_ref']=='ae1c7ea593da45f7299c692a2acd44605c35be09'
    assert oracle['original_sha256']=='b5189f2923153ffa83d0b45a7cdf89873b0f17ebbe6ec1b174c05bab291d73da'
    assert oracle['cases_sha256']==pin(cases_path) and oracle['equal'] is True
    expected={row['id']:row for row in oracle['observations']}
    parameter_path=cases_path.parent/'params-observations-v2.jsonl'
    parameter_cases=cases_path.parent/'params-cases-v2.jsonl'
    assert pin(parameter_path)=='b5e2c9efaa7bf1a8854205e20e872795d15f84a85edca5e743b96505d6d2d76a'
    assert pin(parameter_cases)=='cd4f3e649b09482264c2f3d2a39ec650e48baf111c2555d6640fa257b527005c'
    parameter_expected={row['id']:row for row in map(json.loads,filter(None,parameter_path.read_bytes().split(b'\n')))}
    cases=[json.loads(line) for line in filter(None,cases_path.read_bytes().split(b'\n'))]
    rows=[]
    excluded={'active-state':'real live kernel-ticket behavior covered by native daemon controls',
              'invalid-owner':'trusted owner is not caller selectable; malformed owner covered by daemon protocol controls'}
    report={'schema':'hepta.hia.request-history-public-original-comparison.v1',
            'passed':False,'scope':'actual public native stdio request_history behavior',
            'service_sha256':pin(bundle/'hia-mcp-service'),'manifest_sha256':pin(bundle/'hia-controller.json'),
            'oracle_sha256':pin(oracle_path),'cases_sha256':pin(cases_path),
            'original_rust_case_count':len(cases),'public_exclusions':excluded,
            'fixture_is_not_an_installed_worker':True,'whole_cold_qualified':False,
            'observed_original_parameter_errors_equal':True,
            'typed_diagnostic_decoded_string_limit':1048576,
            'parameter_oracle_sha256':pin(parameter_path),
            'parameter_cases_sha256':pin(parameter_cases),'cases':rows}
    try:
        for index,case in enumerate(cases):
            if case['id'] in excluded:
                continue
            name=case['id'];directory=output/(f'{index:03d}-'+name)
            session=Session(bundle,directory)
            try:
                owner=session.owner()
                assert owner not in ('a'*64,'b'*64,'c'*64,'d'*64,'A'*64)
                session.replace_hot(case,owner)
                before=snapshot(session.state)
                response=session.history(case['params_json'],name)
                baseline=expected[name];kind=baseline['outcome']
                if kind=='ok':
                    result=response['result']
                    assert result['isError'] is False
                    assert result['content']==baseline['call_tool_result']['content'],(name,result,baseline)
                    if 'resultType' in result:assert result['resultType']=='complete'
                elif kind in ('tool_error','join_error'):
                    result=response['result']
                    assert result['isError'] is True
                    assert result['content']==[{'type':'text','text':baseline['public_error']}],(name,result,baseline)
                else:
                    assert kind=='params_error'
                    assert response.get('error')==parameter_expected[name]['error'],(name,response,parameter_expected[name])
                assert snapshot(session.state)==before,(name,'history changed retained metadata')
                if kind=='join_error':
                    session.replace_hot({'owner':case['owner'],'records':[]},owner)
                    after=session.history('{}','after-serialization-failure')
                    assert after['result']['isError'] is True
                    assert after['result']['content']==[{'type':'text','text':UNAVAILABLE}],after
                row={'case':name,'outcome':kind,'passed':True,
                     'exact_text_checked':True}
                if kind=='params_error':
                    row.update(original_deserializer_message=baseline['error'],
                               native_rpc_message=response['error']['message'])
                rows.append(row)
                print('NATIVE_HISTORY_PUBLIC_PASS',name,kind,flush=True)
            finally:
                session.close()
        # Actual rmcp parameter errors, including map ordering, finite numbers
        # and Rust string Debug escaping, are compared as complete error objects.
        diagnostic=Session(bundle,output/'parameter-diagnostics')
        try:
            before=snapshot(diagnostic.state)
            for item in map(json.loads,filter(None,parameter_cases.read_bytes().split(b'\n'))):
                name=item['id']
                if name in expected:
                    continue
                baseline=parameter_expected[name]
                assert 'error' in baseline
                response=diagnostic.history(item['params_json'],name)
                assert response.get('error')==baseline['error'],(name,response,baseline)
                assert snapshot(diagnostic.state)==before
                rows.append({'case':name,'diagnostic':True,'exact_text_checked':True,'passed':True})
                print('NATIVE_HISTORY_PARAMETER_PASS',name,flush=True)
            refused=diagnostic.history(json.dumps({'limit':'x'*1048577}), 'diagnostic-string-cap')
            assert refused.get('error')=={'code':-32602,'message':'Invalid params'},refused
            assert snapshot(diagnostic.state)==before
            rows.append({'case':'diagnostic-string-cap','diagnostic':True,
                         'bounded_fallback':True,'original_diagnostic_text_not_claimed':True,'passed':True})
        finally:
            diagnostic.close()
        # The public catalog is extended without changing the eleven Worker tools.
        session=Session(bundle,output/'discovery')
        try:
            session.connection.send({'jsonrpc':'2.0','id':'catalog','method':'tools/list','params':{}})
            discovery=session.record('catalog',session.connection.read())
            tools=discovery['result']['tools']
            history=[row for row in tools if row['name']=='request_history']
            assert len(tools)==12 and len(history)==1
            schema=json.loads((cases_path.parent/'oracle-params-schema.json').read_text())
            schema.pop('$schema',None)
            assert history[0]['inputSchema']==schema
            assert history[0]['annotations']=={'readOnlyHint':True,'destructiveHint':False,
                                              'idempotentHint':True,'openWorldHint':False}
            before=snapshot(session.state)
            omitted=session.history(label='omitted-arguments',omit_arguments=True)
            assert omitted['result']['content']==expected['empty']['call_tool_result']['content']
            null_arguments=session.history('null','null-arguments')
            assert null_arguments['result']['content']==expected['empty']['call_tool_result']['content']
            assert snapshot(session.state)==before
            rows.append({'case':'catalog-exact-schema-and-omitted-or-null-args','passed':True})
        finally:
            session.close()
        # Reconnecting stdio creates a fresh owner and cannot read old cursors.
        first=Session(bundle,output/'isolation-first')
        try:
            owner=first.owner()
            row={'name':'0'*63+'1.json','raw':json.dumps({
                'request_id':'0'*63+'1','owner':owner,'tool_name':'hia_describe',
                'state':'completed','accepted_unix_ms':7,'elapsed_ms':1},separators=(',',':'))}
            first.replace_hot({'owner':owner,'records':[row]},owner)
            assert len(json.loads(first.history()['result']['content'][0]['text'])['requests'])==1
        finally:
            first.close()
        second=Session(bundle,output/'isolation-second',state=first.state)
        try:
            before=snapshot(second.state)
            answer=second.history()
            assert answer['result']['content']==expected['empty']['call_tool_result']['content']
            refused=second.history(json.dumps({'after_id':'0'*63+'1'}),'old-session-cursor')
            assert refused['result']['isError'] is True
            assert refused['result']['content']==[{'type':'text','text':CURSOR}]
            assert snapshot(second.state)==before
            rows.append({'case':'stdio-owner-reconnect-isolation','passed':True})
        finally:
            second.close()
        report.update(passed=True,public_oracle_cases=sum('outcome' in row for row in rows),
                      public_additional_cases=sum('outcome' not in row and 'diagnostic' not in row for row in rows),
                      parameter_diagnostic_cases=sum('diagnostic' in row for row in rows))
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
    report=qualify(args.bundle.resolve(),args.cases.resolve(),args.oracle.resolve(),args.output.resolve())
    print(json.dumps({key:report[key] for key in ('passed','public_oracle_cases','public_additional_cases',
                                                 'parameter_diagnostic_cases','observed_original_parameter_errors_equal')}))


if __name__=='__main__':
    main()
