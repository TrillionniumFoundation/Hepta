"""Actual development image + Agent artifacts/SQLite/replay observations."""
from __future__ import annotations
import argparse
import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import sys
from unittest.mock import patch

ROOT=Path('/workspace/scratch/623459b0e1bc/Hepta-native-candidate')
sys.path.insert(0,str(ROOT));os.chdir(ROOT)
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_store import wire,digest
from hepta.hia_program import verify_program
from hepta.hia_program_tools import apply_program_patch
from tools.hia_agent_native_qualification import Session,ToolClient
from tests.test_hia_program_tools import scalar_program,add_two_patch


class InterruptedAfterEffect(BaseException):pass


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--fixture',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    for key in list(os.environ):
        if key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'):os.environ.pop(key)
    fixture=args.output/'fixture';fixture.mkdir()
    for name in ('manifest.json','admission-manifest.json'):
        metadata=json.loads((args.fixture/name).read_bytes())
        image=args.fixture/metadata['image_path']
        assert sha256(image.read_bytes()).hexdigest()==metadata['image_sha256']
        shutil.copyfile(image,fixture/metadata['image_path'])
        (fixture/name).write_text(json.dumps(metadata))
    selected=fixture/'manifest.json'
    patch_metadata=json.loads(selected.read_text())
    image=fixture/patch_metadata['image_path']
    captured={name:sha256((ROOT/name).read_bytes()).hexdigest() for name in (
        'hepta/hia_agent_service.py','hepta/hia_agent_candidate_native.py',
        'examples/hia_bootstrap/core_patch.hepta','examples/hia_bootstrap/core_admission.hepta')}
    state=args.output/'state';files=args.output/'files';files.mkdir()
    service=HIAAgentService(state,artifact_roots=(files,))
    client=ToolClient(service.call,validate=False)
    session=Session(client,prefix='independent-native-patch')
    workload={'schema':'hepta.hia.agent.workload.v1','cases':[{
        'function':'increment','arguments':[3],'expected':{'status':'returned','values':[4]}}],
        'warmup_iterations':0,'repetitions':1}
    session.freeze(workload)
    original=scalar_program();request=add_two_patch(original)
    raw_base=json.dumps(original,indent=2).encode()
    raw_patch=json.dumps(request,indent=3).encode().replace(b'"schema"',b'"schem\\u0061"')
    expected_program,expected_diagnostics=apply_program_patch(original,request)
    expected_payloads=(expected_program.canonical_bytes,wire(expected_diagnostics))
    base_ref=session.artifact(raw_base.decode())
    patch_ref=session.artifact(raw_patch.decode())
    arguments=session.arguments(change={'kind':'patch','base_program':base_ref,
        'patch_schema':request['schema'],'patch':patch_ref})
    checks=[]
    def good(label,condition,**details):
        assert condition,(label,details)
        checks.append({'label':label,'passed':True,**details})
    with patch.dict(os.environ,{'HEPTA_HIA_CORE_PATCH_MANIFEST':str(selected)}):
        with patch('hepta.hia_program_tools.apply_program_patch',side_effect=AssertionError('host edit invoked')), \
             patch.object(service,'_program',side_effect=AssertionError('host Core materialization')), \
             patch('hepta.hia_agent_service.decode_json',side_effect=AssertionError('host payload decode')):
            response=service.call('hia_candidate',arguments)
        good('raw Agent completion',response['status']=='completed',response=response)
        result=response['result'];candidate=service.store.get(result['candidate'])[0]
        diagnostics=service.store.get(result['diagnostics'])[0]
        good('complete candidate and diagnostic byte parity',(candidate,diagnostics)==expected_payloads)
        observed=json.loads(diagnostics)
        good('raw artifact and canonical snapshot identities stay distinct',
             base_ref['sha256']==sha256(raw_base).hexdigest()
             and base_ref['sha256']!=verify_program(original).sha256
             and observed['before_sha256']==verify_program(original).sha256
             and observed['original_input_sha256']==observed['before_sha256'])
        good('artifact SHA binds exact emitted payload bytes',
             result['candidate']['sha256']==sha256(candidate).hexdigest()
             and result['diagnostics']['sha256']==sha256(diagnostics).hexdigest())
        # A loaded RX mapping deliberately survives removal of its old disk
        # image. Remove the manifest instead: selection always reopens it.
        missing=selected.with_name(selected.name+'.absent');selected.rename(missing)
        try:
            with patch('hepta.hia_agent_candidate_native.apply_candidate_patch',side_effect=AssertionError('replayed native effect')):
                good('completed replay survives selection loss',service.call('hia_candidate',arguments)==response)
                service.close();service=HIAAgentService(state,artifact_roots=(files,))
                good('completed replay after restart survives selection loss',service.call('hia_candidate',arguments)==response)
            next_args=copy.deepcopy(arguments);next_args['request_key']+='-image-missing'
            rejected=service.call('hia_candidate',next_args)
            good('new selected operation refuses missing manifest without host fallback',
                 rejected['status']=='rejected' and rejected['error']['code']!='E_HIA_REQUEST_UNKNOWN',
                 error=rejected.get('error'))
        finally:missing.rename(selected)
        # Deliberately interrupt after actual native computation and artifact
        # writes but before response journal commit. This is a real durable
        # running row, with an injected BaseException (not an OS kill claim).
        interrupted=copy.deepcopy(arguments);interrupted['request_key']+='-interrupted'
        original_effect=service._hia_candidate;effects=[]
        def interrupt_after_effect(args):
            effects.append(original_effect(args))
            raise InterruptedAfterEffect()
        with patch.object(service,'_hia_candidate',side_effect=interrupt_after_effect):
            try:service.call('hia_candidate',interrupted)
            except InterruptedAfterEffect:pass
            else:raise AssertionError('interruption did not reach actual post-effect point')
        request_key=digest({'tool':'hia_candidate','key':interrupted['request_key']})
        row=service.store.db.execute('SELECT state,response FROM requests WHERE key=?',(request_key,)).fetchone()
        good('interruption retains running intent without response',row['state']=='running' and row['response'] is None and len(effects)==1)
        artifact_count=service.store.db.execute('SELECT count(*) FROM artifacts').fetchone()[0]
        service.close();service=HIAAgentService(state,artifact_roots=(files,))
        with patch('hepta.hia_agent_candidate_native.apply_candidate_patch',side_effect=AssertionError('unknown intent replayed')):
            responses=[service.call('hia_candidate',interrupted) for _ in range(2)]
            good('running intent remains UNKNOWN after restart',all(
                r['status']=='rejected' and r['error']['code']=='E_HIA_REQUEST_UNKNOWN'
                and r['error']['retry_action']=='observe_original' for r in responses))
            changed=copy.deepcopy(interrupted);changed['change']['patch_schema']='hepta.hia.patch.v2'
            conflict=service.call('hia_candidate',changed)
            good('changed unknown retry conflicts',conflict['error']['code']=='E_HIA_REQUEST_CONFLICT')
        row=service.store.db.execute('SELECT state,response FROM requests WHERE key=?',(request_key,)).fetchone()
        good('observation neither replays effects nor completes unknown intent',
             row['state']=='running' and row['response'] is None
             and artifact_count==service.store.db.execute('SELECT count(*) FROM artifacts').fetchone()[0])
    service.close()
    preserved={name:sha256((ROOT/name).read_bytes()).hexdigest()==value for name,value in captured.items()}
    record={'development_only':True,'actual_image_manifest':patch_metadata,
            'captured_source_sha256':captured,'source_preserved':preserved,
            'checks':checks,'interruption_method':'Injected BaseException after real native effect and artifact writes; not an OS kill or fresh cold qualification.'}
    (args.output/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    print('PASS',len(checks),'checks; source preserved',all(preserved.values()),flush=True)
    return not all(preserved.values())


if __name__=='__main__':raise SystemExit(main())
