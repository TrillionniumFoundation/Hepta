"""One-shot retained R8 groups. Authoring this file does not authorize a run."""
from pathlib import Path
import argparse
import json
import os
import runpy
import sys
import traceback
import r8_common as S


def compile_frames(folder, complete, expected):
    rows=[]
    for directory in sorted(folder.rglob('*.full-frames')):
        if not directory.is_dir():
            continue
        row={'path':str(directory),'complete':False,'files':{}}
        for phase in ('before','after'):
            for name in ('source','output','workspace'):
                path=directory/(name+'.'+phase+'.bin')
                if path.is_file():
                    raw,mode,_=S.read_regular(path)
                    row['files'][path.name]=S.pin(raw,mode)
        first=directory/'before.json';last=directory/'after.json'
        if first.is_file() and last.is_file() and len(row['files'])==6:
            before=json.loads(S.read_regular(first)[0]);after=json.loads(S.read_regular(last)[0])
            S.require(before['request']==after['request'] and before['child_pid']==after['child_pid'],
                      'compile frame observation identity differs')
            request=before['request']
            for phase,record in (('before',before),('after',after)):
                for name in ('source','output','workspace'):
                    actual=row['files'][name+'.'+phase+'.bin']
                    S.require(record['frames'][name]=={k:actual[k] for k in ('bytes','sha256')},
                              'compile frame manifest differs')
            output_path=Path(request['output'])
            label=output_path.name.removesuffix('.output.bin')
            stdout=json.loads(S.read_regular(directory.parent/(label+'.stdout.log'))[0])
            receipt=json.loads(S.read_regular(directory.parent/(label+'.receipt.json'))[0])
            S.require(all(receipt.get(k)==v for k,v in stdout.items()),'actual child stdout differs from receipt')
            S.require(after['result_u64']==stdout['result_u64'] and
                      after['native_elapsed_ns']==stdout['native_elapsed_ns'],'actual compiler return differs')
            S.require(row['files']['output.after.bin']['sha256']==stdout['output_sha256'] and
                      row['files']['source.before.bin']['sha256']==request['source_sha256'],
                      'compiler input/output binding differs')
            S.require(S.read_regular(output_path)[0]==S.read_regular(directory/'output.after.bin')[0],
                      'complete compiler output differs')
            S.require(len(S.read_regular(directory/'output.before.bin')[0])==1048576
                      and S.read_regular(directory/'output.before.bin')[0]==bytes([0xa5])*1048576,
                      'original compile output preimage differs')
            S.require(S.read_regular(directory/'workspace.before.bin')[0]==bytes([request['workspace_fill']])*1048576,
                      'original compile workspace preimage differs')
            row['complete']=True
        rows.append(row)
    S.dump(folder/'COMPILE-FRAMES.json',{'calls':len(rows),'rows':rows,'required_complete':complete})
    if complete:
        S.require(len(rows)==expected and all(r['complete'] for r in rows),'six-frame compiler denominator differs')


def child(name):
    phase=next(p for p in S.PLAN['phases'] if p['name']==name)
    out=S.OUTPUT/phase['out']
    S.CURRENT_STAGE_OUT=out
    before=None;initial=None;qualifier=None;old_child=None;old_source=None
    errors=[];returned=None
    try:
        S.require(tuple(sys.version_info[:3])==(3,14,4),'actual314 required')
        initial=S.guards(name);S.dump(out/'BINDINGS-BEFORE.json',initial)
        before=S.source_snapshot(out/'FULL-SOURCE-BEFORE.json')
        sys.path.insert(0,str(S.SOURCE))
        if name=='public-R5-refusal':
            S.dump(out/'REPORT.json',S.public_r5_refusal())
            returned=0
        else:
            script=S.ROOT/phase['script']
            sys.path.insert(0,str(script.parent))
            if phase['compile_calls']:
                from tools import qualify_hia_selfhost as qualifier
                old_child,old_source=qualifier.CHILD,qualifier.SOURCE
                S.require(qualifier.NATIVE_OBSERVER is None and qualifier.NATIVE_LINKED_OBSERVER is None,
                          'unplanned native observer selection')
                S.require(str(old_child)==str(S.SOURCE/'tools/hia_selfhost_child.py'),'original compiler child changed')
                qualifier.CHILD=S.ROOT/'hia_selfhost_child_frames.py'
            module=runpy.run_path(str(script),run_name='_retained_r8_group')
            returned=module['child']()
            S.require(type(returned)is int and returned in (0,1),'original group returned unexpected status')
            if qualifier is not None:
                S.require(qualifier.SOURCE is old_source,'ordinary SOURCE was rebound')
        return returned
    except BaseException as error:
        errors.append({'where':'original-group','type':type(error).__name__,'traceback':traceback.format_exc()})
        raise
    finally:
        if qualifier is not None and old_child is not None:
            qualifier.CHILD=old_child
        for label,action in (
                ('source',lambda:S.source_snapshot(out/'FULL-SOURCE-AFTER.json')),
                ('bindings',lambda:S.guards(name)),
                ('native_frames',lambda:S.validate_native_frames(out,name) if phase['standalone_native_calls'] else None),
                ('semantic_VM_frames',lambda:S.validate_semantic_vm_frames(out,name,returned==0 and not errors)
                        if name in ('semantic-edge-vm','semantic-remaining-vm') else None),
                ('compile_frames',lambda:compile_frames(out,returned==0 and not errors,phase['compile_calls'])
                        if phase['compile_calls'] else None)):
            try:
                value=action()
                if label=='source' and before is not None:
                    S.require(value==before,'complete source/inode state changed')
                if label=='bindings':
                    S.dump(out/'BINDINGS-AFTER.json',value)
                    if initial is not None:S.require(value==initial,'fixed bindings changed')
                if label=='native_frames' and returned==0:
                    S.require(value==phase['standalone_native_calls'],'native complete-frame denominator differs')
            except BaseException as error:
                errors.append({'where':label,'type':type(error).__name__,'traceback':traceback.format_exc()})
        errors.extend({'where':'private-VM-frame-observer',**row} for row in S.VM_OBSERVATION_ERRORS)
        if returned==0 and name in ('pipeline7','tail2') and S.VM_CALLS!=phase['new_VM_calls']:
            errors.append({'where':'private-VM-frame-count','expected':phase['new_VM_calls'],'actual':S.VM_CALLS})
        S.dump(out/'WRAPPER-RESULT.json',{'original_returncode':returned,'errors':errors,
                'original_child_restored':qualifier is None or qualifier.CHILD is old_child,
                'ordinary_SOURCE_rebound':qualifier is not None and qualifier.SOURCE is not old_source,
                'private_VM_frame_observations':S.VM_CALLS,
                'public_R5_pin_changed':False,'new_current_cold':False,'public_profile_qualification':False})
        if errors and returned==0:
            raise AssertionError('post-group custody failed; original observations retained')


def owner_pass(result):
    return (result.get('status')=='OWNED_PROCESS_COMPLETED' and result.get('returncode')==0
            and result.get('supervisor_returncode')==0 and result.get('qualification_seconds')==180
            and result.get('cleanup_seconds')==3 and result.get('timed_out')is False
            and result.get('exit_observed_before_deadline')is True
            and result.get('cleanup',{}).get('complete')is True
            and result.get('cleanup',{}).get('observed_echild')is True)


def driver():
    S.require(tuple(sys.version_info[:3])==(3,14,4),'actual314 launcher required')
    S.guards('_prepare')
    S.prepare_context()
    parent_before=S.source_snapshot(S.OUTPUT/'PARENT-FULL-SOURCE-BEFORE.json')
    rows=[]
    status='FAIL'
    try:
        sys.path.insert(0,str(S.SOURCE))
        from tools.hia_selfhost_process_owner import run_owned
        env=dict(S.PLAN['runtime']['environment'])
        for phase in S.PLAN['phases']:
            out=S.OUTPUT/phase['out'];out.mkdir(parents=True,exist_ok=False)
            command=[sys.executable,'-B',str(Path(__file__).resolve()),'--plan-sha256',S.PLAN['authorization_pin'],
                     '--child',phase['name']]
            S.dump(out/'LAUNCH.json',{'command':command,'environment':env,'qualification_seconds':180,
                   'cleanup_seconds':3,'automatic_retry':False})
            result=run_owned(command,cwd=S.SOURCE,env=env,supervisor_env=env,
                qualification_seconds=180,cleanup_seconds=3,receipt_path=out/'OWNER.json',
                stdout_path=out/'child.stdout.bin',stderr_path=out/'child.stderr.bin')
            S.dump(out/'OWNER-RETURNED.json',result)
            outer={'status':'PASS' if owner_pass(result) else 'FAIL','owner':result,'terminal':result,
                   'matching_cold':False,'whole':False,'whole_native':False}
            S.dump(out/'OUTER.json',outer)
            row={'phase':phase['name'],'owner':result,'pass':owner_pass(result)}
            if row['pass']:
                observed=json.loads(S.read_regular(out/'REPORT.json')[0])
                if phase['name']=='public-R5-refusal':
                    row['pass']=observed['status']=='EXPECTED_PUBLIC_R5_REFUSAL'
                else:
                    row['pass']=observed.get('status')=='PASS'
                    if phase['report_count'] is not None:
                        row['pass']=row['pass'] and observed.get('count')==phase['report_count']
                row['report_identity']=S.pin(S.read_regular(out/'REPORT.json')[0])
            rows.append(row)
            S.dump(S.OUTPUT/('PROGRESS-%02d.json'%len(rows)),{'rows':rows,'automatic_retry':False})
            if not row['pass']:
                break
        status='PASS_PRIVATE_R8_RETAINED_GROUPS_ONLY' if len(rows)==len(S.PLAN['phases']) and all(r['pass'] for r in rows) else 'FAIL'
        return 0 if status.startswith('PASS_') else 1
    finally:
        parent_after=S.source_snapshot(S.OUTPUT/'PARENT-FULL-SOURCE-AFTER.json')
        if parent_after!=parent_before:
            status='FAIL_PARENT_SOURCE_GUARD'
        S.dump(S.OUTPUT/'RESULT.json',{'status':status,'rows':rows,
            'not_started':[p['name'] for p in S.PLAN['phases'][len(rows):]],
            'automatic_retry':False,'public_R5_profile_qualified':False,
            'ordinary_compiler_admission':False,'new_current_cold':False,'whole_native':False})
        S.require(parent_after==parent_before,'parent complete source/inode state changed')


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--plan-sha256',required=True)
    parser.add_argument('--child',choices=[p['name'] for p in S.PLAN['phases']])
    args=parser.parse_args()
    # authorization_pin hashes the fixed plan with this one self-reference
    # field removed, avoiding an impossible recursive content hash.
    material=dict(S.PLAN);expected=material.pop('authorization_pin')
    raw=(json.dumps(material,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    S.require(S.pin(raw)['sha256']==expected==args.plan_sha256,'fixed plan authority differs')
    raise SystemExit(child(args.child) if args.child else driver())
