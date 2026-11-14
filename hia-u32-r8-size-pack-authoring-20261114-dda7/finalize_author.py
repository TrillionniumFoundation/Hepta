"""Finalize only author metadata and independent fixed-input readback."""
from pathlib import Path
import ast
import json
import os
import prepare_author as A

ROOT = Path(__file__).resolve().parent

def replace_metadata(name,raw):
    temporary=ROOT/(name+'.author-finalizing')
    A.write(temporary,raw)
    os.replace(temporary,ROOT/name)

def replace_json(name,value):
    replace_metadata(name,(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode())

def main():
    history=ROOT/'author-history-r3';history.mkdir(exist_ok=False)
    prior={}
    for name in ('INPUTS.json','size_support.py','EXECUTION-PLAN.json','COMMAND-INTENT.json','AUTHOR-READBACK.json'):
        raw,mode,_=A.captured(ROOT/name);A.write(history/name,raw,mode);prior[name]=A.pin(raw,mode)
    A.dump(history/'REASON.json',{'state':'AUTHOR_ONLY_NO_PRODUCT','before':prior,
        'reason':'Bind actual B3 original members and old R8 reports; preserve incomplete terminal failures; final static checks.'})
    inputs=json.loads(A.captured(ROOT/'INPUTS.json')[0])
    for relative,name in (('evidence/compact-build-r1/REPORT.json','history/R8-REPORT.json'),
                          ('evidence/unique-size-r1/RESULT.json','history/R8-SIZE-RESULT.json')):
        origin=A.R8/relative;raw,mode,before=A.captured(origin)
        target=ROOT/'inputs'/name;A.write(target,raw,mode)
        inputs['files'].append({'origin':str(origin),'origin_stat':before,'origin_identity':A.pin(raw,mode),
            'captured':target.relative_to(ROOT).as_posix(),'captured_identity':A.pin(raw,mode)})
    replace_json('INPUTS.json',inputs)
    old_support=A.captured(ROOT/'size_support.py')[0].decode()
    prefix=old_support[:old_support.index('def require(')]
    support=json.loads(A.captured(ROOT/'RETAINED-SUPPORT.json')[0])
    text=prefix+'\n\n'.join(support['functions'][name] for name in A.COMMON)+'\n\n'+A.captured(ROOT/'support_extension.py.txt')[0].decode()
    replace_metadata('size_support.py',text.encode())
    plan=json.loads(A.captured(ROOT/'EXECUTION-PLAN.json')[0])
    old=json.loads(A.captured(ROOT/'inputs/history/R8-REPORT.json')[0])
    plan['original_R8_history'].update(image=old['image'],compiler_image=old['compiler'])
    for row in plan['controls'].values():row['identity']=A.fixed_row(row['path'])['identity']
    plan['controls']['author:CONTRACT.md']=A.fixed_row(ROOT/'CONTRACT.md')
    plan['fixed_input_capture']={'files':len(inputs['files']),
        'bytes':sum(row['captured_identity']['bytes'] for row in inputs['files']),
        'independent_copies':True,'original_members_reextracted':False}
    replace_json('EXECUTION-PLAN.json',plan)
    plan_raw=A.captured(ROOT/'EXECUTION-PLAN.json')[0]
    intent=json.loads(A.captured(ROOT/'COMMAND-INTENT.json')[0])
    intent['argv'][-1]=A.pin(plan_raw)['sha256'];intent['plan']=A.pin(plan_raw)
    replace_json('COMMAND-INTENT.json',intent)

    # Existing receipt and bytes only. No product modules/helpers are imported.
    def data(name):return A.captured(ROOT/'inputs'/name)[0]
    hashes={}
    for row in inputs['files']:
        raw,mode,_=A.captured(ROOT/row['captured']);original,m,stamp=A.captured(row['origin'])
        A.require(raw==original and A.pin(raw,mode)==row['captured_identity']
            and A.pin(original,m)==row['origin_identity'] and stamp==row['origin_stat'],'captured input drift')
        hashes[row['captured']]=A.pin(raw,mode)
    extras={'artifact_sha256','case','format','input_bytes','input_sha256','produced_bytes',
            'produced_image','produced_sha256','runner_sha256','wall_elapsed_ns'}
    report=json.loads(data('retained/REPORT.json'));provider=data('retained/captured-compiler.image.bin')
    observations=[];cap=1<<20
    for label,stage in (('controller',0),('representation',1),('packer',3),('B3',None)):
        folder='u32/' if stage is None else 'retained/'
        image=data(folder+label+'.image.bin');source=data(folder+label+'.input.bin');output=data(folder+label+'.output.bin')
        request=json.loads(data(folder+label+'.request.json'));stdout=json.loads(data(folder+label+'.stdout.log'))
        receipt=json.loads(data(folder+label+'.receipt.json'));selected=A.pin(image if stage is None else provider)['sha256']
        A.require(set(receipt)==set(stdout)|extras and all(receipt[k]==v for k,v in stdout.items()),'complete stdout/receipt projection')
        A.require(receipt['status']=='returned' and receipt['abi_status']==0
            and receipt['result_u64']==receipt['core_u32']==receipt['produced_bytes']==len(image)
            and receipt['produced_sha256']==A.pin(image)['sha256'] and receipt['input_bytes']==len(source)
            and receipt['input_sha256']==receipt['source_sha256']==A.pin(source)['sha256']
            and receipt['source_unchanged'] is True and receipt['image_sha256']==receipt['artifact_sha256']==selected
            and receipt['forbidden_compiler_modules_loaded']==[],'complete old compile binding')
        A.require(data(folder+label+'.stderr.log')==b'' and len(output)==cap and output[:len(image)]==image
            and output[len(image):]==b'\xa5'*(cap-len(image)) and receipt['output_sha256']==A.pin(output)['sha256'],'complete old prefix/tail')
        A.require(request['image_sha256']==selected and request['source_sha256']==A.pin(source)['sha256']
            and request['capacity']==request['workspace_size']==cap and request['workspace_fill']==(90 if stage is None else 0)
            and request['format']=='flat-x86-64','actual original request')
        A.require(receipt['limits']=={'address_bytes':256<<20,'core_dumpable':False,'cpu_seconds':10,
            'output_capacity':cap,'stack_bytes':8<<20,'workspace_bytes':cap},'original limits')
        if stage is not None:A.require(data(folder+label+'.hepta')==source and report['stages'][stage]==receipt,'old report stage')
        observations.append({'label':label,'image':A.pin(image),'source':A.pin(source),
            'request_workspace_fill':request['workspace_fill'],'actual_stdout_projection':True,'complete_prefix_tail':True})
    members=json.loads(A.captured(ROOT/'ACTUAL-INPUT-MANIFEST.json')[0])
    B3members={row['name']:row for row in members['files'] if row['name'].startswith('B3.')};bindings=[]
    for suffix in ('image.bin','input.bin','output.bin','request.json','receipt.json','stdout.log','stderr.log'):
        name='B3.'+suffix;raw=data('u32/'+name);row=B3members[name]
        A.require(A.pin(raw)==row['identity'] and all(row['original_member'][k]==v for k,v in row['identity'].items())
            and all(row['original_NODE'][k]==v for k,v in row['identity'].items())
            and row['original_member']['path']=='retained/'+row['original_NODE']['storage_path'],'original member binding')
        bindings.append({'name':name,'original_member':row['original_member']['path'],'identity':row['identity']})
    projection=json.loads(A.captured(ROOT/'PROJECTION.json')[0])
    for name in A.PACK:
        A.require(A.function_text(ROOT/'retained_pack_contract.py',name)==A.function_text(A.BUILDER,name)
            ==projection['functions'][name]['text'],'retained pack function changed')
    for name in A.COMMON:
        A.require(A.function_text(ROOT/'size_support.py',name)==A.function_text(A.ENTRY/'entry_support.py',name)
            ==support['functions'][name],'retained guard/owner helper changed')
    for name,row in projection['unchanged_loader_files'].items():
        A.require(A.captured(ROOT/name)[0]==A.captured(row['origin'])[0],'retained native observer changed')
    for name in ('run_size_pack.py','size_support.py','retained_pack_contract.py','retained_buffer_observer.py',
                 'retained_buffer_child.py','prepare_author.py','finalize_author.py'):
        ast.parse(A.captured(ROOT/name)[0])
    calls=[]
    for node in ast.walk(ast.parse(A.captured(ROOT/'run_size_pack.py')[0])):
        if (isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name)
                and node.func.value.id=='S' and node.func.attr=='observe'):
            calls.append({'line':node.lineno,'label':ast.literal_eval(node.args[0])})
    A.require([r['label'] for r in sorted(calls,key=lambda x:x['line'])]==['compile-r8','pack-r8'],'exact native callsites')
    for row in plan['controls'].values():A.require(A.fixed_row(row['path'])['identity']==row['identity'],'final control mismatch')
    A.require(48+59889+430261+558378==cap and 491200+557376==cap,'exact capacity arithmetic')
    result={'status':'AUTHOR_ONLY_STATIC_AND_ACTUAL_INPUT_READBACK_PASS','product_executions':0,
        'native_calls':0,'VM_calls':0,'new_CI':0,'input_count':len(hashes),
        'input_bytes':sum(row['bytes'] for row in hashes.values()),'controls':len(plan['controls']),
        'old_actual_receipts':observations,'B3_original_member_bindings':bindings,
        'pack_functions_whole_bytes_exact':list(A.PACK),'guard_owner_helpers_whole_bytes_exact':list(A.COMMON),
        'original_R8_native_observer_and_child_whole_bytes_exact':True,'native_callsites':calls,
        'parent_unknown_count_and_incomplete_terminal_failure_preserved':True,
        'source_snapshot_is_not_run_during_authoring':True,'plan':A.pin(plan_raw),
        'complete_scope_source_manifest':A.fixed_row(ROOT/'FROZEN-3180-SOURCE.json'),
        'three_historical_R8_fields':{'actual_old_image_bytes':562746,'old_conservative_shortfall':6600,'exact_needed_saving':5370}}
    A.dump(ROOT/'STATIC-READBACK.json',result)
    replace_json('AUTHOR-READBACK.json',{k:v for k,v in result.items() if k not in ('old_actual_receipts','B3_original_member_bindings')})
    print(json.dumps({'status':result['status'],'product_executions':0,'input_files':len(hashes),
        'input_bytes':result['input_bytes'],'controls':result['controls'],'plan':A.pin(plan_raw)},sort_keys=True))

if __name__=='__main__':main()
