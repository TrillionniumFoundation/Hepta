"""Independent development-only raw patch-result and journal observation."""
from __future__ import annotations
import argparse
import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import struct
import sys

ROOT = Path('/workspace/scratch/623459b0e1bc/Hepta-native-candidate')
sys.path.insert(0,str(ROOT)); os.chdir(ROOT)
from hepta.hia_program import verify_program
from hepta.hia_program_tools import apply_program_patch
from hepta.hia_agent_store import wire as canonical_wire
from hepta.hia_core_patch_native import envelope
from hepta.hia_agent_candidate_native import NativeAgentCandidatePatch, RESULT_MAGIC
from hepta.hia_core_admission_native import NativeCoreAdmission
from tests.test_hia_program_tools import scalar_program,add_two_patch


def wire(value):
    return json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()


def trap_function(name='f',params=(),returns=(),effects=('trap',),loans=None):
    parameters=[{'name':name,'type':typ} for name,typ in params]
    fn={'name':name,'params':parameters,'returns':list(returns),'effects':list(effects),
        'entry':'entry','blocks':[{'id':'entry','params':copy.deepcopy(parameters),'ops':[],
                                 'term':{'op':'trap','code':'user'}}]}
    if loans is not None:fn['return_loans']=list(loans)
    return fn


def patch_for(base,edits,version=1,policy='preserve'):
    result={'schema':'hepta.hia.patch.v'+str(version),
            'expected_sha256':verify_program(base).sha256,'edits':edits}
    if version==2:result['interface_policy']=policy
    return result


def function_edit(fn,action='replace_function'):
    return {'action':action,'function':fn['name'],'definition':fn}


def cases():
    rows=[]
    def add(label,base,patch,**options):rows.append((label,base,patch,options))
    for version in range(1,9):
        base=scalar_program();base['schema']='hepta.hia.program.v'+str(version)
        request=add_two_patch(base)
        add('primitive-v'+str(version),base,request)
        add('primitive-v'+str(version)+'-raw-spelling',base,request,pretty=True)
        request=copy.deepcopy(request);request.update(schema='hepta.hia.patch.v2',interface_policy='preserve')
        add('primitive-v'+str(version)+'-v2-preserve',base,request)
    base=scalar_program();base['schema']='hepta.hia.program.v8'
    request=add_two_patch(base);request.update(schema='hepta.hia.patch.v2',interface_policy='migrate')
    add('migrate-without-interface-change',base,request)
    for initial_explicit,replacement_explicit in ((False,True),(True,False)):
        original=copy.deepcopy(base)
        if initial_explicit:original['functions'][0]['return_loans']=[None]
        replacement=copy.deepcopy(original['functions'][0])
        if replacement_explicit:replacement['return_loans']=[None]
        else:replacement.pop('return_loans',None)
        add('default-loans-'+str(initial_explicit),original,
            patch_for(original,[function_edit(replacement)]))
    mixed=copy.deepcopy(base)
    names=['zeta','Alpha','a','aa','_x','Z']
    additions=[function_edit(trap_function(n),action='add_function') for n in names]
    add('sorted-additions',mixed,patch_for(mixed,additions,2,'migrate'))
    names=['n'+str(i).zfill(3)+'x'*124 for i in range(64)]
    additions=[function_edit(trap_function(n),action='add_function') for n in reversed(names)]
    add('64-long-interface-names',mixed,patch_for(mixed,additions,2,'migrate'))
    borrowed={'schema':'hepta.hia.program.v8','module':'borrowed_interfaces','functions':[
        trap_function('loans',[('p','readbuf'),('q','readbuf')],['readbuf'],loans=['p'])]}
    revised=copy.deepcopy(borrowed['functions'][0]);revised['return_loans']=['q']
    add('loan-interface-migrate',borrowed,patch_for(borrowed,[function_edit(revised)],2,'migrate'))
    add('loan-interface-preserve-refusal',borrowed,patch_for(borrowed,[function_edit(revised)],2,'preserve'))
    # A large valid base and tiny edit must leave room for a diagnostic larger
    # than the patch wire itself. This targets a different allocation from v58.
    large=scalar_program();template=copy.deepcopy(large['functions'][0])
    large['functions'] += [{**copy.deepcopy(template),'name':'f'+str(i)} for i in range(1023)]
    edit={'action':'replace_terminator','function':'increment','block':'entry',
          'term':{'op':'ret','values':['x']}}
    add('full-1024-functions-small-edit',large,patch_for(large,[edit]))
    base=scalar_program();good=add_two_patch(base)
    add('wrong-declared-v2',base,good,declared=2,expect_declared=True)
    request=copy.deepcopy(good);request.update(schema='hepta.hia.patch.v2',interface_policy='preserve')
    add('wrong-declared-v1',base,request,declared=1,expect_declared=True)
    for label,mutate in [
        ('stale',lambda p:p.update(expected_sha256='0'*64)),
        ('duplicate-edit',lambda p:p['edits'].extend(copy.deepcopy(p['edits']))),
        ('boolean-index',lambda p:p['edits'][0].update(index=False)),
        ('fractional-index',lambda p:p['edits'][0].update(index=0.0)),
        ('overflow-index',lambda p:p['edits'][0].update(index=2**64)),
        ('bad-candidate',lambda p:p['edits'][0]['operation']['attrs'].update(value=True))]:
        request=copy.deepcopy(good);mutate(request);add(label,base,request)
    # Generate interfaces rather than reusing the implementation's own edit
    # tables: whole-program host admission remains the independent oracle.
    rng=random.Random(941772)
    for number in range(500):
        names=['z','A','b','B','_a','aa']
        original={'schema':'hepta.hia.program.v8','module':'random_interfaces',
                  'functions':[trap_function(name,[('arg','u32')],['u32']) for name in names]}
        edits=[]
        for name in rng.sample(names,rng.randrange(1,7)):
            function=copy.deepcopy(next(f for f in original['functions'] if f['name']==name))
            mode=rng.randrange(6)
            if mode==0:
                function['params'][0]['name']='renamed';function['blocks'][0]['params'][0]['name']='renamed'
            elif mode==1:
                function['params'][0]['type']='u64';function['blocks'][0]['params'][0]['type']='u64'
            elif mode==2:function['returns']=['u64']
            elif mode==3:function['effects']=['read','trap']
            elif mode==4:function['return_loans']=[None]
            edits.append(function_edit(function))
        version=rng.choice((1,2));policy=rng.choice(('preserve','migrate')) if version==2 else 'preserve'
        add('random-'+str(number),original,patch_for(original,edits,version,policy))
    return rows


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--patch-image',type=Path,required=True)
    p.add_argument('--patch-receipt',type=Path,required=True)
    p.add_argument('--admission-image',type=Path,required=True)
    p.add_argument('--admission-receipt',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();args.output.mkdir(exist_ok=False,parents=True)
    for key in list(os.environ):
        if key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'):os.environ.pop(key)
    source_paths=('examples/hia_bootstrap/core_patch.hepta','examples/hia_bootstrap/core_admission.hepta',
                  'hepta/hia_agent_candidate_native.py','hepta/hia_agent_service.py')
    captured={name:sha256((ROOT/name).read_bytes()).hexdigest() for name in source_paths}
    patch_bytes=args.patch_image.read_bytes();admission_bytes=args.admission_image.read_bytes()
    receipts={}
    for label,path,data,source in (
        ('patch',args.patch_receipt,patch_bytes,'examples/hia_bootstrap/core_patch.hepta'),
        ('admission',args.admission_receipt,admission_bytes,'examples/hia_bootstrap/core_admission.hepta')):
        receipt=json.loads(path.read_bytes())
        assert receipt['status']=='returned' and receipt['abi_status']==0,receipt
        assert receipt['source_sha256']==captured[source] and receipt['source_unchanged'] is True,receipt
        assert receipt['produced_sha256']==sha256(data).hexdigest(),receipt
        assert receipt['produced_bytes']==len(data),receipt
        assert receipt['forbidden_compiler_modules_loaded']==[],receipt
        receipts[label]={'path':str(path),'sha256':sha256(path.read_bytes()).hexdigest(),
                         'source_sha256':receipt['source_sha256'],'produced_sha256':receipt['produced_sha256'],
                         'compiler_sha256':receipt['artifact_sha256']}
    native=NativeAgentCandidatePatch(patch_bytes,sha256(patch_bytes).hexdigest())
    admission=NativeCoreAdmission(admission_bytes,sha256(admission_bytes).hexdigest())
    rows=cases();differences=[];accepted=0;rejected=0;details=[]
    for index,(label,base,request,options) in enumerate(rows):
        declared=options.get('declared',int(request['schema'][-1]))
        original=verify_program(base)
        raw_base=(b' \n'+json.dumps(base,ensure_ascii=False,indent=2).encode()+b'\t '
                  if options.get('pretty') else original.canonical_bytes)
        raw_request=(json.dumps(request,ensure_ascii=True,indent=2).encode().replace(b'"schema"',b'"schem\\u0061"')
                     if options.get('pretty') else wire(request))
        data=envelope(raw_base,raw_request)
        if options.get('pretty'):data=b' \n'+data+b'\t '
        expected=None;reference_error=None;actual=None;native_error=None
        try:
            candidate,diagnostics=apply_program_patch(original,raw_request)
            if options.get('expect_declared'):raise ValueError('declared patch schema mismatch')
            expected=(candidate.canonical_bytes,canonical_wire(diagnostics));accepted+=1
        except (ValueError,TypeError) as exc:
            reference_error=str(exc);rejected+=1
        try:
            extracted=native.transform(data,extract=True)[0];admission.admit(extracted)
            actual=native.result(data,declared);admission.admit(actual[0])
        except (ValueError,TypeError,RuntimeError,OSError) as exc:
            native_error=str(exc);actual=None
        if expected!=actual:
            difference={'label':label,'reference_error':reference_error,'native_error':native_error,
                        'expected_diagnostics':expected[1].decode() if expected else None,
                        'actual_diagnostics':actual[1].decode() if actual else None}
            differences.append(difference);print('DIFFERENCE',json.dumps(difference),flush=True)
        if label in ('sorted-additions','64-long-interface-names','full-1024-functions-small-edit') or options.get('pretty'):
            details.append({'label':label,'raw_base_sha256':sha256(raw_base).hexdigest(),
                            'canonical_base_sha256':original.sha256,'request_bytes':len(raw_request),
                            'diagnostic_bytes':len(actual[1]) if actual else None,
                            'output_equal':expected==actual})
        if index%100==99:print('CHECKED',index+1,'DIFFERENCES',len(differences),flush=True)
    preserved={name:sha256((ROOT/name).read_bytes()).hexdigest()==digest for name,digest in captured.items()}
    record={'development_only':True,'checks':len(rows),'reference_accepted':accepted,'reference_refused':rejected,
            'patch_image_sha256':sha256(patch_bytes).hexdigest(),
            'admission_image_sha256':sha256(admission_bytes).hexdigest(),
            'captured_source_sha256':captured,'source_preserved':preserved,
            'actual_compile_receipts':receipts,
            'differences':differences,'selected_details':details}
    (args.output/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    print('COMPLETE',len(rows),accepted,rejected,'DIFFERENCES',len(differences),flush=True)
    return bool(differences) or not all(preserved.values())


if __name__=='__main__':raise SystemExit(main())
