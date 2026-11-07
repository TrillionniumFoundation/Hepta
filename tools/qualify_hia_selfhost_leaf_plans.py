"""Compare hotspot-directed v3/v4 plans on complete native self compilation.

This author-side finite campaign never changes backend defaults, deploys an
image, runs a model, or infers NDU value. It retains all plans, costs, original
child evidence, refusals and the explicit canonical fallback invocation.
"""
from __future__ import annotations
import argparse
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import statistics
import struct
import sys
import time
import traceback

ROOT=Path(__file__).resolve().parents[1]
if __package__ in {None,""}: sys.path.insert(0,str(ROOT))
from hepta.hia_agent_assembly import assemble_program
from hepta.hia_agent_contract import PLAN_SCHEMA, validate
from hepta.hia_machine_plan import (MACHINE_V3,MACHINE_V4,VALUE_TYPES,MachinePlanRejected,
    preservation_checks,validate_plan)
from hepta.hia_program_native import compile_program_machine,emit_program_machine
from tools.qualify_hia_machine_registers import explicit_plan
from tools.hia_selfhost_contract import validate_contract
from tools.qualify_hia_selfhost import (SOURCE,SAMPLE,CAPACITY,INVALID,NO_SPACE,
    invoke,source_manifest,hash_reference)


def digest(raw): return sha256(raw).hexdigest()
def put(path,value): Path(path).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
def require(ok,message):
    if not ok: raise AssertionError(message)
def usage():
    own=resource.getrusage(resource.RUSAGE_SELF);child=resource.getrusage(resource.RUSAGE_CHILDREN)
    return {'parent_cpu_ns':int((own.ru_utime+own.ru_stime)*1e9),
        'children_cpu_ns':int((child.ru_utime+child.ru_stime)*1e9),
        'parent_maxrss_kib':own.ru_maxrss,'children_maxrss_kib':child.ru_maxrss}
def host_observation():
    return {'host':'local-cloud-linux-x86_64','uname':list(platform.uname()),
        'loadavg':list(os.getloadavg()),'cpu_count':os.cpu_count(),
        'affinity':sorted(os.sched_getaffinity(0)),'observed_unix_ns':time.time_ns()}


def propose_assignments(document,names,registers):
    """Explicit author-side first-fit plan; the backend separately verifies it."""
    output={}
    for fn in document['functions']:
        if fn['name'] not in names: continue
        mapping={}
        for block in fn['blocks']:
            types={p['name']:p['type'] for p in block['params']}
            starts={p['name']:0 for p in block['params']}
            for index,op in enumerate(block['ops'],1):
                for p in op['out']: types[p['name']]=p['type'];starts[p['name']]=index
            ends=dict(starts)
            for index,op in enumerate(block['ops'],1):
                for value in op['args']: ends[value]=index
            terminal=block['term']; args=[]
            if terminal['op']=='ret': args=terminal['values']
            elif terminal['op']=='jump': args=terminal['args']
            elif terminal['op']=='branch': args=[terminal['cond'],*terminal['then']['args'],*terminal['else']['args']]
            for value in args: ends[value]=len(block['ops'])+1
            occupied={reg:[] for reg in registers}
            for value in sorted(starts,key=lambda v:(starts[v],v)):
                if types[value] not in VALUE_TYPES: continue
                for reg in registers:
                    if all(ends[value]<first or starts[value]>last for first,last in occupied[reg]):
                        mapping[value]=reg;occupied[reg].append((starts[value],ends[value]));break
        output[fn['name']]=mapping
    return output


def profile_identity(path,source):
    path=Path(path); raw=path.read_bytes(); report=json.loads(raw)
    require(report['source_sha256']==digest(source),'profile belongs to other compiler source')
    require(report['claims']['actual_dynamic_pc_samples'] is True,'dynamic PC claim absent')
    symbols=[]
    for line in (path.parent/'symbols.nm').read_text().splitlines():
        cells=line.split()
        if len(cells)==4: symbols.append((int(cells[0],16),int(cells[1],16),cells[3]))
    counts={};total=0
    for row in report['iterations']:
        pcs=(path.parent/f'iteration-{row["iteration"]}.pcs.u64le').read_bytes()
        require(digest(pcs)==row['pc_bytes_sha256'] and len(pcs)==row['samples']*8,'raw PC evidence changed')
        output=(path.parent/f'iteration-{row["iteration"]}.output.bin').read_bytes()
        require(digest(output)==row['output_sha256'] and row['exact_expected_image'] is True,'profiled compiler output changed')
        for (pc,) in struct.iter_unpack('<Q',pcs):
            relative=pc-report['load_base']
            matches=[name for start,size,name in symbols if start<=relative<start+size]
            require(len(matches)==1,'profile attribution is incomplete or ambiguous')
            counts[matches[0]]=counts.get(matches[0],0)+1;total+=1
    require(total==report['samples'] and total>=100,'insufficient actual samples')
    ranked=sorted(counts.items(),key=lambda row:(-row[1],row[0]))
    names=[]
    for name,count in ranked[:2]:
        require(name.startswith('__hia_native_fn_'),'top profile symbol is not a Core helper')
        names.append('f'+name.removeprefix('__hia_native_fn_'))
    return report,{'path':str(path),'sha256':digest(raw),'actual_samples':total,
        'selected_functions':names,'selected_samples':sum(count for _,count in ranked[:2]),
        'attribution':'original per-iteration u64 RIP bytes + nm intervals + recorded load base, recomputed'},names


def run(directory,profile,expected,repetitions=3,prior_preregistration=None):
    directory=Path(directory).resolve()
    require(type(repetitions)is int and 3<=repetitions<=5,'use 3..5 preregistered repetitions')
    require(not directory.is_relative_to(ROOT),'keep evidence outside source')
    directory.mkdir(parents=True,exist_ok=False,mode=0o700)
    initial_free=shutil.disk_usage(directory).free
    require(initial_free>=384<<20,'insufficient free space for preregistered 250 MiB write budget plus margin')
    before=source_manifest(); validate_contract()
    files=['tools/qualify_hia_selfhost_leaf_plans.py','tools/qualify_hia_machine_registers.py',
           'tests/test_hia_machine_leaf_registers.py','docs/HIA_AGENT_MACHINE_PLANS.md']
    identity={**before,**{name:digest((ROOT/name).read_bytes()) for name in files}}
    report={'schema':'hepta.hia.selfhost-leaf-plans.v1','status':'started','source_identity':identity,
        'host_before':host_observation(),'costs':[],'arms':{},'native_invocations':[],
        'rejections':[],'checks':{},'claims':{'default_replaced':False,'real_model_run':False,
        'NDU_incremental_value_measured':False,'general_speedup_proved':False,
        'deployment_or_service_rollback_performed':False},
        'storage':{'initial_free_bytes':initial_free,'write_budget_bytes':250<<20,
                   'phase_free_margin_bytes':192<<20}}
    started=time.monotonic_ns(); initial=usage()
    ledger=directory/'COST_EVENTS.jsonl'
    def event(value):
        with ledger.open('ab') as output:
            output.write((json.dumps(value,sort_keys=True)+'\n').encode())
            output.flush();os.fsync(output.fileno())
    def timed(label,action):
        require(shutil.disk_usage(directory).free>=192<<20,'free-space safety margin reached before '+label)
        current=usage()
        used_cpu=current['parent_cpu_ns']+current['children_cpu_ns']-initial['parent_cpu_ns']-initial['children_cpu_ns']
        require(used_cpu<90_000_000_000,'aggregate CPU budget margin reached before '+label)
        require(time.monotonic_ns()-started<155_000_000_000,'campaign deadline margin reached before '+label)
        event({'event':'phase_begin','phase':label,'unix_ns':time.time_ns(),'usage':usage()})
        a=time.monotonic_ns();u=usage(); result=action();v=usage()
        row={'phase':label,'wall_ns':time.monotonic_ns()-a,
            'parent_cpu_ns':v['parent_cpu_ns']-u['parent_cpu_ns'],
            'children_cpu_ns':v['children_cpu_ns']-u['children_cpu_ns'],
            'parent_maxrss_kib':v['parent_maxrss_kib'],'children_maxrss_kib':v['children_maxrss_kib']}
        event({'event':'phase_end',**row});report['costs'].append(row)
        return result
    def native(label,image,data,**kwargs):
        observed,raw=timed('fresh-child-application:'+label,
            lambda:invoke(directory,label,image,data,**kwargs))
        report['native_invocations'].append(observed)
        require(observed.get('status')=='returned' and observed.get('abi_status')==0,'native application failed: '+label)
        return observed,raw
    try:
        source=SOURCE.read_bytes();sample=SAMPLE.read_bytes();expected=Path(expected).read_bytes()
        prof,pin,names=profile_identity(profile,source)
        require(digest(expected)==prof['expected_image_sha256'],'fixed reference image differs')
        checked=timed('source-validation',lambda:assemble_program(source)); document=checked.as_dict()
        for name in names: require(name in {f['name'] for f in document['functions']},'sampled function absent')
        configs=[('canonical',None,None),('v3-two',MACHINE_V3,('r12','r13')),
            ('v3-five',MACHINE_V3,('rbx','r12','r13','r14','r15')),
            ('v4-two',MACHINE_V4,('r8','r9')),
            ('v4-seven',MACHINE_V4,('r8','r9','rbx','r12','r13','r14','r15'))]
        plans={}
        for name,schema,regs in configs:
            if schema is None: plans[name]=None;continue
            assignments=timed('plan-generation:'+name,lambda:propose_assignments(document,names,regs))
            plan=explicit_plan(checked,assignments,compact=True);plan['schema']=schema;plans[name]=plan
        require(all(set(plans['v3-two']['value_registers'][n])==set(plans['v4-two']['value_registers'][n]) for n in names),
                'two-register controls do not place the same values')
        order=[[configs[(i+2*r)%len(configs)][0] for i in range(len(configs))] for r in range(repetitions)]
        prereg={'profile':pin,'core_sha256':checked.sha256,'compiler_source_sha256':digest(source),
            'expected_successor_sha256':digest(expected),'repetitions':repetitions,'order':order,
            'plans':plans,'choice_surface':'v4 leaf caller-clobbered scalar registers; no default change',
            'measurement':'native wall in fresh child; complete compiler source each time; fixed reference bytes; no model/NDU claim',
            'limits':{'per_child_cpu_seconds':10,'per_child_wall_seconds':20,'address_bytes':256<<20,
                      'stack_bytes':8<<20,'source_output_workspace_each_bytes':1<<20,
                      'aggregate_cpu_seconds':100,'wall_seconds':180,'write_bytes':250<<20}}
        if prior_preregistration is not None:
            prior_raw=Path(prior_preregistration).read_bytes(); prior=json.loads(prior_raw)
            for key in ('profile','core_sha256','compiler_source_sha256','expected_successor_sha256',
                        'repetitions','order','plans'):
                require(prior[key]==prereg[key],'fresh complete batch changed prior '+key)
            prereg['previous_incomplete_batch']={'preregistration_sha256':digest(prior_raw),
                'same_arms_inputs_order_repetitions':True,'prior_observations_used_as_new_measurements':False}
        put(directory/'PREREGISTRATION.json',prereg)
        with (directory/'PREREGISTRATION.json').open('rb') as saved:os.fsync(saved.fileno())
        report['preregistration_sha256']=digest((directory/'PREREGISTRATION.json').read_bytes())
        report['dynamic_profile']=pin
        for name,plan in plans.items():
            put(directory/(name+'.plan.json'),plan)
            if plan is not None:
                timed('plan-validation:'+name,lambda:validate(plan,PLAN_SCHEMA))
                timed('plan-lifetime-leaf-validation:'+name,lambda:validate_plan(checked,plan))
            machine=timed('emission:'+name,lambda:emit_program_machine(checked,machine_plan=plan,
                foreign_buffer_exports=(('f0',CAPACITY),)))
            image=directory/(name+'.so')
            receipt=timed('link-and-revalidate:'+name,lambda:compile_program_machine(machine,program=checked,
                output=image,linker='ld',machine_plan=plan))
            report['arms'][name]={'image':str(image),'image_sha256':digest(image.read_bytes()),
                'shared_bytes':image.stat().st_size,'object_bytes':len(machine.object_bytes),
                'text_bytes':len(machine.text_bytes),'function_frames':list(machine.function_frames),
                'preservation_checks':[] if plan is None else preservation_checks(plan,checked),
                'native_compiler_ns':[],'receipt':receipt}
        require(report['arms']['canonical']['image_sha256']==prof['image_sha256'],
                'new canonical compiler is not the exact dynamically sampled image')
        bad=deepcopy(plans['v4-seven']);bad['core_sha256']='0'*64
        refused={'wrong-core':bad}
        bad=deepcopy(plans['v4-seven']);bad['value_registers']['f0']={'v3':'r8'};refused['non-leaf-call']=bad
        bad=deepcopy(plans['v4-seven']);bad['value_registers'][names[0]]={'v0':'r9'};refused['borrowed-resource']=bad
        bad=deepcopy(plans['v4-two']);bad['schema']=MACHINE_V3;refused['v3-register-boundary']=bad
        for name,plan in refused.items():
            put(directory/('refused-'+name+'.plan.json'),plan)
            def reject():
                try: validate_plan(checked,plan)
                except MachinePlanRejected as exc:return {'case':name,'exception':type(exc).__name__,'message':str(exc)}
                raise AssertionError('invalid plan accepted: '+name)
            report['rejections'].append(timed('rejection:'+name,reject))
        for repeat,sequence in enumerate(order):
            for name in sequence:
                image=Path(report['arms'][name]['image'])
                observed,raw=native(f'measure-{repeat}-{name}',image,source,image_format='seed-shared',workspace_fill=0x5a)
                require(observed['core_u32']==len(expected) and raw[:len(expected)]==expected
                    and raw[len(expected):]==b'\xa5'*(CAPACITY-len(expected)) and observed['source_unchanged'],
                    'complete compiler bytes/effects differ: '+name)
                report['arms'][name]['native_compiler_ns'].append(observed['native_elapsed_ns'])
        sample_image=None
        for name in plans:
            image=Path(report['arms'][name]['image'])
            observed,raw=native(name+'-sample-compile',image,sample,image_format='seed-shared')
            produced=raw[:observed['core_u32']]
            if sample_image is None: sample_image=produced
            require(produced==sample_image,'sample emission differs')
            sample_path=directory/(name+'-sample.image');sample_path.write_bytes(produced)
            for index,data in enumerate((b'',b'hot leaf',bytes(range(256)))):
                observed,out=native(name+'-sample-run-'+str(index),sample_path,data,capacity=1,workspace_size=1)
                expected_hash=hash_reference(data)
                require(observed['core_u32']==expected_hash and out==bytes([expected_hash&255]) and observed['source_unchanged'],
                        'sample scalar/memory oracle differs')
            observed,_=native(name+'-invalid',image,b'not-hia\n',image_format='seed-shared')
            require(observed['core_u32']==INVALID and observed['output_unchanged'],'source rejection changed')
            observed,_=native(name+'-short-output',image,source,image_format='seed-shared',capacity=len(expected)-1)
            require(observed['core_u32']==NO_SPACE and observed['output_unchanged'],'output preflight changed')
            observed,_=native(name+'-short-workspace',image,source,image_format='seed-shared',workspace_size=1024)
            require(observed['core_u32']==NO_SPACE and observed['output_unchanged'],'workspace preflight changed')
        observed,raw=native('canonical-fallback',Path(report['arms']['canonical']['image']),source,image_format='seed-shared')
        require(observed['core_u32']==len(expected) and raw[:len(expected)]==expected,'canonical fallback differs')
        report['fallback']={'scope':'fresh local invocation of unchanged canonical compiler; no deployed state changed',
            'native_ns':observed['native_elapsed_ns'],'produced_sha256':digest(raw[:len(expected)])}
        for row in report['arms'].values():
            values=row['native_compiler_ns'];row['timing_summary_ns']={'median':statistics.median(values),'min':min(values),'max':max(values)}
        report['ratios']={
            'v4_two_over_v3_two':report['arms']['v4-two']['timing_summary_ns']['median']/report['arms']['v3-two']['timing_summary_ns']['median'],
            'v4_seven_over_v3_five':report['arms']['v4-seven']['timing_summary_ns']['median']/report['arms']['v3-five']['timing_summary_ns']['median']}
        require(source_manifest()==before,'source closure changed during campaign')
        report['checks']={'dynamic_profile_recomputed':True,'same_two_register_value_set':True,
            'all_complete_compiler_outputs_equal':True,'all_native_sample_oracles_pass':True,
            'all_source_capacity_refusals_transactional':True,'invalid_plans_refused':len(report['rejections'])==4,
            'canonical_fallback_exact':True,'source_unchanged':True}
        require(sum(p.stat().st_size for p in directory.iterdir() if p.is_file())<240<<20,'campaign file budget exceeded')
        report['status']='passed'
    except BaseException as exc:
        report['status']='failed';report['error']={'type':type(exc).__name__,'message':str(exc)}
        (directory/'failure.log').write_text(traceback.format_exc())
        raise
    finally:
        report['host_after']=host_observation();final=usage()
        report['storage']['final_free_bytes']=shutil.disk_usage(directory).free
        report['storage']['actual_file_bytes_before_final_report']=sum(p.stat().st_size for p in directory.iterdir() if p.is_file())
        report['total_cost']={'wall_ns':time.monotonic_ns()-started,
            'parent_cpu_ns':final['parent_cpu_ns']-initial['parent_cpu_ns'],
            'children_cpu_ns':final['children_cpu_ns']-initial['children_cpu_ns'],
            'parent_maxrss_kib':final['parent_maxrss_kib'],'children_maxrss_kib':final['children_maxrss_kib'],
            'model_calls':0,'model_tokens':0,'gpu_seconds':0}
        put(directory/'RESULT.json',report)
        with (directory/'RESULT.json').open('rb') as saved:os.fsync(saved.fileno())
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',type=Path,required=True);parser.add_argument('--expected',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--repetitions',type=int,default=3)
    parser.add_argument('--prior-preregistration',type=Path)
    args=parser.parse_args();result=run(args.output,args.profile,args.expected,args.repetitions,args.prior_preregistration)
    print(json.dumps({'status':result['status'],'ratios':result['ratios'],
        'native_invocations':len(result['native_invocations']),'total_cost':result['total_cost']},sort_keys=True))
