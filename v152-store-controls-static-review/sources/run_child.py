"""One original 180+3 owner child; Native and VM are actual controlled executions."""
from pathlib import Path
import argparse
import sys
import time
import traceback
sys.path.insert(0,str(Path(__file__).absolute().parent))
import qualification_support as S

def execute(path,sha):
    request_row=S.G.capture(Path(path));request_raw=S.fixed(request_row)
    S.require(request_row['pin']['sha256']==sha,'whole child request differs')
    request=S.G.decode(request_raw);plan_row,plan,generation=S.load(request['plan']['path'],request['plan']['pin']['sha256'])
    S.require(request['plan']==plan_row and request['schema']==S.SCHEMA+'.request' and request['limits']==plan['limits'],'fixed actual child request required')
    stage=request['stage'];S.require(stage in plan['stages'],'unknown frozen stage')
    folder=Path(request['directory']);S.require(folder==Path(plan['scope'])/'attempt-r1'/('%02d-'%(plan['stages'].index(stage)+1)+stage),'exact stage directory differs')
    runtime,_=S.G.import_runtime(plan)
    runtime.guard_runtime_context(plan['runtime'])
    actual_runtime=runtime.capture_runtime_context()
    S.require(actual_runtime==plan['runtime'],'fixed actual runtime context differs')
    before=S.guard(plan,generation,runtime.guard_runtime_context)
    prior_rows=S.prior_readback(request['prior_inventories'])
    result=dict(schema=S.SCHEMA+'.child',status='FAIL',stage=stage,request=request_row,started_ns=time.monotonic_ns(),
        full_before=before,actual_runtime=actual_runtime,compile_calls=0,Native_calls=0,VM_calls=0,default=False,whole=False,durability=False,errors=[])
    engine=None
    try:
        sys.path.insert(0,plan['source'])
        if stage.startswith('compile-'):
            component=stage[8:];S.require(request['build'] is None,'no future image accepted')
            output=folder/'compile';output.mkdir(mode=0o700)
            result['compile_calls']=1
            result['build']=S.compile_component(plan,component,output)
        else:
            component=stage.split('-',1)[0];build=request['build']
            image=S.image_guard(plan,build)
            S.require(build['component']==component,'wrong actual built component')
            source=S.fixed(plan['components'][component]['asset']);oracle=S.load_oracle(plan,component)
            # Cooperative protection retains every original source/runtime inode,
            # original authors and all explicit new controls/compiler inputs.
            S.G.fence(generation,[*plan['controls'].values(),*plan['inputs'].values(),plan['compiler'],
                *plan['generation_files'],*plan['terminal_files'],*request['prior_inventories'],
                *prior_rows,*build['files'],request_row])
            from observations import PairEngine
            import head_cases,catalog_cases
            engine=PairEngine(source,image,plan['components'][component]['asset']['pin']['sha256'],folder/'frames')
            result['cases']=(head_cases if component=='head' else catalog_cases).run(engine,oracle,stage)
            S.require(result['cases']['cases']==plan['groups'][stage]['cases']
                and len(engine.calls)==plan['groups'][stage]['paired_calls'],
                'all frozen case IDs and real paired call counts required')
        result['status']='PASS'
    except BaseException:result['errors'].append(traceback.format_exc())
    finally:
        if engine is not None:
            try:engine.close()
            except BaseException:result['errors'].append(traceback.format_exc())
            result['Native_calls']=len(engine.calls);result['VM_calls']=sum(r.get('vm_attempts',0) for r in engine.calls)
            if not result['errors']:
                try:result['frames']=S.frames(folder,plan,component,build)
                except BaseException:result['errors'].append(traceback.format_exc())
        try:
            S.require(S.fixed(request_row)==request_raw,'frozen request changed')
            S.require(S.prior_readback(request['prior_inventories'])==prior_rows,'complete prior artifacts changed')
            after=S.guard(plan,generation,runtime.guard_runtime_context);S.equal(before,after);result['full_after']=after
        except BaseException:result['errors'].append(traceback.format_exc())
        if result['errors']:result['status']='FAIL'
        result['finished_ns']=time.monotonic_ns();S.write(folder/'CHILD-RESULT.json',result)
    return 0 if result['status']=='PASS' else 1

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--request',required=True);p.add_argument('--sha256',required=True)
    a=p.parse_args();raise SystemExit(execute(a.request,a.sha256))
