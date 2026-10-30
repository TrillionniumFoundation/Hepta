#!/usr/bin/env python3
"""Development-only observation normalization profile; not a CRC study retry."""
from __future__ import annotations

from collections import Counter
import cProfile
from hashlib import sha256
import io
import json
from pathlib import Path
import pstats
import sys
import time
from unittest.mock import patch

REPO = Path('/workspace/scratch/793cbcdf54ed/Hepta')
OUT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))
from hepta import hia_finite_context as fc
from hepta.hia_crc_kernel import step

original = fc._observation


def proposed(value):
    if type(value) is int:
        fc._require(0 <= value <= fc.MASK32, 'invalid oracle u32 result')
        return {'status': 'returned', 'values': [value]}
    return original(value)


def outcome(function, value):
    try:
        return ('returned', function(value))
    except Exception as error:
        return ('rejected', type(error).__name__, str(error))


def main():
    # These artificial inputs are not any preregistered CRC phase corpus.
    requests = tuple((i, 0, 1, 0x81234567 ^ i, (0xEDB88320, 0x82F63B78, 0x12345678, 0)[i],
                      tuple((j*37+i*11) & 255 for j in range(4096))) for i in range(4))
    class IntSubclass(int):
        pass
    inputs = [0,1,127,2**31,fc.MASK32,-1,fc.MASK32+1,True,False,None,0.0,'0',[],(),IntSubclass(1),
              {'status':'returned','values':[0]}, {'status':'returned','values':[fc.MASK32]},
              {'status':'trapped','code':'overflow'}, {'status':'trapped','code':'not-a-trap'},
              {'status':'returned','values':[True]}, {'status':'returned','values':[]},
              {'status':'returned','values':[0],'extra':0}, {'status':'returned','values':[fc.MASK32+1]}]
    comparisons=[]
    for index,value in enumerate(inputs):
        before,after=outcome(original,value),outcome(proposed,value)
        assert before==after, (index,before,after)
        comparisons.append({'case':index,'input_type':type(value).__name__,'same_outcome':True,'kind':before[0]})
    fresh=[]
    for function in (original,proposed):
        left,right=function(7),function(7)
        left['values'][0]=1
        assert right=={'status':'returned','values':[7]}
        value={'status':'returned','values':[11]}
        copied=function(value)
        value['values'][0]=9
        assert copied=={'status':'returned','values':[11]}
        fresh.append(True)
    results={}
    outputs={}
    oracle_calls={}
    for name,function in (('old',original),('proposed',proposed)):
        calls=[]
        def observed_oracle(state,parameter):
            calls.append((state,parameter))
            return step(state,parameter)
        profiler=cProfile.Profile()
        started=time.monotonic_ns()
        with patch.object(fc,'_observation',function):
            profiler.enable()
            answer=fc._expected(requests,observed_oracle)
            profiler.disable()
        wall=time.monotonic_ns()-started
        output=io.StringIO()
        stats=pstats.Stats(profiler,stream=output).sort_stats('cumulative')
        stats.print_stats(24)
        (OUT/(name+'-profile.log')).write_text(output.getvalue())
        profiler.dump_stats(str(OUT/(name+'.pstats')))
        json_calls={key:0 for key in ('dumps','loads')}
        for (filename,_line,function_name),record in stats.stats.items():
            if function_name in json_calls and filename.endswith('/json/__init__.py'):
                json_calls[function_name]+=record[1]
        results[name]={'profiled_wall_ns':wall,'oracle_calls':len(calls),'json_calls':json_calls,
                       'returned_tuple_sha256':sha256(fc._wire(answer)).hexdigest(),
                       'oracle_arguments_sha256':sha256(fc._wire(calls)).hexdigest(),
                       'note':'One diagnostic pass with profiling enabled; not a wall-time estimate for CI or formal study economics.'}
        outputs[name],oracle_calls[name]=answer,calls
    assert outputs['old']==outputs['proposed']
    assert oracle_calls['old']==oracle_calls['proposed']
    assert len(oracle_calls['old'])==16384
    assert results['old']['json_calls']=={'dumps':16384,'loads':16384}
    assert results['proposed']['json_calls']=={'dumps':0,'loads':0}
    trap_results={}
    for name,function in (('old',original),('proposed',proposed)):
        calls=[]
        def trap_oracle(state,value):
            calls.append((state,value))
            return {'status':'trapped','code':'overflow'} if value==2 else (state+value)&fc.MASK32
        with patch.object(fc,'_observation',function):
            answer=fc._expected(((1,0,0,7,0,(1,2,3)),),trap_oracle)
        trap_results[name]={'output':answer,'calls':calls}
    assert trap_results['old']==trap_results['proposed']
    assert trap_results['old']['calls']==[(7,1),(8,2)]
    failed=json.loads(Path('/workspace/scratch/793cbcdf54ed/ci-triage-20261030/crc-000ac-study-RESULT.json').read_text())
    report={
        'schema':'hepta.hia.crc-oracle-normalization-diagnostic.v1',
        'base_commit':'000acac3c357430ca062957ba288756a8d89e147',
        'base_finite_context_sha256':sha256((REPO/'hepta/hia_finite_context.py').read_bytes()).hexdigest(),
        'diagnostic_kind':'Pure Python development inputs, no native context, no registered corpus, no study retry.',
        'old_ci_result_remains_failed':True,
        'old_ci_observed':{
            'qualified':failed['qualified'],'whole_study_wall_ns':failed['whole_study_wall_ns'],
            'cold_setup_ns':failed['cold_setup_ns'],'contexts_attempted':failed['contexts_attempted'],
            'calls_observed':sum(r.get('calls',0) for r in failed['samples']),
            'trace_preparation_wall_ns':sum(r.get('trace_preparation_wall_ns',0) for r in failed['samples']),
            'native_outer_wall_ns':sum(r.get('native_outer_wall_ns',0) for r in failed['samples'])},
        'profiles':results,'exact_old_new_outcomes':comparisons,'fresh_container_checks':fresh,
        'trap_prefix_old_new':trap_results,'every_oracle_call_and_order_preserved':True,
        'registered_protocol_or_budget_changed':False,'formal_study_reexecuted':False,
        'new_full_crc_ci_success_established':False,
    }
    (OUT/'RESULT.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'profiles':results,'outcome_cases':len(comparisons),'same_output_calls_and_prefix':True,
                      'formal_study_reexecuted':False,'report':str(OUT/'RESULT.json')},sort_keys=True))


if __name__=='__main__':
    main()
