#!/usr/bin/env python3
"""Preregistered paired-clock diagnostic; historical wall-time gates stay unchanged.

Replays every archived wrapper-v2 cohort with the original binary bytes. This
is a new host/observer experiment, not an independently rebuilt qualification.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import time

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from tools.qualify_hia_reduction_release import checksum

ARCHIVE=ROOT/'experiments/hia_empty_wrapper_20261103/execution.tar.xz'
ARCHIVE_SHA='ab1481e162e3c0b6414a2fa7a0b8f43f7a83e00315748a36b6e0576beb533ddc'
DRIVER=ROOT/'benchmarks/hia_reduction_tail_diagnostic/driver.c'
PREFIX='empty-wrapper-observation-1dfbfd1-r1/'

def digest(raw): return sha256(raw).hexdigest()
def write(path,value):
    path.write_text(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n')

def inspect_response(row, expected):
    for key in ('n','seed','calls','samples','warmup'):
        if type(row.get(key)) is not int or row[key]!=expected[key]:
            raise ValueError('diagnostic request identity mismatch')
    observations=row.get('observations')
    if type(observations) is not list or len(observations)!=expected['samples']:
        raise ValueError('incomplete diagnostic samples')
    oracle=sum(checksum(expected['workload'],expected['n'],(expected['seed']+i)&(2**32-1))
               for i in range(expected['calls']))
    for sample in observations:
        if type(sample) is not dict or set(sample)!={'wall_ns','cpu_envelope_ns','checksum'}:
            raise ValueError('unexpected sample fields')
        if any(type(v) is not int or not 0<=v<2**64 for v in sample.values()):
            raise ValueError('invalid sample value')
        if sample['checksum']!=oracle: raise ValueError('independent batch oracle mismatch')
    for key in ('wall_resolution_ns','cpu_resolution_ns'):
        if type(row.get(key)) is not int or row[key]<=0: raise ValueError('invalid clock resolution')
    return row

def run(output,cc):
    output=Path(output).resolve();output.mkdir(parents=True,exist_ok=False)
    archive_raw=ARCHIVE.read_bytes()
    if digest(archive_raw)!=ARCHIVE_SHA: raise ValueError('pinned archive changed')
    with tarfile.open(ARCHIVE) as archive:
        report=json.load(archive.extractfile(PREFIX+'RESULT.json'))
        products={}
        for workload,arms in report['artifacts'].items():
            for arm,identity in arms.items():
                name=workload+'/'+arm+'.so'
                raw=archive.extractfile(PREFIX+name).read()
                if digest(raw)!=identity['sha256']: raise ValueError('archived library identity mismatch')
                target=output/name;target.parent.mkdir(exist_ok=True);target.write_bytes(raw)
                products[(workload,arm)]={'path':str(target),'sha256':digest(raw)}
    cc=Path(shutil.which(cc) or cc).resolve()
    compiler={'path':str(cc),'sha256':digest(cc.read_bytes()),
              'version':subprocess.check_output([str(cc),'--version'],text=True)}
    # Freeze exact archive order, all arms, all lengths/seeds/loads, before any
    # target-library execution. No selection of tail samples or best-of retry.
    requests=[{k:row[k] for k in ('workload','group','backend','n','seed','calls','samples')}
              for row in report['measurements']]
    for row in requests: row['warmup']=report['protocol']['warmup_calls']
    source={str(p.relative_to(ROOT)):digest(p.read_bytes()) for p in (DRIVER,Path(__file__))}
    registration={'schema':'hepta.hia.reduction-tail-diagnostic.v1','archive_sha256':ARCHIVE_SHA,
        'historical_source':report.get('source_before'),'source_sha256':source,'compiler':compiler,
        'host':platform.platform(),'affinity':sorted(os.sched_getaffinity(0)),
        'selected_cpu':min(os.sched_getaffinity(0)),'requests':requests,
        'samples':sum(r['samples'] for r in requests),'clock_order':'thread CPU start, wall start, batch, wall end, thread CPU end',
        'scope':'observer perturbation and new shared host; no historical causal attribution, sample exclusion or gate replacement',
        'production_activation_allowed':False,'performance_qualified':False}
    write(output/'REGISTRATION.json',registration)
    command=[str(cc),'-std=c11','-O2','-Wall','-Wextra','-Werror',str(DRIVER),'-ldl','-o',str(output/'driver')]
    built=subprocess.run(command,capture_output=True,text=True,timeout=60)
    write(output/'BUILD.json',{'argv':command,'returncode':built.returncode,'stdout':built.stdout,'stderr':built.stderr})
    built.check_returncode()
    original_affinity=os.sched_getaffinity(0)
    result={'schema':registration['schema'],'status':'running','registration_sha256':digest((output/'REGISTRATION.json').read_bytes()),
            'driver_sha256':digest((output/'driver').read_bytes()),'observations':[],
            'authority':'DENY_ALL','performance_qualified':False,'historical_gates_changed':False}
    started=time.monotonic_ns()
    try:
        os.sched_setaffinity(0,{registration['selected_cpu']})
        for index,request in enumerate(requests):
            library=products[(request['workload'],request['backend'])]
            argv=[str(output/'driver'),library['path'],*[str(request[k]) for k in ('n','seed','calls','samples','warmup')]]
            completed=subprocess.run(argv,capture_output=True,text=True,timeout=35)
            record={'request':request,'returncode':completed.returncode,'stdout':completed.stdout,'stderr':completed.stderr}
            result['observations'].append(record)
            completed.check_returncode()
            record['response']=inspect_response(json.loads(completed.stdout),request)
            if index%100==0: write(output/'RESULT.json',result)
        result['status']='completed'
    except BaseException as error:
        result.update(status='failed',error={'type':type(error).__name__,'message':str(error)})
        raise
    finally:
        os.sched_setaffinity(0,original_affinity)
        result['wall_ns']=time.monotonic_ns()-started
        result['inputs_unchanged']=all(digest(Path(v['path']).read_bytes())==v['sha256'] for v in products.values()) and all(digest((ROOT/p).read_bytes())==h for p,h in source.items()) and digest(cc.read_bytes())==compiler['sha256']
        result['driver_unchanged']=digest((output/'driver').read_bytes())==result['driver_sha256']
        write(output/'RESULT.json',result)
    return result

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True);parser.add_argument('--cc',default='gcc')
    args=parser.parse_args();result=run(args.output,args.cc)
    print(json.dumps({k:result[k] for k in ('status','inputs_unchanged','driver_unchanged','wall_ns')}))
