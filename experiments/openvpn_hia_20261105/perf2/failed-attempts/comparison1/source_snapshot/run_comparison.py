#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""One fixed-budget comparison of original C, old HIA and the frozen candidate.

Requires previous qualified objects. Symbol renaming permits old and new objects
in one process; all executable-section bytes are checked unchanged by objcopy.
Does not rewrite LLVM or accept an unqualified candidate object.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import struct
import subprocess
import time
HERE=Path(__file__).resolve().parent
EXPERIMENT=HERE.parent
ROOT=EXPERIMENT.parents[1]

def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save(p,v): Path(p).write_text(json.dumps(v,indent=2,sort_keys=True)+'\n')
def executable_sections(p):
    b=Path(p).read_bytes()
    if b[:6]!=b'\x7fELF\x02\x01':raise ValueError('expected ELF64 little endian')
    offset=struct.unpack_from('<Q',b,40)[0]
    entry,count=struct.unpack_from('<HH',b,58)
    sections={}
    for i in range(count):
        _,_,flags,_,start,size,_,_,_,_=struct.unpack_from('<IIQQQQIIQQ',b,offset+i*entry)
        if flags&4:sections[i]=b[start:start+size]
    return sections

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for flag in ('old-run','new-run','openvpn-source','openvpn-build','clang','output'):
        p.add_argument('--'+flag,type=Path,required=True)
    a=p.parse_args()
    old,new,source,build,clang,out=(getattr(a,x).resolve() for x in ('old_run','new_run','openvpn_source','openvpn_build','clang','output'))
    if out.exists():p.error('output must be new; failures and samples are never overwritten')
    out.mkdir(parents=True)
    report={'schema':'hepta.openvpn-hia.same-run-six-arm.v1','ok':False,
            'started_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'commands':[],
            'plan':json.loads((HERE/'plan.json').read_text())['benchmark_plan'],
            'source_sha256':{'paired_benchmark.c':sha(HERE/'paired_benchmark.c'),'run_comparison.py':sha(__file__)},
            'limitations':['Both HIA variants retain range admission and byte/state contracts.',
               'Shared host, no frequency lock or exclusive CPU.',
               'Batch average nanoseconds per call, not request-tail latency.',
               'C buffer control calls separately compiled official C; optimization visibility differs.',
               'Different raw/adapter harness timings do not give exact additive adapter cost.',
               'No tunnel/DCO performance or production-hotspot qualification.']}
    def run(label,command):
        row={'label':label,'command':list(map(str,command))};report['commands'].append(row)
        start=time.monotonic()
        try:r=subprocess.run(row['command'],capture_output=True,timeout=60)
        except subprocess.TimeoutExpired as e:
            row.update(timed_out=True,returncode=None)
            (out/(label+'.stdout')).write_bytes(e.stdout or b'');(out/(label+'.stderr')).write_bytes(e.stderr or b'')
            raise
        row.update(returncode=r.returncode,elapsed_seconds=time.monotonic()-start)
        (out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr)
        if r.returncode:raise RuntimeError(label+' failed; retained output')
        return r.stdout.decode()
    try:
        plan=json.loads((HERE/'plan.json').read_text())
        before=json.loads((old/'summary.json').read_text());after=json.loads((new/'summary.json').read_text())
        if not before['ok'] or not after['ok']:raise ValueError('both objects require completed qualification')
        if str(source)!=after['upstream_source'] or str(build)!=after['upstream_build']:
            raise ValueError('source/build must match the qualified C objects')
        if sha(old/'packet.o')!=plan['old_object_sha256'] or sha(old/'adapter.o')!=plan['old_adapter_sha256']:
            raise ValueError('old baseline differs from predeclared identity')
        for label,directory,receipt in [('old',old,before),('new',new,after)]:
            for obj in ('packet.o','adapter.o'):
                if sha(directory/obj)!=receipt['artifact_sha256'][obj]:raise ValueError(label+' object differs from receipt')
        if before['compiler']['sha256']!=after['compiler']['sha256'] or sha(clang)!=before['compiler']['sha256']:
            raise ValueError('old/new/C compilers must be identical')
        if before['c_flags']!=after['c_flags']:raise ValueError('C flags changed')
        for name in ('upstream-packet-id.o','c-buffer-control.o','adapter.o'):
            if sha(old/name)!=sha(new/name):raise ValueError('unchanged C control/adapter object differs: '+name)
        for rel,expected in after['local_sources'].items():
            if sha(ROOT/rel)!=expected:raise ValueError('candidate source changed after qualification: '+rel)
        if not after.get('sanitizer') or any(after['sanitizer'][k]['failures'] for k in after['sanitizer']):
            raise ValueError('candidate requires passing C-side sanitizer gates')
        regression=json.loads((HERE/'regression44.json').read_text())
        if regression['exit_code'] or sha(ROOT/'hepta/hia_program_llvm.py')!=regression['backend_sha256']:
            raise ValueError('backend differs from passing regression snapshot')
        report['regression_receipt_sha256']=sha(HERE/'regression44.json')
        report['code_size']={label:{'object_bytes':(d/'packet.o').stat().st_size,
                                   'executable_section_bytes':sum(map(len,executable_sections(d/'packet.o').values()))}
                             for label,d in [('old',old),('new',new)]}
        report['old_receipt_sha256']=sha(old/'summary.json');report['new_receipt_sha256']=sha(new/'summary.json')
        report['compiler']=after['compiler'];report['flags']=after['c_flags']
        report['object_sha256']={label:{n:sha(d/n) for n in ('packet.o','adapter.o','upstream-packet-id.o','c-buffer-control.o')} for label,d in [('old',old),('new',new)]}
        all_objects=[];report['renaming']=[]
        for label,directory in [('old',old),('new',new)]:
            mapping={}
            for operation in ('read','write','read_epoch','write_epoch'):
                mapping['ovpn_hia_packet_id_'+operation]='ovpn_hia_'+label+'_packet_id_'+operation
                mapping['hia_packet_id_'+operation]='hia_'+label+'_packet_id_'+operation
                mapping['__wrap_packet_id_'+operation]='__wrap_'+label+'_packet_id_'+operation
            mapping_file=out/(label+'-symbols.txt')
            mapping_file.write_text(''.join(k+' '+v+'\n' for k,v in mapping.items()))
            for obj in ('packet.o','adapter.o'):
                destination=out/(label+'-'+obj)
                run('rename-'+label+'-'+obj,['objcopy','--redefine-syms='+str(mapping_file),directory/obj,destination])
                if executable_sections(directory/obj)!=executable_sections(destination):
                    raise ValueError('symbol renaming changed executable bytes')
                report['renaming'].append({'input':str(directory/obj),'input_sha256':sha(directory/obj),
                    'output':str(destination),'output_sha256':sha(destination),'executable_sections_identical':True})
                all_objects.append(destination)
        flags=after['c_flags']
        run('compile-benchmark',[clang,*flags,'-c',HERE/'paired_benchmark.c','-o',out/'paired-benchmark.o'])
        run('link-benchmark',[clang,'-O3','-Wl,--gc-sections',new/'upstream-packet-id.o',new/'c-buffer-control.o',
                              *all_objects,out/'paired-benchmark.o','-o',out/'paired-benchmark'])
        cpus=sorted(os.sched_getaffinity(0));os.sched_setaffinity(0,{cpus[0]})
        report['host']={'platform':platform.platform(),'cpu_affinity':sorted(os.sched_getaffinity(0)),
                        'allowed_cpus_before':cpus,'load_average_before':os.getloadavg()}
        raw=run('samples',[out/'paired-benchmark'])
        report['host']['load_average_after']=os.getloadavg()
        rows=[json.loads(line) for line in raw.splitlines()]
        arms=rows[0]['arms'];samples=rows[1:]
        if len(samples)!=72 or any(r['calls']!=1000000 or not r['equal_sinks'] for r in samples):
            raise ValueError('incomplete fixed-budget samples or unequal observations')
        report['samples_sha256']=sha(out/'samples.stdout');report['samples_discarded']=0
        report['results']={}
        for mode,name in enumerate(('long_write','long_read','epoch_write','epoch_read')):
            selected=[r for r in samples if r['mode']==mode]
            if len(selected)!=18:raise ValueError('mode budget mismatch')
            summary={arm:{'samples':18,'median_ns_per_call':statistics.median(r['ns'][i]/r['calls'] for r in selected),
                          'minimum_ns_per_call':min(r['ns'][i]/r['calls'] for r in selected),
                          'maximum_ns_per_call':max(r['ns'][i]/r['calls'] for r in selected)} for i,arm in enumerate(arms)}
            summary['comparison']={kind:{'median_paired_new_over_old':statistics.median(r['ns'][new_i]/r['ns'][old_i] for r in selected),
                                         'new_faster_pairs':sum(r['ns'][new_i]<r['ns'][old_i] for r in selected),
                                         'pairs':18} for kind,old_i,new_i in [('raw',2,3),('adapter',4,5)]}
            summary['comparison']['new_adapter_over_original_ratio_of_medians']=summary['new_hia_adapter']['median_ns_per_call']/summary['original_c']['median_ns_per_call']
            report['results'][name]=summary
        report['benchmark_binary_sha256']=sha(out/'paired-benchmark')
        report['ok']=True
    except Exception as e:
        report['error']=repr(e);raise
    finally:
        report['finished_utc']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime());save(out/'summary.json',report)
    print(json.dumps({'ok':report['ok'],'summary':str(out/'summary.json'),'results':report['results']},indent=2))
if __name__=='__main__':main()
