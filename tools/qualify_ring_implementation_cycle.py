#!/usr/bin/env python3
"""Qualify a real stable-ABI upstream implementation change and native hosts.

This separate profile translates captured inline-array C bodies through checked
Hepta and the independent C backend. It preserves both revisions' distinct
semantics and unread payload. It does not claim formal source equivalence,
Rust-backed safety, arbitrary C support, or physical device qualification.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import random
import re
import resource
import shutil
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from tools.migrate_c_inline_record_project import migrate_inline_project, load_contract
from tools.qualify_ring_maintenance import (tree_identity, git_object, materialize,
    verify_materialized, make_wrapper, expected_thread_observation, validate_observation, quantile)

FIXTURE=ROOT/'tests/fixtures/c_migration/ring_buffer_implementation_history'
PROTOCOL=ROOT/'experiments/ring_implementation_cycle/PROTOCOL.json'
HOST=ROOT/'tools/fixtures/ring_inline_host.c'
SUPERVISOR=ROOT/'examples/hia_filecheck/rss_supervisor.c'
PINNED={'before':('8f133fe1ea0b0ce0095bb9552ba7fbb7caeac600','d2db09d1576bfcc635b212f598ee727a0a04f007'),
        'after':('bbe82ad2b460db79d94bbb847dd3b3ece4f191cb','ae95a50c8ce843ca48a07a8465a09ada7efbe0da')}


def require(value,message):
    if not value: raise ValueError(message)


def identity(path):
    path=Path(path); raw=path.read_bytes()
    return {'path':str(path.absolute()),'bytes':len(raw),'sha256':sha256(raw).hexdigest()}


def write_json(path,value):
    Path(path).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def verify_upstream(fixture=FIXTURE):
    fixture=Path(fixture); manifest=json.loads((fixture/'UPSTREAM.json').read_text()); inventories={}
    require(manifest['repository']=='https://github.com/AndersKaloer/Ring-Buffer','upstream repository drift')
    require([v['name'] for v in manifest['versions']]==list(PINNED),'upstream versions drift')
    for version in manifest['versions']:
        require((version['commit'],version['tree'])==PINNED[version['name']],'pinned upstream identity drift')
        require(len(version['files'])==8 and tree_identity(version['files'])==version['tree'],'incomplete original upstream tree')
        for entry in version['files']:
            blob=fixture/'blobs'/entry['git_blob'];require(blob.is_file() and not blob.is_symlink(),'ordinary upstream blob required')
            raw=blob.read_bytes();require(len(raw)==entry['bytes'] and sha256(raw).hexdigest()==entry['sha256'] and git_object('blob',raw)==entry['git_blob'],'upstream blob mismatch')
        inventories[version['name']]={e['path']:(e['mode'],e['git_blob']) for e in version['files']}
    a,b=inventories['before'],inventories['after']
    require(sorted(p for p in a.keys()|b.keys() if a.get(p)!=b.get(p))==['ringbuffer.c'],'expected an implementation-only upstream fix')
    return manifest


def operation_stream(seed,random_operations):
    # Regression prefix differentiates both historical semantics before random
    # stateful coverage. All external outputs have 256 initialized backing bytes.
    operations=[('I',[]),('A',[10,20,30,40]),('R',[0]),('R',[1]),('D',[]),('P',[0]),('E',[]),
                ('I',[]),('A',list(range(255))),('P',[126]),('P',[127]),('R',[127]),('D',[]),
                ('I',[]),('Q',[255]),('D',[]),('A',[]),('R',[255])]
    rng=random.Random(seed)
    for ordinal in range(random_operations):
        op=rng.choice(['Q','Q','A','A','D','R','R','P','E'])
        if ordinal%97==0: op='I'
        if op=='Q': values=[rng.randrange(256)]
        elif op=='A': values=[rng.randrange(256) for _ in range(rng.choice([0,1,2,7,63,127,128,255]))]
        elif op in {'R','P'}: values=[rng.choice([0,1,2,7,63,126,127,128,255])]
        else: values=[]
        operations.append((op,values))
    return operations


def encode_operations(operations):
    return ''.join(op+(' '+str(len(values)) if op=='A' else '')+''.join(' '+str(v) for v in values)+'\n' for op,values in operations).encode()


def oracle(operations,revision):
    """Independent byte/state model with separately specified legacy extra pop."""
    require(revision in PINNED,'unknown model revision')
    payload=bytearray([0xa5]*128);head=tail=0; rows=[]
    def take(output,index):
        nonlocal tail
        if head==tail:return False
        output[index]=payload[tail];tail=(tail+1)%128;return True
    for op,values in operations:
        returned=0;output=bytearray([0xa5]*256)
        if op=='I':head=tail=0
        elif op in {'Q','A'}:
            for byte in values:
                if (head+1)%128==tail:tail=(tail+1)%128
                payload[head]=byte;head=(head+1)%128
        elif op=='D':returned=int(take(output,0))
        elif op=='P':
            if values[0]<(head-tail)%128:output[0]=payload[(tail+values[0])%128];returned=1
        elif op=='R':
            length=values[0]
            if revision=='before':
                while take(output,returned):
                    if returned>=length:break
                    returned+=1
            else:
                while returned<length and take(output,returned):returned+=1
        else:require(op=='E','unknown model operation')
        rows.append({'return':returned,'head':head,'tail':tail,'count':(head-tail)%128,'empty':int(head==tail),'full':int((head+1)%128==tail),'payload':payload.hex(),'output':output.hex()})
    return rows


def source_bindings():
    paths=[Path(__file__),ROOT/'tools/migrate_c_inline_record_project.py',ROOT/'tools/qualify_ring_maintenance.py',ROOT/'tools/qualify_c_ring_buffer.py',ROOT/'tools/qualify_c_migration.py',HOST,SUPERVISOR,PROTOCOL,*sorted((ROOT/'hepta').glob('*.py')),*sorted(FIXTURE.rglob('*'))]
    return {str(p.relative_to(ROOT)):identity(p)['sha256'] for p in paths if p.is_file()}


class Evidence:
    def __init__(self,directory):
        self.directory=Path(directory);self.directory.mkdir(parents=True)
        self.commands=self.directory/'commands';self.commands.mkdir()
        self.count=0;self.phases=[];self.started=time.perf_counter_ns()
        self.event('instrumentation_started',scope='from runner start onward; earlier engineering and preparation not timed')

    def event(self,event,**values):
        row={'schema':'hepta.migration.prospective-work-event.v1','event':event,'utc':datetime.now(timezone.utc).isoformat(),'monotonic_ns':time.perf_counter_ns(),**values}
        with (self.directory/'WORK_JOURNAL.jsonl').open('a') as stream:stream.write(json.dumps(row,sort_keys=True)+'\n')

    @contextmanager
    def stage(self,name):
        start=time.perf_counter_ns();self.event('stage_started',name=name);ok=False
        try:yield;ok=True
        finally:
            row={'name':name,'wall_ns':time.perf_counter_ns()-start,'ok':ok};self.phases.append(row);self.event('stage_completed',**row)

    def command(self,argv,name,*,cwd=None,input_bytes=None,expected=0):
        self.count+=1;tag=f'{self.count:04d}-{name}';argv=list(map(str,argv))
        if input_bytes is not None:(self.commands/(tag+'.stdin')).write_bytes(input_bytes)
        start=time.perf_counter_ns();p=subprocess.run(argv,cwd=cwd,input=input_bytes,capture_output=True,timeout=120)
        elapsed=time.perf_counter_ns()-start
        stdout=self.commands/(tag+'.stdout');stderr=self.commands/(tag+'.stderr');stdout.write_bytes(p.stdout);stderr.write_bytes(p.stderr)
        receipt={'argv':argv,'cwd':str(cwd or ROOT),'returncode':p.returncode,'wall_ns':elapsed,'stdout':identity(stdout),'stderr':identity(stderr)}
        if input_bytes is not None:receipt['stdin']=identity(self.commands/(tag+'.stdin'))
        write_json(self.commands/(tag+'.json'),receipt)
        self.event('command_completed',name=name,receipt=str(self.commands/(tag+'.json')),returncode=p.returncode,wall_ns=elapsed)
        require(expected is None or p.returncode==expected,f'{name}: exit {p.returncode}; retained stderr {stderr}')
        return p.stdout


def verify_committed(evidence,bindings,commit,development):
    require(re.fullmatch('[0-9a-f]{40}',commit) is not None,'source SHA must be full hexadecimal Git commit')
    head=evidence.command(['git','rev-parse','HEAD'],'git-head',cwd=ROOT).decode().strip()
    if development:return {'commit':commit,'checkout_head':head,'frozen':False,'reason':'explicit development run with working sources; no formal claim'}
    rows=evidence.command(['git','ls-tree','-r','--full-tree',commit,'--',*bindings],'git-source-inventory',cwd=ROOT).decode().splitlines();tree={}
    for row in rows:
        metadata,path=row.split('\t',1);mode,kind,blob=metadata.split();require(kind=='blob' and mode in {'100644','100755'},'source file mode');tree[path]=blob
    require(set(tree)==set(bindings),'source absent from registered commit')
    for path,digest in bindings.items():
        raw=(ROOT/path).read_bytes();require(sha256(raw).hexdigest()==digest and git_object('blob',raw)==tree[path],'source differs from registered commit: '+path)
    return {'commit':commit,'checkout_head':head,'frozen':True,'files':len(tree),'all_git_blob_and_sha256_match':True}


def qualify(output,*,source_sha,native_host,clang,cc,development=False):
    evidence=Evidence(output);out=evidence.directory;protocol=json.loads(PROTOCOL.read_text())
    report={'schema':'hepta.ring-implementation-cycle.result.v1','ok':False,'status':'running','development':development,'source_sha':source_sha,'protocol':protocol,
        'versions':{},'host':{'system':platform.system(),'machine':platform.machine(),'release':platform.release()},
        'claims':{'source_equivalence_proved':False,'whole_language_safety_proved':False,'rust_codegen_used':False,'standalone_hia_core_llvm_qualified':False,'physical_hardware_qualified':False,'unsynchronized_shared_access_safe':False,'optimization_advantage':False},
        'costs':{'human_engineering_seconds':None,'human_review_seconds':None,'agent_input_tokens':None,'agent_output_tokens':None,'agent_reasoning_tokens':None,
                 'missing_usage_reason':'No human attestation or model usage receipt is available; unknown is not zero.','earlier_engineering_setup_wall_ns':None}}
    bindings=source_bindings();write_json(out/'SOURCE_BINDINGS.json',bindings);write_json(out/'PROTOCOL.json',protocol)
    try:
        require(platform.system()=='Linux' and native_host in protocol['hosts'] and platform.machine()==native_host,'requested native Linux host not observed')
        require(protocol['schema']=='hepta.ring-implementation-cycle.protocol.v1' and protocol['revisions']=={k:v[0] for k,v in PINNED.items()},'protocol identity drift')
        with evidence.stage('source_and_upstream_verification'):
            report['registration']=verify_committed(evidence,bindings,source_sha,development);manifest=verify_upstream();report['upstream']=manifest
            cc=str(Path(shutil.which(cc) or cc).resolve());clang=str(Path(shutil.which(clang) or clang).resolve())
            require(Path(shutil.which('gcc')).resolve()==Path(cc),'original Makefile compiler gcc must equal selected --cc')
            report['toolchains']={name:{**identity(path),'version':evidence.command([path,'--version'],name+'-version').decode()} for name,path in [('cc',cc),('clang',clang)]}
        work=out/'workspace';work.mkdir();supervisor=work/'rss-supervisor'
        with evidence.stage('host_observer_build'):
            evidence.command([cc,'-std=c11','-O2','-Wall','-Wextra',SUPERVISOR,'-o',supervisor],'build-rss-supervisor')
        operations=operation_stream(protocol['trace_seed'],protocol['random_operations']);encoded=encode_operations(operations);(out/'OPERATIONS.txt').write_bytes(encoded)
        observations={};plans={}
        for version in manifest['versions']:
            name=version['name'];project=work/name;migrated=work/(name+'-translated');entry={'upstream_commit':version['commit'],'upstream_tree':version['tree'],'original_source_edits':0};report['versions'][name]=entry
            with evidence.stage(name+'.original_project_materialization'):
                materialize(version,project,FIXTURE);database=project/'compile_commands.json'
                write_json(database,[{'directory':str(project),'file':str(project/'ringbuffer.c'),'arguments':['gcc','-Wall','-g','-O2','-std=c99','-c',str(project/'ringbuffer.c'),'-o',str(project/'ringbuffer.o')]}])
            with evidence.stage(name+'.capture_translation_check_compile'):
                result=migrate_inline_project(database,migrated,contracts=load_contract(FIXTURE/('contracts-'+name+'.json')),clang=clang,cc=cc,verify_native=True)
                write_json(out/(name+'-migration.json'),result);require(result['ok'],name+' migration failed; receipt retained')
                require(len(result['functions'])==protocol['functions'] and result['declaration_inventory_complete'],'incomplete implementation migration')
                entry['migration_receipt']=identity(out/(name+'-migration.json'));entry['hepta_source']=identity(migrated/'source.hepta');entry['generated_c']=identity(migrated/'generated.c')
            with evidence.stage(name+'.original_build_and_client'):
                examples=project/'examples';evidence.command(['make','clean'],name+'-original-clean',cwd=examples);evidence.command(['make'],name+'-original-make',cwd=examples)
                original_stdout=evidence.command([examples/'simple'],name+'-original-client');(examples/'simple').rename(examples/'simple.original')
            with evidence.stage(name+'.implementation_switch_original_build_and_client'):
                wrapper,_=make_wrapper(migrated,cc=cc,original=project/'ringbuffer.c',library=migrated/'libtranslated.so')
                evidence.command(['make','clean'],name+'-migrated-clean',cwd=examples)
                evidence.command(['make','CC='+sys.executable+' '+str(wrapper)],name+'-migrated-make',cwd=examples)
                migrated_stdout=evidence.command([examples/'simple'],name+'-migrated-client');(examples/'simple').rename(examples/'simple.translated')
                require(original_stdout==migrated_stdout,'unchanged original example differs')
                entry['original_makefile_client']={'stdout_equal':True,'stdout_bytes':len(original_stdout),'stdout_sha256':sha256(original_stdout).hexdigest(),'makefile_edited':False,'client_edited':False,'payload_initialization_added_to_original_client':False,'cc_substitution_log':identity(migrated/'cc-invocations.jsonl')}
            with evidence.stage(name+'.native_harness_build'):
                original=project/'liboriginal.so';host=project/'host'
                evidence.command([cc,'-std=c99','-Wall','-g','-O2','-shared','-fPIC',project/'ringbuffer.c','-o',original],name+'-original-library')
                evidence.command([cc,'-std=c11','-O2','-Wall','-Wextra','-Werror','-pthread','-I'+str(project),HOST,'-ldl','-o',host],name+'-host-build')
                entry['native_artifacts']={key:identity(value) for key,value in [('original',original),('translated',migrated/'libtranslated.so'),('host',host)]}
            expected=oracle(operations,name);(out/(name+'-ORACLE.jsonl')).write_text(''.join(json.dumps(row,sort_keys=True)+'\n' for row in expected));entry['functional']={}
            with evidence.stage(name+'.revision_specific_full_state_verification'):
                for arm,library in [('original',original),('translated',migrated/'libtranslated.so')]:
                    abi=json.loads(evidence.command([host,library,'abi'],name+'-'+arm+'-abi'))
                    require({k:abi[k] for k in ['record_size','record_align','buffer_offset','tail_offset','head_offset','buffer_capacity']}=={'record_size':130,'record_align':1,'buffer_offset':0,'tail_offset':128,'head_offset':129,'buffer_capacity':128},'native ABI layout mismatch')
                    raw=evidence.command([host,library,'trace'],name+'-'+arm+'-trace',input_bytes=encoded);rows=[json.loads(line) for line in raw.splitlines()]
                    require(rows==expected,name+' '+arm+' full-state oracle mismatch');observations[(name,arm)]=rows
                    entry['functional'][arm]={'operations':len(rows),'all_full_state_rows_equal_independent_oracle':True,'abi':abi,'trace_sha256':sha256(raw).hexdigest()}
                    devices=json.loads(evidence.command([host,library,'devices'],name+'-'+arm+'-os-devices'));require(devices['descriptors_before']==devices['descriptors_after'] and devices['ring_roundtrip'] and devices['physical_device'] is False,'device recovery mismatch')
                    entry.setdefault('os_descriptors',{})[arm]=devices
                verify_materialized(version,project)
            with evidence.stage(name+'.guard_failure_and_parent_recovery'):
                entry['guard_faults']=[json.loads(evidence.command([host,migrated/'libtranslated.so','fault',str(mode)],name+'-guard-'+str(mode))) for mode in range(5)]
            plans[name]=(host,original,migrated/'libtranslated.so')
        with evidence.stage('wrong_revision_and_contract_negative_controls'):
            controls=[]
            for name,other in [('before','after'),('after','before')]:
                for arm in ['original','translated']:
                    actual=observations[(name,arm)];wrong=oracle(operations,other);first=next((i for i,(a,b) in enumerate(zip(actual,wrong)) if a!=b),None)
                    require(first is not None,'wrong-revision oracle failed to detect semantic change');controls.append({'candidate_revision':name,'arm':arm,'wrong_oracle_revision':other,'rejected':True,'first_mismatch_operation':first})
            invalid=load_contract(FIXTURE/'contracts-before.json');invalid['functions']['ring_buffer_dequeue_arr']['slice_extra']['data']=0
            bad=migrate_inline_project(work/'before'/'compile_commands.json',work/'legacy-wrong-extent',contracts=invalid,clang=clang,cc=cc,verify_native=True);write_json(out/'legacy-wrong-extent-migration.json',bad);require(bad['ok'],'negative extent control did not compile')
            negative=json.loads(evidence.command([plans['before'][0],work/'legacy-wrong-extent'/'libtranslated.so','fault','5'],'legacy-missing-extra-extent'))
            report['negative_controls']={'wrong_revision':controls,'legacy_missing_extent':negative}
        with evidence.stage('native_rss_concurrency_and_batch_tail_observation'):
            for name,(host,original,migrated) in plans.items():
                report['versions'][name]['host_samples']=[]
                for profile in protocol['batch_profiles']:
                    expected=expected_thread_observation(profile['threads'],protocol['batches_per_thread'],protocol['transactions_per_batch'])
                    for repeat in range(protocol['repeats']):
                        arms=[('original',original),('translated',migrated)]
                        if repeat%2:arms.reverse()
                        for arm,library in arms:
                            label=f"{name}-{profile['name']}-{repeat}-{arm}";receipt=out/(label+'-RSS.json')
                            command=[supervisor,receipt,host,library,'concurrency',profile['threads'],int(profile['shared']),protocol['batches_per_thread'],protocol['transactions_per_batch']]
                            observed=json.loads(evidence.command(command,label));validate_observation(observed,profile,protocol,expected);rss=json.loads(receipt.read_text())
                            require(rss['child_exit_code']==0 and rss['child_signal']==0 and rss['child_wait4_ru_maxrss_kib']>0,'RSS supervisor child failed')
                            report['versions'][name]['host_samples'].append({'profile':profile['name'],'arm':arm,'repeat':repeat,'observation':observed,'rss':rss,'batch_p50_ns':quantile(observed['batch_ns'],50),'batch_p95_ns':quantile(observed['batch_ns'],95),'batch_p99_ns':quantile(observed['batch_ns'],99),'rss_interpretation':'whole process observed peak including pre-exec baseline, not attribution to ring or hard memory bound'})
        with evidence.stage('cleanup_and_source_reverification'):
            for version in manifest['versions']:
                project=work/version['name'];evidence.command(['make','clean'],version['name']+'-final-build-clean',cwd=project/'examples');verify_materialized(version,project)
            require(source_bindings()==bindings,'qualification source changed while running')
        report.update(ok=True,status='qualified_finite_native_maintenance_and_host_profiles')
        report['maintenance']={'actual_upstream_implementation_changed':True,'all_nine_bodies_retranslated_each_revision':True,'original_interface_and_build_preserved':True,'legacy_extra_pop_and_write_preserved':True,'new_short_read_fix_observed':True,'manual_upstream_source_edits':0,'migration_path':'captured C -> checked Hepta -> independent C backend -> original C ABI'}
    except Exception as error:
        report.update(ok=False,status='failed',error={'type':type(error).__name__,'message':str(error)})
    finally:
        report['costs'].update(runner_wall_ns=time.perf_counter_ns()-evidence.started,top_level_command_invocations=evidence.count,phases=evidence.phases,phase_wall_ns_sum=sum(p['wall_ns'] for p in evidence.phases),phase_scope='non-overlapping explicitly instrumented runner stages; setup outside stages and final evidence serialization not assigned a fake zero')
        report['costs']['parent_and_child_cpu_seconds_observed']={key:getattr(resource.getrusage(who),attr) for key,who,attr in [('parent_user',resource.RUSAGE_SELF,'ru_utime'),('parent_system',resource.RUSAGE_SELF,'ru_stime'),('children_user',resource.RUSAGE_CHILDREN,'ru_utime'),('children_system',resource.RUSAGE_CHILDREN,'ru_stime')]}
        write_json(out/'RESULT.json',report);evidence.event('qualification_finished',ok=report['ok'],result=identity(out/'RESULT.json'))
        members={str(path.relative_to(out)):identity(path) for path in sorted(out.rglob('*')) if path.is_file() and path.name!='MANIFEST.json'}
        write_json(out/'MANIFEST.json',{'schema':'hepta.ring-implementation-evidence.v1','files':members})
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',required=True);parser.add_argument('--source-sha',required=True);parser.add_argument('--native-host',choices=['x86_64','aarch64'],required=True);parser.add_argument('--clang',default='clang-20');parser.add_argument('--cc',default='gcc');parser.add_argument('--development',action='store_true');args=parser.parse_args()
    result=qualify(args.output,source_sha=args.source_sha,native_host=args.native_host,clang=args.clang,cc=args.cc,development=args.development)
    print(json.dumps({'ok':result['ok'],'status':result['status'],'error':result.get('error'),'result':str(Path(args.output).absolute()/'RESULT.json')}));return 0 if result['ok'] else 1


if __name__=='__main__':raise SystemExit(main())
