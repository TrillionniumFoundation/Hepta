#!/usr/bin/env python3
"""Read CI ZIPs, retained test IDs/observations and immutable Git blobs only.

No archive extraction, import of project code, native/model/tokenizer execution,
network fetch or credential changes. A successful audit is not a fresh CI run.
"""
import argparse
import ast
import collections
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile
import zipfile

MAX_FILE=64*1024*1024
MAX_ARCHIVE_CONTENT=1024*1024*1024
TEST_ID=re.compile(r'\btest[A-Za-z0-9_]* \((tests\.[^)\r\n]+)\)')
PROVIDERS={'json_scalar_reasoning':'score','two_file_signature_repair':'span','owner_flow_repair':'touch','saturating_score':'score','wide_span_upgrade':'span','owned_byte_return':'touch','owner_pair_replace':'replace'}
READS={}
GROUPS={}

def sha(data):return hashlib.sha256(data).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def require(condition,message):
    if not condition:raise ValueError(message)
def file_identity(path):
    path=Path(path);h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1048576),b''):h.update(block)
    return {'path':str(path),'bytes':path.stat().st_size,'sha256':h.hexdigest()}
def safe(path):
    p=PurePosixPath(path)
    return bool(path) and not p.is_absolute() and '..' not in p.parts and '\\' not in path
def read_member(z,name):
    require(safe(name),'unsafe requested member')
    info=z.getinfo(name);require(info.file_size<=MAX_FILE,'oversized member: '+name)
    data=z.read(info)
    READS[str(z.filename)+'!'+name]={'archive':str(z.filename),'member':name,'bytes':len(data),'sha256':sha(data)}
    return data
def load(z,name):return json.loads(read_member(z,name))
def check_zip(z):
    members=z.infolist();names=[m.filename for m in members]
    require(len(names)==len(set(names)),'duplicate archive path')
    require(sum(m.file_size for m in members)<=MAX_ARCHIVE_CONTENT,'archive budget')
    for m in members:
        mode=(m.external_attr>>16)&0xffff
        require(safe(m.filename),'unsafe archive path')
        require(not (m.flag_bits&1),'encrypted member')
        require(not stat.S_ISLNK(mode),'symbolic link member')
        require(m.file_size<=MAX_FILE,'oversized archive member')
    return {'members':len(members),'uncompressed_bytes':sum(m.file_size for m in members),'safe_unique_unencrypted_names':True}
def register_group(name,source):
    require(type(source) is dict and all(safe(p) and re.fullmatch('[0-9a-f]{64}',v) for p,v in source.items()),'invalid source inventory '+name)
    GROUPS[name]=source

def git_output(repo,args,allow_failure=False):
    env=dict(os.environ,GIT_NO_LAZY_FETCH='1',GIT_TERMINAL_PROMPT='0',GIT_ALLOW_PROTOCOL='file')
    p=subprocess.run(['git','-C',str(repo),*args],capture_output=True,env=env,timeout=45)
    if not allow_failure:require(p.returncode==0,'read-only git command failed')
    return p

def verify_git_sources(repo,commit):
    expected={};contexts=collections.defaultdict(list)
    for group,source in GROUPS.items():
        for path,digest in source.items():
            require(path not in expected or expected[path]==digest,'different source hashes for same tree path: '+path)
            expected[path]=digest;contexts[path].append(group)
    env=dict(os.environ,GIT_NO_LAZY_FETCH='1',GIT_TERMINAL_PROMPT='0',GIT_ALLOW_PROTOCOL='file')
    checked=[]
    # A prefilled temporary stdin avoids a pipe deadlock while reading bodies.
    # No object bytes are materialized into the checkout or review directory.
    with tempfile.TemporaryFile() as request, tempfile.TemporaryFile() as errors:
        for path in sorted(expected):request.write((commit+':'+path+'\n').encode())
        request.seek(0)
        proc=subprocess.Popen(['git','-C',str(repo),'cat-file','--batch'],stdin=request,stdout=subprocess.PIPE,stderr=errors,env=env)
        try:
            for path in sorted(expected):
                header=proc.stdout.readline().decode().strip().split()
                require(len(header)==3 and header[1]=='blob','missing or non-blob source: '+path)
                size=int(header[2]);require(size<=MAX_FILE,'source blob budget')
                digest=hashlib.sha256();remaining=size
                while remaining:
                    chunk=proc.stdout.read(min(1048576,remaining));require(bool(chunk),'truncated Git object')
                    digest.update(chunk);remaining-=len(chunk)
                require(proc.stdout.read(1)==b'\n','Git batch delimiter')
                require(digest.hexdigest()==expected[path],'Git source digest mismatch: '+path)
                checked.append({'path':path,'blob':header[0],'bytes':size,'sha256':digest.hexdigest(),'groups':contexts[path]})
            require(proc.wait(timeout=30)==0,'Git source stream failed')
        finally:
            if proc.poll() is None:proc.kill();proc.wait()
    return checked

def observe(value,language,task):
    require(type(value) is dict and value.get('status')=='correct','observation is not correct')
    require(all(value.get(k) is True for k in ['native_executed','artifact_unchanged','resource_contract_passed','vm_contract_passed']),'missing observation gate')
    execution=value['execution'];require(execution['returncode']==0 and execution['timeout'] is False,'native exit or timeout')
    observed=value['observations'];expected=value['expected']
    require(bool(observed) and len(observed)==len(expected),'empty or incomplete observations')
    parsed=[]
    for line in execution['stdout'].splitlines():
        require(re.fullmatch(r'[0-9]+(?: [0-9]+){11,13}',line) is not None,'native stdout shape')
        parsed.append([int(v) for v in line.split()])
    require(parsed==observed,'stdout/observation mismatch')
    require([r[:2] for r in observed]==expected,'output/expected mismatch')
    provider=PROVIDERS[task];allocations=1 if provider=='touch' else 3 if provider=='replace' else 0
    peak=8 if provider=='touch' else 17 if provider=='replace' else 0
    for row in observed:
        require(len(row)==(14 if language=='rust' else 12),'resource observation width')
        for start in [2,7]:
            require(row[start]==row[start+1] and row[start]<=allocations and row[start+2]==0 and row[start+3]<=peak and row[start+4]==0,'native resource arithmetic')
        if language=='rust':require(row[12:]==[1,1],'Rust provider witness')
    vm=value['hia_vm']
    if language=='rust':require(vm is None,'Rust incorrectly presented as independent HIA VM')
    else:
        require(type(vm) is list and len(vm)==len(observed),'missing HIA VM observations')
        for i,pair in enumerate(vm):
            require(len(pair)==2,'HIA entry/provider pair')
            for part,item in enumerate(pair):
                require(item['status']=='returned' and item['values']==[observed[i][part]] and item['provider_contract'] is True,'HIA VM value/provider gate')
                r=item['resources'];require(r['allocations']==r['frees']==allocations,'HIA allocation accounting')
                require(r['live_owners']==r['live_bytes']==r['live_local_loans']==0 and r['peak_bytes']<=peak,'HIA live/peak accounting')
    return len(observed)

def check_references(z,public_source,expected_count,prefix):
    prefix=prefix.rstrip('/')+'/'
    require(safe(prefix),'unsafe reference prefix')
    plan=load(z,prefix+'PLAN.json');result=load(z,prefix+'REFERENCES.json')
    require(result['source_commit']==plan['source_commit']==public_source,'reference source attribution')
    require(all(result[k]==v for k,v in plan.items()),'plan/result drift')
    require(result['complete'] is True and result['status']=='all_references_attempted','incomplete references')
    require(result['source_unchanged'] is True and result['tools_unchanged'] is True,'reference identity boundary')
    require(result['attempted_count']==result['passed']==plan['expected_count']==expected_count,'reference counts')
    require(result['missing_ids']==[],'missing reference IDs')
    for key in ['model_requests','tokenizer_invocations','agent_successes']:require(result[key]==0,'reference/model conflation')
    require(result['capacity_qualified'] is False and result['model_qualified'] is False,'reference/qualification conflation')
    register_group('reference_source',plan['source_bindings'])
    for path,digest in plan['source_bindings'].items():require(sha(read_member(z,prefix+'source_snapshot/'+path))==digest,'reference snapshot digest')
    protocol_paths=[p for p,d in plan['source_bindings'].items() if p.endswith('/PROTOCOL.json') and d==plan['protocol_sha256']]
    require(len(protocol_paths)==1,'ambiguous reference protocol')
    cfg=load(z,prefix+'source_snapshot/'+protocol_paths[0])
    ids=['calibration/'+t+'/calibration' for t in cfg['qualification']['tasks']]
    arms=cfg['arms']
    for i,task in enumerate(cfg['tasks']):ids += ['main/'+task+'/'+a for a in arms[i%4:]+arms[:i%4]]
    require(ids==plan['expected_ids']==[r['id'] for r in result['rows']],'reference registered order')
    require(len(ids)==len(set(ids))==expected_count and set(plan['task_inputs'])==set(ids),'reference unique registry')
    rows=[];artifacts=[]
    for row in result['rows']:
        folder=prefix+row['id']+'/'
        require(load(z,folder+'ROW.json')==row,'reference row persistence')
        require(row['passed'] is True and row['source_unchanged'] is True and row['tools_unchanged'] is True,'reference row gate')
        require(row['model_requests']==0 and row['model_answer'] is False,'reference origin')
        inp=load(z,folder+'INPUT.json');query=inp['query']
        require(sha(canonical(inp))==row['input_sha256'],'input digest')
        require(inp['task_sha256']==plan['task_inputs'][row['id']],'task input digest')
        require(inp['model_requests']==0 and inp['reference_is_model_answer'] is False,'input/model conflation')
        answer_hash=sha(canonical(inp['reference_response']))
        require(answer_hash==inp['reference_response_sha256']==row['reference_response_sha256'],'reference response digest')
        require(sha(canonical({k:v for k,v in query.items() if k!='query_sha256'}))==query['query_sha256']==row['query_sha256'],'query digest')
        require(query['source_revision']==row['source_revision'],'source revision')
        public=row['public'];built=public['build'];hidden=row['terminal_hidden']
        require(public['accepted'] is True and public['status']=='correct','public acceptance gate')
        require(built['status']=='compiled' and built['native_built'] is True and built['language']==row['language'],'native compilation gate')
        require(built['compile']['returncode']==0,'compiler failed')
        require(built['compiler']==plan['tools']['clang' if row['language']=='hia' else 'rustc'],'compiler metadata drift')
        require(public==load(z,folder+'reference/STUDY_EVALUATION.json'),'persisted public record')
        require(built==load(z,folder+'reference/candidate/BUILD.json'),'persisted build record')
        require(hidden==load(z,folder+'TERMINAL_HIDDEN.json'),'persisted hidden record')
        public_count=observe(public['public'],row['language'],row['task'])
        hidden_count=observe(hidden,row['language'],row['task'])
        artifact_name=folder+'reference/candidate/candidate';binary=read_member(z,artifact_name)
        require(built['artifact']['path'].endswith('/'+artifact_name),'artifact path escapes expected row')
        require(binary.startswith(b'\x7fELF') and len(binary)==built['artifact']['bytes'] and sha(binary)==built['artifact']['sha256'],'ELF artifact bytes/hash')
        artifacts.append({'member':artifact_name,'kind':'native_executable','bytes':len(binary),'sha256':sha(binary)})
        if row['language']=='hia':
            core_name=folder+'reference/candidate/candidate.hia.json';core=read_member(z,core_name)
            require(built['core_path'].endswith('/'+core_name) and sha(core)==built['core_sha256'],'HIA Core bytes')
            native=built['native_compile'];object_name=folder+'reference/candidate/candidate.o';obj=read_member(z,object_name)
            require(native['ok'] is True and native['kind']=='object','HIA native object gate')
            require(native['output'].endswith('/'+object_name) and len(obj)==native['artifact_bytes'] and sha(obj)==native['artifact_sha256'],'HIA object bytes')
            require(native['core_sha256']==native['input_sha256']==built['core_sha256'],'Core/native input binding')
            artifacts += [{'member':object_name,'kind':'HIA_native_object','bytes':len(obj),'sha256':sha(obj)},{'member':core_name,'kind':'HIA_Core','bytes':len(core),'sha256':sha(core)}]
        rows.append({'id':row['id'],'language':row['language'],'interface':row['interface'],'all_recorded_gates':True,'public_cases':public_count,'hidden_cases':hidden_count,'native_sha256':sha(binary)})
    require(len([n for n in z.namelist() if n.startswith(prefix) and n.endswith('/ROW.json')])==expected_count,'extra or missing reference ROW file')
    return {'rows':rows,'reference_count':len(rows),'reference_prefix':prefix,'source_snapshot_files':len(plan['source_bindings']),'artifacts':artifacts,'runtime_tool_identities_compared_as_records_only':True,'capacity_qualified':False,'model_qualified':False,'model_requests':0,'scope':'Actual retained CI observations and bytes checked; no native rerun, hardware attestation or independent solver/compiler trust proof.'}

def check_source(z,args):
    regression=load(z,'regression.json')
    require(regression=={'tests':args.source_tests,'failures':0,'errors':0,'skipped':0},'source regression totals')
    log=Path(args.source_log).read_text();ids=TEST_ID.findall(log)
    require(len(ids)==len(set(ids))==args.source_tests,'source test ID count/duplicates')
    safety=load(z,'safety.json')
    require(safety['tests_run']==safety['expected_tests']==37 and len(safety['tests'])==37,'safety counts')
    require(safety['status']=='passed' and safety['source_stable'] is True,'safety gate')
    require(all(v['status']=='passed' for v in safety['tests'].values()),'safety failed test')
    safety_ids=TEST_ID.findall(safety['log']);require(len(safety_ids)==len(set(safety_ids))==37 and set(safety_ids)==set(safety['tests']),'safety individual IDs')
    require(safety['source_before']==safety['source_after'],'safety source drift');register_group('safety',safety['source_before'])
    for k in ['head_before','head_after']:require(safety[k]['returncode']==0 and safety[k]['stdout'].strip()==args.public_source,'safety source attribution')
    registration=load(z,'scalar-lowering/registration.json');register_group('scalar_lowering',registration['source'])
    require(registration['head']==args.public_source,'scalar source attribution')
    qual=load(z,'scalar-lowering/qualification.json')
    require(qual['passed'] is True and qual['source_unchanged'] is True and qual['source_commit']==args.public_source,'scalar qualification')
    require(qual['obligations']==qual['verified']==449 and qual['unknown']==qual['refuted']==0,'scalar counts')
    require([v['status'] for v in qual['negative_controls']]==['refuted']*4+['rejected_profile'],'negative controls')
    manifest=load(z,'scalar-lowering/manifest.json')
    for name,d in manifest.items():
        data=read_member(z,'scalar-lowering/'+name);require(len(data)==d['bytes'] and sha(data)==d['sha256'],'scalar manifest '+name)
    prefixes=sorted(n for n in z.namelist() if re.fullmatch(r'scalar-lowering/obligation-\d{3}\.json',n))
    require(len(prefixes)==449,'missing scalar record')
    for number,name in enumerate(prefixes):
        require(name==f'scalar-lowering/obligation-{number:03d}.json','scalar order')
        ob=load(z,name);stem=name[:-5]
        require(ob['status']=='verified' and ob['verified'] is True and ob['solver_result']=='unsat' and ob['actual_emitter_output'] is True,'scalar obligation gate')
        require(sha(read_member(z,stem+'.hia.json'))==ob['core_sha256'],'scalar Core hash')
        require(sha(read_member(z,stem+'.ll'))==ob['llvm_sha256'],'scalar LLVM hash')
        smt=read_member(z,stem+'.smt2');suffix=b'\n(check-sat)\n'
        require(smt.endswith(suffix) and sha(smt[:-len(suffix)])==ob['query_sha256'],'scalar query hash')
    payload=load(z,'legacy-core-payload.json');register_group('payload',payload['source']['dependencies_sha256'])
    require(payload['source']['commit']==args.public_source and payload['status']=='completed' and payload['source_unchanged'] is True,'payload source/result')
    refs=check_references(z,args.public_source,args.reference_count,args.reference_prefix)
    return {'regression_tests':len(ids),'distinct_regression_ids':len(set(ids)),'regression_test_ids':ids,'safety_tests':37,'safety_test_ids':safety_ids,'scalar_obligations':449,'scalar_manifest_members_verified':len(manifest),'negative_controls':5,'references':refs,'cross_suite_test_overlap':len(set(ids)&set(safety_ids))}

def check_broad(z,args):
    prefix='Hepta/Hepta/artifacts/verified-optimization/regression/'
    result=load(z,prefix+'result.json');plan=load(z,prefix+'plan.json');log=read_member(z,prefix+'tests.log')
    require(sha(log)==result['log_sha256'],'broad log digest')
    ids=TEST_ID.findall(log.decode())
    require(len(ids)==len(set(ids))==result['tests']==args.broad_tests,'broad test count or duplicate IDs')
    require(result['passed'] is True and result['failures']==result['errors']==0 and result['skipped']==[] and result['failure_details']==[],'broad failures/skips')
    require(result['git_base']==args.public_source and result['source_unchanged'] is True,'broad source attribution')
    require(len(result['modules'])==len(set(result['modules'])),'broad module duplicate')
    register_group('broad_regression',result['source_sha256'])
    require(plan['source_sha256']==result['source_sha256'],'broad before/after source')
    native=[]
    if args.broad_log:
        for line in Path(args.broad_log).read_text().splitlines():
            if '"native_observations"' not in line:continue
            start=line.find('{')
            if start>=0:
                try:value=json.loads(line[start:])
                except ValueError:continue
                if 'native_observations' in value:native.append(value)
        require(len(native)==1 and native[0]=={'passed':True,'native_observations':36,'error':None},'native NDU console result')
    return {'tests':len(ids),'distinct_test_ids':len(set(ids)),'test_ids':ids,'failures':0,'errors':0,'skipped':0,'modules':len(result['modules']),'native_ndu_console_observation':native,'native_ndu_count_independently_reexecuted':False,'source_inventory_files':len(result['source_sha256'])}

def check_metadata(path,archive,expected_head,expected_tree,local_source):
    if not path:return None
    p=Path(path);j=json.loads(p.read_text());actual=file_identity(archive)
    require(j['downloaded_bytes']==actual['bytes'] and j['downloaded_sha256']==actual['sha256'] and j['metadata_digest_matches'] is True,'download metadata digest')
    art=j['artifact'];require(art['digest']=='sha256:'+actual['sha256'] and art['size_in_bytes']==actual['bytes'],'GitHub artifact digest')
    require(art['workflow_run']['head_sha']==expected_head,'GitHub artifact source')
    if 'tree' in j:require(j['tree']==expected_tree,'metadata tree')
    if 'local_same_tree_source' in j:require(j['local_same_tree_source']==local_source,'metadata local alias')
    return {'receipt':file_identity(path),'artifact_id':art['id'],'workflow_run_id':art['workflow_run']['id'],'head_sha':expected_head,'artifact_digest':art['digest'],'bytes':art['size_in_bytes'],'download_or_signed_url_recorded_by_reviewer':False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['source-archive','source-sha256','source-log','source-metadata','repository','local-source','public-source','tree','output']:p.add_argument('--'+name,required=True)
    for name in ['broad-archive','broad-sha256','broad-log','broad-metadata']:p.add_argument('--'+name)
    p.add_argument('--reference-prefix',default='agent-tool-native-references');p.add_argument('--source-tests',type=int,default=238);p.add_argument('--broad-tests',type=int,default=750);p.add_argument('--reference-count',type=int,default=19)
    args=p.parse_args();out=Path(args.output);out.mkdir(parents=True,exist_ok=False)
    report={'schema':'hepta.ci.independent-artifact-review.v1','started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'passed':False,'source_public_commit':args.public_source,'source_local_same_tree_commit':args.local_source,'expected_tree':args.tree,'reviewer_execution':{'native':0,'model':0,'tokenizer':0,'compiler':0,'tests':0,'solver':0,'network_fetches':0},'review_script_sha256':sha(Path(__file__).read_bytes())}
    try:
        before=file_identity(args.source_archive);require(before['sha256']==args.source_sha256,'source ZIP digest')
        report['source_archive']=before
        require(git_output(args.repository,['rev-parse',args.local_source+'^{tree}']).stdout.decode().strip()==args.tree,'local tree mismatch')
        pub=git_output(args.repository,['rev-parse','--verify',args.public_source+'^{tree}'],allow_failure=True)
        report['public_commit_object_available_locally']=pub.returncode==0
        if pub.returncode==0:require(pub.stdout.decode().strip()==args.tree,'public tree mismatch')
        report['source_metadata']=check_metadata(args.source_metadata,args.source_archive,args.public_source,args.tree,args.local_source)
        with zipfile.ZipFile(args.source_archive) as z:
            report['source_zip']=check_zip(z);report['source_results']=check_source(z,args)
        if args.broad_archive:
            ident=file_identity(args.broad_archive);require(ident['sha256']==args.broad_sha256,'broad ZIP digest')
            report['broad_archive']=ident
            report['broad_metadata']=check_metadata(args.broad_metadata,args.broad_archive,args.public_source,args.tree,args.local_source)
            with zipfile.ZipFile(args.broad_archive) as z:
                report['broad_zip']=check_zip(z);report['broad_results']=check_broad(z,args)
        sources=verify_git_sources(args.repository,args.local_source)
        report['git_source_blobs_verified']=len(sources);report['source_groups']={g:len(v) for g,v in GROUPS.items()}
        report['source_file_checks']=sources
        report['source_log']=file_identity(args.source_log)
        if args.broad_log:report['broad_log']=file_identity(args.broad_log)
        require(file_identity(args.source_archive)==before,'source ZIP changed during review')
        if args.broad_archive:require(file_identity(args.broad_archive)==report['broad_archive'],'broad ZIP changed during review')
        report['passed']=True
    except Exception as error:
        report['error']={'type':type(error).__name__,'message':str(error)}
    report['completed_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    report['limits']=['The reviewer inspected retained CI bytes/logs and immutable Git objects, without rerunning tests/native/solver/model/tokenizer/compiler.','Remote tool identities and source-stability flags are producer records, not independently measured remote hardware or tool binary attestations.','Input task/case hashes and persisted records are checked for consistency; this audit does not independently regenerate all fixtures or establish language/translation soundness.','Distinct test IDs are established within each identified suite only; overlapping suites must not be added into an independent-test denominator.','Human references remain engineering controls: model requests and Agent successes are zero, capacity/model qualification remains false for this CI wrapper.','The 36 native NDU observations are read from the separate job-log result; no new NDU net-benefit or performance claim is made.']
    (out/'REVIEW.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
    (out/'READ_MEMBERS.json').write_text(json.dumps({'schema':'hepta.ci.review-read-members.v1','files':list(READS.values())},indent=2,ensure_ascii=False)+'\n')
    print(json.dumps({'passed':report['passed'],'error':report.get('error'),'source_tests':report.get('source_results',{}).get('distinct_regression_ids'),'references':report.get('source_results',{}).get('references',{}).get('reference_count'),'broad_distinct_test_ids':report.get('broad_results',{}).get('distinct_test_ids'),'git_source_blobs_verified':report.get('git_source_blobs_verified'),'review':str(out/'REVIEW.json')},indent=2))
    return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
