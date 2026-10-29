#!/usr/bin/env python3
"""Independent read-only audit of retained 2026-10-28/29 closure evidence."""
from __future__ import annotations
import argparse, collections, datetime, hashlib, json, pathlib, subprocess, sys, time

ROOT = pathlib.Path('/tmp/hepta-next-convergence-review-20261029')
SOURCE = '93b1c8002c2a41573080cca41a279a0a0fa4e915'
REPORT = {'schema':'hepta.hia.closure-evidence-audit.v1','reviewed_source_commit':SOURCE,
          'native_builds':0,'model_requests':0,'performance_experiments':0,
          'indexed_files':[], 'index_snapshots':[], 'fragment_datasets':[], 'source_bindings':[], 'same_tree_mappings':[],
          'findings':[], 'limitations':[]}
DECODED = {}
BLOB_CACHE = {}

def digest(raw): return hashlib.sha256(raw).hexdigest()
def canonical(value): return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()
def pairs(rows):
    result={}
    for key,value in rows:
        if key in result: raise ValueError('duplicate JSON object key: '+key)
        result[key]=value
    return result
def parse(raw): return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda s: (_ for _ in ()).throw(ValueError(s)))
def git(*args): return subprocess.check_output(['git',*args],cwd=ROOT,text=True,timeout=30).strip()
def git_blob(commit,path):
    key=(commit,path)
    if key not in BLOB_CACHE:
        BLOB_CACHE[key]=subprocess.check_output(['git','show',commit+':'+path],cwd=ROOT,timeout=30)
    return BLOB_CACHE[key]
def check(condition,message):
    if not condition: raise ValueError(message)
def load(path): return parse(path.read_bytes())
def bound(base,path,row):
    file=(base/path).resolve()
    check(file.is_relative_to(ROOT),'retained path escapes review checkout: '+str(file))
    raw=file.read_bytes()
    check(len(raw)==row['bytes'] and digest(raw)==row['sha256'],'retained file digest mismatch: '+str(file))
    REPORT['indexed_files'].append({'path':str(file.relative_to(ROOT)),'bytes':len(raw),'sha256':digest(raw)})
    return raw

def fragments(path,index):
    check(index.get('all_json_values_retained') is True and index.get('omitted_paths')==[], 'lossless claim not retained')
    nodes={}; strings={}; records=0
    for part in index['files']:
        lines=bound(path.parent,part['path'],part).splitlines()
        check(len(lines)==part['records'],'fragment record count mismatch')
        records+=len(lines)
        for line in lines:
            row=parse(line); pointer=row['pointer']; kind=row['kind']
            check(type(pointer) is str, 'nontext pointer')
            if kind=='string_part':
                check(set(row)=={'pointer','kind','index','value'} and type(row['index']) is int and row['index']>=0 and type(row['value']) is str,'malformed string part')
                group=strings.setdefault(pointer,{})
                check(row['index'] not in group,'duplicate string fragment')
                group[row['index']]=row['value']
            else:
                check(pointer not in nodes,'duplicate JSON-fragment node')
                nodes[pointer]=row
    used=set(); used_strings=set()
    def build(pointer):
        check(pointer not in used,'node used twice')
        used.add(pointer); row=nodes[pointer]; kind=row['kind']
        if kind=='value':
            check(set(row)=={'pointer','kind','value'},'malformed value node')
            return row['value']
        if kind=='object':
            check(set(row)=={'pointer','kind','keys'} and type(row['keys']) is list and all(type(k) is str for k in row['keys']),'malformed object node')
            check(len(row['keys'])==len(set(row['keys'])),'duplicate object-child key')
            return {k:build(pointer+'/'+k.replace('~','~0').replace('/','~1')) for k in row['keys']}
        if kind=='array':
            check(set(row)=={'pointer','kind','length'} and type(row['length']) is int and row['length']>=0,'malformed array node')
            return [build(pointer+'/'+str(i)) for i in range(row['length'])]
        if kind=='string':
            check(set(row)=={'pointer','kind','parts','characters'} and type(row['parts']) is int and row['parts']>=0,'malformed string node')
            parts=strings[pointer]; used_strings.add(pointer)
            check(set(parts)==set(range(row['parts'])),'extra or missing string part')
            value=''.join(parts[i] for i in range(row['parts']))
            check(len(value)==row['characters'],'string character count mismatch')
            return value
        raise ValueError('unknown fragment node kind: '+kind)
    value=build('')
    check(used==set(nodes) and used_strings==set(strings),'unreachable fragment nodes or strings')
    raw=canonical(value)
    check(digest(raw)==index['retained_canonical_sha256'] and len(raw)==index['retained_json_bytes'],'canonical value digest mismatch')
    original=pathlib.Path(index['original_source']); available=original.is_file()
    if available:
        original_raw=original.read_bytes()
        check(len(original_raw)==index['original_bytes'] and digest(original_raw)==index['original_sha256'],'original raw digest mismatch')
        check(canonical(parse(original_raw))==raw,'retained value differs from original JSON')
    key=str(path.relative_to(ROOT))
    DECODED[key]=value
    REPORT['fragment_datasets'].append({'index':key,'parts':len(index['files']),'records':records,'nodes':len(nodes),'string_part_groups':len(strings),'retained_canonical_sha256':digest(raw),'retained_json_bytes':len(raw),'original_source':str(original),'original_raw_compared':available})

def indexed_evidence():
    for path in sorted((ROOT/'experiments').rglob('INDEX.json')):
        index=load(path)
        REPORT['index_snapshots'].append({'path':str(path.relative_to(ROOT)),'sha256':digest(path.read_bytes())})
        if index.get('schema')=='hepta.hia.json-fragments.v1': fragments(path,index); continue
        if 'datasets' in index:
            check(index.get('canonical_values_lossless') is True,'top index loses canonical values')
            for group in ['datasets','supporting_files']:
                for row in index[group]: bound(path.parent,row['path'],row)
        if 'files' in index:
            items=index['files']
            if type(items) is dict:
                for name,row in items.items(): bound(path.parent,name,row)
            else:
                for row in items: bound(path.parent,row['path'],row)
        if 'parts' in index:
            raw=b''.join(bound(path.parent,row['path'],row) for row in index['parts'])
            check(digest(raw)==index['concatenation_sha256'],'concatenated JSONL digest mismatch')
            check(len(raw.splitlines())==index['records'],'concatenated JSONL record count mismatch')
            for line in raw.splitlines(): parse(line)
            REPORT['concatenated_rust_execution_records']=index['records']
    for name,field in [('experiments/hia_next_payload_bound/manifest.json','files'),('experiments/hia_agent_factorial_v4_20261028/results_20261028/TEXT_AUDIT.json','text_files')]:
        path=ROOT/name
        for file,row in load(path)[field].items(): bound(path.parent,file,row)
    path=ROOT/'experiments/hia_agent_factorial_v5_20261028/evidence/RAW_MANIFEST.json'
    rows=load(path); included=0
    for row in rows:
        if row['included_in_compact_evidence']:
            if 'run' in row:
                retained_group={'hepta-next-agent-v5-into-typecheck-01':'independent_unchanged_rustc_typecheck'}.get(row['run'],row['run'])
                file=retained_group+'/'+row['relative_path']
            else:
                original=pathlib.Path(row['path'])
                options=['controls_and_preflight/'+original.name,'controls_and_preflight/'+original.parent.name+'-'+original.name]
                present=[v for v in options if (path.parent/v).is_file()]
                check(len(present)==1,'ambiguous or missing retained auxiliary file')
                file=present[0]
            bound(path.parent,file,row); included+=1
    REPORT['v5_manifest']={'all_inventory_records':len(rows),'included_files_checked':included,'not_duplicated_into_git':len(rows)-included}

def source_bindings(label,commit,mapping,tree=None):
    actual_tree=git('rev-parse',commit+'^{tree}')
    if tree is not None: check(actual_tree==tree,'source tree mismatch: '+label)
    changed=[]
    for path,claimed in sorted(mapping.items()):
        if isinstance(claimed,dict): claimed=claimed['sha256']
        check(digest(git_blob(commit,path))==claimed,'source binding does not match original Git blob: '+label+' '+path)
        current=ROOT/path
        if current.is_file() and digest(current.read_bytes())!=claimed:changed.append(path)
    REPORT['source_bindings'].append({'evidence':label,'source_commit':commit,'source_tree':actual_tree,'source_files_checked':len(mapping),'later_integrated_bytes_differ':changed,'historical_results_not_relabelled':True})

def source_evidence():
    for group in ['hia_ndu_activation/results_20261028','hia_ndu_prepared_reuse/results_20261029']:
        p='experiments/'+group+'/REGISTRATION.json'; x=load(ROOT/p)
        source_bindings(p,x['source_commit'],x['source_sha256'])
        result=DECODED['experiments/'+group+'/result/INDEX.json']
        top=load(ROOT/'experiments'/group/'INDEX.json')
        check(top['source_commit']==x['source_commit']==result['source_commit'],'NDU source label mismatch')
        check(result['source_unchanged'] is True and result['prior_negative_results_replaced'] is False,'NDU result provenance status changed')
        check(result['authority']=='DENY_ALL' and result['safety_certificate'] is False and result['statistical_superiority_established'] is False,'NDU research authority changed')
    for name,x in DECODED.items():
        if name.endswith('qualification/INDEX.json'):
            source_bindings(name,x['git'],x['source_bindings'])
            parent=pathlib.Path(name).parent.parent
            top=load(ROOT/parent/'INDEX.json')
            check(top['source_commit']==x['git'],'application source label mismatch')
            check(x['performance_advantage_gate'] is False,'historical negative performance gate changed')
    p='experiments/hia_next_safety/results_20261028/REGISTRATION.json'; x=load(ROOT/p)
    source_bindings(p,x['head'],x['source'])
    p='experiments/hia_next_safety/artifact_review_20261029/REVIEW.json'; x=load(ROOT/p)
    source_bindings(p,x['reviewed_commit'],x['reviewed_source_sha256'],x['reviewed_tree'])
    p='experiments/hia_next_safety/agent_v6_review_20261029/REVIEW.json'; x=load(ROOT/p)
    source_bindings(p,x['reviewed_final_commit'],x['source_sha256'],x['reviewed_final_tree'])
    p='experiments/hia_next_safety/payload_review_20261029/REVIEW.json'; x=load(ROOT/p)
    source_bindings(p,x['reviewed_source_commit'],x['reviewed_source_sha256'],x['reviewed_source_tree'])
    p='experiments/hia_next_payload_bound/legacy-analysis.json'; x=load(ROOT/p)
    source_bindings(p,x['source']['commit'],x['source']['dependencies_sha256'],x['source']['tree'])
    p='experiments/hia_legacy_queue/rust_shadow_20261029/RESULT.json'; x=load(ROOT/p)
    source_bindings(p,x['source_commit'],x['rust_source'])
    p='experiments/hia_agent_factorial_v4_20261028/results_20261028/SOURCE_IDENTITIES.json'; x=load(ROOT/p)
    source_bindings(p,x['calibration_source_commit'],x['source_bindings'])
    for p in sorted((ROOT/'experiments/hia_agent_factorial_v5_20261028/evidence').glob('*/PLAN.json')):
        x=load(p); source_bindings(str(p.relative_to(ROOT)),x['source_commit'],x['source_bindings'])
    # The later public source is an exact-tree alias, never a replacement execution SHA.
    for p in ['experiments/hia_legacy_queue/results_20261028/SUMMARY.json','experiments/hia_next_safety/results_20261028/SOURCE.json']:
        x=load(ROOT/p); measured=x.get('measured_source_commit',x.get('source_commit'))
        tree=x.get('measured_source_tree',x.get('source_tree'))
        public=x['public_same_tree_source']
        check(git('rev-parse',measured+'^{tree}')==git('rev-parse',public+'^{tree}')==tree,'public same-tree alias mismatch')
        REPORT['same_tree_mappings'].append({'evidence':p,'measured_source':measured,'public_alias':public,'tree':tree,'execution_source_not_relabelled':True})
    # Import provenance is compared at its original import commit; later fixes remain separate.
    imported=['hepta/migration_ir.py','tools/c2hepta.py','tests/test_c2hepta_api_path_isolation.py','tests/test_c2hepta_bounded_source.py','tests/test_migration_ir_identifier_guard.py','tests/test_migration_ir_literal_guard.py','tests/test_migration_ir_neg_payload_guard.py','tests/test_migration_ir_parser_budget.py','tests/test_migration_ir_structural_budget.py']
    donor='a14291c804814c83d69a2def9e8df442d2091d62'; recipient=git('rev-parse','8508232')
    for p in imported:check(git_blob(donor,p)==git_blob(recipient,p),'audit donor file was not imported byte-for-byte')
    REPORT['audit_import']={'donor':donor,'import_commit':recipient,'files_byte_identical':imported,'later_snapshot_fixes_not_relabelled':True}
    base='2f49151ab9d8812eeb02ac2056f224f140099d76'
    unchanged=['hepta/hia_program.py','hepta/hia_program_runtime.py','hepta/hia_schema.py','hepta/hia_json_preflight.py','hepta/hia_static_budget.py','hepta/hia_prepared.py','hepta/hia_program_llvm.py']
    for p in unchanged:check(git_blob(base,p)==git_blob(SOURCE,p),'canonical boundary changed unexpectedly: '+p)
    REPORT['canonical_boundaries_byte_equal_to_round_base']={p:digest(git_blob(SOURCE,p)) for p in unchanged}
    # Verify, but do not execute or relabel, the independent follow-up CI correction.
    follow='1468550226bfe199b97b9d845f2983829d105936'
    workflow=git_blob(follow,'.github/workflows/hepta-six-outcomes.yml').decode()
    runner=git_blob(follow,'tools/qualify_hia_verified_increment.py').decode()
    check('tests.test_hia_entry_payload_bound' not in git_blob(SOURCE,'.github/workflows/hepta-six-outcomes.yml').decode(),'frozen finding no longer describes source')
    check('tests.test_hia_entry_payload_bound' in workflow and 'tests.test_hia_entry_payload_bound' in runner,'follow-up omits payload regression')
    for text in ['experiments/hia_next_payload_bound/**','tests/fixtures/hia_payload_bound/**','tools/analyze_hia_entry_payload.py','--require-clean-source']:
        check(text in workflow,'follow-up omits payload workflow binding: '+text)
    check('tests/fixtures/hia_payload_bound' in runner,'follow-up omits payload fixture source inventory')
    REPORT['findings'].append({'id':'payload-profile-ci-wiring','found_at':SOURCE,'status':'closed_by_independent_followup','corrective_commit':follow,'correction_inspected_not_executed_here':True,'description':'Frozen six-outcome and verified-increment suites omitted the new entry payload tests and six-outcome paths/actual CLI; follow-up binds tests, fixture and clean-source CLI.'})


def scalar_and_text_evidence():
    # Existing all-input queries are reviewed as retained evidence, never silently rerun.
    directory=ROOT/'experiments/hia_next_safety/results_20261028'
    rows=[]
    for p in sorted(directory.glob('obligations-*.jsonl')):
        rows.extend(parse(line) for line in p.read_bytes().splitlines())
    check(len(rows)==449,'retained scalar obligation inventory changed')
    REPORT['scalar_obligations_retained_not_rerun']=len(rows)
    directory=ROOT/'experiments/hia_agent_factorial_v4_20261028/results_20261028'
    rows=[parse(line) for line in (directory/'RAW_TRANSPORT.jsonl').read_bytes().splitlines()]
    for row in rows:
        raw=row['original_utf8'].encode('utf-8')
        check(len(raw)==row['bytes'] and digest(raw)==row['sha256'],'raw transport UTF-8 no longer matches original digest')
    REPORT['v4_transport_original_strings_verified']=len(rows)
    REPORT['limits']=['Hashes and Git object equality establish byte provenance, not producer authenticity or compiler correctness.', 'Original raw JSON is compared when the retained absolute source remains available; absence is recorded.', 'Model weights, installed toolchains, complete raw native archives and remote CI are not independently requalified by this compact-evidence pass.', 'No model, native compiler, kernel, optimizer, solver matrix or performance experiment is executed by this audit.', '152 lightweight regressions have a separate source-bound run receipt; earlier producer native/solver/model observations retain their original commits.', 'Negative performance/NDU/Agent gates are not upgraded by metadata or source compatibility checks.']


def cross_result_evidence():
    ndu=[]
    for group in ['hia_ndu_activation/results_20261028','hia_ndu_prepared_reuse/results_20261029']:
        value=DECODED['experiments/'+group+'/result/INDEX.json']
        summary=load(ROOT/'experiments'/group/'SUMMARY.json')
        shared=sorted((set(value)&set(summary))-{'schema'})
        for key in shared:check(value[key]==summary[key],'NDU summary changed retained result value: '+key)
        count=sum(len(episode['observations']) for episode in value['application_episodes'])
        check(all(episode['admitted'] is True for episode in value['application_episodes']),'policy episode was not admitted')
        check(value['analysis']['activation_implies_net_benefit'] is False,'activation changed into benefit claim')
        expected_episodes=summary.get('policy_episodes',summary.get('episodes'))
        expected_outputs=summary.get('policy_outputs',summary.get('native_executions'))
        check(len(value['application_episodes'])==expected_episodes and count==expected_outputs,'summary observation count mismatch')
        ndu.append({'group':group,'common_summary_fields_equal':shared,'policy_episodes':expected_episodes,'native_policy_outputs':count,'claimed_new_performance_advantage':False})
    REPORT['ndu_summary_reconciliation']=ndu
    # One exact captured Core connects native migration, static payload and Rust shadow evidence.
    fixture=ROOT/'tests/fixtures/hia_payload_bound/legacy_core.hia.json'; core_digest=digest(fixture.read_bytes())
    payload=load(ROOT/'experiments/hia_next_payload_bound/legacy-analysis.json')
    check(payload['input_file_sha256']==payload['analysis']['core_sha256']==core_digest,'payload input/Core digest differs')
    body=dict(payload['analysis']); claimed=body.pop('sha256')
    check(digest(canonical(body))==claimed,'payload deterministic analysis digest differs')
    core_checks=[]
    for name,value in DECODED.items():
        if name.endswith('qualification/INDEX.json'):
            check(value['migration']['program_sha256']==core_digest,'migration refers to another Core')
            core_checks.append(name)
    shadow=load(ROOT/'experiments/hia_legacy_queue/rust_shadow_20261029/RESULT.json')
    check(shadow['core_sha256']==core_digest,'Rust shadow refers to another Core')
    REPORT['same_actual_core']={'fixture':str(fixture.relative_to(ROOT)),'sha256':core_digest,'bytes':fixture.stat().st_size,'migration_reports':core_checks,'payload_analysis_sha256':claimed,'payload_bound':payload['analysis']['entry_bounds'],'rust_shadow_sha256':shadow['core_sha256'],'no_new_native_or_payload_execution':True}
    # Independently recompute already recorded formal and failed/development costs.
    directory=ROOT/'experiments/hia_agent_factorial_v5_20261028/evidence'
    summary=load(directory/'SUMMARY.json'); results={}
    for row in summary['runs']:
        run=row['id']; raw=(directory/run/'RESULT.json').read_bytes(); value=parse(raw); plan=load(directory/run/'PLAN.json')
        check(digest(raw)==row['result']['sha256'] and len(raw)==row['result']['bytes'],'Agent result digest differs from summary')
        check(value['source_commit']==plan['source_commit']==row['source_commit'] and value['source_bindings']==plan['source_bindings'],'Agent plan/result source drift')
        check(value['plan_sha256']==digest((directory/run/'PLAN.json').read_bytes()),'Agent plan byte binding differs')
        check(value['calibration_eligible'] is False,'v5 negative qualification changed')
        for key in ['requests','responses','known_input_tokens','known_output_tokens','total_tokens','unknown_usage_requests','experiment_wall_ns','human_repairs','valid_observation']:
            check(value[key]==row[key],'Agent run summary differs from original: '+key)
        results[run]=value
    formal=['v5-qwen1_5b-04','v5-qwen7b-01']; diagnostic=['v5-qwen1_5b-01','v5-qwen1_5b-03']
    for label,names in [('formal_totals',formal),('diagnostic_and_prebinding_totals',diagnostic),('all_v5_model_run_totals',formal+diagnostic)]:
        for key,total in summary[label].items(): check(sum(results[name][key] for name in names)==total,'Agent full cost total differs: '+label+' '+key)
    check(summary['main_cells_started']==summary['main_model_requests']==0 and summary['qualified_language_or_agent_efficiency_claim'] is False,'v5 unrun main experiment became qualified')
    REPORT['v5_recorded_costs_recomputed']={label:summary[label] for label in ['formal_totals','diagnostic_and_prebinding_totals','all_v5_model_run_totals']}
    REPORT['v5_main_untouched']={'main_cells_started':0,'main_model_requests':0,'qualified_language_or_agent_efficiency_claim':False}


def main():
    global ROOT
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=pathlib.Path,required=True)
    parser.add_argument('--output',type=pathlib.Path,required=True)
    options=parser.parse_args()
    ROOT=options.root.resolve()
    if options.output.exists(): raise ValueError('audit output must not already exist')
    started=time.monotonic_ns()
    before={'commit':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'status':git('status','--porcelain=v1')}
    check(before['commit']==SOURCE and before['status']=='','review checkout is not the frozen clean source')
    indexed_evidence()
    source_evidence()
    scalar_and_text_evidence()
    cross_result_evidence()
    REPORT['snapshot']=before
    REPORT['snapshot_unchanged']=before=={'commit':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'status':git('status','--porcelain=v1')}
    REPORT['audit_script_sha256']=digest(pathlib.Path(__file__).read_bytes())
    REPORT['command']=[sys.executable,str(pathlib.Path(__file__).resolve()),*sys.argv[1:]]
    REPORT['python']={'executable':sys.executable,'version':sys.version,'sha256':digest(pathlib.Path(sys.executable).resolve().read_bytes())}
    REPORT['environment']='shared-cloud-scratch-not-verified-user-dot'
    files=REPORT.pop('indexed_files')
    REPORT['indexed_file_checks']={'count':len(files),'unique_paths':len({row['path'] for row in files}),'retained_bytes':sum({row['path']:row['bytes'] for row in files}.values()),'ordered_checks_canonical_sha256':digest(canonical(files))}
    REPORT['summary']={'fragment_datasets':len(REPORT['fragment_datasets']),'fragment_records':sum(row['records'] for row in REPORT['fragment_datasets']),'original_json_files_compared':sum(row['original_raw_compared'] for row in REPORT['fragment_datasets']),'source_groups':len(REPORT['source_bindings']),'original_source_bindings':sum(row['source_files_checked'] for row in REPORT['source_bindings']),'independent_producer_native_or_model_tests_rerun':False,'scientific_gates_upgraded':False}
    REPORT['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    REPORT['elapsed_ns']=time.monotonic_ns()-started
    with options.output.open('x') as stream:
        stream.write(json.dumps(REPORT,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'indexed_file_checks':REPORT['indexed_file_checks'],'summary':REPORT['summary'],'v5_manifest':REPORT['v5_manifest'],'snapshot_unchanged':REPORT['snapshot_unchanged']},sort_keys=True))

if __name__=='__main__':main()
