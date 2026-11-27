from pathlib import Path
from hashlib import sha256
import json,os,re,time,traceback,zlib
BASE=Path('/home/qq/hia-native-self-rewrite-20261111-dda7/e03-deadline-phase-v70-r1')
ROOT=BASE/'run'
OUT=BASE/'analysis-r1'
OUT.mkdir(mode=0o700,exist_ok=False)
def write(name,value):
    (OUT/name).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
def record(path,raw=None):
    path=Path(path)
    if raw is None:raw=path.read_bytes()
    return {'path':str(path),'bytes':len(raw),'sha256':sha256(raw).hexdigest()}
owner={'pid':os.getpid(),'ppid':os.getppid(),'cgroup':Path('/proc/self/cgroup').read_text(),'scope':'OWN_PROCESS_LOCATION_ONLY_NOT_TERMINAL'}
write('owner-process.json',owner)
result={'schema':'hepta.hia.e03-deadline-phase-analysis.v1','scope':'READ_ONLY_DERIVATION_FROM_ORIGINAL_FOUR_CASE_DIAGNOSTIC','qualification':False,'source_modified':False,'original_limits_ms':{'total':3000,'native':1000},'cases':[],'owner_process':owner,'cpu_overlap':'UNKNOWN','timing_note':'Inclusive instrumented wall durations; nested labels must not be summed.'}
retained={}
try:
    raw=(ROOT/'report.json').read_bytes()
    if sha256(raw).hexdigest()!='55d170322117bb7cc1bfbdd183f45c39605a6df60ac435651bfac8461cb0e821':raise ValueError('original report changed')
    report=json.loads(raw)
    if report['status']!='FOUR_ORIGINAL_CASES_OBSERVED' or len(report['cases'])!=4:raise ValueError('original report incomplete')
    result['original_report']=record(ROOT/'report.json',raw)
    retained[str(ROOT/'report.json')]=raw
    archived=[]
    for case in report['cases']:
        key=case['route']+'--'+case['test']
        event_path=Path(case['events']['path'])
        event_raw=event_path.read_bytes()
        if sha256(event_raw).hexdigest()!=case['events']['sha256']:raise ValueError('events changed')
        events=json.loads(event_raw)
        byid={e['id']:e for e in events}
        if len(byid)!=len(events) or len(events)!=case['event_count']:raise ValueError('event identities differ')
        for e in events:
            if e['parent'] is not None and e['parent'] not in byid:raise ValueError('missing event parent')
        def under(event,ancestor):
            ident=event['id'];seen=set()
            while ident is not None:
                if ident==ancestor:return True
                if ident in seen:raise ValueError('event ancestry cycle')
                seen.add(ident);ident=byid[ident]['parent']
            return False
        def aggregate(items):
            out={}
            for e in items:
                a=out.setdefault(e['function'],{'calls':0,'inclusive_ns':0,'raised':0})
                a['calls']+=1;a['inclusive_ns']+=e['inclusive_ns'];a['raised']+=e['outcome']=='raised'
            return out
        if aggregate(events)!=case['aggregate_inclusive']:raise ValueError('aggregate does not reproduce original report')
        state_path=event_path.parent/'state-observations.json'
        state_raw=state_path.read_bytes();state=json.loads(state_raw)
        logs_raw=Path(case['log']['path']).read_bytes()
        if sha256(logs_raw).hexdigest()!=case['log']['sha256']:raise ValueError('original log changed')
        retained[str(event_path)]=event_raw;retained[str(state_path)]=state_raw;retained[case['log']['path']]=logs_raw
        selected=state['session_context']['id']
        contexts=state['tables']['contexts']
        context=next(c for c in contexts if c['id']==selected)
        created=int(context['created_ns']);deadline=created+3_000_000_000
        service_calls=[]
        for e in events:
            if e['function']!='service.call':continue
            children=[v for v in events if v['function']=='contract.file_digests' and under(v,e['id'])]
            start=int(e['start_wall_ns'])
            service_calls.append({'id':e['id'],'tool':e.get('tool'),'start_wall_ns':str(start),'start_from_context_ns':start-created,'finish_from_context_ns':start+e['inclusive_ns']-created,'inclusive_ns':e['inclusive_ns'],'outcome':e['outcome'],'response_status':e.get('response_status'),'digest_calls':len(children),'digest_inclusive_ns':sum(v['inclusive_ns'] for v in children)})
        selected_events=[e for e in events if int(e['start_wall_ns'])>=created]
        boundary_events=[e for e in events if e['function'] in ('service._hia_evaluate','service._required_claims')]
        boundaries=[{**{k:e[k] for k in ('id','parent','function','start_wall_ns','inclusive_ns','outcome')},'start_from_context_ns':int(e['start_wall_ns'])-created,'finish_from_context_ns':int(e['start_wall_ns'])+e['inclusive_ns']-created} for e in boundary_events]
        descriptor={'case':key,'original_successful':case['successful'],'original_errors':len(case['errors']),'context_id':selected,'created_ns':str(created),'deadline_ns':str(deadline),'source_context_observations':record(state_path,state_raw),'service_calls':service_calls,'after_context_events_aggregate':aggregate(selected_events),'evaluation_boundaries':boundaries,'full_event_count':len(events),'event_start_filter':'start_wall_ns >= original stored context.created_ns; aggregate is not a non-overlapping total'}
        result['cases'].append(descriptor)
        compressed=zlib.compress(event_raw,9)
        artifact=OUT/(key+'.events.json.zlib')
        with artifact.open('xb') as f:f.write(compressed)
        archived.append({'compressed':record(artifact,compressed),'original':record(event_path,event_raw)})
        for suffix,value in [('state-observations.json',state_raw),('unittest.log',logs_raw)]:
            target=OUT/(key+'.'+suffix)
            with target.open('xb') as f:f.write(value)
            archived.append({'copy':record(target,value),'source':str(state_path) if suffix.startswith('state') else case['log']['path']})
    result['original_evidence_unchanged']=all(Path(p).read_bytes()==v for p,v in retained.items())
    if not result['original_evidence_unchanged']:raise ValueError('original evidence changed during analysis')
    result['archives']=archived
    result['status']='ORIGINAL_EVENTS_ANALYZED'
except BaseException:
    result['status']='ANALYSIS_FAILED';result['exception']=traceback.format_exc()
    raise
finally:
    write('report.json',result)
    print(json.dumps({'report':record(OUT/'report.json'),'status':result.get('status'),'owner_process':owner}),flush=True)
