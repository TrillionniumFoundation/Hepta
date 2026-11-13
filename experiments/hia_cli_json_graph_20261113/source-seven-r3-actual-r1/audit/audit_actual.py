"""Read-only audit of the one completed R3 source-seven invocation.

No project import, source generation, HIA/native/compiler or test execution.
Current-bound owner closure is checked before child bodies are opened.
This audit qualifies only the completed seven source components; native/17/46 remain unexecuted.
"""
from __future__ import annotations
import ast
import hashlib
import json
import os
from pathlib import Path
import stat

BASE = Path('/home/qq/hia-rewrite-20261113-e26e-r1/cli-source-seven-r3')
ROOT = Path('/home/qq/hia-rewrite-20261113-e26e-r1/cli-source-seven-r3-actual-audit-r1')
FIELDS = ('dev','ino','mode','uid','gid','nlink','size','mtime_ns','ctime_ns')
EXPECTED = {
    'request': 'fa3025318a5dcb96165320294e192e99e7208b09ab9e9e1102d39e0c408cbc0f',
    'configuration': 'c90ea5dca3760bb8cdcca0b73906f2b3cb2fd02e3d9aef0f1dc49739534aaed1',
    'guardian': '0f8323882df8f9d48cfccdf7b2ce622b2fef4585c81c0095f2dd803f81e8a141',
    'report': '64bbbca878181911397447e65dbea12440bfeb6d7c30a9f2bda3c52a6c73b3ac',
}
COMPONENTS = ('body','unpack','call_dispatch','call','call_fast','call_prologue','send')
LIMITS = dict(source_bytes=1048576, functions=128, blocks_per_function=256,
              blocks_total=1536, parameters_or_arguments=16, ssa_names_per_function=2048,
              instruction_results=3, function_results=3, instructions=8192)
checks = []
records = {}
def require(ok, label):
    checks.append({'check': label, 'passed': bool(ok)})
    if not ok:
        raise ValueError(label)
def ident(st):
    return [getattr(st, 'st_' + x) for x in FIELDS]
def dig(raw):
    return {'bytes':len(raw), 'sha256':hashlib.sha256(raw).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def read(path, *, system=False):
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink < 1:
        raise ValueError('regular file required '+str(path))
    if system:
        if before.st_uid != 0 or stat.S_IMODE(before.st_mode) & 0o022:
            raise ValueError('fixed root readonly system role required '+str(path))
    elif before.st_nlink != 1 or before.st_uid != os.geteuid():
        raise ValueError('owned single-link file required '+str(path))
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        require(ident(os.fstat(fd))==ident(before),'descriptor:'+str(path))
        out=bytearray()
        while len(out)<before.st_size:
            part=os.read(fd,min(65536,before.st_size-len(out)))
            if not part: raise ValueError('short '+str(path))
            out.extend(part)
        require(not os.read(fd,1),'no-growth:'+str(path))
        require(ident(os.fstat(fd))==ident(before)==ident(path.lstat()),'stable:'+str(path))
    finally:
        os.close(fd)
    raw=bytes(out)
    rec={'path':str(path),**dig(raw),'mode':stat.S_IMODE(before.st_mode),'identity':ident(before)}
    records[str(path)]=rec
    return raw,rec
def obj(path, sha=None, *, system=False):
    raw, rec=read(path,system=system)
    if sha: require(rec['sha256']==sha,'fixed-sha:'+str(path))
    return json.loads(raw), raw, rec
def pinned(rec, *, system=False):
    raw,got=read(rec['path'], system=system)
    require(all(got[k]==rec[k] for k in ('path','bytes','sha256','identity')),'reported-identity:'+rec['path'])
    return raw
def write(name, data):
    p=ROOT/name
    fd=os.open(p,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        view=memoryview(data)
        while view:
            n=os.write(fd,view)
            if n<=0:raise OSError('short audit write')
            view=view[n:]
        os.fsync(fd)
        os.lseek(fd,0,os.SEEK_SET)
        out=bytearray()
        while True:
            part=os.read(fd,65536)
            if not part:break
            out.extend(part)
        if bytes(out)!=data:raise ValueError('audit readback')
    finally:os.close(fd)
    return {'path':str(p),**dig(data)}
def wire(o):
    return (json.dumps(o,sort_keys=True,ensure_ascii=True,indent=2)+'\n').encode()
def measure(d, assembly):
    rows=[]
    for fn in d['functions']:
        names={p['name'] for p in fn['params']}
        maxp=len(fn['params']); maxa=0; maxout=0; ops=0
        for b in fn['blocks']:
            names.update(p['name'] for p in b['params'])
            maxp=max(maxp,len(b['params']))
            for op in b['ops']:
                names.update(p['name'] for p in op['out'])
                maxa=max(maxa,len(op['args']))
                maxout=max(maxout,len(op['out']))
                ops+=1
            term=b['term']
            if term['op']=='jump':maxa=max(maxa,len(term['args']))
            elif term['op']=='branch':maxa=max(maxa,len(term['then']['args']),len(term['else']['args']))
            elif term['op']=='ret':maxa=max(maxa,len(term['values']))
        rows.append(dict(name=fn['name'],blocks=len(fn['blocks']),operations=ops,
                         ssa_names=len(names),parameters=maxp,arguments=maxa,
                         instruction_results=maxout,function_results=len(fn['returns'])))
    actual=dict(source_bytes=len(assembly),functions=len(rows),
                blocks_per_function=max(x['blocks'] for x in rows),
                blocks_total=sum(x['blocks'] for x in rows),
                parameters_or_arguments=max(max(x['parameters'],x['arguments']) for x in rows),
                ssa_names_per_function=max(x['ssa_names'] for x in rows),
                instruction_results=max(x['instruction_results'] for x in rows),
                function_results=max(x['function_results'] for x in rows),
                instructions=sum(x['operations'] for x in rows))
    return dict(actual=actual,limits=LIMITS,functions=rows,
                source_lines_diagnostic=len(assembly.splitlines()),compiler_line_gate_executed=False,
                within_limits=all(v<=LIMITS[k] for k,v in actual.items()))

def main():
    # Only controls and the completed parent receipt precede this closure gate.
    req,reqraw,reqpin=obj(BASE/'guardian/REQUEST.json',EXPECTED['request'])
    guardian,graw,gpin=obj(BASE/'guardian/guardian.json',EXPECTED['guardian'])
    life=guardian['lifecycle']; cleanup=life['cleanup']
    require(guardian['schema']=='hepta.hia.external-qualification-guardian.v1','guardian schema')
    require(guardian['lifecycle_implementation_sha256']=='36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2','369 exact')
    require(guardian['command']==req['command'] and guardian['cwd']==req['cwd'],'actual command cwd')
    require(guardian['external_controller_seconds']==req['controller_seconds']==life['qualification_seconds']==180 and life['cleanup_seconds']==3,'180 and 3')
    require(life['schema']==guardian['schema']+'.lifecycle' and life['subreaper_enabled'] is True,'owner schema subreaper')
    require(cleanup['complete'] is True and cleanup['observed_echild'] is True and cleanup['leader_reaped'] is True
            and cleanup['remaining_direct_children']==[] and cleanup['errors']==[] and cleanup['deadline_exceeded'] is False,'closed current owner')
    require(life['returncode']==0 and life['status']=='OWNED_PROCESS_COMPLETED' and life['timed_out'] is False
            and life['exit_observed_before_deadline'] is True and life['interrupted_signals']==[] and not life.get('owner_error'),'natural source success only')
    events=life['events']; child=life['qualification_pid']
    require([x['kind'] for x in events]==['qualification_started','owned_child_observed','qualification_exit_observed','owned_child_reaped'],'four natural events')
    require(all(x['pid']==child for x in events) and events[1]['ppid']==life['supervisor_pid']
            and events[2]['si_code']==1 and events[2]['si_status']==0 and events[3]['returncode']==0,'same child events')
    require(events[1]['start_ticks']==events[3]['start_ticks'] and life['direct_and_adopted_children']==[
        {k:events[1][k] for k in ('pgid','pid','ppid','sid','start_ticks')}],'single recorded child identity')
    require(guardian['status']=='EXTERNAL_OWNED_PROCESS_COMPLETED' and guardian['whole_native_delivery_qualified'] is False,'source-only guardian completed; native not qualified')
    require(guardian['post_owner_body_reads']=={'child_logs':'READ_COMPLETE','permitted':True,'reason':'BOUND_OWNER_CLOSED','source_after':'READ_COMPLETE'},'closed reader gate')
    require(guardian['source_identities_before']==req['source_identities']==guardian['source_identities_after']
            and guardian['input_identity_preserved'] is True,'248 raw before after hashes')

    # Child output reads start here, after the current bound ECHILD gate.
    for path,sha in guardian['logs'].items():
        raw,pin=read(path);require(pin['sha256']==sha,'child log original:'+path)
    report,rraw,rpin=obj(BASE/'actual/REPORT.json',EXPECTED['report'])
    config,craw,cpin=obj(BASE/'control/CONFIG.json',EXPECTED['configuration'])
    require(pinned(report['configuration'])==craw,'actual configuration raw')
    require(report['schema']=='hia.cli-json.call-send-source-seven.r3.v1' and report['status']=='SEVEN_SOURCE_COMPONENTS_PASS_PENDING_OUTER_GUARDIAN','worker source-seven pass')
    require([r['name'] for r in report['components']]==list(COMPONENTS),'full7 order')
    require([[r['name'],r['module']] for r in report['components']]==config['components'],'full7 exact modules')
    require(config['limits']==LIMITS and len(LIMITS)==9,'original nine caps')
    require(report['effect_guard']=={'installed_before_project_import':True,'scope_verified_without_attempts':True}
            and report['forbidden_attempts']==[] and report['native_executed'] is False
            and report['product_callers_executed'] is False,'guard and empty complete effect ledger')
    require(report['original_cli_ids']==config['original_cli_ids'] and len(report['original_cli_ids'])==17
            and report['trace_plan_ids']==config['trace_plan_ids'] and len(report['trace_plan_ids'])==46
            and report['counts_are_plan_only'] is True,'17 and 46 not executed')
    require(report['runtime_before']==report['runtime_after']==config['runtime']['file'],'runtime before after exact')
    require(pinned(report['runtime_before'],system=True)==read(config['runtime']['file']['path'],system=True)[0],'runtime complete bytes')
    before_raw=pinned(report['source_before']); after_raw=pinned(report['source_after'])
    require(before_raw==after_raw,'198 source before after raw equality')
    before=json.loads(before_raw); require(set(before)==set(config['source_pins']) and len(before)==198,'198 physical population')
    source=Path(config['source_root'])
    names=[]
    for parent,dirs,files in os.walk(source,followlinks=False):
        for name in dirs:
            if not stat.S_ISDIR((Path(parent)/name).lstat().st_mode): raise ValueError('source symlink directory')
        for name in files:names.append((Path(parent)/name).relative_to(source).as_posix())
    require(sorted(names)==sorted(before),'full source leaf set')
    for name,rec in before.items():
        raw=pinned(rec);expect=config['source_pins'][name]
        require(dig(raw)==expect and rec['identity']==config['source_identity9'][name],'full source binding:'+name)
    require(sum(v['bytes'] for v in before.values())==3123349,'source bytes3123349')
    for name,path in report['actual_repository_modules'].items():
        require(path in before,'actual imported source bound:'+name)
    roles,_,_=obj(BASE/'proof/INPUT-ROLES.json')
    systems={r['path']:r for r in roles['system_inputs']}
    require(len(systems)==14 and len(req['source_identities'])==248,'fixed owned system population')
    for path,sha in req['source_identities'].items():
        raw,pin=read(path,system=path in systems)
        require(pin['sha256']==sha,'actual fixed input:'+path)
        if path in systems:
            require(all(pin[k]==systems[path][k] for k in ('bytes','sha256','git_blob','mode','identity')),'system role unchanged:'+path)

    component_rows=[]
    expected_names={'REPORT.json','source.before.json','source.after.json'}
    for row in report['components']:
        name=row['name']
        authored=pinned(row['authoring_source']); expected_names.add(name+'.authoring.py.txt')
        ast.parse(authored,filename=name+'.authoring.py.txt')
        require(row['status']=='SOURCE_CORE_AND_CAPS_PASS_NOT_NATIVE' and row['error'] is None,'component success:'+name)
        draw=pinned(row['document']);vraw=pinned(row['verified_document']);assembly=pinned(row['assembly']);capsraw=pinned(row['caps'])
        expected_names.update(name+suffix for suffix in ('.document.json','.verified.json','.hiaasm','.caps.json'))
        require(draw==vraw,'full document roundtrip bytes:'+name)
        measurement=measure(json.loads(vraw),assembly)
        require(measurement==json.loads(capsraw) and measurement['within_limits'] is True,'independent9 cap metrics:'+name)
        component_rows.append({'name':name,'status':row['status'],'assembly':dig(assembly),'metrics':measurement['actual'],
                               'source_lines_diagnostic':measurement['source_lines_diagnostic'],'elapsed_ns':row['elapsed_ns']})
    require(set(p.name for p in (BASE/'actual').iterdir())==expected_names,'complete fixed actual set')
    require(report['errors']==[] and 'error_traceback' not in report,'no recorded aggregate failure')

    # AST-only audit: never import the seven modules or execute SOURCE bodies.
    unary=[]
    for label, module in config['components']:
        path=source/Path(*module.split('.')).with_suffix('.py')
        raw,_=read(path)
        tree=ast.parse(raw)
        assignments=[n for n in tree.body if isinstance(n,ast.Assign) and
                     any(isinstance(t,ast.Name) and t.id=='SOURCE' for t in n.targets)]
        require(len(assignments)==1 and isinstance(assignments[0].value,ast.Constant)
                and type(assignments[0].value.value) is str,'literal SOURCE:'+label)
        embedded=ast.parse(assignments[0].value.value)
        for n in ast.walk(embedded):
            if isinstance(n,ast.UnaryOp):
                unary.append({'component':label,'line_in_SOURCE':n.lineno,'ast':ast.dump(n)})
    require(unary==[],'all7 source literals have no unsupported unary operation')

    audit={'schema':'hia.cli-json.source-seven.r3.actual-readonly-audit.v1',
           'audit_status':'READONLY_AUDIT_PASS_SEVEN_SOURCE_COMPONENTS_ONLY',
           'request_commit':'a66b7478ad1596384c5aa137aa0b652a79a16cae',
           'request':reqpin,'guardian':gpin,'report':rpin,
           'original_result':report['status'],'passed_components':7,'expected_components':7,
           'components':component_rows,'original_caps':LIMITS,'worker_elapsed_ns':report['elapsed_ns'],
           'owner_events':events,'owner_cleanup':cleanup,'owner_returncode':0,
           'source_files':198,'source_bytes':3123349,'fixed_inputs':248,
           'source_before_after_and_physical_bytes_unchanged':True,
           'forbidden_attempts':[],'native_and_original17_and46_executions':0,
           'compiler_line_gate_executed':False,'unary_operator_inventory':unary,
           'audit_runs_no_project_code':True,'checks':checks}
    inventory=[records[x] for x in sorted(records)]
    ip=write('READ-ORIGINALS.json',wire({'schema':'hia.cli-json.r3.read-originals.v1','files':inventory}))
    ap=write('AUDIT.json',wire(audit))
    print(json.dumps({'audit':ap,'inventory':ip,'check_count':len(checks),'originals':len(inventory),
                      'status':audit['audit_status'],'components':component_rows},sort_keys=True))

if __name__=='__main__':
    main()
