"""Independent metadata/AST review. Never import or execute a reviewed file."""
from pathlib import Path, PurePosixPath
import ast
import collections
import copy
import hashlib
import json
import os
import stat
import time
import traceback

OUT = Path(__file__).parent
R3 = Path('/tmp/hia-u32-r8-post-reset-r3-dda7')
R2 = Path('/tmp/hia-r8-source-recovery-20261114-r1/frozen-author-r2')
SOURCE = Path('/tmp/hia-r8-source-recovery-20261114-r1/source')
KEYS = ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
DETAIL = {'schema':'hepta.r8.r3.independent-static-review-details.v1',
          'read_files':{}, 'new_stat_checks':{}, 'checks':[], 'failures':[],
          'inverse_changes':{}, 'script_rows':[], 'references':[], 'copies':[],
          'future_oracles':[], 'source_stat_rows':{}, 'runtime_stat_rows':{}}
CURRENT = {}
CACHE = {}

def encode(v):
    return (json.dumps(v, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()

def pin(raw, mode=None):
    value = {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
             'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
    if mode is not None:
        value.update(mode=mode,git_mode='100755' if mode & 0o111 else '100644')
    return value

def stamp(s):
    return [getattr(s,k) for k in KEYS]

def need(condition, message):
    if not condition:
        raise AssertionError(message)

def note(name, **fields):
    DETAIL['checks'].append({'name':name,'status':'PASS',**fields})

def read(path):
    path = Path(path)
    key = str(path)
    if key in CACHE:
        return CACHE[key]
    first = path.lstat()
    need(stat.S_ISREG(first.st_mode), 'not regular: '+key)
    fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        need(stamp(os.fstat(fd))==stamp(first),'open identity differs: '+key)
        parts=[]
        remaining=first.st_size+1
        while remaining:
            part=os.read(fd,min(remaining,1<<20))
            if not part: break
            parts.append(part);remaining-=len(part)
        raw=b''.join(parts)
        need(len(raw)==first.st_size,'extent changed: '+key)
        need(stamp(first)==stamp(os.fstat(fd))==stamp(path.lstat()),'read changed: '+key)
    finally:
        os.close(fd)
    CURRENT[key]=stamp(first)
    DETAIL['read_files'][key]={'identity':pin(raw,stat.S_IMODE(first.st_mode)),
                              'seven_stats':stamp(first)}
    CACHE[key]=raw
    return raw

def load(path):
    return json.loads(read(path))

def exact_identity(path, expected):
    raw=read(path)
    actual=DETAIL['read_files'][str(Path(path))]['identity']
    need(set(expected)<=set(actual),'unknown pin key: '+str(path))
    need(all(actual[k]==v for k,v in expected.items()),'fixed identity differs: '+str(path))
    return raw

def exact_descriptor(row):
    raw=exact_identity(row['path'],row['identity'])
    need(CURRENT[row['path']]==row['new_seven_stats'],'descriptor stat differs: '+row['path'])
    return raw

def stat_only(path, expected):
    path=Path(path); actual=stamp(path.lstat())
    need(stat.S_ISREG(actual[2]) and actual[3]==1,'not independent regular: '+str(path))
    need(actual==expected,'current seven stats differ: '+str(path))
    CURRENT[str(path)]=actual
    DETAIL['new_stat_checks'][str(path)]=actual
    return actual

def changes(a,b,path=()):
    if type(a) is not type(b):
        return [{'operation':'replace','path':list(path),'before':a,'after':b}]
    if isinstance(a,dict):
        rows=[]
        for key in sorted(set(a)|set(b)):
            if key not in a: rows.append({'operation':'add','path':list(path+(key,)),'after':b[key]})
            elif key not in b: rows.append({'operation':'remove','path':list(path+(key,)),'before':a[key]})
            else: rows.extend(changes(a[key],b[key],path+(key,)))
        return rows
    if isinstance(a,list) and len(a)==len(b):
        return [r for i,(x,y) in enumerate(zip(a,b)) for r in changes(x,y,path+(i,))]
    if a==b: return []
    return [{'operation':'replace','path':list(path),'before':a,'after':b}]

def apply_rows(value, rows, reverse=False):
    value=copy.deepcopy(value)
    for row in reversed(rows) if reverse else rows:
        parent=value
        for key in row['path'][:-1]:parent=parent[key]
        key=row['path'][-1];op=row['operation']
        if reverse:
            if op=='add':
                need(parent[key]==row['after'],'inverse add operand differs');del parent[key]
            elif op=='remove':
                need(key not in parent,'inverse remove destination present');parent[key]=row['before']
            else:
                need(parent[key]==row['after'],'inverse replace operand differs');parent[key]=row['before']
        else:
            if op=='add':
                need(key not in parent,'forward add destination present');parent[key]=row['after']
            elif op=='remove':
                need(parent[key]==row['before'],'forward remove operand differs');del parent[key]
            else:
                need(parent[key]==row['before'],'forward replace operand differs');parent[key]=row['after']
    return value

def plan_inverse(filename, record, wanted):
    old_raw=read(R2/filename);new_raw=read(R3/filename)
    old=json.loads(old_raw);new=json.loads(new_raw);declared=load(R3/record)
    actual=changes(old,new)
    need(encode(old)==old_raw and encode(new)==new_raw,'plan canonical serialization differs')
    need(len(actual)==wanted and actual==declared['changes'],'independent change list differs: '+filename)
    need(encode(apply_rows(new,actual,True))==old_raw,'whole inverse differs: '+filename)
    need(encode(apply_rows(old,actual))==new_raw,'whole forward differs: '+filename)
    exact_descriptor(declared['original_plan']);exact_descriptor(declared['current_plan'])
    for value in (old,new):
        material=dict(value);expected=material.pop('authorization_pin')
        need(hashlib.sha256(encode(material)).hexdigest()==expected,'authorization pin differs')
    DETAIL['inverse_changes'][filename]=actual
    note(filename+' whole forward/inverse',changes=len(actual),before=pin(old_raw),after=pin(new_raw))
    return old,new,actual

def functions(raw):
    text=raw.decode();lines=text.splitlines(keepends=True);result={}
    def walk(nodes,prefix=''):
        for node in nodes:
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                name=prefix+node.name
                if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                    start=min([node.lineno]+[d.lineno for d in node.decorator_list])-1
                    result[name]=''.join(lines[start:node.end_lineno]).encode()
                walk(node.body,name+'.')
    walk(ast.parse(text).body)
    return result

def safe_path(path):
    p=PurePosixPath(path)
    need(p.as_posix()==path and p.is_absolute() and '..' not in p.parts,'noncanonical absolute path')
    return p

def main():
    old,new,execution_changes=plan_inverse('EXECUTION-PLAN.json','R3-PLAN-INVERSE.json',1147)
    oo,no,oracle_changes=plan_inverse('ORACLE-RESTORE-PLAN.json','R3-ORACLE-INVERSE.json',666)
    prep=load(R3/'PREPARATION-PLAN.json');proj=load(R3/'R3-SOURCE-PROJECTION.json')
    roles=load(R3/'POST-RESET-ROLE-BINDINGS.json')
    source_changes={r['path']:r for r in proj['changes']}
    need(len(source_changes)==7,'changed source path denominator differs')
    changed_controls={k for k in old['controls'] if new['controls'][k]!=old['controls'][k]}
    wanted_changed_controls=set(source_changes)|{'fixtures/REPORT.json','ORACLE-RESTORE-PLAN.json'}
    need(changed_controls==wanted_changed_controls,'changed control set differs')
    need(set(new['controls'])-set(old['controls'])=={'POST-RESET-PROVENANCE.json','POST-RESET-ROLE-BINDINGS.json'},
         'new control set differs')
    allow_runtime={('runtime','environment','HOME'),('runtime','environment','LD_LIBRARY_PATH'),
                   ('runtime','executable','path'),('runtime','executable','resolved_path'),
                   ('runtime','library','path')}
    for r in execution_changes:
        p=tuple(r['path'])
        allowed=(p in {('authorization_pin',),('output',),('requires_prior_original_oracle_restore',),('source','path')}
                 or p in allow_runtime
                 or len(p)==3 and p[0]=='fixed_inputs' and p[2]=='path'
                 or len(p)==2 and p[0]=='original_observation_paths'
                 or len(p)==3 and p[0]=='controls' and p[1] in wanted_changed_controls and p[2] in {'bytes','sha256','git_blob'}
                 or len(p)==2 and p[0]=='controls' and p[1] in {'POST-RESET-PROVENANCE.json','POST-RESET-ROLE-BINDINGS.json'} and r['operation']=='add')
        need(allowed,'non-allowed execution change: '+repr(p))
    oracle_scalar={('archive','path'),('authorization_pin',),('destination',),('original_manifest','path'),
                   ('root_full_readback','path'),('scope',),('all_other_required_files_at_declared_rebound_paths',),
                   ('all_other_required_files_stay_at_declared_original_paths',)}
    for r in oracle_changes:
        p=tuple(r['path'])
        need(p in oracle_scalar or len(p)==3 and p[0]=='required' and p[2]=='path'
             or len(p)==2 and p[0]=='original_observation_paths','non-allowed oracle change: '+repr(p))
    need(no['all_other_required_files_at_declared_rebound_paths']==oo['all_other_required_files_stay_at_declared_original_paths']==360,
         'metadata rename changed count')
    need(no['scope']==oo['scope']+'; post-reset paths, original absent-path provenance retained','scope label differs')
    need(new['requires_prior_original_oracle_restore']==no['authorization_pin'],'oracle authorization chain differs')
    note('strict change categories',execution=1147,oracle=666,changed_controls=sorted(changed_controls),new_controls=2)

    # Literal whole-file projection, not a permissive AST normalization.
    seven=[p['script'] for p in old['phases'] if p['script'] is not None]
    need(len(seven)==7 and seven==[r['path'] for r in proj['seven_scripts']],'seven-script order differs')
    supports=['semantic/authoring/support.py','aggregate/successor-r2/authoring/support.py',
              'aggregate/successor-r3/authoring/support.py']
    for name in seven+supports:
        before=read(R2/name);after=read(R3/name);row=source_changes.get(name)
        reps=[] if row is None else row['replacements']
        restored=after;forward=before
        for rep in reps:
            a=rep['after'].encode();b=rep['before'].encode()
            need(forward.count(b)==rep['count'],'forward literal count differs: '+name)
            forward=forward.replace(b,a)
        for rep in reversed(reps):
            a=rep['after'].encode();b=rep['before'].encode()
            need(restored.count(a)==rep['count'],'inverse literal count differs: '+name)
            restored=restored.replace(a,b)
        need(forward==after and restored==before,'whole script projection differs: '+name)
        if row:
            need(pin(before,0o644)==row['before'] and pin(after,0o644)==row['after'],'source projection pins differ')
        if name in supports:
            need(functions(before)==functions(after),'support function bytes changed: '+name)
        else:
            declared=next(r for r in proj['seven_scripts'] if r['path']==name)
            need(declared['replacements']==reps and declared['before']==pin(before,0o644)
                 and declared['after']==pin(after,0o644),'seven-script pin/projection differs')
        DETAIL['script_rows'].append({'path':name,'before':pin(before),'after':pin(after),
           'whole_inverse_equal':True,'whole_forward_equal':True,'replacements':reps,
           'all_function_bytes_equal_before_inverse':functions(before)==functions(after),
           'function_count':len(functions(before))})
    four=['run_controls.py','r8_common.py','restore_oracles.py','r8_private_reference.py']
    for name in four:
        need(read(R3/name)==read(R2/name),'original complete runner changed: '+name)
    original_private=functions(read(SOURCE/'hepta/hia_linux_file_roundtrip.py'))
    private=functions(read(R3/'r8_private_reference.py'))
    for name in ('_checked_components','execute_linux_file_roundtrip'):
        need(original_private[name]==private[name],'private admission body differs: '+name)
    bfixture=load(R2/'fixtures/REPORT.json');afixture=load(R3/'fixtures/REPORT.json')
    fdiff=changes(bfixture,afixture)
    need(fdiff==[{'operation':'replace','path':['build','executable'],
                 'before':str(Path(old['output'])/'aggregate/successor-r2/evidence/build-r2/built/private-R8.elf'),
                 'after':str(Path(new['output'])/'aggregate/successor-r2/evidence/build-r2/built/private-R8.elf')}],
         'fixture contains more than executable-path change')
    need(encode(apply_rows(afixture,fdiff,True))==read(R2/'fixtures/REPORT.json'),'fixture full-byte inverse differs')
    need(proj['derived_fixture_hash']=={'before':hashlib.sha256(read(R2/'fixtures/REPORT.json')).hexdigest(),
                                      'after':hashlib.sha256(read(R3/'fixtures/REPORT.json')).hexdigest()},
         'fixture derived hash differs')
    note('seven scripts and three supports',whole_script_inverses=7,support_function_bodies=3,
         four_whole_files=four,private_original_functions=2,fixture_changes=fdiff)

    references=prep['references']
    need(references==roles['references'] and len(references)==948,'948 references differ')
    need(list(old['fixed_inputs'])==list(new['fixed_inputs'])==[r['role'] for r in references],
         'original role order differs')
    recovered=json.loads(exact_descriptor(prep['authority_files']['restored_inputs_manifest']))
    need(len(recovered['files'])==944 and len(recovered['references'])==948,'restored authority count differs')
    recfiles={r['original_path']:r for r in recovered['files']}
    need(len(recfiles)==944,'restored original-path uniqueness differs')
    old_to_new={};old_to_rec={};new_to_old={};unique={}
    for i,r in enumerate(references):
        original=old['fixed_inputs'][r['role']];now=new['fixed_inputs'][r['role']]
        need(r['ordinal']==i and r['original_path']==original['path']
             and r['identity']==original['identity'] and r['phases']==original['phases'],
             'role original identity/phase differs: '+r['role'])
        need(now=={**original,'path':r['execution_path']},'execution row differs beyond path')
        rr=recovered['references'][i]
        need(rr['ordinal']==i and all(rr['original'][k]==r[v] for k,v in
             [('role','role'),('path','original_path'),('identity','identity'),('phases','phases')]),
             'recovered original ordered reference differs')
        need(r['recovered_path']==str(Path(recovered['root'])/rr['target']),'recovered target path differs')
        rf=recfiles[r['original_path']]
        need(rf['required_identity']==r['identity'] and rf['current']['mode']==r['identity']['mode']
             and rf['current']['new_seven_stats']==r['recovered_new_seven_stats'],
             'recovered per-file identity/stat differs')
        stat_only(r['recovered_path'],r['recovered_new_seven_stats'])
        need(old_to_new.setdefault(r['original_path'],r['execution_path'])==r['execution_path'],
             'duplicate original mapped differently')
        need(old_to_rec.setdefault(r['original_path'],r['recovered_path'])==r['recovered_path'],
             'duplicate original recovered differently')
        need(new_to_old.setdefault(r['execution_path'],r['original_path'])==r['original_path'],
             'distinct original paths collide at target')
        unique.setdefault(r['original_path'],r)
        DETAIL['references'].append({'ordinal':i,'role':r['role'],'phases':r['phases'],
            'original_path':r['original_path'],'recovered_path':r['recovered_path'],
            'execution_path':r['execution_path'],'identity':r['identity'],
            'recovered_new_seven_stats':r['recovered_new_seven_stats'],'binding_kind':r['binding_kind']})
    need(len(unique)==len(old_to_rec)==len(new_to_old)==944,'944 distinct coverage differs')
    need(len(set(old_to_rec.values()))==944,'recovered-path alias differs')
    need(sum(r['identity']['bytes'] for r in references)==717016014,'reference bytes differ')
    need(sum(r['identity']['bytes'] for r in unique.values())==710690611,'unique bytes differ')
    copied={};copy_order=[]
    for r in prep['copy_files']:
        relative=PurePosixPath(r['destination_relative'])
        need(relative.as_posix()==r['destination_relative'] and not relative.is_absolute()
             and '..' not in relative.parts and relative.parts[0]=='inputs','unsafe relative target')
        destination=str(Path(prep['input_view'])/relative)
        need(destination==old_to_new[r['original_path']],'copy destination mapping differs')
        original=unique[r['original_path']]
        need(all(r[k]==original[k] for k in ('identity','recovered_path','recovered_new_seven_stats')),
             'copy identity/source differs')
        need(r['reference_ordinals']==[i for i,v in enumerate(references) if v['original_path']==r['original_path']],
             'duplicate copy reference ordinals differ')
        need(r['original_path'] not in copied,'copy duplicates original path')
        copied[r['original_path']]=destination;copy_order.append(r['original_path'])
        DETAIL['copies'].append({'original_path':r['original_path'],'destination':destination,
                                'identity':r['identity'],'reference_ordinals':r['reference_ordinals']})
    expected_copy_order=[p for p,r in unique.items() if r['binding_kind']=='future-independent-808-copy']
    need(copy_order==expected_copy_order and len(copied)==808,'808 copy order/count differs')
    future={};future_order=[]
    for r in prep['future_oracle_files']:
        need(r['original_path'] not in future and r['path']==old_to_new[r['original_path']]
             and r['identity']==unique[r['original_path']]['identity'],'future oracle mapping differs')
        future[r['original_path']]=r['path'];future_order.append(r['path']);DETAIL['future_oracles'].append(r)
    need(len(future)==136 and not(set(copied)&set(future)) and set(copied)|set(future)==set(unique),
         '808 plus 136 partition differs')
    targets=set(new_to_old)
    for path in targets:
        p=safe_path(path)
        need(not any(str(parent) in targets for parent in p.parents),'target file/directory prefix conflict')
    need(all(not Path(p).exists() and not Path(p).is_symlink() for p in prep['must_be_absent']),
         'future stage path already exists')
    need(no['restore_order']==oo['restore_order'] and len(no['required'])==len(oo['required'])==496,
         '496 required / 136 restore order differs')
    for logical,row in no['required'].items():
        original=oo['required'][logical]
        need(row=={**original,'path':old_to_new[original['path']]},'oracle required row differs beyond path')
    original_restore_paths=[no['required'][p]['path'] for p in no['restore_order']]
    need(set(future_order)==set(original_restore_paths), 'future oracle set differs from original restore')
    expected_future_order=[r['execution_path'] for r in unique.values()
                           if r['binding_kind']=='future-original-136-owner']
    need(future_order==expected_future_order, 'future allocation metadata lost original role order')
    DETAIL['future_metadata_order_vs_restore_order']={
        'metadata_uses_first_occurrence_original_role_order':True,
        'actual_restore_order_preserved_exactly_from_R2':no['restore_order']==oo['restore_order'],
        'metadata_not_consumed_by_original_restore_runner':True,
        'different_positions':sum(a!=b for a,b in zip(future_order,original_restore_paths)),
        'future_metadata_paths':future_order,'original_restore_paths':original_restore_paths}
    for name,path in oo['original_observation_paths'].items():
        need(no['original_observation_paths'][name]==old_to_new[path], 'oracle observation map differs')
    for name,path in old['original_observation_paths'].items():
        need(new['original_observation_paths'][name]==old_to_new[path], 'execution observation map differs')
    need(sum(unique[p]['identity']['bytes'] for p in copied)==132337387
         and sum(unique[p]['identity']['bytes'] for p in future)==578353224,'partition bytes differ')
    group=collections.Counter(PurePosixPath(r['destination_relative']).parts[1] for r in prep['copy_files'])
    need(group=={'compact':361,'kernel':434,'other':13},'copy family coverage differs')
    note('complete input mapping',references=948,unique_originals=944,copies=808,future_original_restore=136,
         copied_bytes=132337387,future_restore_bytes=578353224,duplicate_references=4,
         copy_families=dict(group),required_oracle_inputs=496,observation_map=162)

    # Read all metadata/control bytes. Payloads are linked to the independently
    # restored manifests and checked for current stats, not rehashed here.
    for name,row in new['controls'].items():exact_identity(R3/name,row)
    for name,row in old['controls'].items():exact_identity(R2/name,row)
    need(len(prep['controlled_files'])==70 and len(prep['authority_files'])==15,'preparation closure count differs')
    for row in prep['controlled_files'].values():exact_descriptor(row)
    for row in prep['authority_files'].values():exact_descriptor(row)
    exact_descriptor(prep['runner'])
    source_map=json.loads(exact_descriptor(prep['source_map']))
    frozen=load(R3/'FROZEN-3180-SOURCE.json')
    need(len(source_map)==3180 and str(SOURCE)==prep['source'],'source map count/root differs')
    # FROZEN map is keyed directly by source path.
    need(set(frozen)==set(source_map),'frozen/current source pathset differs')
    for name,row in source_map.items():
        need(row['identity']==frozen[name],'source original content/mode declaration differs')
        stat_only(SOURCE/name,row['seven_stats']);DETAIL['source_stat_rows'][name]=row['seven_stats']
    runtime_map=json.loads(exact_descriptor(prep['runtime_map']))
    need(runtime_map['root']==prep['runtime_root'] and len(runtime_map['files'])==2496,'runtime count/root differs')
    for row in runtime_map['files']:
        stat_only(Path(prep['runtime_root'])/row['path'],row['new_file_seven_stat'])
        DETAIL['runtime_stat_rows'][row['path']]=row['new_file_seven_stat']
    for kind in ('executable','library'):
        a=old['runtime'][kind];b=new['runtime'][kind]
        need({k:v for k,v in a.items() if k not in {'path','resolved_path'}}==
             {k:v for k,v in b.items() if k not in {'path','resolved_path'}},'runtime content pin changed')
        rr=next(r for r in runtime_map['files'] if str(Path(prep['runtime_root'])/r['path'])==b['path'])
        need(all(rr['pin'][k]==b['identity'][k] for k in ('bytes','sha256','git_blob'))
             and rr['mode']==b['identity']['mode'], 'runtime map pin/mode differs')
    note('current fixed control/payload bindings',execution_controls=len(new['controls']),
         preparation_controls=70,authority_files=15,source_current_stats=3180,
         runtime_current_stats=2496,recovered_unique_input_current_stats=944,
         payload_rehash='not performed; exact declared pins cross-checked to full restored authority; current seven stats checked')

    for name,runner,plan_name in [('PREPARATION-LAUNCH.json','prepare_input_view.py','PREPARATION-PLAN.json'),
                                  ('ORACLE-LAUNCH.json','restore_oracles.py','ORACLE-RESTORE-PLAN.json'),
                                  ('PRODUCT-LAUNCH.json','run_controls.py','EXECUTION-PLAN.json')]:
        launch=load(R3/name);exact_descriptor(launch['plan']);exact_descriptor(launch['runner'])
        need(launch['runner']['path']==str(R3/runner) and launch['plan']['path']==str(R3/plan_name),
             'launch fixed path differs')
        need(launch['environment']==new['runtime']['environment'] and launch['maximum_attempts']==1,
             'launch environment/retry differs')
        expected=['/usr/bin/env','-i',*[k+'='+v for k,v in sorted(new['runtime']['environment'].items())],
                  new['runtime']['executable']['path'],'-B',str(R3/runner)]
        tail=(['--plan',str(R3/plan_name),'--plan-sha256',pin(read(R3/plan_name))['sha256']]
              if name=='PREPARATION-LAUNCH.json' else ['--plan-sha256',load(R3/plan_name)['authorization_pin']])
        need(launch['argv']==expected+tail,'literal launch argv differs')
        if name=='PRODUCT-LAUNCH.json':
            need(launch['groups']==old['phases'] and launch['budgets']==old['budgets']
                 and launch['minimum_free_bytes']==old['minimum_free_bytes']==3221225472,
                 'launch product gates differ')
        if name=='ORACLE-LAUNCH.json':
            need(launch['owner_seconds']==180 and launch['cleanup_seconds']==3,'oracle launch budget differs')
    note('exact launch references',launches=3,attempts_each=1,products_executed=0)
    DETAIL['preserved_execution_fields']={k:new[k] for k in ('budgets','phases','maximum_actual_calls',
          'minimum_free_bytes','fail_stop','automatic_retry','native_guard_hex','ordinary_SOURCE_rebound',
          'ordinary_compiler_admission','public_R5_entry_unchanged','public_component_pins',
          'private_reference_only','historical_R5_semantic_six','historical_R8_size',
          'matching_current_new_cold','whole_native')}
    fs=os.statvfs('/dev/shm');block=fs.f_frsize
    allocated=lambda rows:sum(((r['identity']['bytes']+block-1)//block)*block for r in rows)
    DETAIL['storage_sample_not_execution_admission']={'filesystem':'/dev/shm','sample_time_ns':time.time_ns(),
         'free_bytes':fs.f_bavail*block,'copy_allocated_bound':allocated(prep['copy_files']),
         'oracle_allocated_bound':allocated(prep['future_oracle_files']),
         'required_before_preparation':allocated(prep['copy_files'])+allocated(prep['future_oracle_files'])+
             prep['product_floor_bytes']+prep['reserve_bytes']+prep['metadata_allowance_bytes'],
         'product_floor_bytes':prep['product_floor_bytes'],'reserve_bytes':prep['reserve_bytes'],
         'metadata_allowance_bytes':prep['metadata_allowance_bytes'],
         'no_storage_guard_executed':True}
    note('original gates and current metadata reviewed',products=0,binder=0,copies=0,project_imports=0)

start=time.time_ns()
try:
    main()
except BaseException:
    DETAIL['failures'].append(traceback.format_exc())
finally:
    for path,before in CURRENT.items():
        try:
            if stamp(Path(path).lstat())!=before:
                DETAIL['failures'].append('Final seven-stat drift: '+path)
        except BaseException:
            DETAIL['failures'].append('Final stat unavailable: '+path+'\n'+traceback.format_exc())
    DETAIL['status']='FAIL_STATIC_REVIEW' if DETAIL['failures'] else 'PASS_STATIC_REVIEW_ONLY'
    DETAIL['started_unix_ns']=start;DETAIL['ended_unix_ns']=time.time_ns()
    DETAIL['project_imports']=0;DETAIL['reviewed_script_execution']=0;DETAIL['products']=0
    raw=encode(DETAIL)
    with (OUT/'DETAILS.json').open('xb') as f:f.write(raw)
    result={'schema':'hepta.r8.r3.independent-static-review.v1','status':DETAIL['status'],
            'reviewer':'hia_surface_audit','r3':str(R3),'frozen_r2':str(R2),
            'checks':DETAIL['checks'],'failures':DETAIL['failures'],'details':pin(raw),
            'validator':pin(Path(__file__).read_bytes()),
            'full_read_metadata_files':len(DETAIL['read_files']),
            'current_payload_stat_files':len(DETAIL['new_stat_checks']),
            'full_payload_rehash':False,'source_or_payload_copies':0,'project_imports':0,
            'binder':0,'products':0,'ci':0,
            'limits':'Static author/preflight review only; no runtime import, storage admission, oracle owner or semantic qualification.'}
    with (OUT/'RESULT.json').open('xb') as f:f.write(encode(result))
    print(json.dumps(result,sort_keys=True))
    if DETAIL['failures']:raise SystemExit(1)
