"""One authorized independent byte-copy and runtime binding; no products.

Runtime capture imports the original helper after complete source binding.
No compiler, HIA, VM, unittest, or process owner is called by this preparer.
"""
from __future__ import annotations
import argparse
import time
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).absolute().parent))
from execution_support import *


def protected_source_guard(plan):
    value=plan['protected_source']; expected=decode(checked(value['map']))
    state=decode(checked(value['state']));root=Path(value['root'])
    require(metadata(root)==state and len(expected)==3180,'protected restored source state differs')
    flat={n:{'bytes':r['identity']['bytes'],'mode':r['identity']['git_mode'],
        'git_blob':r['identity']['git_blob'],'sha256':r['identity']['sha256']} for n,r in expected.items()}
    require(observer.snapshot(root)==flat and metadata(root)==state,'protected R8 source bytes/stat changed')
    return {'files':3180,'all_bytes_read':True,'map':value['map']['pin']}


def preparation_guard(plan):
    for row in plan['controls'].values():checked(row)
    for row in plan['provenance'].values():checked(row)
    checked(plan['projected_source_map']);checked(plan['origin_rows'])
    require(plan['compiler']['pin']==B3_PIN,'ordinary B3 differs');checked(plan['compiler'])
    require(plan['limits']==LIMITS and plan['storage_floor']==MINIMUM_FREE,'budgets differ')
    guard_directories(plan['parent_ancestors']);guard_directories(plan['author_ancestors'])
    runtime_files_guard(plan)
    return protected_source_guard(plan)


def write_source(path,raw,mode):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb')as stream:
        stream.write(raw);stream.flush();os.fchmod(stream.fileno(),mode)
    return capture(path,maximum=max(CAPACITY,len(raw)))


def bind(plan_path,expected_sha):
    descriptor=capture(Path(plan_path),maximum=16<<20);raw=checked(descriptor)
    require(hashlib.sha256(raw).hexdigest()==expected_sha,'preparation plan raw differs')
    plan=decode(raw)
    require(plan['schema']==SCHEMA+'.preparation' and plan['state']=='AUTHORING_ONLY_AWAITING_ROOT_AUTHORIZATION',
            'fixed author plan required')
    require(sys.implementation.name=='cpython' and sys.version_info[:3]==(3,14,4)
            and sys.flags.isolated and sys.flags.dont_write_bytecode,'actual restored3.14.4 -I -B required')
    scope=Path(plan['scope'])
    require(scope==Path('/tmp/hia-op13-execution-r2-dda7') and not os.path.lexists(scope)
            and Path(__file__).absolute()==Path(plan['controls']['bind_execution.py']['path']),
            'one absent independent target and bound preparer required')
    before=preparation_guard(plan);available=floor(scope.parent)
    origins=decode(checked(plan['origin_rows']));projected_raw=checked(plan['projected_source_map'])
    projected=decode(projected_raw)
    require(len(origins)==len(projected)==3210 and [r['relative']for r in origins]==sorted(projected)
            and observer.tree_digest(projected)==SOURCE_TREE,'complete exact source union required')
    for row in origins:
        require(row['descriptor']['pin']==projected[row['relative']],'source authority differs')
        checked(row['descriptor'])
    scope.mkdir(mode=0o700);source=scope/'source';source.mkdir(mode=0o700)
    result={'schema':SCHEMA+'.binding-result','status':'FAIL','started_ns':time.monotonic_ns(),
        'preparation_plan':descriptor,'protected_source_before':before,'products_executed':0,
        'current_cold':False,'default':False,'whole':False,'free_bytes_before':available,'copy_rows':0}
    copies=[]
    try:
        original_inodes={(r['descriptor']['stat']['st_dev'],r['descriptor']['stat']['st_ino'])for r in origins}
        created=set()
        with(scope/'COPY-ROWS.jsonl').open('xb')as journal:
            for row in origins:
                raw_source=checked(row['descriptor']);name=row['relative']
                require(not Path(name).is_absolute() and all(x not in ('','.', '..')for x in name.split('/')),
                        'source relative path differs')
                current=write_source(source/name,raw_source,int(projected[name]['mode'][-3:],8))
                inode=(current['stat']['st_dev'],current['stat']['st_ino'])
                require(current['pin']==projected[name] and inode not in original_inodes|created,
                        'source must have independent exact inode/bytes/mode')
                created.add(inode)
                record={'relative':name,'origin':row['descriptor'],'created':current}
                journal.write((json.dumps(record,sort_keys=True)+'\n').encode());journal.flush()
                copies.append(record);result['copy_rows']=len(copies)
        state=metadata(source)
        require(len(created)==3210 and observer.snapshot(source)==projected and metadata(source)==state,
                'full copied source readback failed')
        with(scope/'SOURCE-MAP.json').open('xb')as f:f.write(projected_raw)
        publish(scope/'SOURCE-STATE.json',state);publish(scope/'COPIES.json',copies)
        for row in origins:checked(row['descriptor'])
        require(preparation_guard(plan)==before,'protected input/source changed while copying')
        bound={k:plan[k]for k in ('controls','provenance','compiler','runtime_map','limits','storage_floor',
            'author_ancestors','template','component_sources','authority_names')}
        bound.update(schema=SCHEMA,state='BOUND_AWAITING_ROOT_AUTHORIZATION',scope=str(scope),source=str(source),
            source_tree=SOURCE_TREE,source_map=capture(scope/'SOURCE-MAP.json'),
            source_state=capture(scope/'SOURCE-STATE.json'),attempt=str(scope/'attempt-r1'),
            scope_ancestors=directory_binding(scope),preparation_plan=descriptor,copies=capture(scope/'COPIES.json'))
        runtime,_=import_runtime(bound);bound['runtime']=runtime.capture_runtime_context()
        expected=plan['expected_runtime']
        require(bound['runtime']['version']==[3,14,4]
                and bound['runtime']['launch_executable']==expected['executable']['path']
                and bound['runtime']['executable']['sha256']==expected['executable']['pin']['sha256']
                and bound['runtime']['library']['path']==expected['library']['path']
                and bound['runtime']['library']['sha256']==expected['library']['pin']['sha256'],
                'fresh actual runtime differs from restored authority')
        for row in expected.values():checked(row)
        all_guards(bound,runtime.guard_runtime_context)
        require(preparation_guard(plan)==before,'final protected authorities changed')
        publish(scope/'BOUND-PLAN.json',bound)
        result.update(status='BOUND_NOT_EXECUTED',plan=capture(scope/'BOUND-PLAN.json'),source_files=3210,
            source_tree=SOURCE_TREE,source_map=bound['source_map'],source_state=bound['source_state'],
            runtime=bound['runtime'],next_launch_requires_root_review=True)
    except BaseException:result['traceback']=traceback.format_exc()
    finally:
        result['finished_ns']=time.monotonic_ns()
        try:
            result['protected_source_after']=preparation_guard(plan)
            require(result['protected_source_after']==before,'terminal protected sources changed')
        except BaseException:result.update(status='FAIL',terminal_guard_error=traceback.format_exc())
        publish(scope/'BINDING-RESULT.json',result)
    return 0 if result['status']=='BOUND_NOT_EXECUTED' else 1


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--plan',required=True)
    parser.add_argument('--plan-sha256',required=True);a=parser.parse_args()
    raise SystemExit(bind(a.plan,a.plan_sha256))
