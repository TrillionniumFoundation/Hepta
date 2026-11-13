"""One frozen source/VM request; the existing process owner bounds the worker."""
from pathlib import Path
import argparse
import hashlib
import importlib
import importlib.util
import json
import os
import stat
import sys
import time
import traceback

ROOT=Path(__file__).resolve().parents[1]

def require(condition,message):
    if not condition:raise RuntimeError(message)
def identity(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(path,maximum=64<<20):
    path=Path(path);before=path.lstat()
    require(path.is_absolute() and path.resolve(strict=True)==path and stat.S_ISREG(before.st_mode)
            and before.st_nlink==1 and before.st_size<=maximum,'exact bounded regular file required')
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC),'rb') as stream:
        require(identity(os.fstat(stream.fileno()))==identity(before),'input changed before full read')
        raw=stream.read();require(identity(os.fstat(stream.fileno()))==identity(before),'input changed during full read')
    require(len(raw)==before.st_size and identity(path.lstat())==identity(before),'input changed after full read')
    return raw,{'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'identity':identity(before)}
def create(path,value):
    raw=value if isinstance(value,bytes) else (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    observed,pin=read(path);require(observed==raw,'created original differs');return pin
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module);return module
def inputs(q):
    found=[]
    for row in q['inputs']:
        raw,pin=read(row['path']);require(pin=={k:row[k] for k in pin},'frozen input differs: '+row['path']);found.append(pin)
    require(len(found)==len({r['path'] for r in found}),'duplicate frozen input path');return found
def source_records(q):
    raw,_=read(q['source_catalog']);catalog=json.loads(raw);base=Path(q['source_root'])
    require(len(catalog)==1686,'source population differs');actual={}
    for name,pin in catalog.items():
        require(not name.startswith('/') and '..' not in Path(name).parts,'nonrelative source name')
        body,observed=read(base/name)
        require(all(observed[k]==pin[k] for k in observed),'complete source identity differs: '+name)
        require(hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest()==pin['git_blob'],'source Git identity differs')
        actual[name]={**observed,'git_blob':pin['git_blob']}
    names=set()
    for parent,dirs,files in os.walk(base,followlinks=False):
        for name in dirs:require(stat.S_ISDIR((Path(parent)/name).lstat().st_mode),'source directory link')
        for name in files:names.add(str((Path(parent)/name).relative_to(base)))
    require(names==set(catalog),'source namespace changed');return actual
def check_imports(q):
    catalog=json.loads(read(q['source_catalog'])[0]);expected={v['path']:v for v in catalog.values()}
    expected.update({v['path']:v for v in q['inputs']})
    found=[]
    for name,module in sorted(sys.modules.items()):
        if not any(name==prefix or name.startswith(prefix+'.') for prefix in ('hepta','tools','tests')):continue
        filename=getattr(module,'__file__',None)
        if filename is None:
            require(name=='tools','unexpected project namespace');found.append({'module':name,'namespace_only':True});continue
        path=str(Path(filename).resolve());require(path in expected and path.endswith('.py'),'unbound project import: '+name)
        raw,pin=read(path);require(all(pin[k]==expected[path][k] for k in pin),'imported source changed: '+name)
        found.append({'module':name,'source':pin})
    require(any(r['module']==q['test_module'] for r in found),'source test module not observed')
    return found
def vm_readback(q,out):
    raw,pin=read(out/'tests/VM-RAW.json',64<<20);value=json.loads(raw)
    require(value['schema']=='hia.sqlite-btree-cell.source-vm-raw.v1' and value['native_executed'] is False and value['compiler_executed'] is False,'VM scope differs')
    calls=value['calls'];counts={name:0 for name in q['expected_ids']};sequence=[]
    require(len(calls)==q['expected_vm_returns']==339,'VM population differs')
    for row in calls:
        require(row['case'] in counts and row['actual_returned'] is True and type(row['status']) is int,'VM call missing actual return')
        for before,after in [('source_before_hex','source_after_hex'),('control_before_hex','control_after_hex')]:
            require(row[before]==row[after] and bytes.fromhex(row[before]).hex()==row[before],'VM immutable span changed')
        a,b=bytes.fromhex(row['output_before_hex']),bytes.fromhex(row['output_after_hex'])
        require(len(a)==len(b),'VM output extent changed')
        if row['status'] in (0xfffffffd,0xfffffffe,0xfffffffc,0xfffffffb,0xfffffffa,0xfffffff9):require(a==b,'refused VM modified output')
        else:require(row['status']==128,'unexpected VM return')
        counts[row['case']]+=1;sequence.append(row['case'])
    require(counts==q['expected_vm_by_id'] and sequence==[name for name in q['expected_ids'] for _ in range(counts[name])],'ordered VM population differs')
    return {'pin':pin,'calls':len(calls),'by_id':counts,'whole_raw_buffers_read':True}
def worker(q,request_raw,request_sha):
    import ctypes
    import mmap
    import socket
    import subprocess
    import unittest
    out=Path(q['output_root']);tests=out/'tests';tests.mkdir(mode=0o700)
    report={'schema':'hia.sqlite-btree-cell.source12-report.v1','status':'HOLD','expected_ids':q['expected_ids'],
            'loaded_ids':[],'actual_ids':[],'success_ids':[],'failures':[],'errors':[],'skips':[],
            'expected_failures':[],'unexpected_successes':[],'loader_errors':[],'denied_effects':[],'exception':None,'secondary_errors':[],
            'native_executed':False,'C_compiler_or_oracle_executed':False,'database_opened':False,'network_used':False}
    before=inputs(q);source_before=source_records(q);create(tests/'SOURCE-BEFORE.json',source_before)
    create(tests/'INPUTS-BEFORE.json',before)
    def deny(label):
        def forbidden(*a,**kw):report['denied_effects'].append(label);raise RuntimeError('source-only forbidden effect: '+label)
        return forbidden
    def audit(event,args):
        if event in {'subprocess.Popen','os.system','os.fork','os.forkpty','os.posix_spawn','os.posix_spawnp','os.exec','pty.spawn','ctypes.dlopen','ctypes.dlsym','sqlite3.connect','mmap.__new__'} or event.startswith('socket.'):
            deny('audit:'+event)()
    started=time.monotonic()
    try:
        sys.addaudithook(audit);subprocess.Popen=deny('Popen');os.system=deny('system')
        ctypes.CDLL=deny('CDLL');ctypes.PyDLL=deny('PyDLL');mmap.mmap=deny('mmap');socket.create_connection=deny('socket')
        os.environ['HEPTA_SQLITE_BTREE_CELL_SOURCE_EVIDENCE']=str(tests)
        sys.path[:0]=[str(ROOT/'inputs'),q['source_root']]
        hepta=importlib.import_module('hepta');hepta.__path__[:]=[str(ROOT/'inputs/hepta'),str(Path(q['source_root'])/'hepta')]
        importlib.import_module('tools');importlib.import_module('tests')
        native=importlib.import_module('hepta.hia_json_preflight_native');native.NativeHiaJsonImage.__init__=deny('native image construction')
        author_name='tools.generate_hia_sqlite_btree_cell'
        author_spec=importlib.util.spec_from_file_location(author_name,q['generator_path'])
        author_module=importlib.util.module_from_spec(author_spec);sys.modules[author_name]=author_module
        author_spec.loader.exec_module(author_module)
        setattr(sys.modules['tools'],'generate_hia_sqlite_btree_cell',author_module)
        spec=importlib.util.spec_from_file_location(q['test_module'],ROOT/'inputs/tests/test_hia_sqlite_btree_cell_source.py')
        module=importlib.util.module_from_spec(spec);sys.modules[q['test_module']]=module;spec.loader.exec_module(module)
        cls=module.SQLiteBtreeCellSourceTests;names=[x.rsplit('.',1)[1] for x in q['expected_ids']]
        require(tuple(names)==module.EXPECTED_NAMES and set(names)=={n for n in cls.__dict__ if n.startswith('test_')},'source method selection differs')
        require(list(module.EXPECTED_COUNTS)==list(q['expected_vm_by_id'].values()),'frozen per-method population differs')
        suite=unittest.TestSuite(cls(n) for n in names);report['loaded_ids']=[x.id() for x in suite]
        require(report['loaded_ids']==q['expected_ids'],'source loader population differs')
        class Result(unittest.TextTestResult):
            def startTest(self,test):report['actual_ids'].append(test.id());super().startTest(test)
            def addSuccess(self,test):report['success_ids'].append(test.id());super().addSuccess(test)
        with (tests/'unittest.log').open('x',encoding='utf-8') as log:
            result=unittest.TextTestRunner(stream=log,verbosity=2,resultclass=Result).run(suite)
            log.flush();os.fsync(log.fileno())
        report['tests_run']=result.testsRun
        for key,rows in [('failures',result.failures),('errors',result.errors),('skips',result.skipped),('expected_failures',result.expectedFailures)]:
            report[key]=[{'id':t.id(),'detail':detail} for t,detail in rows]
        report['unexpected_successes']=[t.id() for t in result.unexpectedSuccesses]
        report['imports']=check_imports(q);report['VM']=vm_readback(q,out)
    except BaseException as exc:report['exception']={'type':type(exc).__name__,'traceback':traceback.format_exc()}
    finally:
        try:
            after=inputs(q);source_after=source_records(q)
            create(tests/'INPUTS-AFTER.json',after);create(tests/'SOURCE-AFTER.json',source_after)
            require(before==after and source_before==source_after,'source inputs changed');report['inputs_unchanged']=True
        except BaseException as exc:report['secondary_errors'].append({'type':type(exc).__name__,'traceback':traceback.format_exc()})
    passed=(report['exception'] is None and not report['secondary_errors'] and report.get('inputs_unchanged') is True
            and report.get('tests_run')==12 and report['expected_ids']==report['loaded_ids']==report['actual_ids']==report['success_ids']
            and all(report[k]==[] for k in ('failures','errors','skips','expected_failures','unexpected_successes','loader_errors','denied_effects')))
    report['seconds']=time.monotonic()-started;report['status']='SOURCE12_BTREE_CELL_VM_PASS_ONLY' if passed else 'HOLD'
    create(tests/'REPORT.json',report);print(json.dumps({'status':report['status'],'tests':report.get('tests_run'),'seconds':report['seconds']}),flush=True)
    return 0 if passed else 1
def parent(q,raw,request_sha):
    before=inputs(q);out=Path(q['output_root'])
    require(out.is_absolute() and out.parent.resolve()==out.parent and not os.path.lexists(out),'fresh output root required')
    capacity=os.statvfs(out.parent)
    require(capacity.f_bavail*capacity.f_frsize>=512<<20 and capacity.f_favail>=4096,'source storage reserve insufficient')
    out.mkdir(mode=0o700);create(out/'REQUEST.original.json',raw);create(out/'INPUTS-BEFORE.json',before)
    final={'schema':'hia.sqlite-btree-cell.source12-final.v1','status':'HOLD','closed':False,'natural':False,'errors':[],
           'request_sha256':request_sha,'qualification_seconds':180,'cleanup_seconds':3,'native_or_SQL_executed':False}
    command=[q['runtime']['executable'],'-I','-S','-B',str(Path(__file__).resolve()),'--request',str(ROOT/'REQUEST-r3.json'),'--sha256',request_sha,'--worker']
    try:
        owner=load('record_original_process_owner',q['owner_path'])
        wrapper=owner.run_owned(command,cwd=ROOT,env=q['environment'],stdout_path=out/'stdout.log',stderr_path=out/'stderr.log',receipt_path=out/'owner.json',qualification_seconds=180,cleanup_seconds=3)
        create(out/'OWNER-WRAPPER.json',wrapper)
        life_raw,_=read(out/'owner.json');bound_raw,_=read(out/'owner.json.request.json');life=json.loads(life_raw);bound=json.loads(bound_raw)
        owner_sha=next(r['sha256'] for r in q['inputs'] if r['path']==q['owner_path'])
        require(all(wrapper.get(k)==v for k,v in life.items()) and wrapper['receipt_sha256']==hashlib.sha256(life_raw).hexdigest()
                and life['request_sha256']==hashlib.sha256(bound_raw).hexdigest()
                and life['implementation_sha256']==bound['implementation_sha256']==owner_sha
                and life['schema']==bound['schema']==wrapper['schema']=='hepta.hia.selfhost-process-owner.v1'
                and bound['command']==command and bound['cwd']==str(ROOT) and bound['env']==q['environment']
                and bound['stdout_path']==str(out/'stdout.log') and bound['stderr_path']==str(out/'stderr.log') and bound['receipt_path']==str(out/'owner.json')
                and bound['qualification_seconds']==life['qualification_seconds']==180 and bound['cleanup_seconds']==life['cleanup_seconds']==3,'current owner binding differs')
        clean=life.get('cleanup',{})
        closed=(life.get('subreaper_enabled') is True and life.get('qualification_started') is True
                and all(clean.get(k) is True for k in ('attempted','complete','observed_echild','leader_reaped'))
                and clean.get('deadline_exceeded') is False and clean.get('errors')==[] and clean.get('remaining_direct_children')==[])
        final['closed']=closed;require(closed,'current owner has not established ECHILD; child originals unread')
        kinds=[x.get('kind') for x in life.get('events',[])]
        natural=(wrapper.get('supervisor_returncode')==life.get('returncode')==0 and life.get('status')=='OWNED_PROCESS_COMPLETED'
                 and life.get('timed_out') is False and life.get('exit_observed_before_deadline') is True and life.get('event_overflow') is False
                 and life.get('interrupted_signals')==[] and life.get('owner_error') is None
                 and kinds==['qualification_started','owned_child_observed','qualification_exit_observed','owned_child_reaped'])
        final['natural']=natural
        report=json.loads(read(out/'tests/REPORT.json')[0]);final['worker_status']=report['status']
        require(natural and report['status']=='SOURCE12_BTREE_CELL_VM_PASS_ONLY','source worker did not pass naturally')
        final['status']='SOURCE12_BTREE_CELL_VM_PASS_ONLY'
    except BaseException as exc:final['errors'].append({'type':type(exc).__name__,'traceback':traceback.format_exc()})
    finally:
        if final['closed']:
            try:
                after=inputs(q);create(out/'INPUTS-AFTER.json',after);require(after==before,'parent inputs changed')
                original=[];total=0
                for base,dirs,files in os.walk(out,followlinks=False):
                    for name in dirs:require(stat.S_ISDIR((Path(base)/name).lstat().st_mode),'unexpected output directory link')
                    for name in sorted(files):
                        b,pin=read(Path(base)/name,64<<20);total+=len(b);original.append(pin)
                        require(len(original)<=64 and total<=128<<20,'bounded source evidence output exceeded')
                final['originals']=create(out/'ORIGINALS.json',{'files':original,'bytes':total,'after_bound_ECHILD':True})
            except BaseException as exc:final['status']='HOLD';final['errors'].append({'type':type(exc).__name__,'traceback':traceback.format_exc()})
        else:final['child_originals_not_read_or_enumerated']=True
        if final['errors']:final['status']='HOLD'
        create(out/'FINAL.json',final)
    print(json.dumps({'status':final['status'],'closed':final['closed'],'natural':final['natural']}),flush=True)
    return 0 if final['status']=='SOURCE12_BTREE_CELL_VM_PASS_ONLY' else 1
def main():
    p=argparse.ArgumentParser();p.add_argument('--request',type=Path,required=True);p.add_argument('--sha256',required=True);p.add_argument('--worker',action='store_true');a=p.parse_args()
    require(a.request==ROOT/'REQUEST-r3.json','unexpected request path')
    raw,_=read(a.request);require(hashlib.sha256(raw).hexdigest()==a.sha256,'request hash differs');q=json.loads(raw)
    require(q['schema']=='hia.sqlite-btree-cell.source12-request.v1' and q['qualification_seconds']==180 and q['cleanup_seconds']==3,'frozen operation differs')
    require(len(q['expected_ids'])==12 and len(set(q['expected_ids']))==12,'source population differs')
    require(str(Path(sys.executable).resolve())==q['runtime']['executable'] and sys.version==q['runtime']['version'] and dict(os.environ)==q['environment'],'runtime or clean environment differs')
    return worker(q,raw,a.sha256) if a.worker else parent(q,raw,a.sha256)
if __name__=='__main__':raise SystemExit(main())
