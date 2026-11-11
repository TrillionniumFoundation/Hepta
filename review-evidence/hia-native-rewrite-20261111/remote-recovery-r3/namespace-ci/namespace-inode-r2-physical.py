"""NEW actual inode-owner plus sealed FS ELF physical tests; no ordinary Store claim.

The Python code here is a development oracle/router. It never decides inode
conflicts, masks, retire order or kernel errno mapping. Those decisions are HIA.
The final fixed native namespace coordinator remains a separate required owner.
"""
import sys
sys.dont_write_bytecode=True
import ctypes,errno,fcntl,gzip,hashlib,importlib.util,json,os,stat,struct,traceback,unittest
from pathlib import Path
CLIENT_SHA="00981a3f7bbd195dd5522858d6c032e19a4789900317ff8637be1d811a77893d"
REPLAY_SHA="d81356c9bdee5889f562720048b1ac654cfd74f02cb16bb61ff55f1e675c3881"
ELF_SHA="1a83b401f48b03f36cc9fb7da2fac8fc28a3ea5f8c5c364dffbd2787eac8f7f6"
FS_SOURCE_SHA="7e19f56989fda5170b42e045701707cd771b2cd184f8e47b904a7df5070086c8"
CANARY=bytes(range(144,176))
def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def main():
    context_path=Path(os.environ["HIA_NAMESPACE_CI_CONTEXT"]).resolve()
    context=json.loads(context_path.read_bytes())
    ref=Path(context["reference"]);tree=Path(context["namespace_working"])
    evidence=Path(context["namespace_evidence"]);out=evidence/"physical-r1"
    out.mkdir(parents=True,exist_ok=False);(out/"source").mkdir()
    fixtures=tree.parent/"physical-fixtures-r1";fixtures.mkdir()
    pins={}
    def pin(path,expected=None):
        path=Path(path).resolve();raw=path.read_bytes()
        row=dict(bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(path.stat().st_mode))
        if expected is not None:assert row["sha256"]==expected
        if str(path) in pins:assert pins[str(path)]==row
        pins[str(path)]=row;return raw
    def load(name,path,expected=None):
        raw=pin(path,expected);spec=importlib.util.spec_from_file_location(name,path)
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module
        exec(compile(raw,str(path),"exec"),module.__dict__);return module
    pin(context_path);pin(__file__)
    sys.path.insert(0,str(ref))
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program_runtime import _Machine,_Owner,_View
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    for name in ("generate_hia_agent_namespace_store","generate_hia_agent_namespace_objects","generate_hia_agent_namespace_inode"):
        load("tools."+name,tree/"tools"/(name+".py"))
    fixture=load("namespace_inode_protocol_fixture",tree/"tests/test_hia_agent_namespace_inode.py")
    transport=load("namespace_inode_real_fs_transport",context["carrier_client"],CLIENT_SHA)
    replay=load("namespace_inode_real_fs_trace_replay",context["carrier_replay"],REPLAY_SHA)
    prior=json.loads(pin(evidence/"validation-r1/result.json"))
    assert prior["status"]=="PASS" and prior["source_unchanged"] and prior["produced_image_before_after_equal"]
    for row in prior["tests"].values():
        assert row["passed"] and 0<row["tests_loaded"]==row["tests_run"]==len(row["test_ids"])==18
        assert not any(row[k] for k in ("failures","errors","skipped","expected_failures","unexpected_successes"))
    native_path=Path(prior["image"]["path"]);native_raw=pin(native_path,prior["image"]["sha256"])
    source=pin(tree/"examples/hia_bootstrap/agent_namespace_inode_r2.hiaasm",prior["source_sha256"])
    program=assemble_program(source);entry=program.as_dict()["functions"][0]
    executable=Path(context["filesystem_executable"])
    elf=pin(executable,ELF_SHA);assert len(elf)==181257 and stat.S_IMODE(executable.stat().st_mode)==0o755
    assert elf[3648:]==pin(context["filesystem_image"],"f1d81566c18556fcdddafb84546f4f6208b7a83f9351583e999e5ecb6379618c")
    fs_source=pin(tree/"examples/hia_bootstrap/agent_namespace_filesystem_r3.hiaasm",FS_SOURCE_SHA)
    fs_program=assemble_program(fs_source)
    for module in tuple(sys.modules.values()):
        name=getattr(module,"__file__",None)
        if name:
            path=Path(name).resolve()
            if path.is_relative_to(ref) and path.suffix==".py":pin(path)
    for number,(path,row) in enumerate(pins.items()):
        target=out/"source"/str(number)/Path(path).name;target.parent.mkdir(parents=True)
        target.write_bytes(Path(path).read_bytes());target.chmod(row["mode"])
    save(out/"source-before.json",pins)
    import sqlite3
    with sqlite3.connect(":memory:") as db:
        sqlite_identity=dict(version=sqlite3.sqlite_version,source_id=db.execute("select sqlite_source_id()").fetchone()[0],
            compile_options=[r[0] for r in db.execute("pragma compile_options")])
    report=dict(status="INCOMPLETE",scope="NEW_ACTUAL_INODE_IMAGE_AND_REAL_FS_PROVIDER_COMPONENT",
        native_inode_entries=0,vm_inode_entries=0,actual_provider_commands=0,registries=0,
        fs_replays=[],observations={},sqlite=sqlite_identity,
        private_python_router_is_development_only=True,fixed_namespace_coordinator_closed=False,
        ordinary_store_closed=False,migration_closed=False,prior_kernel_carrier_counts_inherited=False)
    libc=ctypes.CDLL(None,use_errno=True)
    libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
    libc.mmap.restype=ctypes.c_void_p
    libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int];libc.mprotect.restype=ctypes.c_int
    libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t];libc.munmap.restype=ctypes.c_int
    class Buffer:
        def __init__(self,size,initial=b"",readonly=False):
            assert len(initial)<=size
            self.size=size;self.middle=(size+64+4095)&~4095;self.total=self.middle+8192;self.base=None
            address=libc.mmap(None,self.total,0,0x22,-1,0)
            if address==ctypes.c_void_p(-1).value:raise OSError(ctypes.get_errno(),"mmap")
            self.base=address;self.address=address+4128
            try:
                if libc.mprotect(address+4096,self.middle,3):raise OSError(ctypes.get_errno(),"mprotect RW")
                ctypes.memmove(self.address-32,CANARY,32);ctypes.memmove(self.address+size,CANARY,32)
                if initial:ctypes.memmove(self.address,initial,len(initial))
                if readonly and libc.mprotect(address+4096,self.middle,1):raise OSError(ctypes.get_errno(),"mprotect RO")
            except BaseException:self.close();raise
        def read(self):return ctypes.string_at(self.address,self.size)
        def check(self):
            assert ctypes.string_at(self.address-32,32)==CANARY
            assert ctypes.string_at(self.address+self.size,32)==CANARY
        def close(self):
            if self.base is not None:
                base=self.base;self.base=None
                if libc.munmap(base,self.total):raise OSError(ctypes.get_errno(),"munmap")
    image=NativeHiaJsonImage(native_raw,sha(native_raw))
    assert image.image_sha256==sha(native_raw)
    class Registry:
        def __init__(self,carrier,directory):
            self.carrier=carrier;self.directory=directory;directory.mkdir()
            self.work=bytearray(512);self.native_work=Buffer(512);self.call_number=0;self.event=None
            report["registries"]+=1;self.session=(97,report["registries"])
            self.events=[];self.closed=False;self.ledger=None
            try:
                self.ledger=gzip.open(directory/"entries.jsonl.gz","wt",encoding="utf-8")
                last=carrier.requests[-1]["header"]
                raw=fixture.frame(1,session=self.session,fs=carrier.session,watermarks=(carrier.call_number,last[5]))
                code,h,_=self.invoke(raw)
                assert (code,h[14])==(0,1)
            except BaseException:self.close();raise
        def invoke(self,raw):
            raw=bytes(raw);before=bytes(self.work)
            assert self.native_work.read()==before
            owners=[_Owner(-1,bytearray(raw)),_Owner(-2,bytearray(256)),_Owner(-3,bytearray(before))]
            machine=_Machine(program,4000000,16<<20,None,64)
            expected=machine.invoke(entry,[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
            report["vm_inode_entries"]+=1
            a=o=None
            try:
                a=Buffer(len(raw),raw,True);o=Buffer(256)
                actual=int(image._entry(a.address,a.size,o.address,o.size,self.native_work.address,self.native_work.size))
                report["native_inode_entries"]+=1
                output=o.read();after=self.native_work.read()
                for item in (a,o,self.native_work):item.check()
                row=dict(index=report["native_inode_entries"],input_hex=raw.hex(),pre_workspace_hex=before.hex(),
                    actual_return=actual,expected_return=expected,actual_output_hex=output.hex(),
                    expected_output_hex=bytes(owners[1].data).hex(),actual_workspace_hex=after.hex(),
                    expected_workspace_hex=bytes(owners[2].data).hex(),source_unchanged=a.read()==raw,
                    guards=True,readonly_input=True,provider="ACTUAL_FIXED_FS_ELF")
                self.ledger.write(json.dumps(row,sort_keys=True,separators=(",",":"))+"\n");self.ledger.flush()
                assert bytes(owners[0].data)==raw and row["source_unchanged"]
                assert actual==expected and output==bytes(owners[1].data) and after==bytes(owners[2].data)
                self.work[:]=after;self.event=struct.unpack("<32Q",output)
                assert self.event[1]==actual
                return actual,self.event,output
            finally:
                for item in (o,a):
                    if item is not None:item.close()
        def start(self,command,handle=0,*,value=0,offset=0,count=0):
            self.call_number+=1
            raw=fixture.frame(command,session=self.session,call=self.call_number,handle=handle,
                value=value,offset=offset,count=count,lease=7000+self.call_number)
            self.original=raw
            result=self.invoke(raw)
            while result[0]==2:
                need=result[1][15];assert need>len(self.work)
                old=bytes(self.work);next_work=Buffer(need,old)
                self.native_work.close();self.native_work=next_work
                self.work.extend(bytes(need-len(self.work)))
                assert bytes(self.work[:len(old)])==old
                result=self.invoke(raw)
            return result
        def actual_reply(self):
            h=self.event;assert h[1]==1
            op=h[7];assert op in (8,15,17)
            c=self.carrier;c.call_number+=1
            args=(h[16],h[17],h[18],h[19]) if op==17 else (h[16],)
            request=transport.frame(2,session=c.session,call=c.call_number,operation=op,args=args,lease=h[5])
            header,_=c.request(request,label="actual-inode-peer-"+str(op))
            path=c.output/"requests"/str(len(c.requests)-1)/"output.bin"
            output=path.read_bytes()
            assert struct.unpack_from("<32Q",output)==header and header[1]==0
            item=dict(action=h[5],operation=op,args=list(args),request_sha256=sha(request),
                actual_output_sha256=sha(output),raw_errno=header[7],carrier_request=len(c.requests)-1,
                exact_source_lease=h[5],registry_call=h[4])
            self.events.append(item);save(self.directory/"provider-events.json",self.events)
            report["actual_provider_commands"]+=1
            return fixture.frame(6,session=self.session,call=h[4],action=h[5],handle=h[6],
                operation=op,lease=h[11],body=request+output)
        def command(self,command,handle=0,**kw):
            result=self.start(command,handle,**kw)
            while result[0]==1:result=self.invoke(self.actual_reply())
            assert result[0]==0,result[1]
            return result[1]
        def register(self,token):
            h=self.command(2,value=token);assert h[8:10]==(0,0)
            return h[10]
        def close(self):
            if self.closed:return
            self.closed=True
            if self.ledger is not None:self.ledger.close()
            if self.native_work is not None:self.native_work.close()
            if hasattr(self,"events"):save(self.directory/"provider-events.json",self.events)
    cas=out/"fixture-cas";cas.mkdir()
    def snapshot(root,label):
        rows=[]
        for path in [root,*sorted(root.rglob("*"))]:
            info=path.lstat();item=dict(path="." if path==root else path.relative_to(root).as_posix(),
                type=stat.S_IFMT(info.st_mode),mode=stat.S_IMODE(info.st_mode),device=info.st_dev,inode=info.st_ino,
                uid=info.st_uid,gid=info.st_gid,links=info.st_nlink,bytes=info.st_size)
            if stat.S_ISREG(info.st_mode):
                raw=path.read_bytes();h=sha(raw);dest=cas/h
                if not dest.exists():dest.write_bytes(raw)
                assert dest.read_bytes()==raw;item.update(sha256=h,content_bytes=len(raw),cas=h)
            elif stat.S_ISLNK(info.st_mode):item["link_hex"]=os.fsencode(os.readlink(path)).hex()
            rows.append(item)
        save(out/"fixture-snapshots"/(label+".json"),rows)
    def replay_one(c):
        row=replay.replay(fs_program,c.output);row["directory"]=str(c.output);report["fs_replays"].append(row)
    class Physical(unittest.TestCase):
        def setUp(self):
            self.fx=fixtures/self._testMethodName;self.fx.mkdir()
            self.case=out/"cases"/self._testMethodName;self.case.mkdir(parents=True)
            self.addCleanup(snapshot,self.fx,self._testMethodName+"-final")
        def carrier(self,name="fs",session=(19,1)):
            return transport.Carrier(executable,self.case/name,self.fx,session=session)
        def registry(self,c,name="registry"):
            r=Registry(c,self.case/name);self.addCleanup(r.close);return r
        def file(self,name="original"):
            path=self.fx/name;path.write_bytes(bytes(512));return path
        def open(self,c,name="original",flags=os.O_RDWR):
            return c.call(1,0,flags,0,body=os.fsencode(name))[0][8]
        def blocked(self,fd):
            with self.assertRaises(OSError) as raised:fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB,1,120,os.SEEK_SET)
            self.assertIn(raised.exception.errno,(errno.EACCES,errno.EAGAIN))
        def available(self,fd):
            fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB,1,120,os.SEEK_SET)
            fcntl.lockf(fd,fcntl.LOCK_UN,1,120,os.SEEK_SET)
        def success(self,h):self.assertEqual(h[8:10],(0,0))
        def test_01_actual_stat_and_deferred_alias_lifo_preserve_foreign_lock(self):
            path=self.file();os.link(path,self.fx/"alias-a");os.link(path,self.fx/"alias-b")
            actual=path.stat();observer=os.open(path,os.O_RDWR)
            try:
                with self.carrier() as c:
                    r=self.registry(c);tokens=[self.open(c,n) for n in ("original","alias-a","alias-b")]
                    handles=[r.register(t) for t in tokens];a,b,d=handles
                    self.assertEqual((fixture.q(r.work,66),fixture.q(r.work,67),fixture.q(r.work,74)),
                        (actual.st_dev,actual.st_ino,actual.st_uid))
                    self.success(r.command(3,a,value=2,count=1));self.blocked(observer)
                    before=len(r.events)
                    self.success(r.command(5,b));self.success(r.command(5,d))
                    self.assertEqual(len(r.events),before);self.blocked(observer)
                    self.success(r.command(4,a,value=2,count=1))
                    tail=r.events[before:];self.assertEqual([v["operation"] for v in tail],[17,8,8])
                    self.assertEqual([v["args"][0] for v in tail[1:]],[tokens[2],tokens[1]])
                    self.available(observer);self.success(r.command(5,a));c.close_all()
                replay_one(c)
            finally:os.close(observer)
            report["observations"]["deferred_alias_preserves_lock_and_lifo"]=True
            report["observations"]["actual_uid"]=actual.st_uid
        def test_02_shared_holder_no_redundant_os_lock_or_premature_unlock(self):
            path=self.file();os.link(path,self.fx/"alias");observer=os.open(path,os.O_RDWR)
            try:
                with self.carrier() as c:
                    r=self.registry(c);a=r.register(self.open(c));b=r.register(self.open(c,"alias"))
                    self.success(r.command(3,a,value=1,count=1));before=len(r.events)
                    self.success(r.command(3,b,value=1,count=1));self.success(r.command(3,a,value=1,count=1))
                    self.success(r.command(4,a,value=1,count=1));self.assertEqual(len(r.events),before)
                    self.blocked(observer)
                    self.success(r.command(4,b,value=1,count=1));self.assertEqual(len(r.events),before+1)
                    self.available(observer)
                    self.success(r.command(5,a));self.success(r.command(5,b));c.close_all()
                replay_one(c)
            finally:os.close(observer)
            report["observations"]["shared_holder_reference_counts"]=True
        def test_03_local_conflicts_do_not_call_os_and_other_inode_is_independent(self):
            self.file();self.file("other");os.link(self.fx/"original",self.fx/"alias")
            with self.carrier() as c:
                r=self.registry(c);a=r.register(self.open(c));b=r.register(self.open(c,"alias"));d=r.register(self.open(c,"other"))
                self.success(r.command(3,a,value=2,count=8));before=len(r.events)
                for kind in (1,2):
                    h=r.command(3,b,value=kind,count=1);self.assertEqual(h[8:10],(5,0))
                self.assertEqual(len(r.events),before)
                self.success(r.command(3,d,value=2,count=8));self.assertEqual(len(r.events),before+1)
                self.success(r.command(4,a,value=2,count=8));self.success(r.command(4,d,value=2,count=8))
                for handle in (a,b,d):self.success(r.command(5,handle))
                c.close_all()
            replay_one(c);report["observations"]["local_conflict_and_inode_separation"]=True
        def test_04_foreign_real_fcntl_busy_then_success(self):
            path=self.file();observer=os.open(path,os.O_RDWR)
            try:
                fcntl.lockf(observer,fcntl.LOCK_EX|fcntl.LOCK_NB,1,120,os.SEEK_SET)
                with self.carrier() as c:
                    r=self.registry(c);a=r.register(self.open(c))
                    h=r.command(3,a,value=2,count=1);self.assertEqual(h[8],5)
                    self.assertIn(h[9],(errno.EACCES,errno.EAGAIN))
                    self.assertEqual(fixture.q(r.work,(512+40)//8),0)
                    fcntl.lockf(observer,fcntl.LOCK_UN,1,120,os.SEEK_SET)
                    self.success(r.command(3,a,value=2,count=1));self.blocked(observer)
                    self.success(r.command(4,a,value=2,count=1));self.available(observer)
                    self.success(r.command(5,a));c.close_all()
                replay_one(c)
            finally:os.close(observer)
            report["observations"]["actual_foreign_busy_and_release"]=True
        def test_05_real_sqlite_writer_both_directions_through_policy(self):
            path=self.fx/"state.sqlite3";db=sqlite3.connect(path,timeout=0,isolation_level=None);transcript=[]
            def sql(text):
                try:
                    rows=db.execute(text).fetchall();transcript.append(dict(sql=text,rows=rows,status="RETURN"));return rows
                except BaseException as error:
                    transcript.append(dict(sql=text,status="ERROR",type=type(error).__name__,message=str(error),
                        sqlite_errorcode=getattr(error,"sqlite_errorcode",None)));raise
            try:
                self.assertEqual(sql("pragma journal_mode=WAL"),[("wal",)])
                sql("pragma synchronous=FULL");sql("create table sample(value integer)")
                with self.carrier() as c:
                    r=self.registry(c);a=r.register(self.open(c,"state.sqlite3-shm"))
                    sql("begin immediate")
                    h=r.command(3,a,value=2,count=1);self.assertEqual(h[8],5);self.assertIn(h[9],(errno.EACCES,errno.EAGAIN))
                    sql("rollback");self.success(r.command(3,a,value=2,count=1))
                    with self.assertRaises(sqlite3.OperationalError) as raised:sql("begin immediate")
                    self.assertEqual(raised.exception.sqlite_errorcode,sqlite3.SQLITE_BUSY)
                    self.success(r.command(4,a,value=2,count=1))
                    sql("begin immediate");sql("insert into sample values(7)");sql("commit")
                    self.assertEqual(sql("select value from sample"),[(7,)])
                    self.success(r.command(5,a));c.close_all()
                replay_one(c);snapshot(self.fx,self._testMethodName+"-db-open")
            finally:save(self.case/"sql.json",transcript);db.close()
            report["observations"]["actual_sqlite_wal_writer_both_directions"]=True
        def test_06_two_actual_carriers_and_registries_fence_each_other(self):
            self.file()
            with self.carrier("fs-a",(19,1)) as a,self.carrier("fs-b",(19,2)) as b:
                ra=self.registry(a,"registry-a");rb=self.registry(b,"registry-b")
                ha=ra.register(self.open(a));hb=rb.register(self.open(b))
                self.success(ra.command(3,ha,value=2,count=1))
                result=rb.command(3,hb,value=2,count=1);self.assertEqual(result[8],5)
                self.assertIn(result[9],(errno.EACCES,errno.EAGAIN))
                self.success(ra.command(4,ha,value=2,count=1));self.success(rb.command(3,hb,value=2,count=1))
                result=ra.command(3,ha,value=1,count=1);self.assertEqual(result[8],5)
                self.success(rb.command(4,hb,value=2,count=1))
                self.success(ra.command(5,ha));self.success(rb.command(5,hb));a.close_all();b.close_all()
            replay_one(a);replay_one(b);report["observations"]["two_actual_sessions_contend"]=True
        def test_07_actual_readonly_descriptor_ebadf_is_busy(self):
            self.file()
            with self.carrier() as c:
                r=self.registry(c);a=r.register(self.open(c,flags=os.O_RDONLY))
                result=r.command(3,a,value=2,count=1);self.assertEqual(result[8:10],(5,errno.EBADF))
                self.assertEqual(fixture.q(r.work,(512+40)//8),0)
                self.success(r.command(5,a));c.close_all()
            replay_one(c);report["observations"]["actual_ebadf_maps_busy"]=True
        def test_08_actual_result_deliberately_withheld_then_unknown_is_permanent(self):
            self.file()
            with self.carrier() as c:
                r=self.registry(c);token=self.open(c)
                code,h,_=r.start(2,value=token);self.assertEqual(code,1)
                completed=r.actual_reply();(self.case/"withheld-actual-ack.bin").write_bytes(completed)
                unknown=fixture.frame(7,session=r.session,call=h[4],action=h[5],handle=h[6],operation=h[7],lease=h[11])
                code,_,_=r.invoke(unknown);self.assertEqual(code,0xfffffffd)
                frozen=bytes(r.work);before=len(r.events)
                self.assertEqual(r.invoke(completed)[0],0xfffffffd)
                self.assertEqual(bytes(r.work),frozen);self.assertEqual(len(r.events),before)
                c.call(8,token);c.close_all()
            replay_one(c)
            report["observations"]["deliberate_unknown_after_real_reply_poisoned"]=True
            report["observations"]["unknown_control_is_not_claimed_actual_lost_syscall"]=True
        def test_09_seventeen_real_inodes_grow_without_fixed_row_quota(self):
            for i in range(17):self.file("item-"+str(i))
            with self.carrier() as c:
                r=self.registry(c);handles=[r.register(self.open(c,"item-"+str(i))) for i in range(17)]
                self.assertEqual(handles,list(range(1,18)));self.assertEqual(fixture.q(r.work,7),32)
                for handle in reversed(handles):self.success(r.command(5,handle))
                self.assertEqual(fixture.q(r.work,8),0);c.close_all()
            replay_one(c);report["observations"]["actual_dynamic_inode_growth"]=True
    try:
        suite=unittest.defaultTestLoader.loadTestsFromTestCase(Physical);ids=[t.id() for t in suite]
        assert 0<len(ids)==len(set(ids))==9
        with (out/"tests.stdout.log").open("w",encoding="utf-8") as stream:
            result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
        tests=dict(test_ids=ids,tests_loaded=len(ids),tests_run=result.testsRun,
            failures=[(t.id(),v) for t,v in result.failures],errors=[(t.id(),v) for t,v in result.errors],
            skipped=[(t.id(),v) for t,v in result.skipped],expected_failures=[(t.id(),v) for t,v in result.expectedFailures],
            unexpected_successes=[t.id() for t in result.unexpectedSuccesses])
        tests["passed"]=result.wasSuccessful() and result.testsRun==len(ids) and not any(tests[k] for k in (
            "failures","errors","skipped","expected_failures","unexpected_successes"))
        report["tests"]=tests;save(out/"tests.json",tests)
        assert tests["passed"]
        assert report["native_inode_entries"]==report["vm_inode_entries"]>0
        assert report["actual_provider_commands"]>0 and len(report["fs_replays"])==10
        report.update(status="PASS",fs_native_entries=sum(r["native_entries"] for r in report["fs_replays"]),
            fs_vm_entries=sum(r["vm_entries"] for r in report["fs_replays"]),
            fs_actual_primitive_acks=sum(r["actual_primitive_acks"] for r in report["fs_replays"]))
    except BaseException as error:
        report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc());traceback.print_exc()
    finally:
        image._mapping.close()
        after={str(p):dict(bytes=len(p.read_bytes()),mode=stat.S_IMODE(p.stat().st_mode),sha256=sha(p.read_bytes())) for p in map(Path,pins)}
        report.update(source_before=pins,source_after=after,source_pins_unchanged=after==pins)
        if after!=pins:report["status"]="FAIL"
        save(out/"summary.json",report)
        print(json.dumps({k:report[k] for k in ("status","scope","native_inode_entries","vm_inode_entries","actual_provider_commands",
            "source_pins_unchanged","fixed_namespace_coordinator_closed")},sort_keys=True),flush=True)
    return 0 if report["status"]=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
