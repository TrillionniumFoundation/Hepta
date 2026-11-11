"""Actual fixed three-image fencing process tests and complete retained-VM replay.

No Python callback routes namespace operations. Python owns test setup/oracles,
raw process transport, explicit strace fault controls, and the independent replay.
DMS128, root admission, migration and ordinary AgentStore remain open.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import argparse,ctypes,errno,fcntl,hashlib,importlib.util,json,os,select,shutil,signal,sqlite3,stat,struct,subprocess,time,traceback,unittest
from pathlib import Path
CLIENT_SHA="666936f0f00b7ce0758005c50ad49bf344bd24839989f5942ee19d7b41119362"
REPLAY_SHA="9f7c2bf8ffa4c666ecae9b784161fdff55b3844971f4397dec517056797d60c2"
MASK=(1<<64)-1
def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--context",type=Path,required=True)
    parser.add_argument("--client",type=Path,required=True)
    parser.add_argument("--replay",type=Path,required=True)
    args=parser.parse_args()
    assert sys.version_info[:3]==(3,12,14)
    pins={}
    def pin(path,expected=None):
        path=Path(path).resolve();info=path.lstat()
        assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
        raw=path.read_bytes();row=dict(bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(info.st_mode))
        if expected is not None:assert row["sha256"]==expected
        if str(path) in pins:assert pins[str(path)]==row
        pins[str(path)]=row
        return raw
    def module(name,path,expected=None):
        raw=pin(path,expected);spec=importlib.util.spec_from_file_location(name,path)
        value=importlib.util.module_from_spec(spec);sys.modules[name]=value
        exec(compile(raw,str(path),"exec"),value.__dict__);return value
    context=json.loads(pin(args.context));ref=Path(context["reference"])
    tree=Path(context["namespace_working"]);evidence=Path(context["namespace_evidence"])
    out=evidence/"carrier-native-r1";out.mkdir();(out/"source").mkdir();cas=out/"cas";cas.mkdir()
    built=json.loads(pin(evidence/"carrier-build-r1/summary.json"))
    assert built["status"]=="PASS_BUILD_ONLY" and built["source_pins_unchanged"]
    assert built["packer_entries"]==len(built["packer_controls"])==14
    executable=Path(built["executable"]["path"]);pin(executable,built["executable"]["sha256"])
    assert stat.S_IMODE(executable.stat().st_mode)==0o755
    sys.path.insert(0,str(ref))
    transport=module("namespace_fencing_actual_client",args.client,CLIENT_SHA)
    replayer=module("namespace_fencing_exact_replayer",args.replay,REPLAY_SHA)
    from hepta.hia_agent_assembly import assemble_program
    import hepta.hia_agent_assembly,hepta.hia_program_runtime
    assert Path(hepta.hia_agent_assembly.__file__).resolve()==ref/"hepta/hia_agent_assembly.py"
    assert Path(hepta.hia_program_runtime.__file__).resolve()==ref/"hepta/hia_program_runtime.py"
    programs={}
    for role in (1,2,3):
        row=built["exact_roles"][str(role)]
        source=pin(row["source"]["path"],row["source"]["sha256"])
        image=pin(row["image"]["path"],row["image"]["sha256"])
        assert len(image)==row["image"]["bytes"]
        programs[role]=assemble_program(source)
    pin(__file__)
    for value in tuple(sys.modules.values()):
        filename=getattr(value,"__file__",None)
        if filename:
            path=Path(filename).resolve()
            if path.is_relative_to(ref) and path.suffix==".py":pin(path)
    for number,(path,row) in enumerate(list(pins.items())):
        target=out/"source"/str(number)/Path(path).name;target.parent.mkdir(parents=True)
        target.write_bytes(Path(path).read_bytes());target.chmod(row["mode"])
    with sqlite3.connect(":memory:") as conn:
        sqlite_identity=dict(version=sqlite3.sqlite_version,
            source_id=conn.execute("select sqlite_source_id()").fetchone()[0],
            compile_options=[row[0] for row in conn.execute("pragma compile_options")])
    report=dict(status="INCOMPLETE",scope="ACTUAL_FIXED_FS_INODE_FENCING_ELF_COMPONENT",
        sqlite=sqlite_identity,legacy_sqlite3461_claimed=False,ordinary_store_closed=False,
        root_policy_closed=False,DMS_lifetime_closed=False,migration_closed=False,python_router_used=False,
        replay=[],observations={},source_before=pins)
    # Each raw primitive record is an observation, never a replacement syscall.
    def primitive_records(directory):
        raw=(directory/"trace.bin").read_bytes();at=0;events=[];pending=None
        while at<len(raw):
            h=struct.unpack_from("<8Q",raw,at);at+=64
            role=replayer.MAGICS[h[0]]
            if h[1]==1:at+=h[3]+h[4]+h[5]
            elif h[1]==2:
                output=raw[at:at+h[4]];at+=h[4]+h[5]
                if role==1 and h[6]==1:pending=struct.unpack_from("<32Q",output)
            elif h[1]==3:
                assert role==1 and pending is not None
                ack=raw[at:at+h[3]];at+=h[3]
                events.append(dict(operation=h[5],raw_return=h[6],raw_fd=pending[8],
                    arguments=list(pending[8:12]),ack_sha256=sha(ack),sequence=h[7]))
                pending=None
            else:assert h[1]==4
        assert at==len(raw)
        return events
    def replay_instance(directory,**kwargs):
        result=replayer.replay(directory,programs,**kwargs)
        report["replay"].append(result);return result
    def snapshot(root,label):
        rows=[]
        for path in [root,*sorted(root.rglob("*"))]:
            info=path.lstat();row=dict(path="." if path==root else path.relative_to(root).as_posix(),
                type=stat.S_IFMT(info.st_mode),mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid,
                device=info.st_dev,inode=info.st_ino,nlink=info.st_nlink,bytes=info.st_size)
            if stat.S_ISREG(info.st_mode):
                raw=path.read_bytes();digest=sha(raw);destination=cas/digest
                if not destination.exists():destination.write_bytes(raw)
                assert destination.read_bytes()==raw
                row.update(sha256=digest,content_bytes=len(raw),cas="cas/"+digest)
            elif stat.S_ISLNK(info.st_mode):row["target_hex"]=os.fsencode(os.readlink(path)).hex()
            rows.append(row)
        save(root.parent/(label+".json"),rows)
        return rows
    def flock(kind,offset=120,count=1):
        return struct.pack("<hh4xqqi4x",kind,os.SEEK_SET,offset,count,0)
    def query(fd,offset=120,count=1):
        return struct.unpack("<hh4xqqi4x",fcntl.fcntl(fd,fcntl.F_GETLK,flock(fcntl.F_WRLCK,offset,count)))
    def set_lock(fd,kind,offset=120,count=1):
        return fcntl.fcntl(fd,fcntl.F_SETLK,flock(kind,offset,count))
    parent_helper=out/"parent-helper.py"
    parent_helper.write_text(
        "import importlib.util,json,os,pathlib,sys,time\n"
        "spec=importlib.util.spec_from_file_location('transport',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)\n"
        "c=m.Carrier(sys.argv[2],sys.argv[3],sys.argv[4])\n"
        "h,_=c.call(1,a=os.O_RDWR|os.O_CREAT,b=0o600,body=b'held');handle=h[8]\n"
        "c.call(2,handle,a=2,count=1)\n"
        "p=pathlib.Path(sys.argv[5]);tmp=p.with_suffix('.tmp');tmp.write_text(json.dumps(dict(parent=os.getpid(),native=c.process.pid)));tmp.rename(p)\n"
        "while True:time.sleep(1)\n")
    pin(parent_helper)
    class ActualFencing(unittest.TestCase):
        def setUp(self):
            self.case=out/self._testMethodName;self.case.mkdir()
            self.fx=self.case/"fixture";self.fx.mkdir();self.created=0
            snapshot(self.fx,"before")
        def tearDown(self):
            rows=snapshot(self.fx,"after")
            # The public evidence sealer rejects live hardlinks. Keep each real
            # fixture inode and link relation intact in the isolated work tree,
            # after preserving every original byte and mode in CAS + metadata.
            retained=tree.parent/"retained-physical-fixtures-r1"/self._testMethodName
            retained.parent.mkdir(exist_ok=True)
            self.assertFalse(retained.exists())
            original=str(self.fx);self.fx.rename(retained)
            for row in rows:
                path=retained if row["path"]=="." else retained/row["path"]
                info=path.lstat()
                actual=dict(type=stat.S_IFMT(info.st_mode),mode=stat.S_IMODE(info.st_mode),
                    uid=info.st_uid,gid=info.st_gid,device=info.st_dev,inode=info.st_ino,
                    nlink=info.st_nlink,bytes=info.st_size)
                self.assertEqual(actual,{key:row[key] for key in actual})
                if stat.S_ISREG(info.st_mode):
                    raw=path.read_bytes();self.assertEqual(sha(raw),row["sha256"])
                    self.assertEqual(len(raw),row["content_bytes"])
                    self.assertEqual(raw,(cas/row["sha256"]).read_bytes())
                elif stat.S_ISLNK(info.st_mode):
                    self.assertEqual(os.fsencode(os.readlink(path)).hex(),row["target_hex"])
            save(self.case/"fixture-custody.json",dict(
                status="COMPLETE_CONTENT_AND_MODE_SNAPSHOT_LIVE_INODES_RETAINED",
                original_path=original,retained_path=str(retained),members=rows,
                original_bytes_modes_inode_links_verified_after_relocation=True,
                archived_representation="Full CAS bytes plus before/after type/mode/uid/gid/device/inode/nlink/size/target metadata; live hardlinks are retained outside the evidence output."))
        def carrier(self,**kwargs):
            self.created+=1
            return transport.Carrier(executable,self.case/("native-"+str(self.created)),self.fx,**kwargs)
        def opened(self,c,path=b"held",flags=None):
            if flags is None:flags=os.O_RDWR|os.O_CREAT|os.O_CLOEXEC
            h,_=c.call(1,a=flags,b=0o600,body=path);self.assertGreater(h[8],0);return h[8]
        def test_01_real_fixed_chain_fd_zero_maps_and_complete_cleanup(self):
            with self.carrier() as c:
                handle=self.opened(c)
                c.call(2,handle,a=2,count=1);c.call(3,handle,a=2,count=1)
                c.call(4,handle)
                maps,fds=c.snapshot_owned_process("quiescent")
                self.assertFalse(any("w" in line.split()[1] and "x" in line.split()[1] for line in maps.decode().splitlines()))
                self.assertFalse(any(row["target"]==str(self.fx/"held") for row in fds))
            actual=primitive_records(c.output)
            self.assertEqual([row["operation"] for row in actual],[1,15,17,17,8])
            self.assertEqual(actual[0]["raw_return"],0)
            replay_instance(c.output)
            report["observations"]["actual_fs_inode_coordinator_chain"]=True
            report["observations"]["actual_raw_fd_zero"]=True
            report["observations"]["no_writable_executable_maps"]=True
        def test_02_alias_retirement_preserves_lock_then_closes_lifo(self):
            path=self.fx/"held";path.write_bytes(b"native")
            os.link(path,self.fx/"alias")
            parent=os.open(path,os.O_RDWR)
            try:
                with self.carrier() as c:
                    a=self.opened(c);b=self.opened(c,b"alias");d=self.opened(c)
                    c.call(2,a,a=2,count=1)
                    self.assertEqual(query(parent)[0],fcntl.F_WRLCK);self.assertEqual(query(parent)[4],c.process.pid)
                    c.call(4,b);c.call(4,d)
                    self.assertEqual(query(parent)[4],c.process.pid)
                    prior=primitive_records(c.output)
                    self.assertFalse(any(r["operation"]==8 for r in prior))
                    c.call(3,a,a=2,count=1)
                    self.assertEqual(query(parent)[0],fcntl.F_UNLCK)
                    now=primitive_records(c.output)
                    opened=[r["raw_return"] for r in now if r["operation"]==1]
                    closed=[r["raw_fd"] for r in now if r["operation"]==8]
                    self.assertEqual(closed,list(reversed(opened[1:])))
                    c.call(4,a)
                replay_instance(c.output)
                report["observations"]["actual_deferred_alias_lifo_preserves_process_lock"]=True
            finally:os.close(parent)
        def test_03_shared_reference_counts_do_not_unlock_other_holder(self):
            path=self.fx/"held";path.write_bytes(b"x");parent=os.open(path,os.O_RDWR)
            try:
                with self.carrier() as c:
                    a=self.opened(c);b=self.opened(c)
                    c.call(2,a,a=1,count=1)
                    before=len(primitive_records(c.output))
                    c.call(2,b,a=1,count=1);c.call(3,a,a=1,count=1)
                    self.assertEqual(len(primitive_records(c.output)),before)
                    self.assertEqual(query(parent)[0],fcntl.F_RDLCK)
                    c.call(3,b,a=1,count=1)
                    self.assertEqual(query(parent)[0],fcntl.F_UNLCK)
                    c.call(4,a);c.call(4,b)
                replay_instance(c.output)
                report["observations"]["actual_shared_refcount"]=True
            finally:os.close(parent)
        def test_04_foreign_writer_busy_and_local_conflict_are_distinct(self):
            path=self.fx/"held";path.write_bytes(b"x");parent=os.open(path,os.O_RDWR)
            try:
                with self.carrier() as c:
                    a=self.opened(c);b=self.opened(c)
                    set_lock(parent,fcntl.F_WRLCK)
                    c.call(2,a,a=2,count=1,expect_code=5,expect_errno=errno.EAGAIN)
                    set_lock(parent,fcntl.F_UNLCK)
                    c.call(2,a,a=2,count=1)
                    before=len(primitive_records(c.output))
                    c.call(2,b,a=2,count=1,expect_code=5)
                    self.assertEqual(len(primitive_records(c.output)),before)
                    c.call(3,a,a=2,count=1);c.call(4,a);c.call(4,b)
                replay_instance(c.output)
                report["observations"]["actual_foreign_busy_then_success"]=True
                report["observations"]["local_busy_has_no_syscall"]=True
            finally:
                set_lock(parent,fcntl.F_UNLCK);os.close(parent)
        def test_05_two_actual_independent_native_coordinators_contend(self):
            with self.carrier(session=(1,2)) as a,self.carrier(session=(3,4)) as b:
                ha=self.opened(a);hb=self.opened(b)
                self.assertNotEqual(a.process.pid,b.process.pid)
                a.call(2,ha,a=2,count=1)
                b.call(2,hb,a=2,count=1,expect_code=5,expect_errno=errno.EAGAIN)
                a.call(3,ha,a=2,count=1)
                b.call(2,hb,a=2,count=1);b.call(3,hb,a=2,count=1)
                a.call(4,ha);b.call(4,hb)
            replay_instance(a.output);replay_instance(b.output)
            report["observations"]["two_actual_native_sessions"]=True
        def test_06_real_sqlite_wal_writer_both_directions(self):
            conn=sqlite3.connect(self.fx/"state.sqlite3",isolation_level=None,timeout=0)
            try:
                self.assertEqual(conn.execute("pragma journal_mode=wal").fetchone()[0],"wal")
                conn.execute("create table t(value)");conn.execute("begin immediate")
                with self.carrier() as c:
                    handle=self.opened(c,b"state.sqlite3-shm",flags=os.O_RDWR)
                    c.call(2,handle,a=2,count=1,expect_code=5,expect_errno=errno.EAGAIN)
                    conn.execute("rollback");c.call(2,handle,a=2,count=1)
                    with self.assertRaises(sqlite3.OperationalError) as caught:conn.execute("begin immediate")
                    self.assertEqual(caught.exception.sqlite_errorcode,sqlite3.SQLITE_BUSY)
                    c.call(3,handle,a=2,count=1)
                    conn.execute("begin immediate");conn.execute("commit")
                    c.call(4,handle)
                replay_instance(c.output)
                report["observations"]["actual_sqlite_writer_bidirectional"]=True
            finally:conn.close()
        def test_07_dynamic_registry_growth_has_no_fixed_row_quota(self):
            with self.carrier() as c:
                handles=[self.opened(c,("inode-"+str(i)).encode()) for i in range(17)]
                self.assertEqual(len(set(handles)),17)
                c.call(2,handles[-1],a=2,b=7,count=1);c.call(3,handles[-1],a=2,b=7,count=1)
                for handle in handles:c.call(4,handle)
            result=replay_instance(c.output)
            self.assertGreater(result["growth_by_role"]["1"],0)
            self.assertGreater(result["growth_by_role"]["2"],0)
            self.assertGreater(result["growth_by_role"]["3"],0)
            report["observations"]["actual_dynamic_all_three_growth"]=True
        def test_08_external_child_header_and_poison_do_not_call_a_peer(self):
            with self.carrier() as c:
                before=len(primitive_records(c.output))
                forged=struct.pack("<8Q",replayer.CHANNEL,2,1,0,256,256,512,1)+bytes(1024)
                h,_=c.request(forged,label="external-forged-child");self.assertEqual(h[1],0xfffffffd)
                raw=transport.frame(2,session=c.session,call=1,operation=1,a=os.O_RDWR|os.O_CREAT,b=0o600,lease=1,body=b"must-not-exist")
                h,_=c.request(raw,label="after-poison");self.assertEqual(h[1],0xfffffffd)
                self.assertEqual(len(primitive_records(c.output)),before)
                self.assertFalse((self.fx/"must-not-exist").exists())
            replay_instance(c.output)
            report["observations"]["external_bytes_cannot_issue_child_channel"]=True
        def test_09_truncated_transport_releases_actual_process_lock(self):
            path=self.fx/"held";path.write_bytes(b"x");parent=os.open(path,os.O_RDWR)
            try:
                c=self.carrier()
                try:
                    handle=self.opened(c);c.call(2,handle,a=2,count=1)
                    self.assertEqual(query(parent)[4],c.process.pid)
                    c._write(struct.pack("<Q",100)+b"x",time.monotonic()+30)
                    c.finish(111)
                    self.assertEqual(query(parent)[0],fcntl.F_UNLCK)
                    set_lock(parent,fcntl.F_WRLCK);set_lock(parent,fcntl.F_UNLCK)
                finally:
                    if not c.completed:c.abort()
                replay_instance(c.output,fatal_code=111)
                report["observations"]["transport_failure_releases_actual_locks"]=True
            finally:os.close(parent)
        def tracer(self,*inject):
            path=shutil.which("strace");self.assertIsNotNone(path,"actual injected syscall controls require installed strace")
            raw=pin(path)
            version=subprocess.run([path,"--version"],capture_output=True,timeout=20)
            self.assertEqual(version.returncode,0)
            (self.case/"strace-version.stdout").write_bytes(version.stdout)
            (self.case/"strace-version.stderr").write_bytes(version.stderr)
            log=self.case/"strace.log"
            save(self.case/"strace-pin.json",dict(path=path,bytes=len(raw),sha256=sha(raw),
                scope="EXPLICIT_ACTUAL_PTRACE_ERRNO_INJECTION_NOT_SPONTANEOUS_KERNEL_ERROR",injections=list(inject)))
            argv=[path,"-qq","-e","trace=fstat,close"]
            for directive in inject:argv+=["-e","inject="+directive]
            return [*argv,"-o",str(log)]
        def test_10_actual_injected_stat_failure_defers_orphan_close_under_lock(self):
            path=self.fx/"held";path.write_bytes(b"x");parent=os.open(path,os.O_RDWR)
            try:
                with self.carrier(launcher=self.tracer("fstat:error=EBADF:when=2")) as c:
                    handle=self.opened(c);c.call(2,handle,a=2,count=1)
                    initial=query(parent);self.assertEqual(initial[0],fcntl.F_WRLCK);self.assertGreater(initial[4],0)
                    h,_=c.call(1,a=os.O_RDWR,b=0o600,body=b"held",expect_code=1,expect_errno=errno.EBADF)
                    self.assertEqual(h[11],1)
                    self.assertEqual(query(parent),initial)
                    self.assertFalse(any(r["operation"]==8 for r in primitive_records(c.output)))
                    h,_=c.call(3,handle,a=2,count=1);self.assertEqual(h[11],0)
                    self.assertEqual(query(parent)[0],fcntl.F_UNLCK)
                    c.call(4,handle)
                text=(self.case/"strace.log").read_text();self.assertIn("INJECTED",text);self.assertIn("EBADF",text)
                replay_instance(c.output)
                report["observations"]["actual_injected_stat_orphan_preserves_held_lock"]=True
            finally:os.close(parent)
        def test_11_actual_injected_close_error_is_consumed_once(self):
            launcher=self.tracer("fstat:error=EBADF:when=1","close:error=EINTR:when=2")
            with self.carrier(launcher=launcher) as c:
                h,_=c.call(1,a=os.O_RDWR|os.O_CREAT,b=0o600,body=b"held",expect_code=1,expect_errno=errno.EBADF)
                self.assertEqual((h[10],h[11]),(errno.EINTR,0))
                prior=primitive_records(c.output)
                self.assertEqual([r["operation"] for r in prior],[1,15,8])
                self.assertEqual(prior[-1]["raw_return"],(-errno.EINTR)&MASK)
                handle=self.opened(c,b"next");c.call(4,handle)
                later=primitive_records(c.output)
                self.assertEqual(sum(r["operation"]==8 for r in later),2)
            replay_instance(c.output)
            report["observations"]["actual_injected_close_error_not_retried"]=True
        def test_12_parent_death_terminates_native_child_and_releases_lock(self):
            self.assertTrue(hasattr(os,"pidfd_open") and hasattr(signal,"pidfd_send_signal"))
            ready=self.case/"ready.json";native_dir=self.case/"native-parent";expected_parent=os.getpid()
            process=None;pidfd=None
            libc=ctypes.CDLL(None,use_errno=True);call=libc.prctl
            call.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong];call.restype=ctypes.c_int
            def parent_lifetime():
                if call(1,signal.SIGKILL,0,0,0):raise OSError(ctypes.get_errno(),"PR_SET_PDEATHSIG")
                if os.getppid()!=expected_parent:os.kill(os.getpid(),signal.SIGKILL)
            with (self.case/"parent.stdout").open("wb") as stdout,(self.case/"parent.stderr").open("wb") as stderr:
                try:
                    process=subprocess.Popen([sys.executable,"-I","-S","-B",str(parent_helper),str(args.client.resolve()),
                        str(executable),str(native_dir),str(self.fx),str(ready)],stdout=stdout,stderr=stderr,
                        stdin=subprocess.DEVNULL,start_new_session=True,preexec_fn=parent_lifetime)
                    deadline=time.monotonic()+30
                    while not ready.exists():
                        self.assertIsNone(process.poll(),"test parent exited before ready")
                        self.assertLess(time.monotonic(),deadline);time.sleep(0.02)
                    ids=json.loads(ready.read_bytes());self.assertEqual(ids["parent"],process.pid)
                    pidfd=os.pidfd_open(ids["native"])
                    raw=(Path("/proc")/str(ids["native"])/"stat").read_bytes()
                    (self.case/"native-proc-before.stat").write_bytes(raw)
                    fields=raw[raw.rfind(b")")+2:].split();self.assertEqual(int(fields[1]),process.pid)
                    os.killpg(process.pid,signal.SIGKILL)
                    self.assertEqual(process.wait(timeout=5),-signal.SIGKILL)
                    poller=select.poll();poller.register(pidfd,select.POLLIN);events=poller.poll(5000)
                    self.assertTrue(events,"native child survived actual parent death")
                    parent=os.open(self.fx/"held",os.O_RDWR)
                    try:self.assertEqual(query(parent)[0],fcntl.F_UNLCK)
                    finally:os.close(parent)
                    save(self.case/"death-observation.json",dict(status="OWNED_CHILD_DEATH_AND_UNLOCK_OBSERVED",
                        parent_pid=process.pid,native_pid=ids["native"],pidfd_events=events,
                        parent_returncode=process.returncode,native_exit_code="NOT_READ_NOT_OUR_CHILD"))
                finally:
                    if process is not None and process.returncode is None:
                        try:os.killpg(process.pid,signal.SIGKILL)
                        except ProcessLookupError:pass
                        process.wait()
                    if pidfd is not None:
                        try:signal.pidfd_send_signal(pidfd,signal.SIGKILL)
                        except ProcessLookupError:pass
                        os.close(pidfd)
            replay_instance(native_dir,signal_termination=True)
            report["observations"]["actual_parent_death_unlock"]=True
    try:
        suite=unittest.defaultTestLoader.loadTestsFromTestCase(ActualFencing)
        ids=[test.id() for test in suite];assert len(ids)==len(set(ids))==12
        with (out/"tests.stderr.log").open("w") as stream:
            result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
        tests=dict(test_ids=ids,tests_loaded=len(ids),tests_run=result.testsRun,
            failures=[(t.id(),v) for t,v in result.failures],errors=[(t.id(),v) for t,v in result.errors],
            skipped=[(t.id(),v) for t,v in result.skipped],expected_failures=[(t.id(),v) for t,v in result.expectedFailures],
            unexpected_successes=[t.id() for t in result.unexpectedSuccesses])
        report["tests"]=tests
        assert result.wasSuccessful() and 0<result.testsRun==12
        assert not any(tests[key] for key in ("failures","errors","skipped","expected_failures","unexpected_successes"))
        report.update(status="PASS",native_entries=sum(row["native_entries"] for row in report["replay"]),
            vm_entries=sum(row["vm_entries"] for row in report["replay"]),
            actual_primitive_acks=sum(row["actual_primitive_acks"] for row in report["replay"]),
            process_traces=len(report["replay"]),
            entries_by_role={str(role):sum(row["entries_by_role"][str(role)] for row in report["replay"]) for role in (1,2,3)},
            actual_child_reply_links=sum(len(row["exact_completed_child_links"]) for row in report["replay"]))
    except BaseException as error:
        report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
        if (out/"tests.stderr.log").exists():print((out/"tests.stderr.log").read_text(),file=sys.stderr,flush=True)
    finally:
        after={}
        for path in pins:
            raw=Path(path).read_bytes();after[path]=dict(bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(Path(path).stat().st_mode))
        report.update(source_before=pins,source_after=after,source_pins_unchanged=pins==after)
        if pins!=after:report["status"]="FAIL"
        save(out/"summary.json",report)
        print(json.dumps(dict(status=report["status"],tests_run=report.get("tests",{}).get("tests_run"),
            native_entries=report.get("native_entries"),actual_primitive_acks=report.get("actual_primitive_acks"),
            process_traces=len(report["replay"]),python_router_used=False,whole_store_closed=False)),flush=True)
    return 0 if report["status"]=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
