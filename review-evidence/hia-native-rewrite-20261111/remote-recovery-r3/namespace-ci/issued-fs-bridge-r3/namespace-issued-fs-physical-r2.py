"""New actual six-role DB inode / DMS / mapping / memory / FS physical gate.

Only HIA chooses policy and continuations. Python supplies explicit fixtures,
observes real other-process POSIX locks and SQLite conflicts, records all bytes,
then replays every actual HIA entry with the retained VM. This is a private
predecessor gate, not complete unixOpen, SQL migration or ordinary AgentStore.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import argparse,errno,fcntl,hashlib,importlib.util,json,os,re,shutil,sqlite3,stat,struct
import signal,subprocess,time,traceback,unittest
from pathlib import Path
CLIENT_SHA="e5cad29b23957856c3a3ae08645eb7a14a62f6b0263fe67720a9560b88e58270"
REPLAY_SHA="060fa3ae8da88e699b881ae5e59f1f49fb030e2f6b02b4082cf16ea3e0d91a6e"
INNER_SHA="ec3b3ce5f7d03b05c8fd4bf4ac17170cb75a3c47b6373ace8bf04b8d6ec8c30f"
EXPECTED_TESTS=42
MASK=(1<<64)-1
PENDING=1073741824
RESERVED=PENDING+1
SHARED=PENDING+2
def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")

# A POSIX record lock belongs to a process and inode, rather than to an fd.
# Opening/closing -shm in the SQLite-owning parent would release its locks.
# This independent observer never inherits a SQLite descriptor and returns the
# complete original bytes, plus two actual F_GETLK observations in its process.
SHM_READ_OBSERVER="""import ctypes,fcntl,hashlib,json,os,resource,struct,sys
parent=int(sys.argv[1])
libc=ctypes.CDLL(None,use_errno=True)
if libc.prctl(1,9,0,0,0):raise OSError(ctypes.get_errno(),'PR_SET_PDEATHSIG')
if os.getppid()!=parent:os._exit(125)
resource.setrlimit(resource.RLIMIT_CPU,(10,10))
resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
fd=os.open(sys.argv[2],os.O_RDONLY|os.O_CLOEXEC)
try:
 def query():
  raw=fcntl.fcntl(fd,fcntl.F_GETLK,struct.pack('<hh4xqqi4x',fcntl.F_WRLCK,os.SEEK_SET,128,1,0))
  return dict(words=list(struct.unpack('<hh4xqqi4x',raw)),raw_hex=raw.hex())
 before=query();st=os.fstat(fd);parts=[]
 while True:
  raw=os.read(fd,65536)
  if not raw:break
  parts.append(raw)
 data=b''.join(parts);after=query();st_after=os.fstat(fd)
 assert (st.st_dev,st.st_ino,st.st_size)==(st_after.st_dev,st_after.st_ino,st_after.st_size)
 assert len(data)==st.st_size
finally:os.close(fd)
report=dict(pid=os.getpid(),parent_pid=parent,device=st.st_dev,inode=st.st_ino,
 bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),before=before,after=after,
 limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),
 address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE))))
sys.stderr.write(json.dumps(report,sort_keys=True)+'\\n');sys.stderr.flush()
at=0
while at<len(data):
 count=os.write(1,data[at:]);assert count>0;at+=count
"""

def read_sqlite_shm_from_fresh_process(path,destination,label):
    destination=Path(destination);started=time.monotonic_ns();parent=os.getpid()
    command=[sys.executable,"-I","-S","-c",SHM_READ_OBSERVER,str(parent),str(path)]
    process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,close_fds=True,start_new_session=True,
        env=dict(PATH="",HOME="",LC_ALL="C",LANG="C"))
    stdout=stderr=b"";timed_out=False
    try:
        try:stdout,stderr=process.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            timed_out=True
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            stdout,stderr=process.communicate()
    finally:
        if process.poll() is None:
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            process.wait()
        if process.stdout is not None:process.stdout.close()
        if process.stderr is not None:process.stderr.close()
        # Reaping/closing occurs before evidence writes, including ENOSPC.
        (destination/(label+".stdout.bin")).write_bytes(stdout)
        (destination/(label+".stderr.log")).write_bytes(stderr)
        save(destination/(label+".process.json"),dict(pid=process.pid,parent_pid=parent,
            returncode=process.returncode,timed_out=timed_out,elapsed_ns=time.monotonic_ns()-started,
            wall_limit_seconds=20,observer_source_sha256=sha(SHM_READ_OBSERVER.encode()),
            stdout_bytes=len(stdout),stdout_sha256=sha(stdout),
            stderr_bytes=len(stderr),stderr_sha256=sha(stderr),HIA_entries=0))
    assert not timed_out and process.returncode==0,(process.returncode,stderr)
    report=json.loads(stderr)
    assert report["pid"]==process.pid and report["parent_pid"]==parent
    assert report["limits"]==dict(cpu=[10,10],address=[256<<20,256<<20],core=[0,0])
    assert report["bytes"]==len(stdout) and report["sha256"]==sha(stdout)
    assert report["before"]==report["after"]
    assert report["before"]["words"]==[fcntl.F_RDLCK,os.SEEK_SET,128,1,parent]
    return stdout
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--context",type=Path,required=True)
    parser.add_argument("--client",type=Path,required=True)
    parser.add_argument("--replay",type=Path,required=True)
    parser.add_argument("--inner-replay",type=Path,required=True)
    args=parser.parse_args()
    assert sys.version_info[:3]==(3,12,14)
    pins={}
    def pin(path,expected=None):
        path=Path(path).absolute();info=path.lstat()
        assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
        path=path.resolve();raw=path.read_bytes()
        row=dict(bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(info.st_mode))
        if expected is not None:assert row["sha256"]==expected,(str(path),row,expected)
        if str(path) in pins:assert pins[str(path)]==row
        pins[str(path)]=row;return raw
    def module(name,path,expected):
        raw=pin(path,expected);spec=importlib.util.spec_from_file_location(name,path)
        value=importlib.util.module_from_spec(spec);sys.modules[name]=value
        exec(compile(raw,str(path),"exec"),value.__dict__);return value
    context=json.loads(pin(args.context));ref=Path(context["reference"])
    evidence=Path(context["namespace_evidence"]);out=evidence/"db-join-native-r1"
    out.mkdir();(out/"source").mkdir();cas=out/"cas";cas.mkdir()
    fixtures=Path(context["namespace_fixtures"]).resolve()
    assert fixtures.is_relative_to(Path(context["base"]).resolve())
    assert not fixtures.is_relative_to(Path(context["output"]).resolve())
    fixtures.mkdir(parents=False,exist_ok=False)
    built=json.loads(pin(evidence/"db-join-build-r1/summary.json"))
    assert built["status"]=="PASS_BUILD_ONLY" and built["source_pins_unchanged"]
    assert built["fresh_role_compiles"]==6 and built["packer_entries"]==len(built["packer_controls"])==33
    executable=Path(built["executable"]["path"]);pin(executable,built["executable"]["sha256"])
    assert stat.S_IMODE(executable.stat().st_mode)==0o755
    sys.path.insert(0,str(ref))
    transport=module("namespace_db_join_actual_client",args.client,CLIENT_SHA)
    replayer=module("namespace_db_join_full_replayer",args.replay,REPLAY_SHA)
    inner=module("namespace_db_join_unchanged_inner_replayer",args.inner_replay,INNER_SHA)
    from hepta.hia_agent_assembly import assemble_program
    programs={}
    for role in (1,2,3,4,5,6):
        row=built["exact_roles"][str(role)]
        source=pin(row["source"]["path"],row["source"]["sha256"])
        image=pin(row["image"]["path"],row["image"]["sha256"])
        assert len(source)==row["source"]["bytes"] and len(image)==row["image"]["bytes"]
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
    report=dict(status="INCOMPLETE",scope="NEW_ACTUAL_FIXED_SIX_ROLE_DB_DMS_FS_PRIVATE_PREDECESSOR",
        sqlite=sqlite_identity,legacy_sqlite3461_claimed=False,ordinary_store_closed=False,
        full_sql31_closed=False,root_policy_closed=False,unixOpen_and_findReusableFd_closed=False,
        migration_closed=False,python_router_used=False,counts_inherited=False,
        actual_euid=os.geteuid(),actual_page=os.sysconf("SC_PAGE_SIZE"),
        fixture_capture="regular bytes CAS plus exact lstat metadata and hardlink topology; live fixtures outside archive",
        native_limits=transport.LIMITS,vm_steps_per_original_entry=4000000,vm_arena_bytes=32<<20,
        replay=[],process_limit_readbacks=[],observations={},source_before=pins)
    def trace_records(directory):
        path=Path(directory)/"trace.bin";size=path.stat().st_size;events=[];entries=[];pending={}
        with path.open("rb") as stream:
            def take(n):
                raw=stream.read(n);assert len(raw)==n;return raw
            while stream.tell()<size:
                h=struct.unpack("<12Q",take(96));role=replayer.MAGICS[h[0]]
                key=(role,h[9])
                if h[1]==1:take(h[3]);take(h[4]);take(h[5])
                elif h[1]==2:
                    output=take(h[4]);work=take(h[5])
                    entry=dict(role=role,node=h[8],context=h[9],serial=h[2],code=h[6],
                        output=output,work=work,trace_offset=stream.tell()-len(output)-len(work)-96)
                    entries.append(entry)
                    if role in (1,3) and h[6]==1:pending[key]=entry
                elif h[1]==3:
                    assert role in (1,3) and key in pending
                    e=pending.pop(key);ack=take(h[3]);words=struct.unpack_from("<32Q",e["output"])
                    events.append(dict(role=role,node=h[8],context=h[9],operation=h[5],raw_return=h[6],
                        syscall=h[4],sequence=h[7],event=list(words),event_sha256=sha(e["output"][:256]),
                        ack_sha256=sha(ack),arguments=list(words[8:12] if role==1 else words[9:15])))
                else:assert h[1]==4
            assert stream.tell()==size
        assert path.stat().st_size==size
        return events,entries
    def replay_instance(directory):
        directory=Path(directory);process=json.loads((directory/"process.json").read_bytes())
        assert process["limits"]==transport.LIMITS
        assert (process["limits"]["cpu_seconds"],process["limits"]["wall_seconds"])==(90,180)
        assert (process["limits"]["address_bytes"],process["limits"]["core_bytes"])==(1<<30,0)
        assert not process["wall_kill_sent"] and process["watchdog_error"] is None
        actual=process["actual_native_identity"];assert actual is not None
        assert actual["actual_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
        result=replayer.replay(directory,programs,inner)
        assert result["native_entries"]==result["vm_entries"]>0 and result["no_masks"]
        report["process_limit_readbacks"].append(dict(path=str(directory/"process.json"),
            sha256=sha((directory/"process.json").read_bytes()),native_pid=actual["pid"],
            limits=process["limits"],actual=actual["actual_limits"],
            wait_status=process["wait_status"],returncode=process["returncode"]))
        report["replay"].append(result)
        save(out/"summary.json",report)
        return result
    def snapshot(root,label,destination):
        rows=[]
        for path in [root,*sorted(root.rglob("*"))]:
            info=path.lstat();row=dict(path="." if path==root else path.relative_to(root).as_posix(),
                type=stat.S_IFMT(info.st_mode),mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid,
                device=info.st_dev,inode=info.st_ino,nlink=info.st_nlink,bytes=info.st_size)
            if stat.S_ISREG(info.st_mode):
                raw=path.read_bytes();digest=sha(raw);target=cas/digest
                if not target.exists():target.write_bytes(raw)
                assert target.read_bytes()==raw
                row.update(sha256=digest,content_bytes=len(raw),cas="cas/"+digest)
            elif stat.S_ISLNK(info.st_mode):row["target_hex"]=os.fsencode(os.readlink(path)).hex()
            rows.append(row)
        save(destination/(label+".json"),rows)
    def lock_bytes(kind,offset,count):
        return struct.pack("<hh4xqqi4x",kind,os.SEEK_SET,offset,count,0)
    def query(fd,offset=SHARED,count=510):
        return struct.unpack("<hh4xqqi4x",fcntl.fcntl(fd,fcntl.F_GETLK,
            lock_bytes(fcntl.F_WRLCK,offset,count)))
    def lock(fd,kind,offset,count):
        return fcntl.fcntl(fd,fcntl.F_SETLK,lock_bytes(kind,offset,count))
    def fs_events(directory,op=None):
        return [e for e in trace_records(directory)[0] if e["role"]==1 and (op is None or e["operation"]==op)]
    def syscall_ordinal(path,name,predicate,*,last=False):
        raw=path.read_bytes();count=0;matches=[]
        for line in raw.decode().splitlines():
            if re.match(r"^"+re.escape(name)+r"\(",line):
                count+=1
                if predicate(line):matches.append((count,line))
        assert matches,(name,raw)
        ordinal,line=matches[-1 if last else 0]
        return dict(syscall=name,ordinal=ordinal,line=line,source_bytes=len(raw),source_sha256=sha(raw))
    def read_owned_mapping(carrier,address,size,label):
        assert 0<=address<=MASK and 0<=size<=32768
        p=Path("/proc")/str(carrier.owned_native_pid())
        raw=(p/"maps").read_bytes();(carrier.output/(label+".maps")).write_bytes(raw)
        matches=[]
        for line in raw.decode().splitlines():
            fields=line.split();first,last=(int(v,16) for v in fields[0].split("-"))
            if first<=address and address+size<=last:matches.append(fields)
        assert len(matches)==1 and "r" in matches[0][1]
        descriptor=os.open(p/"mem",os.O_RDONLY|os.O_CLOEXEC)
        try:content=os.pread(descriptor,size,address)
        finally:os.close(descriptor)
        assert len(content)==size;(carrier.output/(label+".bin")).write_bytes(content)
        return content
    class ActualJoin(unittest.TestCase):
        def setUp(self):
            self.case=out/self._testMethodName;self.case.mkdir()
            self.fx=fixtures/self._testMethodName;self.fx.mkdir();self.created=0
            snapshot(self.fx,"before",self.case)
        def tearDown(self):snapshot(self.fx,"after",self.case)
        def carrier(self,**kwargs):
            self.created+=1
            return transport.Carrier(executable,self.case/("native-"+str(self.created)),self.fx,**kwargs)
        def database(self,name="db",content=b"namespace-main-db-physical"):
            path=self.fx/name;path.write_bytes(content);return path
        def open_token(self,c,path,readonly=False):
            result,_=c.filesystem(1,b=(os.O_RDONLY if readonly else os.O_RDWR)|os.O_CLOEXEC,
                c=0o600,body=os.fsencode(path))
            self.assertGreater(result[8],0);return result[8]
        def register(self,c,path,readonly=False,unix_excl=False):
            token=self.open_token(c,path,readonly)
            before=len(fs_events(c.output,15))
            header,row=c.database(3,token=token,flags=int(readonly)+2*int(unix_excl))
            self.assertEqual(len(fs_events(c.output,15))-before,1)
            info=path.stat();self.assertEqual(header[20:22],(info.st_dev,info.st_ino))
            self.assertGreater(header[14],0);self.assertGreater(row[10],0)
            self.assertGreater(header[25],0)
            return token,header[14],header,row
        def check_lock(self,c,fd,kind,offset=SHARED,count=510):
            result=query(fd,offset,count);self.assertEqual(result[0],kind)
            if kind!=fcntl.F_UNLCK:self.assertEqual(result[4],c.owned_native_pid())
            save(self.case/("observation-"+str(len(report["observations"]))+".json"),
                dict(actual_query=list(result),native_pid=c.owned_native_pid(),offset=offset,count=count))
            report["observations"][self.id()+":"+str(len(report["observations"]))]=list(result)
        def dms(self,c,command,handle,*,a=0,b=0,d=0,expect_code=0,expect_errno=0):
            _,payload=c.call(9,handle,a=command,b=a,c=b,d=d,expect_code=expect_code,expect_errno=expect_errno)
            self.assertGreaterEqual(len(payload),256)
            h=struct.unpack_from("<32Q",payload)
            self.assertEqual(h[0],int.from_bytes(b"HIANDM03","little"))
            self.assertEqual((h[1],h[6],h[7]),(0,expect_code,expect_errno))
            return h
        def attach(self,c,path,handle):
            _,payload=c.call(8,handle,body=os.fsencode(path))
            h=struct.unpack_from("<32Q",payload)
            self.assertEqual((h[0],h[1],h[6],h[7]),
                (int.from_bytes(b"HIANDM03","little"),0,0,0))
            self.assertGreater(h[8],0);return h
        def tracer(self,label,inject=None):
            path=self.case/(label+".strace");binary=shutil.which("strace")
            self.assertIsNotNone(binary,"mandatory actual strace; no skip fallback")
            command=[binary,"-qq","-s","256","-o",str(path),
                "-e","trace=fcntl,fstat,ftruncate,mmap,munmap,close,openat,pwrite64"]
            if inject:command.extend(["-e",inject])
            return command,path

        def test_01_exact_one_fstat_fd_zero_and_actual_retirement(self):
            path=self.database()
            with self.carrier() as c:
                self.assertEqual(fs_events(c.output),[])
                token=self.open_token(c,path)
                self.assertEqual(fs_events(c.output,1)[0]["raw_return"],0)
                read,raw=c.filesystem(2,a=token,b=len(path.read_bytes()),c=0)
                self.assertEqual(raw,path.read_bytes());self.assertEqual(read[8],len(raw))
                header,row=c.database(3,token=token)
                self.assertEqual(len(fs_events(c.output,15)),1)
                info=path.stat();self.assertEqual(header[20:22],(info.st_dev,info.st_ino))
                self.assertEqual(row[12:16],(1,0,0,0))
                close,result=c.database(7,header[14])
                self.assertEqual(result[24],4);self.assertEqual(result[12:16],(0,0,0,0))
                maps,fds=c.snapshot_owned_process("after-retire")
                self.assertFalse(any(x["target"]==str(path) for x in fds))
                self.assertFalse(any("w" in line.split()[1] and "x" in line.split()[1]
                    for line in maps.decode().splitlines()))
                self.assertGreater(close[24],0)
            replay=replay_instance(c.output)
            self.assertEqual(len(replay["actual_DB_context_retirements"]),1)
            self.assertEqual(replay["entries_by_role"]["2"],0)
            self.assertEqual(replay["entries_by_role"]["3"],0)
            self.assertEqual(path.read_bytes(),b"namespace-main-db-physical")

        def test_02_local_shared_shortcut_and_LIFO_deferred_close(self):
            path=self.database();parent=os.open(path,os.O_RDWR|os.O_CLOEXEC)
            try:
                with self.carrier() as c:
                    ta,a,ha,_=self.register(c,path)
                    tb,b,hb,_=self.register(c,path)
                    tc,d,hd,_=self.register(c,path)
                    self.assertEqual(ha[25],hb[25]);self.assertEqual(ha[25],hd[25])
                    actual_fds=[x["raw_return"] for x in fs_events(c.output,1)]
                    c.database(4,a,target=1);before=len(fs_events(c.output,17))
                    _,result=c.database(4,b,target=1)
                    self.assertEqual(result[12:16],(3,2,2,1))
                    self.assertEqual(len(fs_events(c.output,17)),before)
                    self.check_lock(c,parent,fcntl.F_RDLCK)
                    before_close=len(fs_events(c.output,8))
                    c.database(7,b);c.database(7,d)
                    self.assertEqual(len(fs_events(c.output,8)),before_close)
                    self.check_lock(c,parent,fcntl.F_RDLCK)
                    c.database(5,a,target=0)
                    closed=[x["arguments"][0] for x in fs_events(c.output,8)]
                    self.assertEqual(closed,[actual_fds[2],actual_fds[1]])
                    self.check_lock(c,parent,fcntl.F_UNLCK)
                    c.database(7,a)
                    self.assertEqual([x["arguments"][0] for x in fs_events(c.output,8)],
                        [actual_fds[2],actual_fds[1],actual_fds[0]])
                replay_instance(c.output)
            finally:os.close(parent)

        def test_03_reserved_pending_busy_then_explicit_retry(self):
            path=self.database();parent=os.open(path,os.O_RDWR|os.O_CLOEXEC)
            try:
                with self.carrier() as c:
                    _,a,_,_=self.register(c,path);_,b,_,_=self.register(c,path)
                    _,d,_,_=self.register(c,path)
                    c.database(4,a,target=1);c.database(4,b,target=1);c.database(4,a,target=2)
                    _,busy=c.database(4,a,target=4,expect_code=5)
                    self.assertEqual(busy[15],3)
                    self.check_lock(c,parent,fcntl.F_WRLCK,PENDING,1)
                    c.database(4,d,target=1,expect_code=5)
                    c.database(7,b);c.database(7,d)
                    c.database(4,a,target=4)
                    self.check_lock(c,parent,fcntl.F_WRLCK)
                    c.database(5,a,target=1)
                    self.check_lock(c,parent,fcntl.F_RDLCK)
                    self.check_lock(c,parent,fcntl.F_UNLCK,PENDING,2)
                    c.database(7,a);self.check_lock(c,parent,fcntl.F_UNLCK)
                replay_instance(c.output)
            finally:os.close(parent)

        def test_04_foreign_shared_conflict_releases_temporary_pending(self):
            path=self.database();parent=os.open(path,os.O_RDWR|os.O_CLOEXEC)
            try:
                lock(parent,fcntl.F_WRLCK,SHARED,510)
                with self.carrier() as c:
                    _,handle,_,_=self.register(c,path)
                    c.database(4,handle,target=1,expect_code=5,expect_errno=errno.EAGAIN)
                    self.check_lock(c,parent,fcntl.F_UNLCK,PENDING,1)
                    events=fs_events(c.output,17)
                    self.assertEqual(len(events),3)
                    self.assertEqual(events[-1]["arguments"][1:],[2,PENDING,1])
                    lock(parent,fcntl.F_UNLCK,SHARED,510)
                    c.database(4,handle,target=1)
                    self.check_lock(c,parent,fcntl.F_RDLCK)
                    c.database(7,handle);self.check_lock(c,parent,fcntl.F_UNLCK)
                replay_instance(c.output)
            finally:os.close(parent)

        def test_05_foreign_GETLK_and_local_reserved_shortcut(self):
            path=self.database();parent=os.open(path,os.O_RDWR|os.O_CLOEXEC)
            try:
                with self.carrier() as c:
                    _,a,_,_=self.register(c,path);_,b,_,_=self.register(c,path)
                    lock(parent,fcntl.F_WRLCK,RESERVED,1)
                    _,held=c.database(6,a);self.assertEqual(held[10],1)
                    self.assertEqual(len(fs_events(c.output,23)),1)
                    lock(parent,fcntl.F_UNLCK,RESERVED,1)
                    _,free=c.database(6,a);self.assertEqual(free[10],0)
                    c.database(4,a,target=1);c.database(4,a,target=2)
                    before=len(fs_events(c.output,23))
                    _,held=c.database(6,b);self.assertEqual(held[10],1)
                    self.assertEqual(len(fs_events(c.output,23)),before)
                    c.database(7,b);c.database(7,a)
                replay_instance(c.output)
            finally:os.close(parent)

        def test_06_unix_excl_process_lock_survives_logical_unlock(self):
            path=self.database();parent=os.open(path,os.O_RDWR|os.O_CLOEXEC)
            try:
                with self.carrier() as c:
                    _,a,_,_=self.register(c,path,unix_excl=True)
                    _,b,_,_=self.register(c,path,unix_excl=True)
                    c.database(4,a,target=1);c.database(4,b,target=1)
                    self.check_lock(c,parent,fcntl.F_WRLCK)
                    c.database(5,a,target=0)
                    _,state=c.database(5,b,target=0)
                    self.assertEqual(state[25],1);self.assertEqual(state[14],1)
                    self.check_lock(c,parent,fcntl.F_WRLCK)
                    c.database(7,a);self.check_lock(c,parent,fcntl.F_WRLCK)
                    c.database(7,b);self.check_lock(c,parent,fcntl.F_UNLCK)
                events=fs_events(c.output,17)
                self.assertEqual(len(events),1)
                self.assertEqual(events[0]["arguments"][1:],[1,SHARED,510])
                replay_instance(c.output)
            finally:os.close(parent)

        def test_07_actual_hardlink_alias_and_distinct_inode_contexts(self):
            path=self.database();alias=self.fx/"hardlink";os.link(path,alias)
            other=self.database("other");p1=os.open(path,os.O_RDWR);p2=os.open(other,os.O_RDWR)
            try:
                with self.carrier() as c:
                    _,a,ha,_=self.register(c,path);_,b,hb,_=self.register(c,alias)
                    _,d,hd,_=self.register(c,other)
                    self.assertEqual(ha[20:22],hb[20:22]);self.assertEqual(ha[25],hb[25])
                    self.assertNotEqual(ha[20:22],hd[20:22]);self.assertNotEqual(ha[25],hd[25])
                    c.database(4,a,target=1);c.database(4,d,target=1)
                    self.check_lock(c,p1,fcntl.F_RDLCK);self.check_lock(c,p2,fcntl.F_RDLCK)
                    c.database(7,b);self.check_lock(c,p1,fcntl.F_RDLCK)
                    c.database(7,a);self.check_lock(c,p1,fcntl.F_UNLCK)
                    self.check_lock(c,p2,fcntl.F_RDLCK);c.database(7,d)
                    self.check_lock(c,p2,fcntl.F_UNLCK)
                result=replay_instance(c.output)
                self.assertEqual(len(result["actual_DB_context_retirements"]),2)
            finally:os.close(p1);os.close(p2)

        def test_08_readonly_actual_write_lock_errno_preserved(self):
            path=self.database()
            with self.carrier() as c:
                _,handle,_,_=self.register(c,path,readonly=True)
                c.database(4,handle,target=1)
                _,failed=c.database(4,handle,target=4,expect_code=3850,expect_errno=errno.EBADF)
                self.assertEqual(failed[8:10],(3850,errno.EBADF))
                c.database(7,handle)
            failed=[x for x in fs_events(c.output,17) if x["raw_return"]==(-errno.EBADF)&MASK]
            self.assertEqual(len(failed),1)
            replay_instance(c.output)

        def test_09_registered_token_raw_close_bypass_is_permanently_refused(self):
            path=self.database()
            with self.carrier() as c:
                token,_,_,_=self.register(c,path)
                before=len(fs_events(c.output))
                raw=transport.frame(2,session=c.session,call=c.call_number+1,
                    lease=1000+c.call_number+1,a=8,b=token)
                header,_=c.request(raw,label="forbidden-registered-close")
                self.assertEqual(header[1],0xfffffffd)
                header,_=c.request(transport.frame(1,session=c.session,a=171,b=183),
                    label="after-persistent-refusal")
                self.assertEqual(header[1],0xfffffffd)
                self.assertEqual(len(fs_events(c.output)),before)
                _,fds=c.snapshot_owned_process("poison-still-owned-before-exit")
                self.assertTrue(any(row["target"]==str(path) for row in fds))
            result=replay_instance(c.output)
            self.assertEqual(result["actual_DB_context_retirements"],[])
            report["observations"]["poison_exit_cleanup_not_ordinary_retirement"]=True

        def test_10_actual_DMS_map_barrier_and_detach_precede_DB_close(self):
            path=self.database()
            with self.carrier() as c:
                _,handle,_,_=self.register(c,path)
                self.attach(c,path,handle)
                a=self.dms(c,14,handle,a=0,b=1,d=32768)
                self.assertGreater(a[23],0)
                self.dms(c,15,handle)
                fd=os.open(str(path)+"-shm",os.O_RDWR)
                try:self.assertEqual(os.pwrite(fd,b"actual-shared-view",0),18)
                finally:os.close(fd)
                events=trace_records(c.output)[0]
                maps=[x for x in events if x["role"]==3 and x["operation"]==1
                    and x["arguments"][1]==32768 and x["arguments"][3]==1
                    and x["arguments"][5]==0 and x["raw_return"]<MASK-4094]
                self.assertTrue(maps)
                self.assertEqual(read_owned_mapping(c,maps[-1]["raw_return"],18,"actual-shared-view"),
                    b"actual-shared-view")
                actual_dbfd=fs_events(c.output,1)[0]["raw_return"]
                c.database(7,handle)
                events=trace_records(c.output)[0]
                unmaps=[i for i,x in enumerate(events) if x["role"]==3 and x["operation"]==3]
                closes=[i for i,x in enumerate(events) if x["role"]==1 and x["operation"]==8
                    and x["arguments"][0]==actual_dbfd]
                self.assertTrue(unmaps);self.assertEqual(len(closes),1)
                self.assertLess(max(unmaps),closes[0])
            result=replay_instance(c.output)
            self.assertGreater(result["entries_by_role"]["2"],0)
            self.assertGreater(result["entries_by_role"]["3"],0)
            self.assertEqual(len(result["actual_DB_context_retirements"]),1)
            self.assertEqual(len(result["unchanged_inner_replayer"]["exact_retirements"]),1)

        def test_11_actual_SQLite_DELETE_writer_and_main_DB_locks(self):
            path=self.fx/"database.sqlite";conn=sqlite3.connect(path,timeout=0,isolation_level=None)
            try:
                self.assertEqual(conn.execute("pragma journal_mode=delete").fetchone()[0],"delete")
                conn.execute("create table retained(x)");conn.execute("insert into retained values(7)")
                with self.carrier() as c:
                    _,handle,_,_=self.register(c,path)
                    c.database(4,handle,target=1)
                    with self.assertRaises(sqlite3.OperationalError) as caught:conn.execute("begin exclusive")
                    self.assertEqual(caught.exception.sqlite_errorcode,sqlite3.SQLITE_BUSY)
                    c.database(5,handle,target=0)
                    conn.execute("begin immediate")
                    _,reserved=c.database(6,handle);self.assertEqual(reserved[10],1)
                    conn.execute("rollback")
                    c.database(4,handle,target=1);c.database(4,handle,target=2)
                    with self.assertRaises(sqlite3.OperationalError) as caught:conn.execute("begin immediate")
                    self.assertEqual(caught.exception.sqlite_errorcode,sqlite3.SQLITE_BUSY)
                    c.database(5,handle,target=0)
                    conn.execute("begin immediate");conn.execute("rollback")
                    c.database(7,handle)
                self.assertEqual(conn.execute("select * from retained").fetchall(),[(7,)])
                replay_instance(c.output)
                report["observations"]["actual_SQLite_DELETE_conflict_both_directions"]=True
            finally:conn.close()

        def test_12_actual_SQLite_WAL_writer_shared_namespace_lifecycle(self):
            path=self.fx/"database.sqlite";conn=sqlite3.connect(path,timeout=0,isolation_level=None)
            try:
                self.assertEqual(conn.execute("pragma journal_mode=wal").fetchone()[0],"wal")
                conn.execute("create table retained(x)");conn.execute("insert into retained values(9)")
                conn.execute("begin immediate")
                before=read_sqlite_shm_from_fresh_process(Path(str(path)+"-shm"),self.case,"sqlite-before-observer")
                (self.case/"sqlite-before-shm.bin").write_bytes(before)
                with self.carrier() as c:
                    _,handle,_,_=self.register(c,path);c.database(4,handle,target=1)
                    self.attach(c,path,handle)
                    after=read_sqlite_shm_from_fresh_process(Path(str(path)+"-shm"),self.case,"sqlite-after-attach-observer")
                    (self.case/"sqlite-after-attach-shm.bin").write_bytes(after)
                    self.assertEqual(after,before)
                    self.dms(c,14,handle,a=0,b=0,d=32768)
                    self.dms(c,4,handle,a=2,b=0,d=1,expect_code=5,expect_errno=errno.EAGAIN)
                    conn.execute("commit")
                    self.dms(c,4,handle,a=2,b=0,d=1)
                    with self.assertRaises(sqlite3.OperationalError) as caught:conn.execute("begin immediate")
                    self.assertEqual(caught.exception.sqlite_errorcode,sqlite3.SQLITE_BUSY)
                    self.dms(c,5,handle,a=2,b=0,d=1)
                    conn.execute("begin immediate");conn.execute("rollback")
                    c.database(7,handle)
                self.assertEqual(conn.execute("select * from retained").fetchall(),[(9,)])
                replay_instance(c.output)
                report["observations"]["actual_SQLite_WAL_conflict_both_directions"]=True
            finally:conn.close()

        def test_13_actual_FSTAT_fault_before_inode_commit(self):
            path=self.database()
            launcher,baseline=self.tracer("baseline")
            with self.carrier(launcher=launcher) as c:
                _,handle,_,_=self.register(c,path);c.database(7,handle)
            replay_instance(c.output)
            selected=syscall_ordinal(baseline,"fstat",lambda line:True)
            save(self.case/"selected-fstat.json",selected)
            launcher,log=self.tracer("fault",f"inject=fstat:error=EIO:when={selected['ordinal']}")
            with self.carrier(launcher=launcher) as failed:
                token=self.open_token(failed,path)
                header,row=failed.database(3,token=token,expect_code=10,expect_errno=errno.EIO)
                self.assertIsNone(row);self.assertEqual(header[20:22],(0,0))
                failed.filesystem(8,a=token)
            self.assertIn("INJECTED",log.read_text())
            errors=[e for e in fs_events(failed.output,15) if e["raw_return"]==(-errno.EIO)&MASK]
            self.assertEqual(len(errors),1)
            result=replay_instance(failed.output)
            self.assertEqual(result["entries_by_role"]["5"],0)
            self.assertEqual(result["actual_DB_context_retirements"],[])

        def test_14_actual_fcntl_EINTR_is_known_busy_without_implicit_retry(self):
            path=self.database();launcher,baseline=self.tracer("baseline")
            with self.carrier(launcher=launcher) as c:
                _,handle,_,_=self.register(c,path);c.database(4,handle,target=1);c.database(7,handle)
            replay_instance(c.output)
            selected=syscall_ordinal(baseline,"fcntl",
                lambda line:"F_SETLK" in line and "F_RDLCK" in line and f"l_start={PENDING}," in line)
            save(self.case/"selected-fcntl.json",selected)
            launcher,log=self.tracer("fault",f"inject=fcntl:error=EINTR:when={selected['ordinal']}")
            with self.carrier(launcher=launcher) as failed:
                _,handle,_,_=self.register(failed,path)
                before=len(fs_events(failed.output,17))
                failed.database(4,handle,target=1,expect_code=5,expect_errno=errno.EINTR)
                after=fs_events(failed.output,17)
                self.assertEqual(len(after)-before,1)
                self.assertEqual(after[-1]["raw_return"],(-errno.EINTR)&MASK)
                failed.database(4,handle,target=1);failed.database(7,handle)
            self.assertIn("INJECTED",log.read_text());replay_instance(failed.output)

        def test_15_actual_GETLK_failure_retains_error_and_later_call_is_usable(self):
            path=self.database();launcher,baseline=self.tracer("baseline")
            with self.carrier(launcher=launcher) as c:
                _,handle,_,_=self.register(c,path)
                _,state=c.database(6,handle);self.assertEqual(state[10],0);c.database(7,handle)
            replay_instance(c.output)
            selected=syscall_ordinal(baseline,"fcntl",
                lambda line:"F_GETLK" in line and f"l_start={RESERVED}," in line)
            save(self.case/"selected-getlk.json",selected)
            launcher,log=self.tracer("fault",f"inject=fcntl:error=EIO:when={selected['ordinal']}")
            with self.carrier(launcher=launcher) as failed:
                _,handle,_,_=self.register(failed,path)
                _,state=failed.database(6,handle,expect_code=3594,expect_errno=errno.EIO)
                self.assertEqual(state[10],0)
                _,state=failed.database(6,handle);self.assertEqual(state[10],0)
                failed.database(7,handle)
            self.assertIn("INJECTED",log.read_text())
            errors=[e for e in fs_events(failed.output,23) if e["raw_return"]==(-errno.EIO)&MASK]
            self.assertEqual(len(errors),1);replay_instance(failed.output)

        def test_16_actual_close_EINTR_is_not_retried_and_kernel_exit_scope_is_explicit(self):
            path=self.database();launcher,baseline=self.tracer("baseline")
            with self.carrier(launcher=launcher) as c:
                _,handle,_,_=self.register(c,path)
                actual_fd=fs_events(c.output,1)[0]["raw_return"]
                c.database(7,handle)
            replay_instance(c.output)
            selected=syscall_ordinal(baseline,"close",
                lambda line:line.startswith(f"close({actual_fd})"),last=True)
            save(self.case/"selected-close.json",selected)
            launcher,log=self.tracer("fault",f"inject=close:error=EINTR:when={selected['ordinal']}")
            with self.carrier(launcher=launcher) as failed:
                _,handle,_,_=self.register(failed,path)
                _,state=failed.database(7,handle)
                self.assertEqual(state[20],errno.EINTR)
                self.assertEqual(state[24],4)
                errors=[e for e in fs_events(failed.output,8) if e["raw_return"]==(-errno.EINTR)&MASK]
                self.assertEqual(len(errors),1)
                self.assertEqual(len(fs_events(failed.output,8)),1)
                _,descriptors=failed.snapshot_owned_process("injected-close-not-executed")
                # strace deliberately suppresses the actual close. The HIA
                # ownership token is retired once, and the OS fd survives
                # until process exit; this is not an ordinary-success claim.
                self.assertTrue(any(row["target"]==str(path) for row in descriptors))
            self.assertIn("INJECTED",log.read_text())
            result=replay_instance(failed.output)
            self.assertEqual(len(result["actual_DB_context_retirements"]),1)
            report["observations"]["injected_close_EINTR_no_retry_original_ignored_error_retained"]=True

        def test_17_dynamic_inode_index_and_more_than_initial_DB_row_capacity(self):
            paths=[self.database("inode-"+str(i)) for i in range(9)]
            with self.carrier() as c:
                handles=[];generations=[]
                for path in paths:
                    _,handle,h,_=self.register(c,path)
                    handles.append(handle);generations.append(h[25])
                self.assertEqual(len(set(generations)),9)
                for _ in range(16):
                    _,handle,h,_=self.register(c,paths[0])
                    self.assertEqual(h[25],generations[0]);handles.append(handle)
                self.assertEqual(len(handles),25);self.assertEqual(len(set(handles)),25)
                self.assertEqual(len(fs_events(c.output,15)),25)
                for handle in handles:c.database(7,handle)
                _,fds=c.snapshot_owned_process("all-dynamic-contexts-retired")
                names=set(map(str,paths))
                self.assertFalse(any(row["target"] in names for row in fds))
            result=replay_instance(c.output)
            self.assertEqual(len(result["actual_DB_context_retirements"]),9)
            self.assertGreater(result["outer_DB_growth"]["5"],0)
            self.assertGreater(result["outer_DB_growth"]["6"],0)
            nodes=[row for row in result["outer_db_contexts"] if row["role"]==5]
            self.assertEqual(len(nodes),9);self.assertTrue(all(row["retired"] for row in nodes))
            self.assertEqual(len(fs_events(c.output,8)),25)

        def test_18_reserved_header_persistent_refusal_and_abort_cleanup_faults(self):
            with self.carrier() as c:
                raw=bytearray(transport.frame(2,session=c.session,call=1,lease=1001,a=16))
                struct.pack_into("<Q",raw,248,1)
                h,_=c.request(raw,label="reserved-header");self.assertEqual(h[1],0xfffffffd)
                h,_=c.request(transport.frame(1,session=c.session,a=171,b=183),label="after-poison")
                self.assertEqual(h[1],0xfffffffd)
            self.assertEqual(fs_events(c.output),[]);replay_instance(c.output)
            # These are separate non-native fault controls for the exact r4
            # cleanup implementation, not additional native process counts.
            controls=[]
            for label in ("evidence","watchdog-and-evidence","reap-and-evidence"):
                closed=[]
                class Stream:
                    def __init__(self,name):self.name=name;self.closed=False
                    def close(self):self.closed=True;closed.append(self.name)
                class Process:
                    stdin=Stream("stdin");stdout=Stream("stdout")
                obj=object.__new__(transport.Carrier)
                obj.output=self.case/("cleanup-"+label);obj.process=Process()
                obj._ready_read,obj._ready_write=os.pipe2(os.O_CLOEXEC)
                descriptors=(obj._ready_read,obj._ready_write)
                obj.trace_file=Stream("trace");obj.native_identity=None
                obj._watchdog_fired=False;obj._wall_kill_sent=False;obj._watchdog_error=None
                primary=RuntimeError("controlled-"+label)
                evidence_error=OSError(errno.ENOSPC,"controlled evidence write failure")
                def reap(*args,**kwargs):
                    if label=="reap-and-evidence":raise primary
                    return dict(returncode=0,wait_status=0)
                def watchdog():
                    if label=="watchdog-and-evidence":raise primary
                def bad_save(*args,**kwargs):raise evidence_error
                obj._reap=reap;obj._stop_watchdog=watchdog
                original_save=transport.save;transport.save=bad_save
                caught=None
                try:
                    try:obj.abort()
                    except BaseException as error:caught=error
                finally:transport.save=original_save
                expected=evidence_error if label=="evidence" else primary
                self.assertIs(caught,expected)
                self.assertEqual(closed,["stdin","stdout","trace"])
                self.assertIsNone(obj._ready_read);self.assertIsNone(obj._ready_write)
                for descriptor in descriptors:
                    with self.assertRaises(OSError) as error:os.fstat(descriptor)
                    self.assertEqual(error.exception.errno,errno.EBADF)
                notes=getattr(caught,"__notes__",[])
                if label!="evidence":self.assertTrue(any("evidence" in note for note in notes))
                controls.append(dict(label=label,original_exception_identity=True,
                    all_three_streams_closed=True,two_ready_descriptors_consumed_and_closed=True,
                    notes=notes,native_entries=0))
            self.assertEqual(len(controls),3)
            save(self.case/"abort-cleanup-pure-controls.json",controls)
            report["abort_cleanup_pure_controls"]=controls

        def take_reusable(self,c,path,flags=2):
            header,payload=c.call(10,a=flags,body=os.fsencode(path))
            self.assertEqual(header[14],0)
            if not payload:
                self.assertEqual(header[20:22],(0,0))
                return 0,header,None
            self.assertEqual(len(payload),256)
            row=struct.unpack("<32Q",payload)
            self.assertEqual((row[0],row[1],row[8],row[9],row[22]),
                (int.from_bytes(b"HIANDB01","little"),0,0,0,1))
            self.assertEqual(row[24],1)
            self.assertFalse(any(row[29:]))
            return row[10],header,row

        def register_existing_token(self,c,path,token,readonly=False,unix_excl=False):
            before=len(fs_events(c.output,15))
            header,row=c.database(3,token=token,flags=int(readonly)+2*int(unix_excl))
            self.assertEqual(len(fs_events(c.output,15))-before,1)
            info=path.stat()
            self.assertEqual(header[20:22],(info.st_dev,info.st_ino))
            self.assertGreater(header[14],0)
            self.assertGreater(row[10],0)
            return header[14],header,row

        def test_19_empty_inode_directory_has_no_path_stat(self):
            missing=self.fx/"not-present"
            with self.carrier() as c:
                before=list(fs_events(c.output))
                token,header,row=self.take_reusable(c,missing,2)
                self.assertEqual(token,0);self.assertIsNone(row)
                self.assertEqual(fs_events(c.output),before)
            r=replay_instance(c.output)
            self.assertEqual(r["entries_by_role"]["5"],0)
            self.assertEqual(r["actual_DB_context_retirements"],[])

        def test_20_stat_failure_is_a_miss_then_same_session_is_usable(self):
            path=self.database()
            with self.carrier() as c:
                _,handle,_,_=self.register(c,path)
                before=len(fs_events(c.output,18))
                token,_,row=self.take_reusable(c,self.fx/"missing",2)
                self.assertEqual(token,0);self.assertIsNone(row)
                events=fs_events(c.output,18)
                self.assertEqual(len(events)-before,1)
                self.assertEqual(events[-1]["raw_return"],(-errno.ENOENT)&MASK)
                token,_,row=self.take_reusable(c,path,2)
                self.assertEqual(token,0);self.assertIsNotNone(row)
                c.database(4,handle,target=1);c.database(5,handle,target=0)
                c.database(7,handle)
            replay_instance(c.output)

        def test_21_existing_other_inode_does_not_create_a_DB_context(self):
            path=self.database("selected");other=self.database("other")
            with self.carrier() as c:
                _,handle,original,_=self.register(c,path)
                token,header,row=self.take_reusable(c,other,2)
                self.assertEqual(token,0);self.assertIsNone(row)
                self.assertEqual(header[20:22],(0,0))
                token,header,row=self.take_reusable(c,path,2)
                self.assertEqual(token,0);self.assertIsNotNone(row)
                self.assertEqual(header[25],original[25])
                c.database(7,handle)
            r=replay_instance(c.output)
            self.assertEqual(len([v for v in r["outer_db_contexts"] if v["role"]==5]),1)
            self.assertEqual(len(fs_events(c.output,18)),2)

        def test_22_actual_LIFO_first_matching_readonly_and_full_flags(self):
            path=self.database()
            with self.carrier() as c:
                _,keeper,_,_=self.register(c,path)
                t1,h1,_,_=self.register(c,path)
                t2,h2,_,_=self.register(c,path,readonly=True)
                t3,h3,_,_=self.register(c,path)
                c.database(4,keeper,target=1)
                for handle in (h1,h2,h3):c.database(7,handle)
                before=len(fs_events(c.output,8))
                for flags in (0,3):
                    token,_,state=self.take_reusable(c,path,flags)
                    self.assertEqual(token,0);self.assertIsNotNone(state)
                    self.assertEqual(state[12:15],(1,1,1))
                taken=[]
                for flags,expected in ((0x40000002,t3),(2,t1),(1,t2)):
                    token,_,state=self.take_reusable(c,path,flags)
                    self.assertEqual(token,expected);taken.append(token)
                    self.assertEqual(state[12:15],(1,1,1))
                self.assertEqual(len(fs_events(c.output,8)),before)
                new=[]
                for token,readonly,old_handle in ((t3,False,h3),(t1,False,h1),(t2,True,h2)):
                    handle,_,_=self.register_existing_token(c,path,token,readonly)
                    self.assertGreater(handle,old_handle);new.append(handle)
                self.assertEqual(len(set(new)),3)
                token,_,_=self.take_reusable(c,path,2);self.assertEqual(token,0)
                c.database(5,keeper,target=0)
                for handle in (*new,keeper):c.database(7,handle)
            r=replay_instance(c.output)
            self.assertEqual(len(r["actual_DB_context_retirements"]),1)
            self.assertEqual(len(fs_events(c.output,1)),4)
            self.assertEqual(len(fs_events(c.output,15)),7)
            self.assertEqual(len(fs_events(c.output,18)),6)
            self.assertEqual(len(fs_events(c.output,8)),4)

        def test_23_path_stat_follows_hardlink_and_symlink_aliases(self):
            path=self.database();hard=self.fx/"hard";link=self.fx/"link"
            os.link(path,hard);link.symlink_to(hard)
            with self.carrier() as c:
                _,keeper,original,_=self.register(c,path)
                token,old,_,_=self.register(c,hard)
                c.database(4,keeper,target=1);c.database(7,old)
                reused,header,state=self.take_reusable(c,link,2)
                self.assertEqual(reused,token)
                self.assertEqual(header[20:22],original[20:22])
                handle,again,_=self.register_existing_token(c,link,token)
                self.assertEqual(again[25],original[25])
                self.assertGreater(handle,old)
                c.database(5,keeper,target=0)
                c.database(7,handle);c.database(7,keeper)
            r=replay_instance(c.output)
            self.assertEqual(len(r["actual_DB_context_retirements"]),1)
            self.assertEqual(len(fs_events(c.output,18)),1)

        def test_24_retired_directory_uses_empty_fast_path_again(self):
            path=self.database()
            with self.carrier() as c:
                _,handle,old,_=self.register(c,path)
                c.database(7,handle)
                before=len(fs_events(c.output,18))
                token,_,row=self.take_reusable(c,path,2)
                self.assertEqual(token,0);self.assertIsNone(row)
                self.assertEqual(len(fs_events(c.output,18)),before)
                _,new,header,_=self.register(c,path)
                self.assertGreater(header[25],old[25])
                self.assertGreater(new,handle)
                c.database(7,new)
            r=replay_instance(c.output)
            self.assertEqual(len(r["actual_DB_context_retirements"]),2)

        def test_25_failed_unlock_ghost_never_reissues_the_old_handle(self):
            path=self.database()
            launcher,baseline=self.tracer("reuse-baseline")
            with self.carrier(launcher=launcher) as c:
                _,owner,_,_=self.register(c,path)
                _,other,_,_=self.register(c,path)
                c.database(4,owner,target=1);c.database(4,owner,target=4)
                c.database(7,owner);c.database(7,other)
            replay_instance(c.output)
            selected=syscall_ordinal(baseline,"fcntl",lambda line:
                "F_SETLK" in line and "F_UNLCK" in line and
                f"l_start={PENDING}," in line and re.search(r"l_len=2(?:[,}])",line) is not None)
            save(self.case/"selected-failed-unlock.json",selected)
            launcher,log=self.tracer("reuse-fault",
                f"inject=fcntl:error=EIO:when={selected['ordinal']}")
            with self.carrier(launcher=launcher) as failed:
                original_token,owner,_,_=self.register(failed,path)
                _,other,_,_=self.register(failed,path)
                failed.database(4,owner,target=1);failed.database(4,owner,target=4)
                _,closed=failed.database(7,owner)
                self.assertEqual(closed[12:16],(1,1,1,4))
                token,_,taken=self.take_reusable(failed,path,2)
                self.assertEqual(token,original_token)
                self.assertEqual(taken[12:16],closed[12:16])
                fresh,_,_=self.register_existing_token(failed,path,token)
                self.assertGreater(fresh,owner)
                before=len(fs_events(failed.output,17))
                failed.database(4,fresh,target=1,expect_code=5)
                self.assertEqual(len(fs_events(failed.output,17)),before)
                failed.database(7,other)
                _,last=failed.database(7,fresh)
                self.assertEqual(last[24],4);self.assertEqual(last[12:16],(0,0,0,0))
            self.assertIn("INJECTED",log.read_text())
            r=replay_instance(failed.output)
            self.assertEqual(len(r["actual_DB_context_retirements"]),1)
            self.assertEqual(len([x for x in fs_events(failed.output,17)
                if x["raw_return"]==(-errno.EIO)&MASK]),1)

        def test_26_global_reuse_malformed_source_is_persistently_refused(self):
            cases=[
                dict(label="embedded-NUL",handle=0,flags=2,body=b"not"+bytes([0])+b"a-path"),
                dict(label="non-u32-flags",handle=0,flags=1<<32,body=b"path"),
                dict(label="unexpected-handle",handle=1,flags=2,body=b"path"),
            ]
            for case in cases:
                with self.subTest(case=case["label"]):
                    with self.carrier() as c:
                        raw=transport.frame(10,session=c.session,call=1,lease=1001,
                            handle=case["handle"],a=case["flags"],body=case["body"])
                        header,_=c.request(raw,label=case["label"])
                        self.assertEqual(header[1],0xfffffffd)
                        header,_=c.request(transport.frame(10,session=c.session,call=2,
                            lease=1002,a=2,body=b"path"),label="after-poison")
                        self.assertEqual(header[1],0xfffffffd)
                    self.assertEqual(fs_events(c.output),[])
                    replay_instance(c.output)

        def test_27_deferred_reuse_beyond_initial_row_capacity(self):
            path=self.database()
            with self.carrier() as c:
                _,keeper,_,_=self.register(c,path)
                pending=[self.register(c,path)[:2] for _ in range(17)]
                c.database(4,keeper,target=1)
                for token,handle in pending:c.database(7,handle)
                new=[]
                for expected,old in reversed(pending):
                    token,_,state=self.take_reusable(c,path,2)
                    self.assertEqual(token,expected)
                    handle,_,_=self.register_existing_token(c,path,token)
                    self.assertGreater(handle,old);new.append(handle)
                token,_,_=self.take_reusable(c,path,2);self.assertEqual(token,0)
                c.database(5,keeper,target=0)
                for handle in (*new,keeper):c.database(7,handle)
            r=replay_instance(c.output)
            self.assertGreater(r["outer_DB_growth"]["5"],0)
            self.assertGreater(r["outer_DB_growth"]["6"],0)
            self.assertEqual(len(fs_events(c.output,1)),18)
            self.assertEqual(len(fs_events(c.output,15)),35)
            self.assertEqual(len(fs_events(c.output,18)),18)
            self.assertEqual(len(fs_events(c.output,8)),18)

        def test_28_path_replacement_does_not_consume_old_inode_unused_fd(self):
            path=self.database();original_alias=self.fx/"original-alias"
            os.link(path,original_alias)
            with self.carrier() as c:
                _,keeper,original,_=self.register(c,path)
                token,old,_,_=self.register(c,path)
                c.database(4,keeper,target=1);c.database(7,old)
                path.unlink();path.write_bytes(b"replacement-inode")
                self.assertNotEqual(path.stat().st_ino,original_alias.stat().st_ino)
                missing,_,row=self.take_reusable(c,path,2)
                self.assertEqual(missing,0);self.assertIsNone(row)
                reused,header,_=self.take_reusable(c,original_alias,2)
                self.assertEqual(reused,token)
                self.assertEqual(header[20:22],original[20:22])
                handle,_,_=self.register_existing_token(c,original_alias,token)
                c.database(5,keeper,target=0)
                c.database(7,handle);c.database(7,keeper)
            r=replay_instance(c.output)
            self.assertEqual(len(r["actual_DB_context_retirements"]),1)
            self.assertEqual(path.read_bytes(),b"replacement-inode")
            self.assertEqual(original_alias.read_bytes(),b"namespace-main-db-physical")

        def test_29_GETPID_returns_the_actual_owned_native_process(self):
            with self.carrier() as c:
                values=[]
                for _ in range(3):
                    result,body=c.filesystem(26)
                    self.assertEqual(body,b"")
                    self.assertEqual(result[8],c.owned_native_pid())
                    values.append(result[8])
                self.assertEqual(values,[c.owned_native_pid()]*3)
            r=replay_instance(c.output)
            self.assertEqual(len(fs_events(c.output,26)),3)
            self.assertEqual(r["entries_by_role"]["5"],0)

        def test_30_OPEN_WITH_FD_keeps_actual_zero_and_fresh_logical_tokens(self):
            path=self.database(content=b"fs8 actual fd zero")
            with self.carrier() as c:
                first,_=c.filesystem(25,b=os.O_RDONLY|os.O_CLOEXEC,c=0o600,
                    body=os.fsencode(path))
                self.assertGreater(first[8],0);self.assertEqual(first[9],0)
                _,raw=c.filesystem(2,a=first[8],b=path.stat().st_size,c=0)
                self.assertEqual(raw,b"fs8 actual fd zero")
                c.filesystem(8,a=first[8])
                second,_=c.filesystem(28,b=os.O_RDONLY|os.O_CLOEXEC,c=0o600,
                    body=os.fsencode(path))
                self.assertGreater(second[8],first[8]);self.assertEqual(second[9],0)
                c.filesystem(8,a=second[8])
            replay_instance(c.output)
            self.assertEqual([r["raw_return"] for r in fs_events(c.output,25)],[0])
            self.assertEqual([r["raw_return"] for r in fs_events(c.output,28)],[0])

        def test_31_empty_OPEN_CSTR_is_actual_ENOENT_and_issues_no_token(self):
            path=self.database()
            with self.carrier() as c:
                failed,body=c.filesystem(28,b=os.O_RDONLY|os.O_CLOEXEC,c=0o600,
                    body=b"",expect_errno=errno.ENOENT)
                self.assertEqual(body,b"")
                self.assertEqual(failed[8:10],(0,0))
                self.assertEqual(failed[20:22],(0,1))
                events=fs_events(c.output,28)
                self.assertEqual(len(events),1)
                self.assertEqual(events[0]["raw_return"],(-errno.ENOENT)&MASK)
                result,_=c.filesystem(25,b=os.O_RDONLY|os.O_CLOEXEC,c=0o600,
                    body=os.fsencode(path))
                self.assertEqual(result[8],1);self.assertEqual(result[9],0)
                c.filesystem(8,a=result[8])
            replay_instance(c.output)

        def test_32_ACCESS_keeps_real_UID_kernel_permission_and_missing_errors(self):
            path=self.database();path.chmod(0o600)
            self.assertTrue(os.access(path,os.R_OK))
            self.assertFalse(os.access(path,os.X_OK))
            with self.carrier() as c:
                success,body=c.filesystem(27,b=os.R_OK,body=os.fsencode(path))
                self.assertEqual(body,b"");self.assertEqual(success[8],0)
                denied,body=c.filesystem(27,b=os.X_OK,body=os.fsencode(path),
                    expect_errno=errno.EACCES)
                self.assertEqual(body,b"");self.assertEqual(denied[8],0)
                missing,body=c.filesystem(27,b=os.F_OK,
                    body=os.fsencode(self.fx/"missing"),expect_errno=errno.ENOENT)
                self.assertEqual(body,b"");self.assertEqual(missing[8],0)
            replay_instance(c.output)
            self.assertEqual([r["raw_return"] for r in fs_events(c.output,27)],
                [0,(-errno.EACCES)&MASK,(-errno.ENOENT)&MASK])

        def test_33_empty_path_STAT_is_real_before_global_reuse_miss(self):
            path=self.database()
            with self.carrier() as c:
                # The original inode-list shortcut remains before any stat,
                # including when the captured C-string has zero content bytes.
                token,_,row=self.take_reusable(c,b"",2)
                self.assertEqual(token,0);self.assertIsNone(row)
                self.assertEqual(fs_events(c.output,29),[])
                _,handle,_,_=self.register(c,path)
                token,_,row=self.take_reusable(c,b"",2)
                self.assertEqual(token,0);self.assertIsNone(row)
                events=fs_events(c.output,29)
                self.assertEqual(len(events),1)
                self.assertEqual(events[0]["raw_return"],(-errno.ENOENT)&MASK)
                result,raw=c.filesystem(29,body=os.fsencode(path))
                self.assertEqual(len(raw),144)
                expected=path.stat()
                self.assertEqual(result[8:10],(expected.st_dev,expected.st_ino))
                self.assertEqual(struct.unpack_from("<2Q",raw),(expected.st_dev,expected.st_ino))
                c.database(7,handle)
                before=len(fs_events(c.output,29))
                token,_,row=self.take_reusable(c,b"",2)
                self.assertEqual(token,0);self.assertIsNone(row)
                self.assertEqual(len(fs_events(c.output,29)),before)
            replay_instance(c.output)

        def test_34_raw_OPEN_WITH_FD_EINTR_is_not_implicitly_retried(self):
            path=self.database();launcher,baseline=self.tracer("fs8-open-baseline")
            with self.carrier(launcher=launcher) as c:
                result,_=c.filesystem(25,b=os.O_RDONLY|os.O_CLOEXEC,c=0o600,
                    body=os.fsencode(path))
                c.filesystem(8,a=result[8])
            replay_instance(c.output)
            selected=syscall_ordinal(baseline,"openat",lambda line:str(path) in line)
            save(self.case/"selected-open25.json",selected)
            launcher,log=self.tracer("fs8-open-fault",
                f"inject=openat:error=EINTR:when={selected['ordinal']}")
            with self.carrier(launcher=launcher) as failed:
                result,body=failed.filesystem(25,b=os.O_RDONLY|os.O_CLOEXEC,c=0o600,
                    body=os.fsencode(path),expect_errno=errno.EINTR)
                self.assertEqual(body,b"");self.assertEqual(result[20:22],(0,1))
                self.assertEqual(len(fs_events(failed.output,25)),1)
                result,_=failed.filesystem(25,b=os.O_RDONLY|os.O_CLOEXEC,c=0o600,
                    body=os.fsencode(path))
                self.assertEqual(result[8],1);self.assertEqual(result[9],0)
                failed.filesystem(8,a=result[8])
            self.assertIn("INJECTED",log.read_text())
            replay_instance(failed.output)
            self.assertEqual([r["raw_return"] for r in fs_events(failed.output,25)],
                [(-errno.EINTR)&MASK,0])


        def issued_fs_input(self,c,op,*,caller=1,a=0,b=0,carg=0,d=0,body=b""):
            terminal=[entry for entry in trace_records(c.output)[1]
                if entry["role"]==6 and entry["code"]==0]
            self.assertTrue(terminal)
            work=terminal[-1]["work"]
            self.assertEqual(struct.unpack_from("<Q",work,8)[0],1)
            scope=struct.unpack_from("<2Q",work,80)
            call=struct.unpack_from("<Q",work,216)[0]
            self.assertLess(call,MASK);self.assertNotEqual(caller,0)
            values=[int.from_bytes(b"HIANFR03","little"),2,*scope,call+1,0,
                op,0,a,b,carg,d,len(body),caller,*([0]*18)]
            self.assertEqual(len(values),32)
            return struct.pack("<32Q",*values)+body

        def fs_source_records_since(self,directory,offset):
            path=Path(directory)/"trace.bin";end=path.stat().st_size;sources=[]
            with path.open("rb") as stream:
                stream.seek(offset)
                def take(n):
                    raw=stream.read(n);self.assertEqual(len(raw),n);return raw
                while stream.tell()<end:
                    header=struct.unpack("<12Q",take(96));role=replayer.MAGICS[header[0]]
                    if header[1]==1:
                        source=take(header[3]);take(header[4]);take(header[5])
                        if role==1:sources.append(source)
                    elif header[1]==2:
                        take(header[4]);take(header[5])
                    elif header[1]==3:
                        take(header[3])
                    else:self.assertEqual(header[1],4)
                self.assertEqual(stream.tell(),end)
            self.assertEqual(path.stat().st_size,end)
            return sources

        def issued_fs(self,c,op,*,caller=1,a=0,b=0,carg=0,d=0,body=b"",expect_errno=0):
            raw=self.issued_fs_input(c,op,caller=caller,a=a,b=b,carg=carg,d=d,body=body)
            offset=(c.output/"trace.bin").stat().st_size
            _,payload=c.call(11,body=raw)
            self.assertGreaterEqual(len(payload),256)
            result=struct.unpack_from("<32Q",payload)
            self.assertEqual(result[0],int.from_bytes(b"HIANFR03","little"))
            self.assertEqual((result[1],result[6],result[7],result[14],result[15],result[22]),
                (0,op,expect_errno,caller,1,3))
            self.assertEqual(result[2:5],struct.unpack_from("<3Q",raw,16))
            self.assertEqual(len(payload),256+result[16])
            # The first actual FS invocation in this call is the exact issued
            # bytes; subsequent ACK/GROW entries belong to that same call.
            sources=self.fs_source_records_since(c.output,offset)
            self.assertTrue(sources);self.assertEqual(sources[0],raw)
            entries=trace_records(c.output)[1]
            completed=[entry for entry in entries if entry["role"]==1 and entry["code"]==0]
            self.assertTrue(completed)
            actual=completed[-1]["output"]
            self.assertEqual(payload,actual[:256+struct.unpack_from("<Q",actual,128)[0]])
            dms=[entry for entry in entries if entry["role"]==4 and entry["code"]==0]
            self.assertTrue(dms);self.assertEqual(dms[-1]["work"][768:1024],raw[:256])
            return result,payload[256:]

        def test_35_issued_FS_preserves_caller_and_actual_zero_descriptor(self):
            data=b"\x00\xff\nbinary-issued-FS\x80\x00"
            path=self.database(content=data)
            with self.carrier() as c:
                opened,_=self.issued_fs(c,25,caller=MASK,b=os.O_RDWR|os.O_CLOEXEC,
                    carg=0o600,body=os.fsencode(path))
                token=opened[8];self.assertGreater(token,0);self.assertEqual(opened[9],0)
                _,read=self.issued_fs(c,2,caller=1,a=token,b=len(data),carg=0)
                self.assertEqual(read,data)
                changed=b"\xff\x00issued-write"
                written,_=self.issued_fs(c,3,caller=7,a=token,b=2,body=changed)
                self.assertEqual(written[8],len(changed))
                self.assertEqual(path.read_bytes(),data[:2]+changed+data[2+len(changed):])
                self.issued_fs(c,8,caller=2,a=token)
            replay_instance(c.output)
            self.assertEqual([entry["raw_return"] for entry in fs_events(c.output,25)],[0])

        def test_36_issued_and_legacy_gateway_share_one_FS_sequence_and_registry(self):
            path=self.database()
            with self.carrier() as c:
                first,_=c.filesystem(25,b=os.O_RDONLY|os.O_CLOEXEC,body=os.fsencode(path))
                first_token=first[8]
                closed,_=self.issued_fs(c,8,caller=1,a=first_token)
                self.assertGreater(closed[4],first[4])
                second,_=self.issued_fs(c,25,caller=1,b=os.O_RDONLY|os.O_CLOEXEC,
                    body=os.fsencode(path))
                self.assertGreater(second[8],first_token);self.assertEqual(second[9],0)
                c.filesystem(8,a=second[8])
                pid,_=self.issued_fs(c,26,caller=MASK)
                self.assertEqual(pid[8],c.owned_native_pid())
                c.filesystem(26)
            replay_instance(c.output)
            requests=[entry for entry in trace_records(c.output)[1] if entry["role"]==1 and entry["code"]==0]
            calls=[struct.unpack_from("<Q",entry["output"],32)[0] for entry in requests]
            self.assertEqual(calls,list(range(len(calls))))

        def test_37_issued_known_empty_path_errors_keep_following_session_usable(self):
            with self.carrier() as c:
                opened,body=self.issued_fs(c,28,caller=1,b=os.O_RDONLY|os.O_CLOEXEC,
                    body=b"",expect_errno=errno.ENOENT)
                self.assertEqual(body,b"");self.assertEqual(opened[8:10],(0,0))
                result,body=self.issued_fs(c,29,caller=2,body=b"",expect_errno=errno.ENOENT)
                self.assertEqual(body,b"");self.assertEqual(result[16],0)
                pid,_=self.issued_fs(c,26,caller=1)
                self.assertEqual(pid[8],c.owned_native_pid())
            replay_instance(c.output)
            self.assertEqual([r["raw_return"] for r in fs_events(c.output,28)],[(-errno.ENOENT)&MASK])
            self.assertEqual([r["raw_return"] for r in fs_events(c.output,29)],[(-errno.ENOENT)&MASK])

        def test_38_issued_STAT_returns_exact_logical_400_bytes_and_full_real_stat(self):
            path=self.database(content=b"stat-issued")
            expected=path.stat()
            with self.carrier() as c:
                result,raw=self.issued_fs(c,29,caller=901,body=os.fsencode(path))
                self.assertEqual(len(raw),144)
                self.assertEqual(result[16],144)
                self.assertEqual(result[8:10],(expected.st_dev,expected.st_ino))
                self.assertEqual(struct.unpack_from("<2Q",raw),(expected.st_dev,expected.st_ino))
                self.assertEqual(struct.unpack_from("<q",raw,48)[0],expected.st_size)
            replay_instance(c.output)

        def test_39_issued_raw_EINTR_is_one_real_IO_and_no_implicit_retry(self):
            path=self.database();launcher,baseline=self.tracer("issued-open-baseline")
            with self.carrier(launcher=launcher) as c:
                result,_=self.issued_fs(c,25,caller=13,b=os.O_RDONLY|os.O_CLOEXEC,
                    body=os.fsencode(path))
                self.issued_fs(c,8,caller=14,a=result[8])
            replay_instance(c.output)
            selected=syscall_ordinal(baseline,"openat",lambda line:str(path) in line)
            save(self.case/"selected-issued-open.json",selected)
            launcher,log=self.tracer("issued-open-fault",
                f"inject=openat:error=EINTR:when={selected['ordinal']}")
            with self.carrier(launcher=launcher) as failed:
                result,body=self.issued_fs(failed,25,caller=13,b=os.O_RDONLY|os.O_CLOEXEC,
                    body=os.fsencode(path),expect_errno=errno.EINTR)
                self.assertEqual(body,b"");self.assertEqual(result[8:10],(0,0))
                self.assertEqual(len(fs_events(failed.output,25)),1)
                result,_=self.issued_fs(failed,25,caller=14,b=os.O_RDONLY|os.O_CLOEXEC,
                    body=os.fsencode(path))
                self.issued_fs(failed,8,caller=15,a=result[8])
            self.assertIn("INJECTED",log.read_text());replay_instance(failed.output)
            self.assertEqual([row["raw_return"] for row in fs_events(failed.output,25)],
                [(-errno.EINTR)&MASK,0])

        def test_40_issued_raw_close_cannot_bypass_live_DB_token_registration(self):
            path=self.database()
            with self.carrier() as c:
                token,handle,_,_=self.register(c,path)
                before=len(fs_events(c.output))
                raw=self.issued_fs_input(c,8,caller=3,a=token)
                c.call_number+=1
                header,_=c.request(transport.frame(11,session=c.session,call=c.call_number,
                    lease=1000+c.call_number,body=raw),label="issued-registered-close")
                self.assertEqual(header[1],0xfffffffd)
                header,_=c.request(transport.frame(1,session=c.session,a=171,b=183),
                    label="issued-after-permanent-refusal")
                self.assertEqual(header[1],0xfffffffd)
                self.assertEqual(len(fs_events(c.output)),before)
            replay_instance(c.output)

        def test_41_issued_header_sequence_scope_and_extent_refusals_precede_IO(self):
            mutations=[("magic",0,0),("command",8,1),("scope",16,999),("sequence",32,0),
                ("sysseq",40,1),("operation",48,30),("error",56,1),
                ("payload-size",96,1),("zero-caller",104,0),("reserved",112,1)]
            observations=[]
            for label,offset,value in mutations:
                with self.subTest(label=label):
                    with self.carrier() as c:
                        raw=bytearray(self.issued_fs_input(c,26,caller=1))
                        struct.pack_into("<Q",raw,offset,value)
                        before=len(fs_events(c.output))
                        header,_=c.request(transport.frame(11,session=c.session,call=1,lease=1001,
                            body=bytes(raw)),label="issued-"+label)
                        self.assertEqual(header[1],0xfffffffd)
                        header,_=c.request(transport.frame(1,session=c.session,a=171,b=183),
                            label="issued-after-"+label)
                        self.assertEqual(header[1],0xfffffffd)
                        self.assertEqual(len(fs_events(c.output)),before)
                    result=replay_instance(c.output)
                    observations.append(dict(label=label,native_entries=result["native_entries"],
                        VM_entries=result["vm_entries"],actual_primitive_ACKs=len(fs_events(c.output))))
            self.assertEqual(len(observations),10)
            save(self.case/"issued-header-controls.json",observations)

        def test_42_issued_input_and_output_GROW_never_reissue_completed_IO(self):
            data=bytes(range(256))*32+b"tail"
            path=self.database(content=data)
            with self.carrier() as c:
                too_long,_=self.issued_fs(c,28,caller=1,b=os.O_RDONLY|os.O_CLOEXEC,
                    body=b"a"*5000,expect_errno=errno.ENAMETOOLONG)
                self.assertEqual(too_long[16],0)
                opened,_=self.issued_fs(c,25,caller=2,b=os.O_RDONLY|os.O_CLOEXEC,
                    body=os.fsencode(path))
                _,actual=self.issued_fs(c,2,caller=1,a=opened[8],b=len(data),carg=0)
                self.assertEqual(actual,data)
                self.issued_fs(c,8,caller=2,a=opened[8])
            replay_instance(c.output)
            events,entries=trace_records(c.output)
            self.assertEqual(len([row for row in events if row["role"]==1 and row["operation"]==28]),1)
            self.assertEqual(len([row for row in events if row["role"]==1 and row["operation"]==25]),1)
            self.assertEqual(len([row for row in events if row["role"]==1 and row["operation"]==2]),1)
            self.assertTrue(any(row["role"]==6 and row["code"]==2 for row in entries))

    try:
        suite=unittest.defaultTestLoader.loadTestsFromTestCase(ActualJoin)
        ids=[test.id() for test in suite]
        assert len(ids)==len(set(ids))==EXPECTED_TESTS>0
        with (out/"tests.stderr.log").open("w") as stream:
            result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
        tests=dict(test_ids=ids,tests_loaded=len(ids),tests_run=result.testsRun,
            failures=[(t.id(),v) for t,v in result.failures],
            errors=[(t.id(),v) for t,v in result.errors],
            skipped=[(t.id(),v) for t,v in result.skipped],
            expected_failures=[(t.id(),v) for t,v in result.expectedFailures],
            unexpected_successes=[t.id() for t in result.unexpectedSuccesses])
        report["tests"]=tests
        save(out/"summary.json",report)
        assert result.wasSuccessful() and result.testsRun==EXPECTED_TESTS>0
        assert not any(tests[key] for key in
            ("failures","errors","skipped","expected_failures","unexpected_successes"))
        process_paths={str(path.parent) for path in out.glob("test_*/native-*/process.json")}
        replayed={str(Path(row["path"]).parent) for row in report["process_limit_readbacks"]}
        assert process_paths==replayed and len(process_paths)==len(report["replay"])>0
        report.update(status="PASS",native_entries=sum(row["native_entries"] for row in report["replay"]),
            vm_entries=sum(row["vm_entries"] for row in report["replay"]),
            actual_primitive_acks=sum(row["unchanged_inner_replayer"]["actual_primitive_acks"]
                for row in report["replay"]),process_traces=len(report["replay"]),
            entries_by_role={str(role):sum(row["entries_by_role"][str(role)] for row in report["replay"])
                for role in (1,2,3,4,5,6)},
            completed_outer_child_links=sum(len(row["complete_outer_links"]) for row in report["replay"]),
            completed_inner_child_links=sum(len(row["unchanged_inner_replayer"]["exact_completed_child_links"])
                for row in report["replay"]),
            actual_DB_retirements=sum(len(row["actual_DB_context_retirements"]) for row in report["replay"]),
            actual_inner_retirements=sum(len(row["unchanged_inner_replayer"]["exact_retirements"])
                for row in report["replay"]),
            all_actual_trace_processes_fully_replayed=True,
            abort_cleanup_pure_control_count=len(report["abort_cleanup_pure_controls"]))
        assert report["native_entries"]==report["vm_entries"]>0
        assert report["actual_primitive_acks"]>0 and report["abort_cleanup_pure_control_count"]==3
        assert all(report["entries_by_role"][str(role)]>0 for role in (1,2,3,4,5,6))
    except BaseException as error:
        report.update(status="FAIL",error_class=type(error).__name__,error=str(error),
            traceback=traceback.format_exc())
        traceback.print_exc()
        if (out/"tests.stderr.log").exists():
            print((out/"tests.stderr.log").read_text(),file=sys.stderr,flush=True)
    finally:
        after={}
        for path in pins:
            try:
                info=Path(path).lstat();assert stat.S_ISREG(info.st_mode) and not Path(path).is_symlink()
                raw=Path(path).read_bytes()
                after[path]=dict(bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(info.st_mode))
            except BaseException as error:
                after[path]=dict(error_class=type(error).__name__,error=str(error))
        report.update(source_before=pins,source_after=after,source_pins_unchanged=pins==after)
        if pins!=after:report["status"]="FAIL"
        save(out/"summary.json",report)
        print(json.dumps(dict(status=report["status"],tests_run=report.get("tests",{}).get("tests_run"),
            native_entries=report.get("native_entries"),actual_primitive_acks=report.get("actual_primitive_acks"),
            process_traces=len(report["replay"]),python_router_used=False,ordinary_store_closed=False)),flush=True)
    return 0 if report["status"]=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
