"""New actual four-role DMS / SHM map / memory / FS physical tests.

Python supplies explicit fixtures, independent SQLite/POSIX observations and raw
transport. Only HIA chooses child calls, DMS/WAL actions, mapping, and retirement.
Every completed process trace is replayed byte for byte in retained CoreVM.
This is not the ordinary AgentStore, DB-inode/deferred-close or migration gate.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import argparse,ctypes,errno,fcntl,hashlib,importlib.util,json,os,re,select,shutil
import signal,sqlite3,stat,struct,subprocess,time,traceback,unittest
from pathlib import Path
CLIENT_SHA="0d3c64a7d1407c316e22ffecb87d670630a26aeff2970f3cf56f6d698b279a64"
REPLAY_SHA="0b9bab8e16b0174c54062d56c5042afdaea35a1e936932bbd31ade04f06436a6"
MASK=(1<<64)-1
EXPECTED_TESTS=22
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
        path=Path(path).absolute();info=path.lstat()
        assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
        path=path.resolve();raw=path.read_bytes()
        row=dict(bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(info.st_mode))
        if expected is not None:assert row["sha256"]==expected,(str(path),row,expected)
        if str(path) in pins:assert pins[str(path)]==row
        pins[str(path)]=row
        return raw
    def module(name,path,expected=None):
        raw=pin(path,expected);spec=importlib.util.spec_from_file_location(name,path)
        value=importlib.util.module_from_spec(spec);sys.modules[name]=value
        exec(compile(raw,str(path),"exec"),value.__dict__);return value
    context=json.loads(pin(args.context));ref=Path(context["reference"])
    tree=Path(context["namespace_working"]);evidence=Path(context["namespace_evidence"])
    out=evidence/"join-native-r1";out.mkdir();(out/"source").mkdir();cas=out/"cas";cas.mkdir()
    fixture_root=Path(context["namespace_fixtures"]).resolve()
    assert fixture_root.is_relative_to(Path(context["base"]).resolve())
    assert not fixture_root.is_relative_to(Path(context["output"]).resolve())
    fixture_root.mkdir(parents=False,exist_ok=False)
    built=json.loads(pin(evidence/"join-build-r1/summary.json"))
    assert built["status"]=="PASS_BUILD_ONLY" and built["source_pins_unchanged"]
    assert built["fresh_role_compiles"]==4 and built["packer_entries"]==len(built["packer_controls"])==25
    executable=Path(built["executable"]["path"]);pin(executable,built["executable"]["sha256"])
    assert stat.S_IMODE(executable.stat().st_mode)==0o755
    sys.path.insert(0,str(ref))
    transport=module("namespace_join_actual_client",args.client,CLIENT_SHA)
    replayer=module("namespace_join_exact_replayer",args.replay,REPLAY_SHA)
    from hepta.hia_agent_assembly import assemble_program
    programs={}
    for role in (1,2,3,4):
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
    report=dict(status="INCOMPLETE",scope="NEW_ACTUAL_FIXED_DMS_MAP_MEMORY_FS_COMPONENT",
        sqlite=sqlite_identity,legacy_sqlite3461_claimed=False,ordinary_store_closed=False,
        DB_inode_deferred_close_closed=False,root_policy_closed=False,migration_closed=False,
        python_router_used=False,counts_inherited=False,
        fixture_capture="complete snapshot regular-file bytes in CAS plus original modes/inode hardlink topology/symlink targets; live special fixtures outside archive",
        actual_euid=os.geteuid(),actual_page=os.sysconf("SC_PAGE_SIZE"),
        replay=[],observations={},source_before=pins)
    def trace_records(directory):
        """Read only a quiescent exact owned child's complete existing trace."""
        path=Path(directory)/"trace.bin";size=path.stat().st_size;events=[];entries=[];pending={}
        with path.open("rb") as stream:
            def take(n):
                raw=stream.read(n);assert len(raw)==n;return raw
            while stream.tell()<size:
                h=struct.unpack("<12Q",take(96));role=replayer.MAGICS[h[0]]
                key=h[9]
                if h[1]==1:
                    take(h[3]);take(h[4]);take(h[5])
                elif h[1]==2:
                    output=take(h[4]);work=take(h[5])
                    entry=dict(role=role,node=h[8],context=key,serial=h[2],code=h[6],
                        output=output,work=work)
                    entries.append(entry)
                    if role in (1,3) and h[6]==1:pending[key]=entry
                elif h[1]==3:
                    assert role in (1,3) and key in pending
                    e=pending.pop(key);ack=take(h[3]);words=struct.unpack_from("<32Q",e["output"])
                    events.append(dict(role=role,node=h[8],context=key,operation=h[5],raw_return=h[6],
                        syscall=h[4],sequence=h[7],event=list(words),event_sha256=sha(e["output"][:256]),
                        ack_sha256=sha(ack),arguments=list(words[8:12] if role==1 else words[9:15])))
                else:assert h[1]==4
            assert stream.tell()==size
        assert path.stat().st_size==size
        return events,entries
    def replay_instance(directory,**kwargs):
        result=replayer.replay(directory,programs,**kwargs);report["replay"].append(result);return result
    def snapshot(root,label,destination):
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
        save(destination/(label+".json"),rows)
    def lock_bytes(kind,offset=128,count=1):
        return struct.pack("<hh4xqqi4x",kind,os.SEEK_SET,offset,count,0)
    def query(fd,offset=128,count=1):
        return struct.unpack("<hh4xqqi4x",fcntl.fcntl(fd,fcntl.F_GETLK,
            lock_bytes(fcntl.F_WRLCK,offset,count)))
    def lock(fd,kind,offset=128,count=1):
        return fcntl.fcntl(fd,fcntl.F_SETLK,lock_bytes(kind,offset,count))
    def read_owned_mapping(carrier,address,size,label):
        assert 0<=address<=MASK and 0<=size<=32768
        p=Path("/proc")/str(carrier.process.pid)
        raw=(p/"maps").read_bytes();(carrier.output/(label+".maps")).write_bytes(raw)
        matches=[]
        for line in raw.decode().splitlines():
            fields=line.split();first,last=(int(v,16) for v in fields[0].split("-"))
            if first<=address and address+size<=last:matches.append(fields)
        assert len(matches)==1 and "r" in matches[0][1]
        fd=os.open(p/"mem",os.O_RDONLY|os.O_CLOEXEC)
        try:content=os.pread(fd,size,address)
        finally:os.close(fd)
        assert len(content)==size
        (carrier.output/(label+".bin")).write_bytes(content)
        return content,matches[0]
    def mapped_address(carrier,*,node=None,offset=0,flags=1):
        events,_=trace_records(carrier.output)
        candidates=[row for row in events if row["role"]==3 and row["operation"]==1
            and row["raw_return"]<MASK-4094 and row["arguments"][1]==32768
            and row["arguments"][3]==flags and row["arguments"][5]==offset
            and (node is None or row["node"]==node)]
        assert candidates
        return candidates[-1]["raw_return"]
    def trace_syscall_ordinal(path,name,predicate):
        raw=path.read_bytes();lines=raw.decode().splitlines();count=0;selected=[]
        for line in lines:
            if re.match(r"^"+re.escape(name)+r"\(",line):
                count+=1
                if predicate(line):selected.append((count,line))
        assert selected,(name,lines)
        ordinal,line=selected[0]
        return dict(syscall=name,ordinal=ordinal,line=line,source_bytes=len(raw),source_sha256=sha(raw))
    class ActualJoin(unittest.TestCase):
        def setUp(self):
            self.case=out/self._testMethodName;self.case.mkdir()
            self.fx=fixture_root/self._testMethodName;self.fx.mkdir();self.created=0
            snapshot(self.fx,"before",self.case)
        def tearDown(self):snapshot(self.fx,"after",self.case)
        def carrier(self,**kwargs):
            self.created+=1
            return transport.Carrier(executable,self.case/("native-"+str(self.created)),self.fx,**kwargs)
        def database(self,name="db",content=b"namespace-physical-fixture"):
            path=self.fx/name;path.write_bytes(content);return path
        def open_db(self,c,path,readonly=False):
            row,_=c.filesystem(1,b=(os.O_RDONLY if readonly else os.O_RDWR)|os.O_CLOEXEC,
                c=0o600,body=os.fsencode(path))
            self.assertGreater(row[8],0)
            token=row[8];facts,raw=c.filesystem(15,a=token)
            self.assertEqual(len(raw),144)
            actual=path.stat();self.assertEqual((facts[8],facts[9]),(actual.st_dev,actual.st_ino))
            self.assertEqual((facts[10],facts[11],facts[12],facts[13]),
                (actual.st_mode,actual.st_uid,actual.st_gid,actual.st_size))
            return token,facts
        def attach(self,c,path,readonly=False,process=False,code=0,error=0):
            token,facts=self.open_db(c,path,readonly)
            h,_=c.call(2,a=token,b=facts[8],c=facts[9],d=int(readonly),e=int(process),
                body=os.fsencode(path),expect_code=code,expect_errno=error)
            return token,h[8],h
        def detach(self,c,token,connection,*,unlink=False):
            c.call(6,connection,i=int(unlink));c.filesystem(8,a=token)
        def map(self,c,connection,index=0,extend=True,code=0,error=0):
            h,_=c.call(14,connection,a=index,b=int(extend),c=32768,
                expect_code=code,expect_errno=error)
            return h
        def tracer(self,label,inject=None):
            path=self.case/(label+".strace")
            binary=shutil.which("strace");self.assertIsNotNone(binary,"strace is required; no skip fallback")
            command=[binary,"-qq","-s","256","-o",str(path),
                "-e","trace=fcntl,ftruncate,mmap,munmap,close,openat,pwrite64"]
            if inject:command.extend(["-e",inject])
            return command,path
        def baseline(self,label="baseline"):
            path=self.database(label+"-db");launcher,log=self.tracer(label)
            with self.carrier(launcher=launcher) as c:
                token,connection,_=self.attach(c,path)
                self.map(c,connection)
                self.detach(c,token,connection)
            replay_instance(c.output)
            snapshot(self.fx,label+"-after",self.case)
            # Recreate only this test's owned SHM fixture after the first native
            # child was fully reaped. Preserve the snapshot and all trace bytes.
            # The subsequent injected child receives the same absolute DB path
            # and original filesystem state, so path-dependent growth is stable.
            shm=Path(str(path)+"-shm")
            if shm.exists():
                self.assertTrue(stat.S_ISREG(shm.lstat().st_mode) and not shm.is_symlink())
                shm.unlink()
            self.assertEqual(path.read_bytes(),b"namespace-physical-fixture")
            return path,c,log
        def test_01_actual_initialization_gateway_and_fd_zero(self):
            path=self.database()
            with self.carrier() as c:
                events,_=trace_records(c.output);self.assertEqual(events,[])
                token,facts=self.open_db(c,path)
                read,data=c.filesystem(2,a=token,b=path.stat().st_size,c=0)
                self.assertEqual(data,path.read_bytes());self.assertEqual(read[8],len(data))
                c.filesystem(8,a=token)
                maps,fds=c.snapshot_owned_process("after-native-close")
                self.assertFalse(any(row["target"]==str(path) for row in fds))
                self.assertFalse(any("w" in line.split()[1] and "x" in line.split()[1]
                    for line in maps.decode().splitlines()))
            events,_=trace_records(c.output)
            self.assertEqual(events[0]["operation"],1);self.assertEqual(events[0]["raw_return"],0)
            result=replay_instance(c.output)
            self.assertEqual(result["entries_by_role"]["2"],0);self.assertEqual(result["entries_by_role"]["3"],0)
            report["observations"]["actual_initial_fs_issued_no_syscall_and_fd_zero"]=True
        def test_02_new_node_DMS128_truncate_and_shared_lock(self):
            path=self.database();shm=Path(str(path)+"-shm");shm.write_bytes(b"stale"*1000)
            parent=os.open(shm,os.O_RDWR)
            try:
                with self.carrier() as c:
                    token,connection,h=self.attach(c,path)
                    self.assertGreater(connection,0);self.assertEqual(h[10:14],(1,0,0,1))
                    self.assertEqual(shm.stat().st_size,3)
                    self.assertEqual(query(parent)[0],fcntl.F_RDLCK);self.assertEqual(query(parent)[4],c.process.pid)
                    self.detach(c,token,connection)
                    self.assertEqual(query(parent)[0],fcntl.F_UNLCK)
                events,_=trace_records(c.output)
                self.assertTrue(any(e["role"]==1 and e["operation"]==23 for e in events))
                self.assertEqual(sum(e["role"]==1 and e["operation"]==5 for e in events),1)
                observed_uid=[e for e in events if e["role"]==1 and e["operation"]==16]
                self.assertEqual(len(observed_uid),1)
                self.assertEqual(observed_uid[0]["raw_return"],os.geteuid())
                self.assertEqual(any(e["role"]==1 and e["operation"]==24 for e in events),os.geteuid()==0)
                replay_instance(c.output)
            finally:os.close(parent)
        def test_03_same_node_connections_and_WAL_shared_reference_counts(self):
            path=self.database()
            with self.carrier() as c:
                ta,a,ha=self.attach(c,path);tb,b,hb=self.attach(c,path)
                self.assertEqual(ha[9],hb[9]);self.assertEqual(hb[10],2)
                parent=os.open(str(path)+"-shm",os.O_RDWR)
                try:
                    c.call(4,a,f=1,g=2,h=1);c.call(4,b,f=1,g=2,h=1)
                    self.assertEqual(query(parent,122)[0],fcntl.F_RDLCK)
                    c.call(5,a,f=1,g=2,h=1)
                    self.assertEqual(query(parent,122)[0],fcntl.F_RDLCK)
                    c.call(4,a,f=2,g=2,h=1,expect_code=5)
                    c.call(5,b,f=1,g=2,h=1)
                    c.call(4,a,f=2,g=2,h=1)
                    self.assertEqual(query(parent,122)[0],fcntl.F_WRLCK)
                    c.call(5,a,f=2,g=2,h=1)
                    c.call(6,a);c.filesystem(8,a=ta)
                    self.assertEqual(query(parent)[0],fcntl.F_RDLCK)
                    self.detach(c,tb,b);self.assertEqual(query(parent)[0],fcntl.F_UNLCK)
                finally:os.close(parent)
            replay_instance(c.output)
        def test_04_actual_SQLite_writer_and_native_WAL_fence(self):
            path=self.fx/"database.sqlite";db=sqlite3.connect(path,timeout=0,isolation_level=None)
            try:
                self.assertEqual(db.execute("pragma journal_mode=wal").fetchone()[0],"wal")
                db.execute("create table retained(x)");db.execute("insert into retained values(1)")
                db.execute("begin immediate")
                shm=Path(str(path)+"-shm");before=shm.read_bytes()
                (self.case/"sqlite-writer-before-shm.bin").write_bytes(before)
                (self.case/"sqlite-writer-before-db.bin").write_bytes(path.read_bytes())
                (self.case/"sqlite-writer-before-wal.bin").write_bytes(Path(str(path)+"-wal").read_bytes())
                with self.carrier() as c:
                    token,connection,h=self.attach(c,path)
                    after_attach=shm.read_bytes()
                    (self.case/"sqlite-writer-after-native-attach-shm.bin").write_bytes(after_attach)
                    self.assertEqual(after_attach,before)
                    self.map(c,connection,extend=False)
                    c.call(4,connection,f=2,g=0,h=1,expect_code=5,expect_errno=errno.EAGAIN)
                    db.execute("commit")
                    c.call(4,connection,f=2,g=0,h=1)
                    with self.assertRaises(sqlite3.OperationalError) as raised:db.execute("begin immediate")
                    self.assertEqual(raised.exception.sqlite_errorcode,sqlite3.SQLITE_BUSY)
                    c.call(5,connection,f=2,g=0,h=1)
                    db.execute("begin immediate");db.execute("rollback")
                    self.detach(c,token,connection)
                self.assertEqual(db.execute("select * from retained").fetchall(),[(1,)])
                replay_instance(c.output)
                report["observations"]["actual_existing_SQLite_writer_fenced"]=True
            finally:db.close()
        def test_05_external_DMS_exclusive_conflict_is_BUSY_without_truncate(self):
            path=self.database();shm=Path(str(path)+"-shm");shm.write_bytes(b"keep")
            parent=os.open(shm,os.O_RDWR)
            try:
                lock(parent,fcntl.F_WRLCK)
                with self.carrier() as c:
                    token,connection,_=self.attach(c,path,code=5)
                    self.assertEqual(connection,0);self.assertEqual(shm.read_bytes(),b"keep")
                    c.filesystem(8,a=token)
                    lock(parent,fcntl.F_UNLCK)
                    token,connection,_=self.attach(c,path)
                    self.assertEqual(shm.stat().st_size,3);self.detach(c,token,connection)
                replay_instance(c.output)
            finally:os.close(parent)
        def test_06_readonly_unlocked_retry_and_true_readonly_mapping(self):
            path=self.database();shm=Path(str(path)+"-shm");payload=b"R"*32768;shm.write_bytes(payload)
            parent=os.open(shm,os.O_RDWR)
            try:
                with self.carrier() as c:
                    token,connection,h=self.attach(c,path,readonly=True,code=1288)
                    self.assertEqual(h[11:14],(1,1,0))
                    c.call(15,connection)
                    self.assertEqual(query(parent)[0],fcntl.F_UNLCK)
                    lock(parent,fcntl.F_RDLCK)
                    c.call(3,connection)
                    h=self.map(c,connection,extend=False,code=8)
                    self.assertEqual(h[25:27],(32768,1))
                    address=mapped_address(c,node=h[28])
                    content,mapping=read_owned_mapping(c,address,32768,"readonly-region")
                    self.assertEqual(content,payload);self.assertTrue(mapping[1].startswith("r--s"))
                    self.detach(c,token,connection)
                replay_instance(c.output)
            finally:os.close(parent)
        def test_07_noextend_then_exact_pagewise_extension(self):
            path=self.database()
            with self.carrier() as c:
                token,connection,_=self.attach(c,path)
                none=self.map(c,connection,index=1,extend=False)
                self.assertEqual(none[23:27],(0,0,0,0))
                self.assertEqual(Path(str(path)+"-shm").stat().st_size,3)
                h=self.map(c,connection,index=1);self.assertGreater(h[23],0)
                self.assertEqual(h[24:27],(0,32768,3))
                self.assertEqual(Path(str(path)+"-shm").stat().st_size,65536)
                self.detach(c,token,connection)
            events,_=trace_records(c.output)
            writes=[e for e in events if e["role"]==1 and e["operation"]==3]
            self.assertEqual([e["arguments"][1] for e in writes],[4095+4096*i for i in range(16)])
            self.assertTrue(all(e["arguments"][2]==1 and e["raw_return"]==1 for e in writes))
            replay_instance(c.output)
        def test_08_reallocation_copy_shared_bytes_and_view_reuse(self):
            path=self.database()
            with self.carrier() as c:
                token,connection,_=self.attach(c,path);a=self.map(c,connection)
                b=self.map(c,connection,index=1)
                again=self.map(c,connection,index=0,extend=False)
                self.assertEqual(a[23:27],again[23:27])
                self.assertNotEqual(a[23],b[23])
                fd=os.open(str(path)+"-shm",os.O_RDWR)
                try:self.assertEqual(os.pwrite(fd,b"region-one",32768),10)
                finally:os.close(fd)
                address=mapped_address(c,node=b[28],offset=32768)
                content,_=read_owned_mapping(c,address,10,"shared-modification")
                self.assertEqual(content,b"region-one")
                self.detach(c,token,connection)
            events,_=trace_records(c.output)
            self.assertTrue(any(e["role"]==3 and e["operation"]==2 for e in events))
            result=replay_instance(c.output)
            self.assertEqual(len(result["exact_retirements"]),1)
            self.assertEqual(result["exact_retirements"][0]["mask"],3)
        def test_09_single_process_heap_mapping_has_no_SHM_file(self):
            path=self.database()
            with self.carrier() as c:
                token,connection,h=self.attach(c,path,process=True)
                self.assertFalse(Path(str(path)+"-shm").exists())
                h=self.map(c,connection)
                address=mapped_address(c,node=h[28],flags=34)
                content,mapping=read_owned_mapping(c,address,32768,"anonymous-region")
                self.assertEqual(content,bytes(32768));self.assertTrue(mapping[1].startswith("rw-p"))
                c.call(4,connection,f=2,g=0,h=1);c.call(5,connection,f=2,g=0,h=1)
                self.detach(c,token,connection)
            events,_=trace_records(c.output)
            self.assertFalse(any(e["role"]==1 and e["operation"] in (17,23) for e in events))
            replay_instance(c.output)
        def test_10_distinct_nodes_keep_same_token_values_context_scoped(self):
            a=self.database("a");b=self.database("b")
            with self.carrier() as c:
                ta,ca,ha=self.attach(c,a);tb,cb,hb=self.attach(c,b)
                self.assertNotEqual(ha[9],hb[9])
                va=self.map(c,ca);vb=self.map(c,cb)
                self.assertNotEqual(va[28],vb[28])
                aa=mapped_address(c,node=va[28]);ab=mapped_address(c,node=vb[28])
                self.assertNotEqual(aa,ab)
                self.detach(c,ta,ca)
                self.assertEqual(self.map(c,cb,extend=False)[23:27],vb[23:27])
                self.detach(c,tb,cb)
            result=replay_instance(c.output)
            self.assertEqual(len(result["exact_retirements"]),2)
            self.assertEqual(len({x["sequence"] for x in result["actual_contexts"]}),6)
        def test_11_barrier_only_context_retires_without_map_or_address(self):
            path=self.database()
            with self.carrier() as c:
                token,connection,_=self.attach(c,path)
                for _ in range(3):c.call(15,connection)
                self.detach(c,token,connection)
            result=replay_instance(c.output)
            self.assertEqual(result["entries_by_role"]["2"],0)
            self.assertEqual(result["memory_primitive_operation_counts"],{"4":3})
            self.assertEqual(result["exact_retirements"][0]["mask"],2)
        def test_12_retired_contexts_are_never_reused_on_reattach(self):
            path=self.database()
            with self.carrier() as c:
                token,connection,first=self.attach(c,path);self.map(c,connection)
                self.detach(c,token,connection)
                token,connection,second=self.attach(c,path);self.map(c,connection)
                self.assertGreater(second[9],first[9]);self.detach(c,token,connection)
            result=replay_instance(c.output)
            self.assertEqual(len(result["exact_retirements"]),2)
            contexts=[row for row in result["actual_contexts"] if row["role"] in (2,3)]
            self.assertEqual(len(contexts),4);self.assertTrue(all(row["retired"] for row in contexts))
            self.assertEqual([row["sequence"] for row in contexts],[3,4,5,6])
        def test_13_actual_hardlink_identity_keeps_original_SHM_path(self):
            path=self.database();alias=self.fx/"alias";os.link(path,alias)
            with self.carrier() as c:
                ta,a,ha=self.attach(c,path);tb,b,hb=self.attach(c,alias)
                self.assertEqual(ha[9],hb[9]);self.assertFalse(Path(str(alias)+"-shm").exists())
                va=self.map(c,a);vb=self.map(c,b,extend=False)
                self.assertEqual(va[23:27],vb[23:27])
                self.detach(c,ta,a);self.detach(c,tb,b)
            replay_instance(c.output)
        def test_14_final_SHM_symlink_refused_by_actual_no_follow(self):
            path=self.database();target=self.fx/"untouched";target.write_bytes(b"keep-original")
            os.symlink(target,Path(str(path)+"-shm"))
            with self.carrier() as c:
                token,connection,_=self.attach(c,path,code=14,error=errno.ELOOP)
                self.assertEqual(connection,0);c.filesystem(8,a=token)
            self.assertEqual(target.read_bytes(),b"keep-original")
            replay_instance(c.output)
        def test_15_attached_DB_gateway_close_is_permanent_rejection(self):
            path=self.database()
            with self.carrier() as c:
                token,connection,_=self.attach(c,path)
                count=len(trace_records(c.output)[0])
                raw=transport.frame(16,session=c.session,call=c.call_number+1,
                    lease=1000+c.call_number+1,a=8,b=token)
                h,_=c.request(raw,label="attached-close-rejected")
                self.assertEqual(h[1],0xfffffffd)
                h,_=c.request(raw,label="poison-persists");self.assertEqual(h[1],0xfffffffd)
                self.assertEqual(len(trace_records(c.output)[0]),count)
            replay_instance(c.output)
        def test_16_retired_connection_cannot_reopen_mapping(self):
            path=self.database()
            with self.carrier() as c:
                token,connection,_=self.attach(c,path);self.map(c,connection)
                self.detach(c,token,connection)
                before=len(trace_records(c.output)[0])
                raw=transport.frame(14,session=c.session,call=c.call_number+1,
                    lease=1000+c.call_number+1,handle=connection,b=1,c=32768)
                h,_=c.request(raw,label="retired-connection-refused")
                self.assertEqual(h[1],0xfffffffd)
                self.assertEqual(len(trace_records(c.output)[0]),before)
            replay_instance(c.output)
        def test_17_actual_F_GETLK_EINTR_is_preserved_without_faked_retry(self):
            path,_,baseline=self.baseline()
            selected=trace_syscall_ordinal(baseline,"fcntl",lambda line:"F_GETLK" in line)
            save(self.case/"injection-selection.json",selected)
            launcher,log=self.tracer("fault",f"inject=fcntl:error=EINTR:when={selected['ordinal']}")
            with self.carrier(launcher=launcher) as c:
                token,connection,_=self.attach(c,path,code=3850,error=errno.EINTR)
                self.assertEqual(connection,0);c.filesystem(8,a=token)
            events,_=trace_records(c.output)
            actual=[e for e in events if e["role"]==1 and e["operation"]==23]
            self.assertEqual(len(actual),1);self.assertEqual(actual[0]["raw_return"],(-errno.EINTR)&MASK)
            self.assertIn("INJECTED",log.read_text());replay_instance(c.output)
        def test_18_actual_truncate_EINTR_retries_only_in_HIA(self):
            path,_,baseline=self.baseline()
            selected=trace_syscall_ordinal(baseline,"ftruncate",lambda line:True)
            save(self.case/"injection-selection.json",selected)
            launcher,log=self.tracer("fault",f"inject=ftruncate:error=EINTR:when={selected['ordinal']}")
            with self.carrier(launcher=launcher) as c:
                token,connection,_=self.attach(c,path);self.detach(c,token,connection)
            events,_=trace_records(c.output)
            truncates=[e for e in events if e["role"]==1 and e["operation"]==5]
            self.assertEqual([e["raw_return"] for e in truncates],[(-errno.EINTR)&MASK,0])
            self.assertIn("INJECTED",log.read_text());replay_instance(c.output)
        def test_19_actual_file_mmap_failure_preserves_partial_table_and_retry(self):
            path,_,baseline=self.baseline()
            selected=trace_syscall_ordinal(baseline,"mmap",
                lambda line:", 32768," in line and "MAP_SHARED" in line)
            save(self.case/"injection-selection.json",selected)
            launcher,log=self.tracer("fault",f"inject=mmap:error=ENOMEM:when={selected['ordinal']}")
            with self.carrier(launcher=launcher) as c:
                token,connection,_=self.attach(c,path)
                rejected=self.map(c,connection,code=5386,error=errno.ENOMEM)
                self.assertEqual(rejected[23:26],(0,0,0))
                accepted=self.map(c,connection);self.assertGreater(accepted[23],0)
                self.detach(c,token,connection)
            events,_=trace_records(c.output)
            errors=[e for e in events if e["role"]==3 and e["raw_return"]==(-errno.ENOMEM)&MASK]
            self.assertEqual(len(errors),1);self.assertEqual(errors[0]["operation"],1)
            self.assertIn("INJECTED",log.read_text());replay_instance(c.output)
        def test_20_actual_munmap_error_quarantines_context_to_process_exit(self):
            path,_,baseline=self.baseline()
            selected=trace_syscall_ordinal(baseline,"munmap",lambda line:", 32768)" in line)
            save(self.case/"injection-selection.json",selected)
            launcher,log=self.tracer("fault",f"inject=munmap:error=EIO:when={selected['ordinal']}")
            with self.carrier(launcher=launcher) as c:
                token,connection,_=self.attach(c,path);view=self.map(c,connection)
                address=mapped_address(c,node=view[28])
                self.detach(c,token,connection)
                content,_=read_owned_mapping(c,address,1,"quarantined-unmap")
                self.assertEqual(content,b"\0")
            result=replay_instance(c.output)
            self.assertEqual(result["exact_retirements"][0]["quarantined_mappings"],1)
            events,_=trace_records(c.output)
            matching=[e for e in events if e["role"]==3 and e["operation"]==3 and e["arguments"][0]==address]
            self.assertEqual(len(matching),1);self.assertEqual(matching[0]["raw_return"],(-errno.EIO)&MASK)
            self.assertIn("INJECTED",log.read_text())
            report["observations"]["actual_failed_unmap_quarantine_until_exit"]=True
        def test_21_actual_close_EINTR_does_not_repeat_or_claim_closed_fd(self):
            path,base,baseline=self.baseline()
            events,_=trace_records(base.output)
            getlk=next(e for e in events if e["role"]==1 and e["operation"]==23)
            shm_fd=getlk["arguments"][0]
            selected=trace_syscall_ordinal(baseline,"close",lambda line:line.startswith(f"close({shm_fd})"))
            save(self.case/"injection-selection.json",selected)
            launcher,log=self.tracer("fault",f"inject=close:error=EINTR:when={selected['ordinal']}")
            with self.carrier(launcher=launcher) as c:
                token,connection,_=self.attach(c,path);self.map(c,connection)
                parent=os.open(str(path)+"-shm",os.O_RDWR)
                try:
                    self.detach(c,token,connection)
                    self.assertEqual(query(parent)[0],fcntl.F_RDLCK)
                    _,fds=c.snapshot_owned_process("unknown-close-still-open")
                    self.assertTrue(any(row["target"]==str(path)+"-shm" for row in fds))
                finally:os.close(parent)
            parent=os.open(str(path)+"-shm",os.O_RDWR)
            try:self.assertEqual(query(parent)[0],fcntl.F_UNLCK)
            finally:os.close(parent)
            events,_=trace_records(c.output)
            errors=[e for e in events if e["role"]==1 and e["operation"]==8
                and e["raw_return"]==(-errno.EINTR)&MASK]
            self.assertEqual(len(errors),1)
            target=errors[0]["arguments"][0]
            self.assertEqual(sum(e["role"]==1 and e["operation"]==8 and e["arguments"][0]==target
                for e in events),1)
            self.assertIn("INJECTED",log.read_text());replay_instance(c.output)
            report["observations"]["actual_injected_close_unknown_until_exit"]=True
        def test_22_raw_reserved_header_poison_without_primitive(self):
            with self.carrier() as c:
                raw=bytearray(transport.frame(7,session=c.session,call=1,lease=1001,handle=1))
                struct.pack_into("<Q",raw,248,1)
                h,_=c.request(raw,label="nonzero-reserved");self.assertEqual(h[1],0xfffffffd)
                h,_=c.request(transport.frame(1,session=c.session,a=171,b=183,f=3,g=420,h=3),
                    label="permanent-refusal");self.assertEqual(h[1],0xfffffffd)
            self.assertEqual(trace_records(c.output)[0],[]);replay_instance(c.output)
    try:
        suite=unittest.defaultTestLoader.loadTestsFromTestCase(ActualJoin)
        ids=[test.id() for test in suite];assert len(ids)==len(set(ids))==EXPECTED_TESTS
        with (out/"tests.stderr.log").open("w") as stream:
            result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
        tests=dict(test_ids=ids,tests_loaded=len(ids),tests_run=result.testsRun,
            failures=[(t.id(),v) for t,v in result.failures],errors=[(t.id(),v) for t,v in result.errors],
            skipped=[(t.id(),v) for t,v in result.skipped],expected_failures=[(t.id(),v) for t,v in result.expectedFailures],
            unexpected_successes=[t.id() for t in result.unexpectedSuccesses])
        report["tests"]=tests
        assert result.wasSuccessful() and 0<result.testsRun==EXPECTED_TESTS
        assert not any(tests[key] for key in ("failures","errors","skipped","expected_failures","unexpected_successes"))
        report.update(status="PASS",native_entries=sum(row["native_entries"] for row in report["replay"]),
            vm_entries=sum(row["vm_entries"] for row in report["replay"]),
            actual_primitive_acks=sum(row["actual_primitive_acks"] for row in report["replay"]),
            process_traces=len(report["replay"]),
            entries_by_role={str(role):sum(row["entries_by_role"][str(role)] for row in report["replay"])
                for role in (1,2,3,4)},
            actual_child_reply_links=sum(len(row["exact_completed_child_links"]) for row in report["replay"]),
            actual_retirements=sum(len(row["exact_retirements"]) for row in report["replay"]))
    except BaseException as error:
        report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
        if (out/"tests.stderr.log").exists():print((out/"tests.stderr.log").read_text(),file=sys.stderr,flush=True)
    finally:
        after={}
        for path in pins:
            try:
                info=Path(path).lstat();assert stat.S_ISREG(info.st_mode)
                raw=Path(path).read_bytes()
                after[path]=dict(bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(info.st_mode))
            except BaseException as error:after[path]=dict(error_class=type(error).__name__,error=str(error))
        report.update(source_before=pins,source_after=after,source_pins_unchanged=pins==after)
        if pins!=after:report["status"]="FAIL"
        save(out/"summary.json",report)
        print(json.dumps(dict(status=report["status"],tests_run=report.get("tests",{}).get("tests_run"),
            native_entries=report.get("native_entries"),actual_primitive_acks=report.get("actual_primitive_acks"),
            process_traces=len(report["replay"]),python_router_used=False,whole_store_closed=False)),flush=True)
    return 0 if report["status"]=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
