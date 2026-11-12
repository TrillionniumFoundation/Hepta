"""Fresh DMS/FS5 private protocol and selected unix-VFS semantics corpus.
All primitive replies in this file are explicitly synthetic kernel controls.
The native differential executes the actual two HIA images, but this corpus
does not prove the future fixed DMS carrier, mmap, root admission or AgentStore.
"""
import struct,unittest
from pathlib import Path
from hepta.hia_agent_assembly import assemble_program,render_assembly
from hepta.hia_program_runtime import _Machine,_Owner,_View
from tools.generate_hia_agent_namespace_dms_lifetime import document,MAGIC,BAD,CHANNEL,FS_MAGIC
ROOT=Path(__file__).resolve().parents[1]
MASK=(1<<64)-1
REFUSED=0xfffffffd
def q(raw,index):return struct.unpack_from("<Q",raw,index*8)[0]
def put(raw,index,value):struct.pack_into("<Q",raw,index*8,value)
def packet(words,body=b""):
    assert len(words)<=32
    return struct.pack("<32Q",*(list(words)+[0]*(32-len(words))))+body
def channel(raw,origin=1,role=0,result=0,serial=0):
    return struct.pack("<8Q",CHANNEL,origin,role,result,len(raw),serial,0,0)+raw
def request(cmd,*,session=(71,83),call=1,action=0,lease=1001,handle=0,
            token=0,dev=0,ino=0,readonly=0,process=0,kind=0,offset=0,count=0,delete=0,body=b""):
    return packet([MAGIC,cmd,*session,call,action,lease,handle,token,dev,ino,
                   readonly,process,kind,offset,count,len(body),delete],body)
def fs_request(cmd=2,*,session=(941,953),call=1,system=0,operation=0,raw=0,a=0,b=0,c=0,d=0,lease=77,body=b""):
    return packet([FS_MAGIC,cmd,*session,call,system,operation,raw,a,b,c,d,len(body),lease],body)
def stat_bytes(item):
    raw=bytearray(144)
    struct.pack_into("<QQQIIIIQqqq",raw,0,item["dev"],item["ino"],1,item["mode"],item["uid"],item["gid"],0,0,item["size"],4096,8)
    return bytes(raw)

class NamespaceDmsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.programs={}
        cls.sources={}
        for role,name in (("dms","agent_namespace_dms_lifetime_r5.hiaasm"),("fs","agent_namespace_filesystem_r5.hiaasm")):
            raw=(ROOT/"examples/hia_bootstrap"/name).read_bytes()
            program=assemble_program(raw)
            cls.sources[role]=raw;cls.programs[role]=(program,program.as_dict()["functions"][0])
    def invoke_program(self,role,raw,work,capacity=256,steps=4000000):
        original=bytes(raw);out=bytearray(capacity)
        owners=[_Owner(-1,bytearray(original)),_Owner(-2,out),_Owner(-3,work)]
        program,entry=self.programs[role]
        machine=_Machine(program,steps,16<<20,None,64)
        code=machine.invoke(entry,[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
        self.assertEqual(bytes(owners[0].data),original)
        return code,struct.unpack_from("<32Q",out) if capacity>=256 else None,bytes(out)
    def invoke(self,raw,c,steps=4000000):
        return self.invoke_program("dms",raw,c["work"],c["capacity"],steps)
    def primitive(self,c,output):
        h=struct.unpack_from("<32Q",output);op=h[6]
        self.assertIn(op,(1,5,8,9,15,16,17,21,23,24))
        payload=b"";result=0
        args=h[8:12]
        path=output[256:256+h[16]]
        faults=c["faults"].get(op,[])
        error=faults.pop(0) if faults else 0
        if error:
            result=(-error)&MASK
        elif op==1:
            self.assertTrue(path.endswith(b"\0"))
            path=path[:-1]
            if path==b"/dev/null":
                item=dict(dev=1,ino=3,mode=0o20666,uid=0,gid=0,size=0)
            elif path not in c["files"]:
                if not args[1]&64:
                    item=None;result=(-2)&MASK
                else:
                    item=dict(dev=17,ino=10000+len(c["files"]),mode=0o100000|(args[2]&~c["umask"]&0o777),uid=c["euid"],gid=c["egid"],size=0)
                    c["files"][path]=item
            else:item=c["files"][path]
            if item is not None:
                if c["forced_fd"]:fd=c["forced_fd"].pop(0)
                else:
                    fd=0
                    while fd in c["fds"]:fd+=1
                self.assertNotIn(fd,c["fds"]);c["fds"][fd]=item;result=fd
        elif op==15:
            self.assertIn(args[0],c["fds"])
            payload=stat_bytes(c["fds"][args[0]])
        elif op==16:
            result=c["euid"]
        elif op==23:
            lock=c["getlk"].pop(0) if c["getlk"] else 2
            payload=struct.pack("<hh4xqqi4x",lock,0,args[2],args[3],0 if lock==2 else 222)
        elif op==5:
            self.assertIn(args[0],c["fds"]);c["fds"][args[0]]["size"]=args[1]
        elif op==8:
            self.assertIn(args[0],c["fds"]);c["fds"].pop(args[0])
        elif op==9:
            self.assertTrue(path.endswith(b"\0"))
            path=path[:-1]
            if path in c["files"]:del c["files"][path]
            else:result=(-2)&MASK
        elif op==21:
            self.assertIn(args[0],c["fds"])
            c["fds"][args[0]]["mode"]=(c["fds"][args[0]]["mode"]&~0o7777)|args[1]
        elif op==24:
            self.assertIn(args[0],c["fds"])
            c["fds"][args[0]]["uid"]=args[1];c["fds"][args[0]]["gid"]=args[2]
        c["syscalls"].append(dict(operation=op,arguments=args,path_hex=path.hex(),raw_return=result,
             payload_hex=payload.hex(),call=h[4],system=h[5],synthetic_kernel_control=True))
        return fs_request(3,session=c["fs_session"],call=h[4],system=h[5],operation=op,raw=result,lease=h[14],body=payload)
    def fs(self,c,original):
        raw=bytes(original);state=c["fs"]
        for _ in range(2048):
            code,h,out=self.invoke_program("fs",raw,state["work"],state["capacity"])
            state["serial"]+=1
            c["events"].append(dict(role="fs",return_code=code,call=h[4],system=h[5],operation=h[6],serial=state["serial"]))
            if code==2:
                need,capacity=h[17],h[18]
                self.assertTrue(need>len(state["work"]) or capacity>state["capacity"])
                self.assertLessEqual(max(need,capacity),16<<20,"finite fixture allocation bound only")
                if need>len(state["work"]):state["work"].extend(bytes(need-len(state["work"])))
                state["capacity"]=max(capacity,state["capacity"]);continue
            if code==1:
                raw=self.primitive(c,out);continue
            self.assertEqual(code,0,"FS5 refused fixture-issued input")
            return code,h,out,bytes(state["work"]),state["serial"]
        raise AssertionError("finite fixture FS continuation bound exhausted")
    def context(self,*,dbs=1,aliases=True,path=b"/private/db",uid=1001,gid=1001,mode=0o100600,umask=0,low_fds=False,existing_shm=False):
        c=dict(work=bytearray(2048),capacity=256,session=(71,83),call=0,fs_session=(941,953),
               fs=dict(work=bytearray(512),capacity=256,serial=0),events=[],syscalls=[],faults={},getlk=[],
               files={},fds={} if low_fds else {0:None,1:None,2:None},forced_fd=[],euid=uid,egid=gid,umask=umask,
               dbs=[],grows=[],child_packets=[],issued=0)
        self.fs(c,fs_request(1,session=c["fs_session"],call=0,lease=0))
        primary=dict(dev=17,ino=91,mode=mode,uid=uid,gid=gid,size=8192)
        for i in range(dbs):
            p=path if i==0 else path+b".alias"+str(i).encode()
            item=primary if aliases else dict(primary,ino=91+i)
            c["files"][p]=item;c["forced_fd"].append(100+i)
            call=q(c["fs"]["work"],4)+1
            _,h,_,_,_=self.fs(c,fs_request(session=c["fs_session"],call=call,operation=1,a=0,b=2,c=0,lease=900+i,body=p))
            self.assertEqual(h[7],0)
            c["dbs"].append(dict(token=h[8],dev=item["dev"],ino=item["ino"],path=p))
        if existing_shm:c["files"][path+b"-shm"]=dict(primary,ino=333,size=32768)
        c["begin"]=len(c["syscalls"])
        words=[MAGIC,1,*c["session"],0,0,0,0,*c["fs_session"],q(c["fs"]["work"],4),
               q(c["fs"]["work"],5),c["fs"]["serial"],3,420,1]
        code,h,_=self.advance(c,channel(packet(words)))
        self.assertEqual((code,h[6],h[7]),(0,0,0))
        return c
    def calls(self,c):return c["syscalls"][c["begin"]:]
    def ops(self,c):return [x["operation"] for x in self.calls(c)]
    def advance(self,c,raw,stop=False):
        raw=bytes(raw)
        for _ in range(4096):
            code,h,out=self.invoke(raw,c)
            if code==2:
                need,capacity=h[10],h[11]
                self.assertTrue(need>len(c["work"]) or capacity>c["capacity"])
                self.assertLessEqual(max(need,capacity),16<<20,"finite fixture bound only; no engine row/path quota")
                c["grows"].append(dict(origin=q(raw,1),phase=h[12],required_workspace=need,required_output=capacity,
                                       child_invocations=len(c["events"]),input_hex=raw.hex()))
                if need>len(c["work"]):c["work"].extend(bytes(need-len(c["work"])))
                c["capacity"]=max(c["capacity"],capacity)
                continue
            if code==1:
                self.assertEqual((h[6],h[8]),(1,h[16]))
                original=out[256:256+h[16]];self.assertEqual(len(original),h[16])
                c["issued"]+=1
                result,_,output,work,serial=self.fs(c,original)
                body=original+output+work
                ack=packet([MAGIC,8,*c["session"],h[4],h[5],h[9],1,len(original),len(output),len(work),result,serial,0,0,0,len(body)],body)
                raw=channel(ack,2,1,result,serial);c["child_packets"].append(raw);c["pending"]=raw
                if stop:return raw
                continue
            self.assertIn(code,(0,REFUSED))
            c["last"]=h;c["last_output"]=out
            return code,h,out
        raise AssertionError("finite fixture DMS continuation bound exhausted")
    def start(self,c,command,handle=0,*,db=0,readonly=0,process=0,kind=0,offset=0,count=0,delete=0,stop=False):
        c["call"]+=1
        fields={}
        if command==2:
            item=c["dbs"][db]
            fields=dict(token=item["token"],dev=item["dev"],ino=item["ino"],body=item["path"],readonly=readonly,process=process)
        raw=request(command,session=c["session"],call=c["call"],lease=c["call"]+1000,handle=handle,
                    kind=kind,offset=offset,count=count,delete=delete,**fields)
        c["original"]=channel(raw)
        return self.advance(c,c["original"],stop=stop)
    def attached(self,c,db=0,*,readonly=0,process=0,code=0):
        rc,h,_=self.start(c,2,db=db,readonly=readonly,process=process)
        self.assertEqual((rc,h[6]),(0,code));self.assertGreater(h[8],0)
        return h[8]
    def lock(self,c,handle,*,kind=2,offset=0,count=1,code=0):
        rc,h,_=self.start(c,4,handle,kind=kind,offset=offset,count=count)
        self.assertEqual((rc,h[6]),(0,code));return h
    def unlock(self,c,handle,*,kind=2,offset=0,count=1,code=0):
        rc,h,_=self.start(c,5,handle,kind=kind,offset=offset,count=count)
        self.assertEqual((rc,h[6]),(0,code));return h
    def detach(self,c,handle,delete=0):
        code,h,_=self.start(c,6,handle,delete=delete);self.assertEqual((code,h[6]),(0,0));return h
    def refuse(self,c,raw,reason=None,steps=4000000):
        before_events=len(c["events"])
        code,h,_=self.invoke(bytes(raw),c,steps)
        self.assertEqual(code,REFUSED)
        if reason is not None:self.assertEqual(h[13],reason)
        stable=bytes(c["work"])
        code,_,_=self.invoke(channel(packet([MAGIC,1,*c["session"]])),c)
        self.assertEqual(code,REFUSED);self.assertEqual(bytes(c["work"]),stable)
        self.assertEqual(len(c["events"]),before_events)
    def test_01_regeneration_and_original_bootstrap_limits(self):
        d=document()
        self.assertEqual(render_assembly(d).encode(),self.sources["dms"])
        self.assertLessEqual(len(d["functions"]),128)
        self.assertLessEqual(sum(len(f["blocks"]) for f in d["functions"]),1536)
        self.assertLessEqual(max(len(f["blocks"]) for f in d["functions"]),256)
        self.assertLessEqual(sum(len(b["ops"]) for f in d["functions"] for b in f["blocks"]),8192)
        self.assertLessEqual(max(len(b["params"]) for f in d["functions"] for b in f["blocks"]),16)
    def test_02_first_node_exclusive_truncate_three_shared(self):
        c=self.context();h=self.attached(c)
        self.assertEqual(self.ops(c),[15,1,15,16,23,17,5,17])
        locks=[x["arguments"][1:] for x in self.calls(c) if x["operation"]==17]
        self.assertEqual(locks,[(1,128,1),(0,128,1)])
        self.assertEqual(c["files"][b"/private/db-shm"]["size"],3)
        self.assertEqual(c["last"][10:14],(1,0,0,1))
        self.lock(c,h);self.unlock(c,h);self.detach(c,h)
        self.assertEqual(self.ops(c)[-1],8)
    def test_03_same_inode_cached_node_has_no_extra_open_or_stat(self):
        c=self.context(dbs=2);a=self.attached(c,0);before=len(self.calls(c));b=self.attached(c,1)
        self.assertEqual(len(self.calls(c)),before);self.assertEqual(c["last"][10],2)
        self.assertNotEqual(a,b);self.assertNotIn(b"/private/db.alias1-shm",c["files"])
        self.detach(c,a,1);self.assertEqual(len(self.calls(c)),before)
        self.detach(c,b,1);self.assertEqual(self.ops(c)[-2:],[9,8])
        self.assertEqual(bytes.fromhex(self.calls(c)[-2]["path_hex"]),b"/private/db-shm")
    def test_04_shared_reference_unlock_keeps_other_connection(self):
        c=self.context(dbs=2);a=self.attached(c,0);b=self.attached(c,1)
        self.lock(c,a,kind=1,offset=3);before=len(self.calls(c));self.lock(c,b,kind=1,offset=3)
        self.assertEqual(len(self.calls(c)),before)
        self.unlock(c,a,kind=1,offset=3);self.assertEqual(len(self.calls(c)),before)
        self.unlock(c,b,kind=1,offset=3);self.assertEqual(self.ops(c)[-1],17)
        self.assertEqual(self.calls(c)[-1]["arguments"][1:],(2,123,1))
        self.detach(c,a);self.detach(c,b)
    def test_05_local_exclusive_busy_has_no_syscall_or_mutation(self):
        c=self.context(dbs=2);a=self.attached(c,0);b=self.attached(c,1)
        self.lock(c,a);before=len(self.calls(c));self.lock(c,b,code=5)
        self.assertEqual(len(self.calls(c)),before);self.assertEqual(c["last"][14:16],(0,0))
        self.unlock(c,a);self.lock(c,b);self.unlock(c,b);self.detach(c,a);self.detach(c,b)
    def test_06_all_selected_setlk_errno_leave_masks_unchanged(self):
        for error in (4,5,11,13,22):
            with self.subTest(error=error):
                c=self.context();h=self.attached(c);c["faults"][17]=[error]
                before=len(self.calls(c));last=self.lock(c,h,code=5)
                self.assertEqual(last[7],error);self.assertEqual(last[14:16],(0,0))
                self.assertEqual(len(self.calls(c)),before+1)
                self.lock(c,h);c["faults"][17]=[error]
                last=self.unlock(c,h,code=5);self.assertEqual(last[15],1)
                self.unlock(c,h);self.detach(c,h)
    def test_07_foreign_dms_writer_does_not_attempt_shared(self):
        c=self.context();c["getlk"]=[1]
        code,h,_=self.start(c,2)
        self.assertEqual((code,h[6],h[8]),(0,5,0))
        self.assertNotIn(17,self.ops(c));self.assertEqual(self.ops(c)[-1],8)
        self.assertEqual(q(c["work"],11),0);self.assertEqual(q(c["work"],12),0)
    def test_08_readonly_cantinit_attaches_and_remains_live(self):
        c=self.context(existing_shm=True);a=self.attached(c,readonly=1,code=1288)
        self.assertEqual(c["last"][10:14],(1,1,1,0))
        self.assertNotIn(17,self.ops(c));self.assertNotIn(5,self.ops(c))
        self.detach(c,a);self.assertEqual(self.ops(c)[-1],8)
    def test_09_cached_readonly_node_returns_ok_and_retry_uses_same_fd(self):
        c=self.context(dbs=2,existing_shm=True);a=self.attached(c,0,readonly=1,code=1288)
        before=len(self.calls(c));b=self.attached(c,1)
        self.assertEqual(len(self.calls(c)),before);self.assertEqual(c["last"][10:14],(2,1,1,0))
        c["getlk"]=[0];code,h,_=self.start(c,3,a)
        self.assertEqual((code,h[6],h[10:14]),(0,0,(2,1,0,1)))
        self.assertEqual(self.ops(c)[-2:],[23,17])
        self.assertEqual(self.calls(c)[-1]["arguments"][1:],(0,128,1))
        self.detach(c,a);self.detach(c,b)
    def test_10_rw_error_falls_back_to_readonly_existing_file(self):
        c=self.context(existing_shm=True);c["faults"][1]=[30];c["getlk"]=[0]
        a=self.attached(c)
        opens=[x for x in self.calls(c) if x["operation"]==1]
        self.assertEqual([x["arguments"][1] for x in opens],[655426,655360])
        self.assertEqual(c["last"][11],1);self.detach(c,a)
    def test_11_both_open_errors_preserve_last_cantopen_and_session(self):
        c=self.context();c["faults"][1]=[13,2]
        rc,h,_=self.start(c,2);self.assertEqual((rc,h[6],h[7],h[8]),(0,14,2,0))
        self.assertEqual(q(c["work"],11),0);self.assertEqual(q(c["work"],12),0)
        a=self.attached(c);self.detach(c,a)
    def test_12_uid_zero_owns_fchown_decision_and_ignored_failure(self):
        for uid in (0,1001):
            with self.subTest(uid=uid):
                c=self.context(uid=uid,gid=43);c["faults"][24]=[1]
                a=self.attached(c)
                self.assertEqual(self.ops(c).count(24),1 if uid==0 else 0)
                if uid==0:
                    row=next(x for x in self.calls(c) if x["operation"]==24)
                    self.assertEqual(row["arguments"][1:3],(0,43));self.assertEqual(c["last"][17],1)
                self.detach(c,a)
    def test_13_open_and_truncate_eintr_retry_are_specific(self):
        c=self.context();c["faults"][1]=[4,4];c["faults"][5]=[4,4]
        a=self.attached(c)
        self.assertEqual(self.ops(c).count(1),3);self.assertEqual(self.ops(c).count(5),3)
        c["faults"][17]=[4];before=len(self.calls(c));self.lock(c,a,code=5)
        self.assertEqual(len(self.calls(c)),before+1);self.detach(c,a)
    def test_14_low_descriptor_fillers_match_original_open_loop(self):
        c=self.context(low_fds=True);a=self.attached(c)
        fillers=[x for x in self.calls(c) if x["operation"]==1 and bytes.fromhex(x["path_hex"])==b"/dev/null"]
        self.assertEqual(len(fillers),3);self.assertEqual([x["arguments"][1] for x in fillers],[0,0,0])
        self.assertEqual(c["last"][18],3)
        self.assertEqual([x["arguments"][0] for x in self.calls(c) if x["operation"]==8],[0,1,2])
        self.detach(c,a);self.assertEqual(self.calls(c)[-1]["arguments"][0],3)
        self.assertTrue(all(x in c["fds"] for x in (0,1,2)))
    def test_15_database_fstat_error_precedes_node_and_open(self):
        c=self.context();c["faults"][15]=[5]
        code,h,_=self.start(c,2);self.assertEqual((code,h[6],h[7]),(0,1802,5))
        self.assertEqual(self.ops(c),[15]);self.assertEqual((q(c["work"],11),q(c["work"],12)),(0,0))
        a=self.attached(c);self.detach(c,a)
    def test_16_permission_stat_and_chmod_failure_are_ignored(self):
        c=self.context(umask=0o777);c["faults"][21]=[1]
        a=self.attached(c);self.assertEqual(self.ops(c).count(21),1);self.assertEqual(c["last"][17],1);self.detach(c,a)
        c=self.context(umask=0o777);c["faults"][15]=[0,5]
        a=self.attached(c);self.assertNotIn(21,self.ops(c));self.detach(c,a)
    def test_17_truncate_error_survives_cleanup_close_error(self):
        c=self.context();c["faults"][5]=[5];c["faults"][8]=[4]
        code,h,_=self.start(c,2)
        self.assertEqual((code,h[6],h[7],h[17]),(0,4618,5,4))
        self.assertEqual(self.ops(c).count(8),1);self.assertEqual((q(c["work"],11),q(c["work"],12)),(0,0))
    def test_18_dms_getlk_and_both_setlk_errors_have_exact_classes(self):
        c=self.context();c["faults"][23]=[5]
        _,h,_=self.start(c,2);self.assertEqual((h[6],h[7]),(3850,5));self.assertEqual(self.ops(c)[-1],8)
        for stages in ([5],[0,5]):
            c=self.context();c["faults"][17]=list(stages)
            _,h,_=self.start(c,2);self.assertEqual((h[6],h[7]),(5,5));self.assertEqual(self.ops(c)[-1],8)
    def test_19_nonlast_delete_does_not_unlink_and_last_no_delete_keeps_path(self):
        c=self.context(dbs=2);a=self.attached(c,0);b=self.attached(c,1);before=len(self.calls(c))
        self.detach(c,a,1);self.assertEqual(len(self.calls(c)),before)
        self.detach(c,b,0);self.assertIn(b"/private/db-shm",c["files"]);self.assertNotIn(9,self.ops(c))
        self.detach(c,0,1);self.assertEqual(self.ops(c)[-1],8)
    def test_20_last_close_ignored_error_consumes_connection_once(self):
        c=self.context();a=self.attached(c);c["faults"][8]=[4]
        h=self.detach(c,a,1);self.assertEqual(h[17],4)
        self.assertEqual(self.ops(c)[-2:],[9,8]);self.assertEqual((q(c["work"],11),q(c["work"],12)),(0,0))
        self.refuse(c,channel(request(6,session=c["session"],call=c["call"]+1,lease=999,handle=a)),18)
    def test_21_private_user_cannot_issue_child_or_unknown_channel(self):
        for cmd in (8,9):
            c=self.context()
            self.refuse(c,channel(request(cmd,session=c["session"])),46)
        c=self.context();raw=bytearray(channel(request(2,session=c["session"],token=1,body=b"x")))
        put(raw,2,1);self.refuse(c,raw,46)
    def test_22_ack_nonce_source_role_serial_and_action_are_bound(self):
        for change in ("nonce","source","role","serial","action"):
            with self.subTest(change=change):
                c=self.context();raw=bytearray(self.start(c,2,stop=True))
                if change=="nonce":put(raw,10,q(raw,10)+1)
                if change=="source":raw[64+256+16]^=1
                if change=="role":put(raw,2,2)
                if change=="serial":put(raw,5,q(raw,5)+1)
                if change=="action":put(raw,13,q(raw,13)+1)
                self.refuse(c,raw)
    def test_23_grow_keeps_immutable_input_and_does_not_reissue_peer(self):
        c=self.context(dbs=18,path=b"/private/"+b"x"*2048)
        handles=[self.attached(c,i) for i in range(18)]
        self.assertEqual(c["last"][10],18)
        self.assertTrue(any(x["origin"]==1 for x in c["grows"]))
        self.assertTrue(any(x["origin"]==2 for x in c["grows"]))
        self.assertEqual(self.ops(c).count(1),1)
        for h in handles:self.detach(c,h)
        previous=q(c["work"],9);again=self.attached(c,0)
        self.assertGreater(again,previous-1);self.detach(c,again)
    def test_24_short_buffers_and_permanent_poison(self):
        raw=channel(packet([MAGIC,1,71,83,0,0,0,0,941,953,0,0,0,3,420,1]))
        for size in (0,7,8,511,2047):
            work=bytearray(size);code,_,out=self.invoke_program("dms",raw,work,256)
            self.assertEqual((code,out),(REFUSED,bytes(256)))
            if size>=8:self.assertEqual(q(work,0),BAD)
        work=bytearray(2048);code,_,out=self.invoke_program("dms",raw,work,255)
        self.assertEqual((code,out),(REFUSED,bytes(255)));self.assertEqual(q(work,0),BAD)
    def test_25_malformed_later_arena_and_stage_op_are_permanent(self):
        c=self.context();a=self.attached(c)
        first=2048;second=first+q(c["work"],first//8)
        self.assertLess(second,q(c["work"],10));put(c["work"],second//8,0)
        self.refuse(c,channel(request(7,session=c["session"],call=c["call"]+1,lease=991,handle=a)))
        c=self.context();raw=self.start(c,2,stop=True)
        put(c["work"],14,117)
        self.refuse(c,raw,4)
    def test_26_natural_u64_counters_never_wrap(self):
        for index in (4,5,6,7,9):
            with self.subTest(index=index):
                c=self.context();put(c["work"],index,MASK)
                raw=request(2,session=c["session"],call=1,lease=999,token=c["dbs"][0]["token"],
                            dev=17,ino=91,body=b"/private/db")
                self.refuse(c,channel(raw))
    def test_27_process_lock_node_bypasses_physical_shm_only(self):
        c=self.context(dbs=2);a=self.attached(c,0,process=1);b=self.attached(c,1,process=1)
        self.assertEqual(self.ops(c),[15])
        self.lock(c,a);self.lock(c,b,code=5);self.unlock(c,a);self.lock(c,b);self.unlock(c,b)
        self.detach(c,a);self.detach(c,b);self.assertEqual(self.ops(c),[15])
        self.assertNotIn(b"/private/db-shm",c["files"])
    def test_28_duplicate_db_binding_and_unknown_outcome_do_not_publish(self):
        c=self.context();self.attached(c)
        self.refuse(c,channel(request(2,session=c["session"],call=c["call"]+1,lease=999,token=c["dbs"][0]["token"],
                            dev=17,ino=91,body=b"/private/db")),50)
        c=self.context();self.start(c,2,stop=True)
        raw=request(9,session=c["session"],call=c["call"],action=q(c["work"],5),lease=c["call"]+1000)
        self.refuse(c,channel(raw,3,1),7)

    def test_29_exhausted_fs_counters_preserve_cached_attach_and_first_errors(self):
        # A cached same-inode attach is pure: no FS action, call or syscall
        # sequence is consumed, even if one of those counters is exhausted.
        for index in (5,6,7):
            with self.subTest(index=index,case="cached_pure_attach"):
                c=self.context(dbs=2);first=self.attached(c,0)
                before_events=len(c["events"]);before_calls=list(self.calls(c))
                before_fs=bytes(c["fs"]["work"]);before_serial=c["fs"]["serial"]
                put(c["work"],index,MASK)
                second=self.attached(c,1)
                self.assertNotEqual(first,second)
                self.assertEqual(c["last"][10],2)
                self.assertEqual(q(c["work"],index),MASK)
                self.assertEqual(len(c["events"]),before_events)
                self.assertEqual(self.calls(c),before_calls)
                self.assertEqual(bytes(c["fs"]["work"]),before_fs)
                self.assertEqual(c["fs"]["serial"],before_serial)
            with self.subTest(index=index,case="allocation_overflow_precedes_fs"):
                c=self.context();put(c["work"],index,MASK);put(c["work"],9,MASK)
                raw=request(2,session=c["session"],call=1,lease=999,
                            token=c["dbs"][0]["token"],dev=17,ino=91,body=b"/private/db")
                self.refuse(c,channel(raw),16)
            with self.subTest(index=index,case="duplicate_binding_precedes_fs"):
                c=self.context();self.attached(c);put(c["work"],index,MASK)
                raw=request(2,session=c["session"],call=c["call"]+1,lease=999,
                            token=c["dbs"][0]["token"],dev=17,ino=91,body=b"/private/db")
                self.refuse(c,channel(raw),50)

if __name__=="__main__":unittest.main()
