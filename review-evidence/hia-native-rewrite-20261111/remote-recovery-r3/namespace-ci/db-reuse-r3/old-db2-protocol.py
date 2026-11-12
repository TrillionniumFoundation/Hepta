"""New main database inode owner controls, exact selected SQLite C reference.

The reference shared object is built from fourteen unchanged policy functions.
Only the syscall provider is controlled; it never consults the HIA result.
These are private receipt semantics, not real filesystem / ordinary Store proof.
"""
from __future__ import annotations
import ctypes,json,os,random,struct,unittest
from pathlib import Path
from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program_runtime import _Machine,_Owner,_View
MAGIC=int.from_bytes(b"HIANDB01","little");BADMAGIC=int.from_bytes(b"HIADBB01","little")
FS=int.from_bytes(b"HIANFR03","little");BAD=0xfffffffd;MAX=(1<<64)-1
PENDING=1073741824;RESERVED=PENDING+1;SHARED=PENDING+2
def q(raw,word):return struct.unpack_from("<Q",raw,word*8)[0]
def setq(raw,word,value):struct.pack_into("<Q",raw,word*8,value)
def packet(command,nonce=(101,202),caller=0,action=0,handle=0,op=0,value=0,flags=0,lease=0,payload=b"",initial=None):
    words=[0]*32
    words[:10]=[MAGIC,command,*nonce,caller,action,handle,op,value,flags]
    if initial is not None:words[10:14]=initial
    words[15]=lease;words[16]=len(payload)
    return struct.pack("<32Q",*words)+payload
class Oracle:
    def __init__(self,path):
        self.lib=ctypes.CDLL(str(path))
        for name,args,ret in (
            ("oracle_reset",[ctypes.c_uint64]*5,None),
            ("oracle_add_fault",[ctypes.c_uint64]*3,ctypes.c_int),
            ("oracle_getlk_kind",[ctypes.c_int],ctypes.c_int),
            ("oracle_register",[ctypes.c_uint64]*3,ctypes.c_int),
            ("oracle_lock",[ctypes.c_uint64,ctypes.c_int],ctypes.c_int),
            ("oracle_unlock",[ctypes.c_uint64,ctypes.c_int],ctypes.c_int),
            ("oracle_reserved",[ctypes.c_uint64,ctypes.POINTER(ctypes.c_int)],ctypes.c_int),
            ("oracle_close",[ctypes.c_uint64],ctypes.c_int),
            ("oracle_events",[],ctypes.c_uint64),("oracle_files",[],ctypes.c_uint64),
            ("oracle_event",[ctypes.c_uint64,ctypes.POINTER(ctypes.c_uint64)],ctypes.c_int),
            ("oracle_file",[ctypes.c_uint64,ctypes.POINTER(ctypes.c_uint64)],ctypes.c_int),
            ("oracle_group",[ctypes.POINTER(ctypes.c_uint64)],ctypes.c_int),
            ("oracle_unused",[ctypes.c_uint64,ctypes.POINTER(ctypes.c_uint64)],ctypes.c_int),
            ("oracle_abi",[],ctypes.c_uint64)):
            f=getattr(self.lib,name);f.argtypes=args;f.restype=ret
        assert self.lib.oracle_abi()==int.from_bytes(b"HIADCO01","little")
    def row(self,kind,index,count):
        out=(ctypes.c_uint64*count)()
        rc=getattr(self.lib,"oracle_"+kind)(index,out) if index is not None else getattr(self.lib,"oracle_"+kind)(out)
        assert rc==0,(kind,index,rc)
        return tuple(out)
    def events(self,start=0):
        return [self.row("event",i,8) for i in range(start,self.lib.oracle_events())]
    def snapshot(self):
        group=self.row("group",None,10)
        return dict(group=group,files=[self.row("file",i,6) for i in range(self.lib.oracle_files())],
                    deferred=[self.row("unused",i,2) for i in range(group[8])])
    def call(self,command,handle,value,flags,next_handle):
        if command==2:result=next_handle;rc=self.lib.oracle_register(next_handle,value,flags)
        elif command==3:result=handle;rc=self.lib.oracle_lock(handle,value)
        elif command==4:result=handle;rc=self.lib.oracle_unlock(handle,value)
        elif command==5:
            found=ctypes.c_int(-1);rc=self.lib.oracle_reserved(handle,ctypes.byref(found));result=found.value
        elif command==6:result=handle;rc=self.lib.oracle_close(handle)
        else:raise AssertionError(command)
        assert rc>=0,("invalid reference fixture command",command,handle,value,flags)
        if command==2 and rc:result=0
        return rc,result

class NamespaceDBNodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source=Path(os.environ["HIA_NAMESPACE_DB_NODE_SOURCE"]).read_bytes()
        cls.program=assemble_program(source.decode("utf-8"))
        cls.oracle=Oracle(Path(os.environ["HIA_NAMESPACE_DB_NODE_ORACLE"]))
    def observe(self,value):pass
    def invoke_program(self,role,raw,work,capacity=288,steps=4000000):
        self.assertEqual(role,"db_node")
        original=bytes(raw);pre=bytes(work);pre_output=bytes(capacity)
        owners=[_Owner(-1,bytearray(original)),_Owner(-2,bytearray(pre_output)),_Owner(-3,bytearray(pre))]
        machine=_Machine(self.program,steps,32<<20,None,64)
        result=machine.invoke(self.program.as_dict()["functions"][0],[
            _View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
        self.assertEqual(bytes(owners[0].data),original)
        work[:]=owners[2].data;output=bytes(owners[1].data)
        if capacity>=256:self.assertEqual(output[256:],bytes(capacity-256))
        return result,struct.unpack_from("<32Q",output) if capacity>=256 else (),output
    def invoke(self,c,raw,capacity=288):
        return self.invoke_program("db_node",raw,c["work"],capacity)
    def context(self,*,flags=0,dev=7,ino=11,uid=0,gid=0,mode=0o100600,size=1536):
        self.oracle.lib.oracle_reset(dev,ino,mode,uid,gid)
        c=dict(nonce=(101,202),fsnonce=(303,404),call=0,fs_call=0,fs_sys=0,lease=900,
               work=bytearray(size),next_handle=1,dev=dev,ino=ino,mode=mode,uid=uid,gid=gid,
               last_events=[],commands=[],closed=False,flags=flags)
        raw=packet(1,nonce=c["nonce"],initial=(*c["fsnonce"],0,0))
        result=self.invoke(c,raw);self.assertEqual(result[0],0)
        self.assertEqual((q(c["work"],0),q(c["work"],1)),(MAGIC,1))
        return c
    def make_request(self,c,command,handle=0,value=0,flags=0):
        c["call"]+=1;c["lease"]+=1
        return packet(command,c["nonce"],c["call"],handle=handle,value=value,flags=flags,lease=c["lease"])
    def step(self,c,raw):
        result=self.invoke(c,raw)
        while result[0]==2:
            required=result[1][21]
            self.assertGreater(required,len(c["work"]));self.assertEqual(required%128,0)
            prefix=bytes(c["work"]);c["work"].extend(bytes(required-len(prefix)))
            self.assertEqual(bytes(c["work"][:len(prefix)]),prefix)
            result=self.invoke(c,raw)
        return result
    def receipt(self,c,event,words):
        number,op,fd,kind,start,length,raw_result,error=event
        self.assertEqual(words[1],1)
        self.assertEqual((words[7],words[16],words[17],words[18],words[19]),(op,fd,kind,start,length))
        self.assertEqual((words[2],words[3],words[4],words[11]),(*c["nonce"],c["call"],c["lease"]))
        c["fs_call"]+=3;c["fs_sys"]+=5
        fsreq=[0]*32;fsreq[:14]=[FS,2,*c["fsnonce"],c["fs_call"],0,op,0,fd,kind,start,length,0,words[5]]
        out=[0]*32;out[:8]=[FS,0,*c["fsnonce"],c["fs_call"],c["fs_sys"],op,error]
        out[14]=words[5];out[15]=1;out[20]=1;out[21]=1000;out[22]=3
        payload=b""
        if error==0 and op==15:
            actual=bytearray(144)
            struct.pack_into("<QQQIII",actual,0,c["dev"],c["ino"],1,c["mode"],c["uid"],c["gid"])
            struct.pack_into("<q",actual,48,4096)
            payload=bytes(actual);out[8:14]=[c["dev"],c["ino"],c["mode"],c["uid"],c["gid"],4096];out[24]=1
        elif error==0 and op==23:
            got=c.get("getlk",2);pid=0 if got==2 else 731
            payload=struct.pack("<hh4xqqi4x",got,0,RESERVED,1,pid)
            out[8:14]=[got,0,RESERVED,1,pid,0]
        out[16]=len(payload)
        body=struct.pack("<32Q",*fsreq)+struct.pack("<32Q",*out)+payload
        reply=packet(7,c["nonce"],c["call"],words[5],words[6],words[7],lease=c["lease"],payload=body)
        self.observe(dict(kind="controlled_FS_receipt",event=event,request_words=words,receipt_hex=reply.hex(),actual_syscalls=0))
        return reply
    def compare(self,c):
        reference=self.oracle.snapshot();g=reference["group"];w=c["work"]
        retired=q(w,1)==4;assigned=q(w,15)!=0 and not retired
        self.assertEqual(int(assigned),g[0])
        self.assertEqual((q(w,8),q(w,9),q(w,10),q(w,11),q(w,12)),g[3:8])
        if assigned:self.assertEqual((q(w,13),q(w,14)),g[1:3])
        rows={}
        for at in range(1536,1536+q(w,7)*128,128):
            words=struct.unpack_from("<16Q",w,at)
            if words[2]:rows[words[0]]=words
            else:self.assertEqual(words,(0,)*16)
        active={r[0]:r for r in reference["files"] if r[2]}
        actual={handle:r for handle,r in rows.items() if r[2]==1}
        self.assertEqual(set(actual),set(active))
        for handle,r in actual.items():
            item=active[handle];self.assertEqual((r[0],r[1],r[2],r[3],r[4]|r[5]<<1,r[6]),
                (item[0],item[1],1,item[4],item[3],item[5]))
            self.assertEqual((r[9],r[10]),(c["mode"],c["uid"]))
            self.assertEqual(r[11:],(0,)*5)
        deferred=[];cursor=q(w,34);seen=set()
        while cursor:
            self.assertNotIn(cursor,seen);seen.add(cursor)
            r=struct.unpack_from("<16Q",w,cursor)
            self.assertEqual(r[2],2)
            deferred.append((r[1],1 if r[4] else 2));cursor=r[7]
        self.assertEqual(deferred,reference["deferred"])
        self.assertEqual(len(deferred),g[8])
        self.observe(dict(kind="exact_C_semantic_state",reference=reference,workspace_hex=bytes(w).hex(),
            comparison_scope="complete logical file rows, inode counters/lock, LIFO deferred descriptors; separate private issuance metadata",
            private_framing_is_not_OS_authentication=True))
    def run_command(self,c,command,handle=0,value=0,flags=0):
        start=self.oracle.lib.oracle_events()
        expected=self.oracle.call(command,handle,value,flags,c["next_handle"])
        events=self.oracle.events(start);reference=self.oracle.snapshot()
        raw=self.make_request(c,command,handle,value,flags)
        result=self.step(c,raw);index=0
        while result[0]==1:
            self.assertLess(index,len(events),("HIA emitted unrequested syscall",command,events,result[1]))
            reply=self.receipt(c,events[index],result[1]);index+=1
            result=self.invoke(c,reply)
        self.assertEqual(index,len(events),("missing original syscall",command,events,result))
        self.assertEqual(result[0],0,("HIA refusal",command,result[1]))
        self.assertEqual((result[1][8],result[1][10]),expected)
        if command==2 and expected[0]==0:c["next_handle"]+=1
        close_errors=[event[7] for event in events if event[1]==8 and event[7]]
        self.assertEqual(result[1][20],close_errors[0] if close_errors else 0)
        c["last_events"]=events;c["last_result"]=result
        c["commands"].append([command,handle,value,flags,expected[0],expected[1]])
        self.observe(dict(kind="independent_C_operation",command=command,handle=handle,value=value,flags=flags,
            input_hex=raw.hex(),expected_code=expected[0],expected_result=expected[1],
            full_original_events=events,reference_after=reference,actual_output_hex=result[2].hex()))
        self.compare(c)
        return result[1]
    def register(self,c,token,flags=0):
        out=self.run_command(c,2,value=token,flags=flags);self.assertEqual(out[8],0);return out[10]
    def lock(self,c,h,target):return self.run_command(c,3,h,target)
    def unlock(self,c,h,target=0):return self.run_command(c,4,h,target)
    def reserved(self,c,h,kind=2):
        c["getlk"]=kind;self.assertEqual(self.oracle.lib.oracle_getlk_kind(kind),0)
        return self.run_command(c,5,h)
    def close(self,c,h):return self.run_command(c,6,h)
    def fault(self,c,relative,op,error):
        ordinal=self.oracle.lib.oracle_events()+relative
        self.assertEqual(self.oracle.lib.oracle_add_fault(ordinal,op,error),0)
    def poison(self,c,raw,capacity=288):
        result=self.invoke(c,raw,capacity)
        self.assertEqual(result[0],BAD)
        if len(c["work"])>=8:self.assertEqual(q(c["work"],0),BADMAGIC)
        if len(c["work"])>=1536:
            repeated=self.invoke(c,packet(1,c["nonce"],initial=(*c["fsnonce"],0,0)))
            self.assertEqual(repeated[0],BAD)
        return result
    def pending_register(self):
        c=self.context();raw=self.make_request(c,2,value=5)
        result=self.step(c,raw);self.assertEqual(result[0],1)
        event=(1,15,5,0,0,0,0,0)
        return c,self.receipt(c,event,result[1])
    def test_01_zero_identity_uid_and_basic_cycle(self):
        c=self.context(dev=0,ino=0,uid=0);h=self.register(c,5)
        self.reserved(c,h);self.lock(c,h,1);self.lock(c,h,1)
        self.lock(c,h,2);self.lock(c,h,4);self.unlock(c,h,1);self.unlock(c,h);self.close(c,h)
        self.assertEqual(q(c["work"],1),4)
    def test_02_shared_direct_exclusive_has_no_extra_pending(self):
        c=self.context();h=self.register(c,5);self.lock(c,h,1);self.lock(c,h,4)
        self.assertEqual([e[1:6] for e in c["last_events"]],[(17,5,1,SHARED,510)])
        self.unlock(c,h);self.close(c,h)
    def test_03_local_shared_reserved_and_pending_retry(self):
        c=self.context();a=self.register(c,5);b=self.register(c,6);d=self.register(c,7)
        self.lock(c,a,1);self.lock(c,b,1);self.assertEqual(c["last_events"],[])
        self.lock(c,a,2);self.assertEqual(self.lock(c,b,2)[8],5);self.assertEqual(c["last_events"],[])
        self.assertEqual(self.reserved(c,d)[10],1);self.assertEqual(c["last_events"],[])
        self.assertEqual(self.lock(c,a,4)[8],5);self.assertEqual(q(c["work"],11),3)
        self.assertEqual(self.lock(c,d,1)[8],5);self.assertEqual(c["last_events"],[])
        self.unlock(c,b);self.lock(c,a,4)
        self.assertEqual([e[4] for e in c["last_events"]],[SHARED])
        self.unlock(c,a);self.close(c,d);self.close(c,b);self.close(c,a)
    def test_04_deferred_lifo_drains_at_last_lock(self):
        c=self.context();a=self.register(c,5);b=self.register(c,6);d=self.register(c,7)
        self.lock(c,a,1);self.close(c,b);self.assertEqual(c["last_events"],[])
        self.close(c,d);self.unlock(c,a)
        self.assertEqual([(e[1],e[2]) for e in c["last_events"]],[(17,5),(8,7),(8,6)])
        self.close(c,a)
    def test_05_unix_excl_process_lock_and_last_reference(self):
        c=self.context();a=self.register(c,5,2);b=self.register(c,6,2)
        self.lock(c,a,1);self.assertEqual(len(c["last_events"]),1)
        self.assertEqual(c["last_events"][0][1:6],(17,5,1,SHARED,510))
        self.reserved(c,b);self.assertEqual(c["last_events"],[])
        self.lock(c,a,2);self.reserved(c,b);self.lock(c,a,4);self.unlock(c,a)
        self.assertEqual(c["last_events"],[]);self.close(c,a);self.assertEqual(c["last_events"],[])
        self.close(c,b);self.assertEqual([(e[1],e[2]) for e in c["last_events"]],[(8,6),(8,5)])
    def test_06_readonly_excl_does_not_take_process_lock(self):
        c=self.context();h=self.register(c,5,3);self.lock(c,h,1)
        self.assertEqual(len(c["last_events"]),3);self.assertEqual(q(c["work"],12),0)
        self.unlock(c,h);self.close(c,h)
    def test_07_mixed_excl_after_existing_shared_release_branch(self):
        c=self.context();a=self.register(c,5);b=self.register(c,6,2)
        self.lock(c,a,1);self.lock(c,b,1);self.unlock(c,a);self.lock(c,b,2)
        self.assertEqual(q(c["work"],12),1)
        self.close(c,a);self.close(c,b)
    def test_08_first_lock_all_errno_categories(self):
        for error in (13,11,110,16,4,37,1,5):
            with self.subTest(error=error):
                c=self.context();h=self.register(c,5);self.fault(c,1,17,error)
                out=self.lock(c,h,1)
                self.assertEqual(out[8],5 if error in (13,11,110,16,4,37) else 3 if error==1 else 3850)
                self.assertEqual(out[9],error);self.close(c,h)
    def test_09_shared_range_first_error_survives_unlock_error(self):
        for first in (13,4,1,5):
            for second in (0,4,5):
                with self.subTest(first=first,second=second):
                    c=self.context();h=self.register(c,5);self.fault(c,2,17,first)
                    if second:self.fault(c,3,17,second)
                    out=self.lock(c,h,1);self.assertEqual(out[9],first)
                    self.assertEqual(len(c["last_events"]),3);self.close(c,h)
    def test_10_shared_temporary_pending_unlock_failure(self):
        for error in (4,5,13):
            with self.subTest(error=error):
                c=self.context();h=self.register(c,5);self.fault(c,3,17,error)
                out=self.lock(c,h,1);self.assertEqual((out[8],out[9]),(2058,error))
                self.close(c,h)
    def test_11_reserved_failure_and_last_errno_retention(self):
        for error in (1,11,5):
            with self.subTest(error=error):
                c=self.context();h=self.register(c,5);self.lock(c,h,1);self.fault(c,1,17,error)
                self.lock(c,h,2);self.lock(c,h,2);self.unlock(c,h);self.close(c,h)
    def test_12_exclusive_pending_failure_preserves_reserved(self):
        for error in (4,5):
            with self.subTest(error=error):
                c=self.context();h=self.register(c,5);self.lock(c,h,1);self.lock(c,h,2);self.fault(c,1,17,error)
                self.lock(c,h,4);self.assertEqual(q(c["work"],11),2);self.unlock(c,h);self.close(c,h)
    def test_13_exclusive_range_failure_preserves_pending(self):
        for error in (11,1,5):
            with self.subTest(error=error):
                c=self.context();h=self.register(c,5);self.lock(c,h,1);self.lock(c,h,2);self.fault(c,2,17,error)
                self.lock(c,h,4);self.assertEqual(q(c["work"],11),3)
                self.lock(c,h,4);self.assertEqual(len(c["last_events"]),1)
                self.unlock(c,h);self.close(c,h)
    def test_14_downgrade_read_failure_never_reports_busy(self):
        for error in (11,4,5):
            with self.subTest(error=error):
                c=self.context();h=self.register(c,5);self.lock(c,h,1);self.lock(c,h,4);self.fault(c,1,17,error)
                out=self.unlock(c,h,1);self.assertEqual((out[8],out[9]),(2314,error))
                self.assertEqual(q(c["work"],11),4);self.unlock(c,h,1);self.close(c,h)
    def test_15_downgrade_pending_pair_unlock_failure(self):
        c=self.context();h=self.register(c,5);self.lock(c,h,1);self.lock(c,h,4);self.fault(c,2,17,4)
        out=self.unlock(c,h,1);self.assertEqual(out[8],2058);self.assertEqual(q(c["work"],11),4)
        self.unlock(c,h,1);self.close(c,h)
    def test_16_final_unlock_error_clears_logical_lock_and_drains(self):
        c=self.context();a=self.register(c,5);b=self.register(c,6)
        self.lock(c,a,1);self.close(c,b);self.fault(c,1,17,5)
        out=self.unlock(c,a);self.assertEqual(out[8],2058)
        self.assertEqual([(e[1],e[2]) for e in c["last_events"]],[(17,5),(8,6)])
        self.assertEqual((q(c["work"],9),q(c["work"],10),q(c["work"],11)),(0,0,0));self.close(c,a)
    def test_17_close_ignores_known_unlock_failure_and_retires(self):
        for target,relative in ((1,1),(4,1),(4,2)):
            with self.subTest(target=target,relative=relative):
                c=self.context();h=self.register(c,5);self.lock(c,h,1)
                if target==4:self.lock(c,h,4)
                self.fault(c,relative,17,4);out=self.close(c,h)
                self.assertEqual(out[8],0);self.assertEqual(q(c["work"],1),4)
    def test_18_close_failed_unlock_stays_deferred_until_other_close(self):
        c=self.context();a=self.register(c,5);b=self.register(c,6)
        self.lock(c,a,1);self.lock(c,a,4);self.fault(c,1,17,5);self.close(c,a)
        self.assertEqual(q(c["work"],8),1);self.assertEqual(q(c["work"],9),1)
        self.close(c,b);self.assertEqual([(e[1],e[2]) for e in c["last_events"]],[(8,6),(8,5)])
    def test_19_close_eintr_no_retry_and_first_ignored_error(self):
        c=self.context();a=self.register(c,5);b=self.register(c,6);d=self.register(c,7)
        self.lock(c,a,1);self.close(c,b);self.close(c,d)
        self.fault(c,2,8,4);self.fault(c,3,8,5)
        out=self.unlock(c,a);self.assertEqual(out[20],4)
        self.assertEqual([e[1] for e in c["last_events"]],[17,8,8]);self.close(c,a)
    def test_20_check_reserved_actual_kinds_errors_and_local(self):
        c=self.context();a=self.register(c,5);b=self.register(c,6)
        for kind in (0,1,2):self.assertEqual(self.reserved(c,a,kind)[10],int(kind!=2))
        for error in (4,5):
            self.fault(c,1,23,error);out=self.reserved(c,a);self.assertEqual((out[8],out[9]),(3594,error))
        self.lock(c,a,1);self.lock(c,a,2);self.assertEqual(self.reserved(c,b)[10],1)
        self.assertEqual(c["last_events"],[]);self.close(c,b);self.close(c,a)
    def test_21_register_stat_failure_does_not_commit_handle(self):
        for error in (4,5,75):
            with self.subTest(error=error):
                c=self.context();self.fault(c,1,15,error)
                out=self.run_command(c,2,value=5);self.assertEqual((out[8],out[9],out[10]),(10,error,0))
                self.assertEqual(q(c["work"],6),1);h=self.register(c,5);self.assertEqual(h,1);self.close(c,h)
    def test_22_repeated_dynamic_rows_above_allocation_granule(self):
        c=self.context();handles=[self.register(c,i+5,3 if i%3==0 else 0) for i in range(33)]
        self.assertEqual(q(c["work"],7),48)
        self.lock(c,handles[0],1)
        for h in handles[1:]:self.close(c,h)
        self.assertEqual(q(c["work"],8),1);self.unlock(c,handles[0])
        self.assertEqual([e[2] for e in c["last_events"] if e[1]==8],list(range(37,5,-1)))
        self.close(c,handles[0])
    def test_23_seeded_legal_connection_histories(self):
        rng=random.Random(34610041)
        for case in range(12):
            with self.subTest(case=case):
                c=self.context(uid=case,ino=100+case)
                handles=[self.register(c,10+i,2 if case%4==0 else 0) for i in range(3)]
                for step in range(24):
                    state=self.oracle.snapshot()
                    active=[r for r in state["files"] if r[2]]
                    if not active:break
                    selected=rng.choice(active);h=selected[0];level=selected[4]
                    choices=[("unlock",0),("unlock",1)]
                    if level==0:choices.append(("lock",1))
                    else:choices.extend([("lock",1),("lock",2 if level==1 else 4),("lock",4)])
                    if level<=1:choices.append(("reserved",rng.randrange(3)))
                    kind,value=rng.choice(choices)
                    if kind=="lock":self.lock(c,h,value)
                    elif kind=="unlock":self.unlock(c,h,value)
                    else:self.reserved(c,h,value)
                for r in self.oracle.snapshot()["files"]:
                    if r[2]:self.close(c,r[0])
    def test_24_init_header_reserved_bounds_and_persistent_poison(self):
        for word,value in ((0,0),(1,2),(2,0),(4,1),(7,1),(9,1),(10,0),(14,1),(15,1),(16,1),(17,1),(31,1)):
            with self.subTest(word=word):
                raw=bytearray(packet(1,nonce=(101,0),initial=(303,0,0,0)));setq(raw,word,value)
                c=dict(work=bytearray(1536),nonce=(101,0),fsnonce=(303,0))
                self.poison(c,raw)
    def test_25_exact_pending_ack_identity_and_stat_duplicates(self):
        variants=[(word,value) for word,value in ((2,999),(3,999),(4,0),(5,0),(6,1),(7,8),(8,1),(10,1),(15,0),(17,1),
            (32,0),(33,1),(34,999),(36,0),(37,1),(38,8),(40,999),(41,1),(42,1),(43,1),(45,0),(46,1),
            (64,0),(65,1),(66,999),(68,0),(69,0),(70,8),(71,4096),(72,99),(73,99),(74,0),(75,99),(76,99),(77,0),
            (78,0),(79,0),(80,0),(81,1),(82,1),(83,1),(85,0),(86,2),(87,1),(88,0),(89,1))]
        for word,value in variants:
            with self.subTest(word=word):
                c,reply=self.pending_register();raw=bytearray(reply);setq(raw,word,value);self.poison(c,raw)
    def test_26_unknown_then_original_ack_stays_rejected(self):
        c,reply=self.pending_register();words=struct.unpack_from("<32Q",reply)
        unknown=packet(8,c["nonce"],c["call"],words[5],words[6],words[7],lease=c["lease"])
        self.poison(c,unknown);self.assertEqual(self.invoke(c,reply)[0],BAD)
    def test_27_grow_identity_and_sequence_exhaustion(self):
        c=self.context();raw=self.make_request(c,2,value=5);result=self.invoke(c,raw)
        self.assertEqual(result[0],2);self.assertEqual(self.invoke(c,raw)[0],2)
        c["work"].extend(bytes(result[1][21]-len(c["work"])))
        changed=bytearray(raw);setq(changed,8,6);self.poison(c,changed)
        c=self.context(size=3584);setq(c["work"],4,MAX)
        raw=packet(2,c["nonce"],0,value=5,lease=901);self.poison(c,raw)
        c=self.context(size=3584);setq(c["work"],6,MAX)
        raw=packet(2,c["nonce"],1,value=5,lease=901);self.poison(c,raw)
    def test_28_source_and_workspace_invariants(self):
        for word,value in ((0,0),(1,8),(6,0),(7,MAX),(8,2),(9,1),(10,1),(11,4),(12,2),(15,2),(48,1),(96,1)):
            with self.subTest(word=word):
                c=self.context();h=self.register(c,5);setq(c["work"],word,value)
                self.poison(c,self.make_request(c,5,h))
        for row_word,value in ((0,0),(1,0),(2,3),(3,5),(4,2),(5,2),(6,4096),(7,1536),(8,1),(9,1<<32),(10,1<<32),(11,1)):
            with self.subTest(row_word=row_word):
                c=self.context();h=self.register(c,5);setq(c["work"],192+row_word,value)
                self.poison(c,self.make_request(c,5,h))
    def test_29_retired_and_duplicate_close_are_refused(self):
        c=self.context();a=self.register(c,5);b=self.register(c,6);self.close(c,a)
        self.poison(c,self.make_request(c,6,a))
        c=self.context();a=self.register(c,5);self.close(c,a)
        self.poison(c,self.make_request(c,2,value=6))
    def test_30_short_buffers_and_full_payload_extent(self):
        for size in (0,7,8,16,1535):
            c=dict(work=bytearray(size),nonce=(101,202),fsnonce=(303,404))
            self.assertEqual(self.invoke(c,packet(1,c["nonce"],initial=(*c["fsnonce"],0,0)))[0],BAD)
        for cap in (0,1,255):
            c=self.context();self.poison(c,self.make_request(c,2,value=5),cap)
        c,reply=self.pending_register()
        self.poison(c,reply[:-1])
        c,reply=self.pending_register();raw=bytearray(reply+b"\0"*33);setq(raw,16,len(raw)-256)
        self.assertEqual(self.invoke(c,raw)[0],0)
    def test_31_deferred_list_corruption_and_cross_inode(self):
        for word,value in ((34,0),(192+7,1536),(192+8,0)):
            with self.subTest(word=word):
                c=self.context();a=self.register(c,5);b=self.register(c,6)
                self.lock(c,b,1);self.close(c,a);setq(c["work"],word,value)
                self.poison(c,self.make_request(c,5,b))
        c=self.context();h=self.register(c,5)
        raw=self.make_request(c,2,value=6);result=self.step(c,raw);self.assertEqual(result[0],1)
        reply=bytearray(self.receipt(c,(2,15,6,0,0,0,0,0),result[1]))
        setq(reply,72,99);setq(reply,96,99)
        self.poison(c,reply)
    def test_32_getlk_shape_watermark_and_pending_stage(self):
        for mode in ("type","duplicate","reserved","watermark","stage"):
            with self.subTest(mode=mode):
                c=self.context();h=self.register(c,5)
                raw=self.make_request(c,5,h);result=self.step(c,raw);self.assertEqual(result[0],1)
                reply=bytearray(self.receipt(c,(2,23,5,1,RESERVED,1,0,0),result[1]))
                if mode=="type":setq(reply,72,3);setq(reply,96,3)
                elif mode=="duplicate":setq(reply,74,123)
                elif mode=="reserved":setq(reply,88,1)
                elif mode=="watermark":setq(reply,69,q(c["work"],19))
                else:setq(c["work"],29,12)
                self.poison(c,reply)

EXPECTED_TESTS=32
