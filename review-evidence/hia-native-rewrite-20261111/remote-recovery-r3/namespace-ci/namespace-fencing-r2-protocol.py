"""Private protocol corpus for the new fencing image.

Child FS/inode programs execute on retained CoreVM; primitive outcomes here are
explicit synthetic controls. This is not the fixed native carrier's physical
evidence. Separate actual ELF tests and per-entry replay are mandatory.
"""
import struct,unittest
from pathlib import Path
from hepta.hia_agent_assembly import assemble_program,render_assembly
from hepta.hia_program_runtime import _Machine,_Owner,_View
from tools.generate_hia_agent_namespace_fencing import document,MAGIC,BAD,CHANNEL,FS_MAGIC,INODE_MAGIC
ROOT=Path(__file__).resolve().parents[1]
REFUSED=0xfffffffd
MASK=(1<<64)-1
def q(raw,index):return struct.unpack_from("<Q",raw,index*8)[0]
def put(raw,index,value):struct.pack_into("<Q",raw,index*8,value)
def frame(command=2,*,session=(71,83),call=1,operation=0,handle=0,a=0,b=0,c=0,lease=1,body=b""):
    return struct.pack("<32Q",MAGIC,command,*session,call,operation,handle,a,b,c,lease,len(body),*([0]*20))+body
def user(raw):
    return struct.pack("<8Q",CHANNEL,1,0,0,len(raw),0,0,0)+raw
def child(role,result,original,output,work,serial):
    return struct.pack("<8Q",CHANNEL,2,role,result,len(original),len(output),len(work),serial)+original+output+work

class NamespaceFencingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source=(ROOT/"examples/hia_bootstrap/agent_namespace_fencing_r2.hiaasm").read_bytes()
        cls.program=assemble_program(cls.source);cls.entry=cls.program.as_dict()["functions"][0]
        cls.peers={}
        for role,name in ((1,"agent_namespace_filesystem_r4.hiaasm"),(2,"agent_namespace_inode_r2.hiaasm")):
            program=assemble_program((ROOT/"examples/hia_bootstrap"/name).read_bytes())
            cls.peers[role]=(program,program.as_dict()["functions"][0])
    def invoke(self,raw,work,capacity=256,steps=4000000):
        raw=bytes(raw);out=bytearray(capacity)
        owners=[_Owner(-1,bytearray(raw)),_Owner(-2,out),_Owner(-3,work)]
        machine=_Machine(self.program,steps,16<<20,None,64)
        result=machine.invoke(self.entry,[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
        self.assertEqual(bytes(owners[0].data),raw)
        output=bytes(out)
        return result,struct.unpack_from("<32Q",output) if capacity>=256 else None,output
    def context(self,*,session=(71,83)):
        value=dict(work=bytearray(1536),capacity=256,session=session,call=0,
            peers={role:dict(work=bytearray(512),capacity=256,serial=0) for role in (1,2)},
            events=[],syscalls=[],faults={},nextfd=0,files={},fds={},grows=[],child_packets=[])
        raw=frame(1,session=session,call=0,lease=0)
        result=self.advance(value,user(raw))
        self.assertEqual((result[0],result[1][4:10]),(0,(0,0,0,0,0,0)))
        return value
    def peer(self,c,role,original):
        state=c["peers"][role];raw=bytes(original)
        while True:
            program,entry=self.peers[role];output=bytearray(state["capacity"])
            owners=[_Owner(-1,bytearray(raw)),_Owner(-2,output),_Owner(-3,state["work"])]
            machine=_Machine(program,4000000,16<<20,None,64)
            code=machine.invoke(entry,[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
            self.assertEqual(bytes(owners[0].data),raw);state["serial"]+=1
            header=struct.unpack_from("<32Q",output)
            c["events"].append((role,code,header[4],header[5],header[6],state["serial"]))
            if code==2:
                if role==1:need,capacity=header[17],header[18]
                else:need,capacity=header[15],state["capacity"]
                self.assertTrue(need>len(state["work"]) or capacity>state["capacity"])
                self.assertLessEqual(max(need,capacity),16<<20,"finite test allocation guard only")
                if need>len(state["work"]):state["work"].extend(bytes(need-len(state["work"])))
                state["capacity"]=max(state["capacity"],capacity)
                continue
            if role==1 and code==1:
                raw=self.primitive(c,bytes(output));continue
            self.assertIn(code,(0,1,REFUSED))
            packet=child(role,code,original,bytes(output),bytes(state["work"]),state["serial"])
            c["child_packets"].append(packet)
            return packet
    def primitive(self,c,output):
        h=struct.unpack_from("<32Q",output);op=h[6]
        self.assertIn(op,(1,15,17,8))
        queued=c["faults"].get(op,[])
        error=queued.pop(0) if queued else 0
        payload=b"";raw=0
        if error:raw=(-error)&MASK
        elif op==1:
            path=output[256:256+h[16]]
            self.assertTrue(path.endswith(b"\0"))
            fd=c["nextfd"];c["nextfd"]+=1
            if path not in c["files"]:c["files"][path]=(17,len(c["files"])+101,0o100600,0)
            c["fds"][fd]=c["files"][path];raw=fd
        elif op==15:
            device,inode,mode,uid=c["fds"][h[8]]
            payload=bytearray(144)
            struct.pack_into("<QQQIIIIQqqq",payload,0,device,inode,1,mode,uid,0,0,0,123,4096,8)
            payload=bytes(payload)
        elif op==8:
            c["fds"].pop(h[8],None)
        c["syscalls"].append(dict(operation=op,raw_fd=h[8],arguments=h[8:12],
            syscall_sequence=h[5],raw_return=raw,synthetic=True))
        words=[FS_MAGIC,3,h[2],h[3],h[4],h[5],op,raw,0,0,0,0,len(payload),h[14]]+[0]*18
        return struct.pack("<32Q",*words)+payload
    def advance(self,c,raw,stop_role=None):
        raw=bytes(raw)
        for _ in range(256):
            result=self.invoke(raw,c["work"],c["capacity"]);code,h,out=result
            if code==2:
                need,capacity=h[9],h[10]
                self.assertTrue(need>len(c["work"]) or capacity>c["capacity"])
                self.assertLessEqual(max(need,capacity),16<<20,"finite fixture guard, not a namespace quota")
                c["grows"].append(dict(channel=q(raw,1),input=raw,
                    before=len(c["work"]),after=max(need,len(c["work"])),child_entries=len(c["events"])))
                if need>len(c["work"]):c["work"].extend(bytes(need-len(c["work"])))
                c["capacity"]=max(c["capacity"],capacity)
                continue
            if code==1:
                self.assertEqual(h[8],h[16]);self.assertIn(h[6],(1,2))
                original=out[256:256+h[16]]
                self.assertEqual(len(original),h[16])
                packet=self.peer(c,h[6],original)
                c["pending"]=packet
                if stop_role==h[6]:return packet
                raw=packet;continue
            self.assertIn(code,(0,REFUSED))
            c["last"]=h;c["last_output"]=out
            return result
        raise AssertionError("finite fixture continuation bound exhausted")
    def start(self,c,operation,handle=0,*,a=0,b=0,count=0,body=b"",stop_role=None):
        c["call"]+=1
        raw=frame(session=c["session"],call=c["call"],operation=operation,
            handle=handle,a=a,b=b,c=count,lease=c["call"]+1000,body=body)
        c["original"]=user(raw)
        return self.advance(c,c["original"],stop_role=stop_role)
    def opened(self,c,path=b"same",*,flags=0,mode=0o600):
        code,h,_=self.start(c,1,a=flags,b=mode,body=path)
        self.assertEqual((code,h[6],h[7]),(0,0,0));self.assertGreater(h[8],0)
        return h[8]
    def locked(self,c,handle,kind=2,offset=0,count=1):
        code,h,_=self.start(c,2,handle,a=kind,b=offset,count=count)
        self.assertEqual((code,h[6],h[7]),(0,0,0))
    def unlock(self,c,handle,kind=2,offset=0,count=1):
        code,h,_=self.start(c,3,handle,a=kind,b=offset,count=count)
        self.assertEqual((code,h[6],h[7]),(0,0,0));return h
    def refuse(self,c,raw,reason=None):
        code,h,_=self.invoke(raw,c["work"],c["capacity"])
        self.assertEqual(code,REFUSED)
        if reason is not None:self.assertEqual(h[12],reason)
        before=bytes(c["work"])
        code,_,_=self.invoke(user(frame(1,call=0,lease=0)),c["work"],c["capacity"])
        self.assertEqual(code,REFUSED);self.assertEqual(bytes(c["work"]),before)
        self.assertEqual(q(c["work"],0),BAD)
    def test_01_source_profile_and_exact_regeneration(self):
        d=document();self.assertEqual(render_assembly(d).encode(),self.source)
        self.assertLessEqual(len(d["functions"]),128)
        self.assertLessEqual(sum(len(f["blocks"]) for f in d["functions"]),1536)
        self.assertLessEqual(max(len(f["blocks"]) for f in d["functions"]),256)
        self.assertLessEqual(sum(len(b["ops"]) for f in d["functions"] for b in f["blocks"]),8192)
        self.assertLessEqual(max(len(b["params"]) for f in d["functions"] for b in f["blocks"]),16)
    def test_02_initialization_and_complete_open_lock_unlock_retire(self):
        c=self.context();self.assertEqual(len(c["child_packets"]),2);self.assertFalse(c["syscalls"])
        handle=self.opened(c);self.locked(c,handle);self.unlock(c,handle)
        code,h,_=self.start(c,4,handle)
        self.assertEqual((code,h[6],h[8]),(0,0,0))
        self.assertEqual([r["operation"] for r in c["syscalls"]],[1,15,17,17,8])
        self.assertEqual(c["syscalls"][0]["raw_return"],0)
    def test_03_shared_alias_masks_and_lifo_retirement(self):
        c=self.context();a=self.opened(c);b=self.opened(c);d=self.opened(c)
        self.locked(c,a,1)
        before=len(c["syscalls"]);self.locked(c,b,1)
        self.assertEqual(len(c["syscalls"]),before)
        self.assertEqual(self.start(c,4,d)[1][6],0);self.assertEqual(len(c["syscalls"]),before)
        self.unlock(c,a,1);self.assertEqual(len(c["syscalls"]),before)
        self.unlock(c,b,1)
        self.assertEqual([r["operation"] for r in c["syscalls"][before:]],[17,8])
    def test_04_local_conflict_has_no_physical_request(self):
        c=self.context();a=self.opened(c);b=self.opened(c);self.locked(c,a)
        before=len(c["syscalls"])
        for kind in (1,2):
            code,h,_=self.start(c,2,b,a=kind,count=1)
            self.assertEqual((code,h[6],h[7]),(0,5,0))
        self.assertEqual(len(c["syscalls"]),before)
    def test_05_every_selected_lock_errno_stays_busy(self):
        for error in (1,4,9,11,13,22,28,37):
            with self.subTest(error=error):
                c=self.context();a=self.opened(c);c["faults"][17]=[error]
                code,h,_=self.start(c,2,a,a=2,count=1)
                self.assertEqual((code,h[6],h[7]),(0,5,error))
                self.locked(c,a)
    def test_06_open_error_has_no_inode_registration(self):
        c=self.context();before=c["peers"][2]["serial"];c["faults"][1]=[13]
        code,h,_=self.start(c,1,body=b"denied",b=0o600)
        self.assertEqual((code,h[6],h[7],h[8]),(0,1,13,0))
        self.assertEqual(c["peers"][2]["serial"],before)
    def test_07_failed_stat_orphan_waits_for_last_mask(self):
        c=self.context();a=self.opened(c);self.locked(c,a)
        before=len(c["syscalls"]);c["faults"][15]=[9]
        code,h,_=self.start(c,1,body=b"same",b=0o600)
        self.assertEqual((code,h[6],h[7],h[11]),(0,1,9,1))
        self.assertEqual([r["operation"] for r in c["syscalls"][before:]],[1,15])
        self.unlock(c,a)
        self.assertEqual([r["operation"] for r in c["syscalls"][-2:]],[17,8])
        self.assertEqual(c["last"][11],0)
    def test_08_multiple_orphans_close_lifo_and_error_is_not_retried(self):
        c=self.context();a=self.opened(c);self.locked(c,a)
        for _ in range(3):
            c["faults"][15]=[5];self.assertEqual(self.start(c,1,body=b"same")[1][11],_+1)
        c["faults"][8]=[4]
        before=len(c["syscalls"]);h=self.unlock(c,a)
        self.assertEqual(h[10],4);self.assertEqual(h[11],0)
        closed=[r["raw_fd"] for r in c["syscalls"][before:] if r["operation"]==8]
        self.assertEqual(closed,[3,2,1])
        count=len(c["syscalls"]);self.locked(c,a)
        self.assertEqual(len(c["syscalls"]),count+1)
    def test_09_unlocked_failed_stat_closes_before_original_error(self):
        c=self.context();c["faults"][15]=[5];c["faults"][8]=[9]
        code,h,_=self.start(c,1,body=b"bad-stat")
        self.assertEqual((code,h[6],h[7],h[10],h[11]),(0,1,5,9,0))
        self.assertEqual([r["operation"] for r in c["syscalls"]],[1,15,8])
    def test_10_dynamic_rows_and_long_source_without_replaying_children(self):
        c=self.context()
        for number in range(18):self.opened(c,("inode-"+str(number)).encode())
        path=b"x"*4096;self.opened(c,path)
        self.assertEqual(len([r for r in c["syscalls"] if r["operation"]==1]),19)
        self.assertEqual(len([r for r in c["syscalls"] if r["operation"]==15]),19)
        self.assertEqual(c["last"][12],19)
        self.assertTrue(any(g["channel"]==1 for g in c["grows"]))
        self.assertTrue(any(g["channel"]==2 for g in c["grows"]))
    def test_11_user_shape_and_replayed_call_are_permanent(self):
        for field,value in ((0,0),(1,1),(2,999),(4,0),(5,99),(10,0),(12,1)):
            with self.subTest(field=field):
                c=self.context()
                raw=bytearray(frame(session=c["session"],operation=1,body=b"x"))
                put(raw,field,value);self.refuse(c,user(raw))
        c=self.context();self.opened(c);self.refuse(c,c["original"])
    def test_12_wrong_child_source_role_serial_and_frame_are_permanent(self):
        for kind in ("role","serial","source","return","nonce","workmagic","workversion"):
            with self.subTest(kind=kind):
                c=self.context()
                packet=bytearray(self.start(c,1,body=b"x",stop_role=1))
                out=64+q(packet,4);work=out+q(packet,5)
                if kind=="role":put(packet,2,2)
                elif kind=="serial":put(packet,7,0)
                elif kind=="source":packet[64+64]^=1
                elif kind=="return":put(packet,3,1)
                elif kind=="nonce":struct.pack_into("<Q",packet,out+16,0)
                elif kind=="workmagic":struct.pack_into("<Q",packet,work,0)
                else:struct.pack_into("<Q",packet,work+248,0)
                self.refuse(c,bytes(packet))
    def test_13_private_child_channel_is_not_an_external_header_authentication(self):
        c=self.context()
        packet=self.start(c,1,body=b"x",stop_role=1)
        # The real carrier wraps external bytes as USER, regardless of magic.
        self.refuse(c,user(packet))
    def test_14_short_buffers_and_poison_are_lossless(self):
        raw=user(frame(1,call=0,lease=0))
        for size in (0,7,8,511,1535):
            work=bytearray(size);code,h,out=self.invoke(raw,work,256)
            self.assertEqual(code,REFUSED);self.assertEqual(out,bytes(256))
            if size>=8:self.assertEqual(q(work,0),BAD)
        work=bytearray(1536);code,_,out=self.invoke(raw,work,255)
        self.assertEqual((code,out),(REFUSED,bytes(255)));self.assertEqual(q(work,0),BAD)
    def test_15_call_and_action_exhaustion_never_wrap(self):
        c=self.context();put(c["work"],4,MASK)
        self.refuse(c,user(frame(session=c["session"],call=1,operation=1,body=b"x")))
        c=self.context();self.opened(c);put(c["work"],8,MASK)
        before=len(c["events"])
        self.refuse(c,user(frame(session=c["session"],call=2,operation=1,body=b"x")))
        self.assertEqual(len(c["events"]),before)
    def test_16_larger_complete_child_is_bound_across_snapshot_growth(self):
        c=self.context()
        packet=self.start(c,1,body=b"x",stop_role=2)
        # First inode registration request grows its registry before yielding
        # the required real-stat request, so the coordinator needs a snapshot.
        code,h,_=self.invoke(packet,c["work"],c["capacity"])
        self.assertEqual(code,2);self.assertEqual(h[11],4)
        self.assertGreater(h[9],len(c["work"]))
        c["work"].extend(bytes(h[9]-len(c["work"])))
        wrong=bytearray(packet);put(wrong,7,q(wrong,7)+1)
        self.refuse(c,bytes(wrong),17)
