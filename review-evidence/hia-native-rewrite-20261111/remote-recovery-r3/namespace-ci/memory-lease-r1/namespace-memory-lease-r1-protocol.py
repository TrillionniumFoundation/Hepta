"""NEW private memory owner semantics/protocol controls.
The primitive model is synthetic; no OS mapping or physical Store proof.
"""
import struct,unittest
from pathlib import Path
from hepta.hia_agent_assembly import assemble_program,render_assembly
from hepta.hia_program_runtime import _Machine,_Owner,_View
from tools.generate_hia_agent_namespace_memory_leases import document,MAGIC,BAD,CHANNEL
ROOT=Path(__file__).resolve().parents[1]
MASK=(1<<64)-1
REFUSED=0xfffffffd
def q(raw,index):return struct.unpack_from("<Q",raw,index*8)[0]
def put(raw,index,value):struct.pack_into("<Q",raw,index*8,value)
def packet(words,body=b""):
    return struct.pack("<32Q",*(list(words)+[0]*(32-len(words))))+body
def channel(raw,origin=1,primitive=0,serial=0):
    return struct.pack("<8Q",CHANNEL,origin,primitive,0,len(raw),serial,0,0)+raw
def request(c,op,token=0,a=0,b=0,protection=0,fd=0,fs=0,command=2):
    return packet([MAGIC,command,*c["session"],c["call"],0,1000+c["call"],c["node"],
        op,token,a,b,protection,fd,fs,c["generation"]])
class NamespaceMemoryLeaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw=(ROOT/"examples/hia_bootstrap/agent_namespace_memory_leases_r1.hiaasm").read_bytes()
        program=assemble_program(raw)
        cls.sources={"memory":raw};cls.programs={"memory":(program,program.as_dict()["functions"][0])}
    def invoke_program(self,role,raw,work,capacity=256,steps=4000000):
        original=bytes(raw);out=bytearray(capacity)
        owners=[_Owner(-1,bytearray(original)),_Owner(-2,out),_Owner(-3,work)]
        program,entry=self.programs[role];machine=_Machine(program,steps,16<<20,None,64)
        code=machine.invoke(entry,[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
        self.assertEqual(bytes(owners[0].data),original)
        return code,struct.unpack_from("<32Q",out) if capacity>=256 else None,bytes(out)
    def invoke(self,raw,c):return self.invoke_program("memory",raw,c["work"],c["capacity"])
    def context(self,*,page=4096,node=9,generation=71):
        c=dict(session=(173,189),node=node,generation=generation,page=page,work=bytearray(1536),
            capacity=256,call=0,serial=0,maps={},next_address=0x10000000,faults={},syscalls=[],
            grows=[],grow_failure=False,forced_address=None,file=bytes(range(256))*1024)
        raw=packet([MAGIC,1,*c["session"],0,0,0,node,page,generation])
        result=self.invoke(channel(raw),c);self.assertEqual(result[0],0)
        c["last"]=result[1];return c
    def primitive(self,c,out):
        h=struct.unpack_from("<32Q",out);op=h[8];a,b,d,e,f,g=h[9:15]
        self.assertIn(op,(1,2,3,4));faults=c["faults"].get(op,[])
        error=faults.pop(0) if faults else 0;value=0
        if error==0 and op==1:
            self.assertEqual(a,0);self.assertIn(d,(1,3));self.assertIn(e,(1,34))
            rounded=(b+c["page"]-1)&-c["page"]
            address=c["next_address"] if c["forced_address"] is None else c["forced_address"]
            c["forced_address"]=None;c["next_address"]+=rounded+c["page"]
            self.assertNotIn(address,c["maps"])
            memory=bytearray(rounded)
            if e==1:
                self.assertEqual(f,11);self.assertLessEqual(g+b,len(c["file"]))
                memory[:b]=c["file"][g:g+b]
            else:self.assertEqual((f,g),(MASK,0))
            c["maps"][address]=dict(bytes=memory,logical=b,protection=d,flags=e)
            value=address
        elif error==0 and op==2:
            self.assertEqual((e,f,g),(0,0,0))
            self.assertIn(a,c["maps"]);self.assertIn(d,c["maps"])
            self.assertGreaterEqual(len(c["maps"][a]["bytes"]),b);self.assertGreaterEqual(len(c["maps"][d]["bytes"]),b)
            c["maps"][a]["bytes"][:b]=c["maps"][d]["bytes"][:b]
        elif error==0 and op==3:
            self.assertEqual((d,e,f,g),(0,0,0,0));self.assertIn(a,c["maps"])
            self.assertEqual((b+c["page"]-1)&-c["page"],len(c["maps"][a]["bytes"]))
            del c["maps"][a]
        elif error==0 and op==4:self.assertEqual((a,b,d,e,f,g),(0,0,0,0,0,0))
        c["serial"]+=1
        c["syscalls"].append(dict(primitive=op,args=[a,b,d,e,f,g],error=error,value=value,
            source_hex=out.hex(),actual_OS_syscalls=0))
        raw=packet([MAGIC,3,*c["session"],h[4],h[5],h[6],c["node"],
            op,error,value,0,c["serial"],256],out)
        return channel(raw,2,op,c["serial"])
    def drive(self,c,raw,*,stop=False):
        for _ in range(1000):
            result=self.invoke(raw,c);code,h,out=result;c["last"]=h
            if code==2:
                before=len(c["syscalls"]);c["grows"].append(dict(source_hex=bytes(raw).hex(),before=len(c["work"]),need=h[8]))
                if c["grow_failure"]:
                    failed=packet([MAGIC,5,*c["session"],h[4],h[5],h[6],c["node"],12])
                    raw=channel(failed,4);continue
                self.assertGreater(h[8],len(c["work"]));self.assertEqual(h[9],256)
                self.assertLessEqual(h[8],16<<20,"finite fixture allocation only, not a language quota")
                c["work"].extend(bytes(h[8]-len(c["work"])))
                self.assertEqual(before,len(c["syscalls"]));continue
            if code!=1:return result
            raw=self.primitive(c,out)
            if stop:return raw
        self.fail("finite fixture continuation limit")
    def start(self,c,op,token=0,a=0,b=0,protection=0,fd=0,fs=0,command=2,stop=False):
        c["call"]+=1
        return self.drive(c,channel(request(c,op,token,a,b,protection,fd,fs,command)),stop=stop)
    def success(self,c,op,*args,**kwargs):
        result=self.start(c,op,*args,**kwargs)
        self.assertEqual((result[0],result[1][8]),(0,0));return result[1]
    def rows(self,c,state=1):
        return [struct.unpack_from("<10Q",c["work"],i) for i in range(1536,q(c["work"],9),80) if q(c["work"],(i+40)//8)==state]
    def row(self,c,token):
        return next(row for row in self.rows(c) if row[0]==token)
    def refuse(self,c,raw):
        result=self.invoke(raw,c);self.assertEqual(result[0],REFUSED);self.assertEqual(q(c["work"],0),BAD)
        reason=q(c["work"],31)
        again=self.invoke(raw,c);self.assertEqual(again[0],REFUSED);self.assertEqual(q(c["work"],31),reason)
        return result
    def ops(self,c):return [x["primitive"] for x in c["syscalls"]]
    def test_01_source_regeneration_original_bootstrap_limits(self):
        d=document();self.assertEqual(render_assembly(d).encode(),self.sources["memory"])
        self.assertLessEqual(len(d["functions"]),128);self.assertLessEqual(sum(len(f["blocks"]) for f in d["functions"]),1536)
        self.assertLessEqual(max(len(f["blocks"]) for f in d["functions"]),256)
        self.assertLessEqual(sum(len(b["ops"]) for f in d["functions"] for b in f["blocks"]),8192)
        self.assertLessEqual(max(len(b["params"]) for f in d["functions"] for b in f["blocks"]),16)
    def test_02_zero_heap_and_view_binding(self):
        c=self.context();h=self.success(c,3,a=32768);token=h[9]
        row=self.row(c,token);self.assertEqual(row[2:7],(32768,32768,3,1,3))
        self.assertEqual(c["maps"][row[1]]["bytes"],bytes(32768))
        v=self.success(c,7,token,19,31,3,command=6)
        self.assertEqual((v[9],v[10],v[11],v[12]),(token,31,row[1]+19,3));self.assertEqual(self.ops(c),[1])
    def test_03_vector_reallocation_copies_before_old_retirement(self):
        c=self.context();old=self.success(c,1,a=16)[9];row=self.row(c,old)
        c["maps"][row[1]]["bytes"][:16]=bytes(range(16));new=self.success(c,1,old,32,16)[9]
        self.assertNotEqual(new,old);newrow=self.row(c,new)
        self.assertEqual(c["maps"][newrow[1]]["bytes"][:32],bytes(range(16))+bytes(16))
        self.assertEqual(self.ops(c),[1,1,2,3]);self.assertEqual(len(self.rows(c)),1);self.assertEqual(q(c["work"],10),1)
    def test_04_file_readonly_mapping_and_view_protection(self):
        c=self.context();token=self.success(c,2,37,4096,32768,1,11,37)[9];row=self.row(c,token)
        self.assertEqual(row[2:9],(32768,32768,2,1,1,37,4096))
        self.assertEqual(c["maps"][row[1]]["bytes"],c["file"][4096:36864])
        self.success(c,7,token,0,32768,1,command=6)
        c["call"]+=1;self.refuse(c,channel(request(c,7,token,0,1,3,command=6)))
    def test_05_free_once_and_monotonic_reused_record(self):
        c=self.context();a=self.success(c,3,a=16)[9];self.success(c,5,a,16)
        self.assertFalse(self.rows(c));self.assertFalse(c["maps"]);before=q(c["work"],9)
        b=self.success(c,3,a=8)[9];self.assertGreater(b,a);self.assertEqual(q(c["work"],9),before)
        c["call"]+=1;self.refuse(c,channel(request(c,5,a,16)))
    def test_06_mmap_failure_preserves_old_vector_and_next_token(self):
        c=self.context();old=self.success(c,1,a=8)[9];oldrow=self.row(c,old)
        c["faults"][1]=[12];nxt=q(c["work"],8);h=self.start(c,1,old,16,8)[1]
        self.assertEqual(h[8:11],(12,0,0));self.assertEqual(self.row(c,old),oldrow);self.assertEqual(q(c["work"],8),nxt)
        self.assertEqual(self.ops(c),[1,1]);self.assertEqual(len(c["maps"]),1)
        self.success(c,1,old,16,8)
    def test_07_workspace_growth_same_input_once_before_primitive(self):
        c=self.context();token=self.success(c,3,a=8)[9]
        self.assertEqual(len(c["grows"]),1);self.assertEqual(self.ops(c),[1]);self.assertEqual(len(self.rows(c)),1)
        self.assertEqual(self.row(c,token)[2],8)
    def test_08_growth_failure_no_primitive_or_token_issued(self):
        c=self.context();c["grow_failure"]=True;h=self.start(c,3,a=16)[1]
        self.assertEqual(h[8:11],(12,0,0));self.assertFalse(c["syscalls"]);self.assertEqual(q(c["work"],8),1)
        c["grow_failure"]=False;self.success(c,3,a=16)
    def test_09_known_unmap_failure_quarantines_no_view_or_retry(self):
        c=self.context();token=self.success(c,3,a=8)[9];row=self.row(c,token);c["faults"][3]=[22]
        h=self.start(c,5,token,8)[1];self.assertEqual(h[8],22);self.assertFalse(self.rows(c))
        self.assertEqual(len(self.rows(c,2)),1);self.assertIn(row[1],c["maps"])
        before=len(c["syscalls"]);c["call"]+=1;self.refuse(c,channel(request(c,7,token,0,1,1,command=6)))
        self.assertEqual(len(c["syscalls"]),before)
    def test_10_virtual_64k_page_nominal_purge_rounding(self):
        c=self.context(page=65536);token=self.success(c,2,37,0,65536,3,11,37)[9]
        self.success(c,4,token,32768,65536)
        self.assertEqual(self.ops(c),[1,3]);self.assertFalse(self.rows(c));self.assertFalse(c["maps"])
        self.assertEqual(c["syscalls"][-1]["args"][1],32768)
    def test_11_unknown_completion_poison_retains_pending_owners(self):
        c=self.context();old=self.success(c,1,a=8)[9];ack=self.start(c,1,old,16,8,stop=True)
        self.assertEqual(len(c["maps"]),2);h=struct.unpack_from("<32Q",ack,64)
        raw=packet([MAGIC,4,*c["session"],h[4],h[5],h[6],c["node"],1])
        self.refuse(c,channel(raw,3));self.assertEqual(len(c["maps"]),2)
    def test_12_replay_and_stale_lease_rejected(self):
        c=self.context();self.success(c,3,a=8)
        raw=channel(request(c,3,a=8));self.refuse(c,raw)
        c=self.context();self.success(c,3,a=8);c["call"]+=1
        raw=bytearray(channel(request(c,3,a=8)));put(raw,14,1001);self.refuse(c,raw)
    def test_13_completed_source_echo_must_be_exact(self):
        c=self.context();raw=bytearray(self.start(c,3,a=8,stop=True));raw[-1]^=1;self.refuse(c,raw)
    def test_14_primitive_identity_and_serial_are_exact(self):
        for field,value in ((16,4),(20,0),(21,255)):
            c=self.context();raw=bytearray(self.start(c,3,a=8,stop=True));put(raw,field,value);self.refuse(c,raw)
        c=self.context();raw=bytearray(self.start(c,3,a=8,stop=True));put(raw,2,4);self.refuse(c,raw)
    def test_15_unaligned_or_overlapping_mmap_reply_refused(self):
        c=self.context();raw=bytearray(self.start(c,3,a=8,stop=True));put(raw,18,0x10000001);self.refuse(c,raw)
        c=self.context();old=self.success(c,3,a=8)[9];oldrow=self.row(c,old)
        raw=bytearray(self.start(c,3,a=8,stop=True));put(raw,18,oldrow[1]);self.refuse(c,raw)
    def test_16_pending_shape_corruption_refused(self):
        for field,value in ((13,40),(72,4),(73,77),(80,1),(84,1),(85,99),(87,0)):
            c=self.context();raw=self.start(c,3,a=8,stop=True);put(c["work"],field,value);self.refuse(c,raw)
    def test_17_short_views_and_invalid_original_channel(self):
        raw=channel(packet([MAGIC,1,173,189,0,0,0,9,4096,71]))
        for size in (0,7,8,511,1535):
            work=bytearray(size);code,_,out=self.invoke_program("memory",raw,work,256)
            self.assertEqual((code,out),(REFUSED,bytes(256)))
            if size>=8:self.assertEqual(q(work,0),BAD)
        for size in (0,7,255):
            work=bytearray(1536);code,_,out=self.invoke_program("memory",raw,work,size)
            self.assertEqual((code,out),(REFUSED,bytes(size)));self.assertEqual(q(work,0),BAD)
        c=self.context();bad=bytearray(channel(request(c,3,a=8)));put(bad,6,1);self.refuse(c,bad)
    def test_18_natural_counters_do_not_wrap(self):
        c=self.context();put(c["work"],4,MASK);c["call"]=0
        self.refuse(c,channel(request(c,3,a=8)))
        c=self.context();put(c["work"],8,MASK);c["call"]=1
        result=self.drive(c,channel(request(c,3,a=8)));self.assertEqual(result[0],REFUSED);self.assertFalse(c["syscalls"])
        c=self.context();put(c["work"],28,MASK)
        result=self.start(c,3,a=8);self.assertEqual(result[0],REFUSED);self.assertFalse(c["syscalls"])
    def test_19_allocation_size_rounding_overflow_returns_nomem(self):
        c=self.context();h=self.start(c,3,a=MASK)[1]
        self.assertEqual(h[8:11],(12,0,0));self.assertFalse(c["syscalls"])
    def test_20_actual_barrier_continuation_or_permanent_failure(self):
        c=self.context();self.success(c,6);self.assertEqual(self.ops(c),[4])
        c=self.context();c["faults"][4]=[5];result=self.start(c,6)
        self.assertEqual(result[0],REFUSED);self.assertEqual(q(c["work"],0),BAD)
    def test_21_copy_error_is_unknown_and_does_not_retire_old(self):
        c=self.context();old=self.success(c,1,a=8)[9];c["faults"][2]=[5]
        result=self.start(c,1,old,16,8);self.assertEqual(result[0],REFUSED)
        self.assertEqual(self.ops(c),[1,1,2]);self.assertEqual(len(c["maps"]),2)
    def test_22_invalid_raw_fd_mode_and_extent_refused(self):
        for args in ((37,0,32768,3,MASK,37),(37,1,32768,3,11,37),(37,0,0,3,11,37),(37,0,32768,2,11,37),(37,0,32768,3,11,38)):
            c=self.context();c["call"]=1;self.refuse(c,channel(request(c,2,*args)))
    def test_23_zero_address_is_an_opaque_nonzero_handle(self):
        c=self.context();c["forced_address"]=0;token=self.success(c,3,a=8)[9]
        self.assertNotEqual(token,0);self.assertEqual(self.row(c,token)[1],0)
        h=self.success(c,7,token,0,8,3,command=6);self.assertEqual((h[9],h[11]),(token,0))
        self.success(c,5,token,8)
    def test_24_wrong_node_and_generation_refused(self):
        c=self.context();c["call"]=1;raw=bytearray(channel(request(c,3,a=8)));put(raw,15,10);self.refuse(c,raw)
        c=self.context();c["call"]=1;raw=bytearray(channel(request(c,3,a=8)));put(raw,23,72);self.refuse(c,raw)
    def test_25_grow_resumption_input_cannot_change(self):
        c=self.context();c["call"]=1;raw=channel(request(c,3,a=8))
        code,h,_=self.invoke(raw,c);self.assertEqual(code,2);c["work"].extend(bytes(h[8]-len(c["work"])))
        bad=bytearray(raw);put(bad,18,9);self.refuse(c,bad);self.assertFalse(c["syscalls"])
    def test_26_view_range_and_type_are_checked(self):
        for offset,size in ((32768,1),(32767,2),(MASK,1)):
            c=self.context();token=self.success(c,3,a=32768)[9];c["call"]+=1
            self.refuse(c,channel(request(c,7,token,offset,size,1,command=6)))
        c=self.context();token=self.success(c,1,a=8)[9];c["call"]+=1
        self.refuse(c,channel(request(c,7,token,0,8,1,command=6)))
    def test_27_realloc_cleanup_failure_keeps_new_and_quarantines_old(self):
        c=self.context();old=self.success(c,1,a=8)[9];row=self.row(c,old);c["faults"][3]=[22]
        new=self.success(c,1,old,16,8)[9];self.assertNotEqual(new,old)
        self.assertEqual(len(self.rows(c)),1);self.assertEqual(len(self.rows(c,2)),1)
        self.assertEqual(q(c["work"],27),1);self.assertIn(row[1],c["maps"])
        self.assertEqual(self.ops(c),[1,1,2,3])
    def test_28_retired_record_and_reserve_invariants(self):
        c=self.context();a=self.success(c,3,a=8)[9];self.success(c,5,a,8);put(c["work"],192,99)
        c["call"]+=1;self.refuse(c,channel(request(c,3,a=8)))
        c=self.context();self.success(c,3,a=8);put(c["work"],9,q(c["work"],9)-8)
        c["call"]+=1;self.refuse(c,channel(request(c,3,a=8)))
if __name__=="__main__":unittest.main()
