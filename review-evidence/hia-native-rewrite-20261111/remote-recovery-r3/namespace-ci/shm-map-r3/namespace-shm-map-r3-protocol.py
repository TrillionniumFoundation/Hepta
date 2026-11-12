"""NEW complete private SHM-map semantics and protocol corpus.
FS and memory completions here are explicit synthetic controls, never OS proof.
The differential validator will execute the generated HIA image with full buffers.
"""
import struct,unittest
from pathlib import Path
from hepta.hia_agent_assembly import assemble_program,render_assembly
from hepta.hia_program_runtime import _Machine,_Owner,_View
from tools.generate_hia_agent_namespace_shm_map import document,MAGIC,BAD,CHANNEL
ROOT=Path(__file__).resolve().parents[1]
MASK=(1<<64)-1
REFUSED=0xfffffffd
def q(raw,index):return struct.unpack_from("<Q",raw,index*8)[0]
def put(raw,index,value):struct.pack_into("<Q",raw,index*8,value)
def packet(words,body=b""):
    return struct.pack("<32Q",*(list(words)+[0]*(32-len(words))))+body
def channel(raw,origin=1,role=0,result=0,serial=0):
    return struct.pack("<8Q",CHANNEL,origin,role,result,len(raw),serial,0,0)+raw
def request(cmd,*,session=(171,183),call=1,action=0,lease=1001,node=9,index=0,size=0,extend=0,error=0):
    if cmd in (6,7):return packet([MAGIC,cmd,*session,call,action,lease,node,error])
    return packet([MAGIC,cmd,*session,call,action,lease,node,index,size,extend])
class NamespaceShmMapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw=(ROOT/"examples/hia_bootstrap/agent_namespace_shm_map_r3.hiaasm").read_bytes()
        program=assemble_program(raw)
        cls.sources={"map":raw};cls.programs={"map":(program,program.as_dict()["functions"][0])}
    def invoke_program(self,role,raw,work,capacity=257,steps=4000000):
        original=bytes(raw);out=bytearray(capacity)
        owners=[_Owner(-1,bytearray(original)),_Owner(-2,out),_Owner(-3,work)]
        program,entry=self.programs[role]
        machine=_Machine(program,steps,16<<20,None,64)
        code=machine.invoke(entry,[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
        self.assertEqual(bytes(owners[0].data),original)
        return code,struct.unpack_from("<32Q",out) if capacity>=256 else None,bytes(out)
    def invoke(self,raw,c,steps=4000000):
        return self.invoke_program("map",raw,c["work"],c["capacity"],steps)
    def primitive(self,c,output):
        h=struct.unpack_from("<32Q",output);role,op,token,a,b,d=h[6:12]
        self.assertIn(role,(1,2));source=bytes(output[:256+h[16]])
        faults=c["faults"].get((role,op),[])
        error=faults.pop(0) if faults else 0
        value=0;extent=0;data=b""
        if not error and role==1:
            self.assertEqual(token,c["file_token"])
            if op==15:
                self.assertEqual((a,b,d,h[16]),(0,0,0,0))
                data=bytearray(144);put(data,0,17);put(data,1,91);put(data,6,c["filesize"]);data=bytes(data);extent=144
            elif op==3:
                self.assertEqual((b,d,source[256:]),(1,0,b"\0"))
                value=c["short_writes"].pop(0) if c["short_writes"] else 1
                self.assertIn(value,(0,1))
                if value:c["filesize"]=max(c["filesize"],a+1)
            else:self.fail(("unknown synthetic FS operation",op))
        elif not error and role==2:
            if op==1:
                self.assertEqual((d,h[16]),(0,0));self.assertEqual(b,len(c["memory"][token]["bytes"]) if token else 0)
                previous=c["memory"].get(token)
                if previous:self.assertEqual(previous["kind"],"vector")
                raw=bytearray(a)
                if previous:raw[:min(a,b)]=previous["bytes"][:min(a,b)]
                if token and c["same_vector"]:value=token
                else:value=c["next_memory"];c["next_memory"]+=1
                if token:del c["memory"][token]
                c["memory"][value]=dict(kind="vector",bytes=raw,readonly=False)
                extent=a
            elif op==2:
                self.assertEqual(token,c["file_token"]);self.assertIn(d,(1,3));self.assertLessEqual(a+b,c["filesize"])
                value=c["next_memory"];c["next_memory"]+=1;extent=b
                c["memory"][value]=dict(kind="file",bytes=bytearray(b),readonly=d==1,offset=a)
            elif op==3:
                self.assertEqual((token,b,d,h[16]),(0,0,0,0))
                value=c["next_memory"];c["next_memory"]+=1;extent=a
                c["memory"][value]=dict(kind="heap",bytes=bytearray(a),readonly=False)
            elif op==4:
                self.assertEqual(c["memory"][token]["kind"],"file")
                self.assertEqual((a,b,d),(32768,len(c["memory"][token]["bytes"]),0))
                del c["memory"][token]
            elif op==5:
                self.assertIn(c["memory"][token]["kind"],("vector","heap"))
                self.assertEqual((a,b,d),(len(c["memory"][token]["bytes"]),0,0))
                del c["memory"][token]
            elif op==6:
                self.assertEqual((token,a,b,d,h[16]),(0,0,0,0,0))
            else:self.fail(("unknown synthetic memory operation",op))
        elif error and role==2 and op in (4,5):
            # The original unmap/free caller ignores known cleanup errors.
            # This control retires the issued logical lease; it is no OS claim.
            self.assertIn(token,c["memory"]);del c["memory"][token]
        c["serial"][role]+=1
        record=dict(role=role,operation=op,token=token,arguments=[a,b,d],payload_hex=source[256:].hex(),
            error=error,value=value,extent=extent,source_sha256=__import__("hashlib").sha256(source).hexdigest(),
            file_size_after=c["filesize"],actual_OS_syscalls=0)
        c["syscalls"].append(record)
        raw=packet([MAGIC,5,*c["session"],c["call"],h[5],h[14],c["node"],
            role,op,error,value,extent,c["serial"][role],0,0,len(source)+len(data),len(source),len(data)],source+data)
        return channel(raw,2,role,0,c["serial"][role])
    def context(self,*,readonly=0,process=0,pagesize=4096,filesize=3):
        c=dict(session=(171,183),node=9,file_token=0 if process else 27,work=bytearray(1536),capacity=257,
            call=0,filesize=filesize,memory={},next_memory=201,serial={1:0,2:0},
            faults={},short_writes=[],syscalls=[],grows=[],same_vector=False,grow_failure=False)
        raw=packet([MAGIC,1,*c["session"],0,0,901,c["node"],c["file_token"],17,91,
            readonly,process,pagesize,71,83,0,0 if process else 1,101])
        result=self.invoke(channel(raw),c)
        self.assertEqual((result[0],result[1][6]),(0,0));c["last"]=result[1]
        return c
    def drive(self,c,raw,*,stop=False):
        for _ in range(10000):
            code,h,out=self.invoke(raw,c);c["last"]=h
            if code==2:
                before=len(c["syscalls"])
                c["grows"].append(dict(source_hex=bytes(raw).hex(),workspace_before=len(c["work"]),need=h[12],phase=h[17]))
                if c["grow_failure"]:
                    failed=request(7,session=c["session"],call=c["call"],action=h[5],lease=h[14],node=c["node"],error=12)
                    raw=channel(failed,4);continue
                self.assertGreater(h[12],len(c["work"]));self.assertEqual(h[13],257)
                self.assertLessEqual(h[12],16<<20,"finite fixture allocation guard, not a language quota")
                c["work"].extend(bytes(h[12]-len(c["work"])))
                self.assertEqual(before,len(c["syscalls"]));continue
            if code!=1:return code,h,out
            raw=self.primitive(c,out)
            if stop:return raw
        self.fail("finite test continuation guard exceeded")
    def start(self,c,cmd=2,*,index=0,extend=1,stop=False):
        c["call"]+=1
        raw=request(cmd,session=c["session"],call=c["call"],lease=1000+c["call"],node=c["node"],
            index=index,size=32768 if cmd==2 else 0,extend=extend if cmd==2 else 0)
        return self.drive(c,channel(raw),stop=stop)
    def mapped(self,c,*,index=0,extend=1,code=0):
        result=self.start(c,index=index,extend=extend)
        self.assertEqual((result[0],result[1][6]),(0,code));return result[1]
    def refuse(self,c,raw):
        result=self.invoke(raw,c);self.assertEqual(result[0],REFUSED)
        self.assertEqual(q(c["work"],0),BAD)
        again=self.invoke(raw,c);self.assertEqual(again[0],REFUSED)
        self.assertEqual(q(c["work"],0),BAD);return result
    def ops(self,c):return [(x["role"],x["operation"]) for x in c["syscalls"]]
    def test_01_regeneration_original_source_limits(self):
        d=document();self.assertEqual(render_assembly(d).encode(),self.sources["map"])
        self.assertLessEqual(len(d["functions"]),128);self.assertLessEqual(sum(len(f["blocks"]) for f in d["functions"]),1536)
        self.assertLessEqual(max(len(f["blocks"]) for f in d["functions"]),256)
        self.assertLessEqual(sum(len(b["ops"]) for f in d["functions"] for b in f["blocks"]),8192)
        self.assertLessEqual(max(len(b["params"]) for f in d["functions"] for b in f["blocks"]),16)
    def test_02_first_map_writes_every_page_then_realloc_and_mmap(self):
        c=self.context();h=self.mapped(c)
        self.assertEqual(self.ops(c),[(1,15)]+[(1,3)]*8+[(2,1),(2,2)])
        self.assertEqual([x["arguments"][0] for x in c["syscalls"] if x["role"]==1 and x["operation"]==3],
            [4095+4096*i for i in range(8)])
        self.assertEqual(c["filesize"],32768);self.assertEqual(h[9:12],(0,32768,1))
        self.assertEqual(len(c["grows"]),1);self.assertTrue(h[8] in c["memory"])
    def test_03_no_extend_small_file_returns_null_without_allocation(self):
        c=self.context();h=self.mapped(c,extend=0)
        self.assertEqual(h[8:12],(0,0,0,0));self.assertEqual(self.ops(c),[(1,15)])
        self.assertEqual(c["filesize"],3);self.assertEqual(q(c["work"],13),32768)
    def test_04_readonly_results_and_actual_requested_protection(self):
        c=self.context(readonly=1,filesize=32768);h=self.mapped(c,code=8)
        self.assertTrue(h[8]);self.assertEqual(c["syscalls"][-1]["arguments"],[0,32768,1])
        self.assertTrue(c["memory"][h[8]]["readonly"])
        c=self.context(readonly=1);h=self.mapped(c,extend=0,code=8);self.assertEqual(h[8],0)
        c=self.context(readonly=1);c["faults"][(1,15)]=[5]
        h=self.mapped(c,code=4874);self.assertEqual(h[7],5)
    def test_05_cached_mapping_has_no_new_peer_and_same_view(self):
        c=self.context();first=self.mapped(c);before=len(c["syscalls"]);second=self.mapped(c)
        self.assertEqual(second[8:12],first[8:12]);self.assertEqual(len(c["syscalls"]),before)
    def test_06_partial_mmap_failure_keeps_previous_region_and_recovers(self):
        c=self.context();c["faults"][(2,2)]=[0,5]
        h=self.mapped(c,index=2,code=5386);self.assertEqual((h[7],h[8],h[11]),(5,0,1))
        existing=self.mapped(c,index=0);self.assertTrue(existing[8])
        before=len(c["syscalls"]);h=self.mapped(c,index=2);self.assertEqual(h[11],3)
        self.assertEqual(self.ops(c)[before:],[(1,15),(2,1),(2,2),(2,2)])
        self.assertEqual(self.mapped(c,index=0)[8],existing[8])
    def test_07_process_lock_heap_zero_and_allocation_error_classes(self):
        c=self.context(process=1);c["faults"][(2,3)]=[0,12]
        h=self.mapped(c,index=1,code=7);self.assertEqual(h[11],1)
        self.assertNotIn(1,[x["role"] for x in c["syscalls"]])
        old=self.mapped(c,index=0);self.assertEqual(c["memory"][old[8]]["bytes"],bytes(32768))
        self.mapped(c,index=1)
        result=self.start(c,3);self.assertEqual(result[0],0);self.assertFalse(c["memory"])
        self.assertEqual(q(c["work"],1),6)
    def test_08_realloc_failure_preserves_old_table_and_mapping(self):
        c=self.context();first=self.mapped(c);old=q(c["work"],14)
        c["faults"][(2,1)]=[12]
        h=self.mapped(c,index=1,code=3082)
        self.assertEqual((h[7],h[11],q(c["work"],14)),(12,1,old))
        self.assertEqual(self.mapped(c,index=0)[8],first[8]);self.mapped(c,index=1)
    def test_09_pwrite_eintr_retries_only_the_same_current_page(self):
        c=self.context();c["faults"][(1,3)]=[4,4]
        self.mapped(c)
        writes=[x for x in c["syscalls"] if x["role"]==1 and x["operation"]==3]
        self.assertEqual(len(writes),10);self.assertEqual([x["arguments"][0] for x in writes[:3]],[4095]*3)
        c=self.context();c["faults"][(1,15)]=[4]
        self.mapped(c,code=4874);self.assertEqual(self.ops(c),[(1,15)])
    def test_10_zero_write_stops_without_later_page_or_memory_call(self):
        c=self.context();c["short_writes"]=[0]
        h=self.mapped(c,code=4874);self.assertEqual((h[7],h[8]),(0,0))
        self.assertEqual(self.ops(c),[(1,15),(1,3)]);self.assertEqual(c["filesize"],3)
    def test_11_stat_error_commits_size_before_failure(self):
        c=self.context();c["faults"][(1,15)]=[13]
        h=self.mapped(c,code=4874);self.assertEqual(h[7],13);self.assertEqual(q(c["work"],13),32768)
        self.assertFalse(c["memory"]);self.assertEqual(q(c["work"],11),0)
    def test_12_last_purge_ignores_known_unmap_errors_and_retires_once(self):
        c=self.context();self.mapped(c,index=1);c["faults"][(2,4)]=[4,5];c["faults"][(2,5)]=[12]
        before=len(c["syscalls"]);result=self.start(c,3)
        self.assertEqual((result[0],result[1][6],result[1][21]),(0,0,3))
        self.assertEqual(self.ops(c)[before:],[(2,4),(2,4),(2,5)]);self.assertFalse(c["memory"])
        self.assertEqual(q(c["work"],1),6)
        raw=request(3,session=c["session"],call=c["call"]+1,lease=999,node=c["node"])
        self.refuse(c,channel(raw));self.assertEqual(len(c["syscalls"]),before+3)
    def test_13_virtual_64k_page_groups_regions_and_purge_nominal_length(self):
        c=self.context(pagesize=65536,filesize=65536);h=self.mapped(c,index=1)
        self.assertEqual((h[9],h[10],h[11]),(32768,32768,2))
        self.assertEqual(self.ops(c),[(1,15),(2,1),(2,2)])
        self.assertEqual(c["syscalls"][-1]["arguments"],[0,65536,3])
        self.start(c,3);unmap=next(x for x in c["syscalls"] if (x["role"],x["operation"])==(2,4))
        self.assertEqual(unmap["arguments"],[32768,65536,0])
    def test_14_known_growth_allocation_failure_keeps_written_file_and_session(self):
        c=self.context();c["grow_failure"]=True
        h=self.mapped(c,code=3082);self.assertEqual(h[7],12);self.assertEqual(c["filesize"],32768)
        self.assertNotIn(2,[x["role"] for x in c["syscalls"]]);self.assertEqual(q(c["work"],11),0)
        c["grow_failure"]=False;self.mapped(c)
        self.assertEqual(sum(x["operation"]==3 and x["role"]==1 for x in c["syscalls"]),8)
    def test_15_ack_session_action_role_serial_and_source_binding(self):
        for field in ("nonce","action","role","serial","source","extent"):
            with self.subTest(field=field):
                c=self.context();raw=bytearray(self.start(c,stop=True))
                if field=="nonce":put(raw,10,q(raw,10)+1)
                if field=="action":put(raw,13,q(raw,13)+1)
                if field=="role":put(raw,2,2)
                if field=="serial":put(raw,5,q(raw,5)+1)
                if field=="source":raw[64+256+16]^=1
                if field=="extent":put(raw,26,q(raw,26)-1)
                self.refuse(c,raw)
    def test_16_unknown_outcome_retains_uncertain_pending_and_refuses(self):
        c=self.context();self.start(c,stop=True);pending=q(c["work"],35)
        raw=request(6,session=c["session"],call=c["call"],action=q(c["work"],5),lease=q(c["work"],6),node=c["node"])
        self.refuse(c,channel(raw,3));self.assertEqual(q(c["work"],35),pending)
        self.assertEqual(len(c["syscalls"]),1);self.assertFalse(c["memory"])
    def test_17_short_views_do_not_write_beyond_minimum(self):
        raw=channel(packet([MAGIC,1,171,183,0,0,901,9,27,17,91,0,0,4096,71,83,0,1,101]))
        for size in (0,7,8,511,1535):
            work=bytearray(size);code,_,out=self.invoke_program("map",raw,work,257)
            self.assertEqual((code,out),(REFUSED,bytes(257)))
            if size>=8:self.assertEqual(q(work,0),BAD)
        for size in (0,7,255,256):
            work=bytearray(1536);code,_,out=self.invoke_program("map",raw,work,size)
            self.assertEqual(code,REFUSED);self.assertEqual(q(work,0),BAD)
            if size<256:self.assertEqual(out,bytes(size))
    def test_18_state_records_and_pending_shape_reject_before_use(self):
        c=self.context();self.mapped(c);put(c["work"],12,1000)
        raw=request(2,session=c["session"],call=c["call"]+1,lease=999,node=c["node"],size=32768)
        self.refuse(c,channel(raw))
        for field,value in ((16,50),(19,0),(20,0),(35,2),(36,3),(38,7),(128,0)):
            c=self.context();raw=self.start(c,stop=True);put(c["work"],field,value);self.refuse(c,raw)
    def test_19_new_mapping_handle_cannot_alias_table_or_old_mapping(self):
        c=self.context(filesize=32768);raw=self.start(c,stop=True)
        result=self.drive(c,raw,stop=True)  # consumes FSTAT, grows, then obtains REALLOC ACK
        raw=self.drive(c,result,stop=True) # obtains MAP ACK
        forged=bytearray(raw);put(forged,19,q(c["work"],14))
        self.refuse(c,forged)
    def test_20_realloc_same_vector_identity_is_legal(self):
        c=self.context();self.mapped(c);table=q(c["work"],14);c["same_vector"]=True
        self.mapped(c,index=1);self.assertEqual(q(c["work"],14),table)
        self.start(c,3);self.assertFalse(c["memory"])
    def test_21_invalid_user_fields_and_foreign_channels_permanently_refuse(self):
        c=self.context();raw=bytearray(channel(request(2,session=c["session"],node=c["node"],size=32768)))
        put(raw,28,1);self.refuse(c,raw)
        for command in (5,6,7):
            c=self.context();self.refuse(c,channel(request(command,session=c["session"],node=c["node"])))
    def test_22_natural_counters_and_address_arithmetic_do_not_wrap(self):
        c=self.context();put(c["work"],4,MASK)
        self.refuse(c,channel(request(2,session=c["session"],call=0,node=c["node"],size=32768)))
        c=self.context();put(c["work"],5,MASK)
        self.refuse(c,channel(request(2,session=c["session"],call=1,node=c["node"],size=32768)))
        c=self.context();h=self.mapped(c,index=MASK,code=3082);self.assertEqual(h[8],0);self.assertFalse(c["syscalls"])
    def test_23_barrier_is_separate_native_memory_continuation(self):
        c=self.context();result=self.start(c,4);self.assertEqual((result[0],result[1][6]),(0,0))
        self.assertEqual(self.ops(c),[(2,6)])
        c=self.context();c["faults"][(2,6)]=[5]
        result=self.start(c,4);self.assertEqual(result[0],REFUSED);self.assertEqual(q(c["work"],0),BAD)
    def test_24_file_tail_rounding_and_growth_after_partial_mapping(self):
        for size,expected in ((4096,[8191,12287,16383,20479,24575,28671,32767]),
                              (4097,[8191,12287,16383,20479,24575,28671,32767]),
                              (32767,[32767]),(32768,[])):
            c=self.context(filesize=size);self.mapped(c)
            self.assertEqual([x["arguments"][0] for x in c["syscalls"] if (x["role"],x["operation"])==(1,3)],expected)
        c=self.context();c["faults"][(2,2)]=[0,12]
        self.mapped(c,index=1,code=5386);old=self.mapped(c,index=0)[8]
        c["grow_failure"]=True;self.mapped(c,index=4,code=3082)
        self.assertEqual(self.mapped(c,index=0)[8],old);self.assertEqual(q(c["work"],11),1)
        c["grow_failure"]=False;self.mapped(c,index=4);self.start(c,3);self.assertFalse(c["memory"])
if __name__=="__main__":unittest.main()
