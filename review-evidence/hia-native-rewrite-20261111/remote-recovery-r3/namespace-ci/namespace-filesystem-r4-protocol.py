"""NEW FS-r4 protocol/VM fixtures; all original FS-r3 methods retained. Synthetic syscall replies are explicitly private.
A paired actual-image runner may inherit these tests; no case is whole-store
qualification, legacy migration, or proof that a foreign header is authorized.
"""
import struct
import unittest
from pathlib import Path
from hepta.hia_agent_assembly import assemble_program,render_assembly
from hepta.hia_program_runtime import _Machine,_Owner,_View
from tools.generate_hia_agent_namespace_filesystem_r4 import document,MAGIC,BADMAGIC

ROOT=Path(__file__).resolve().parents[1]
BAD=0xfffffffd
MASK=(1<<64)-1

def frame(command,*,session=(0,1),call=0,sequence=0,operation=0,raw=0,args=(0,0,0,0),lease=0,body=b"",reserved=None):
    words=[MAGIC,command,*session,call,sequence,operation,raw&MASK,*args,len(body),lease]+[0]*18
    if reserved:
        for key,value in reserved.items():words[key]=value
    return struct.pack("<32Q",*words)+body

def q(data,word):return struct.unpack_from("<Q",data,word*8)[0]
def poke(data,offset,value):struct.pack_into("<Q",data,offset,value)

def stat_bytes():
    raw=bytearray(range(144))
    struct.pack_into("<QQQIIIIQqqq",raw,0,71,9001,2,0o100600,0,23,0,0,123,4096,8)
    return bytes(raw)

class NamespaceFilesystemR4Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source=(ROOT/"examples/hia_bootstrap/agent_namespace_filesystem_r4.hiaasm").read_bytes()
        cls.program=assemble_program(cls.source)
        cls.entry=cls.program.as_dict()["functions"][0]

    def invoke(self,raw,work,output_size=512,steps=4000000):
        original=bytes(raw)
        output=bytearray(output_size)
        owners=[_Owner(-1,bytearray(raw)),_Owner(-2,output),_Owner(-3,work)]
        machine=_Machine(self.program,steps,16<<20,None,64)
        code=machine.invoke(self.entry,[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
        self.assertEqual(bytes(owners[0].data),original)
        actual=bytes(output)
        header=struct.unpack_from("<32Q",actual) if len(actual)>=256 else None
        return code,header,actual

    def context(self,size=512):
        c=dict(work=bytearray(size),call=0,output=512,session=(0,1),grows=0)
        code,h,raw=self.invoke(frame(1,session=c["session"]),c["work"],c["output"])
        self.assertEqual((code,h[1],h[15],h[20],h[21],h[22]),(0,0,1,0,1,3))
        c["last"]=h
        return c

    def call(self,c,operation,*args,body=b"",auto_grow=True):
        c["call"]+=1
        args=tuple(args)+(0,)*(4-len(args))
        original=frame(2,session=c["session"],call=c["call"],operation=operation,args=args,lease=((1000+c["call"])&MASK) or 1,body=body)
        code,h,raw=self.invoke(original,c["work"],c["output"])
        count=0
        while code==2 and auto_grow:
            count+=1
            self.assertLessEqual(count,2,"finite fixture should need one actual capacity increase")
            self.assertLessEqual(max(h[17],h[18]),8<<20,"test accidentally requested unbounded allocation")
            previous=bytes(c["work"])
            c["work"].extend(bytes(max(0,h[17]-len(c["work"]))))
            self.assertEqual(bytes(c["work"][:len(previous)]),previous)
            c["output"]=max(c["output"],h[18])
            c["grows"]+=1
            code,h,raw=self.invoke(original,c["work"],c["output"])
        c["request"]=original;c["last"]=h;c["last_bytes"]=raw
        return code,h,raw

    def ack_frame(self,c,raw=0,body=b"",command=3):
        h=c["last"]
        return frame(command,session=(h[2],h[3]),call=h[4],sequence=h[5],operation=h[6],raw=raw,lease=h[14],body=body)

    def ack(self,c,raw=0,body=b""):
        source=self.ack_frame(c,raw,body)
        code,h,out=self.invoke(source,c["work"],c["output"])
        c["last"]=h;c["last_bytes"]=out;c["last_ack"]=source
        return code,h,out

    def opened(self,c,fd=0):
        code,h,_=self.call(c,1,0,0,0,body=b"x")
        self.assertEqual(code,1)
        self.assertEqual((h[6],h[8],h[16]),(1,MASK-99,2))
        code,h,_=self.ack(c,fd)
        self.assertEqual((code,h[7]),(0,0))
        return h[8]

    def assert_poisoned(self,c,reason=None):
        frozen=bytes(c["work"])
        code,h,_=self.invoke(frame(1,session=(7,9)),c["work"],c["output"])
        self.assertEqual(code,BAD)
        if reason is not None:self.assertEqual(h[19],reason)
        self.assertEqual(bytes(c["work"]),frozen)

    def test_source_reproduces_and_profile_remains_explicit(self):
        self.assertEqual(self.source,render_assembly(document()).encode())
        doc=self.program.as_dict()
        self.assertLessEqual(len(doc["functions"]),128)
        self.assertLessEqual(sum(len(f["blocks"]) for f in doc["functions"]),1536)
        self.assertLessEqual(max(len(f["blocks"]) for f in doc["functions"]),256)
        self.assertLessEqual(sum(len(b["ops"]) for f in doc["functions"] for b in f["blocks"]),8192)
        self.assertLessEqual(max(len(b["params"]) for f in doc["functions"] for b in f["blocks"]),16)

    def test_all_twenty_two_primitive_selections_and_results(self):
        stat=stat_bytes()
        for operation in range(1,23):
            with self.subTest(operation=operation):
                c=self.context()
                token=self.opened(c,0) if operation in (2,3,4,5,6,8,11,15,17,21) else None
                cases={
                    1:((0,0,0,0),b"path",7,b""),
                    2:((token,7,3,0),b"",3,b"abc"),
                    3:((token,4,0,0),b"a\x00b",2,b""),
                    4:((token,0,0,0),b"",0,stat),
                    5:((token,100,0,0),b"",0,b""),
                    6:((token,0,0,0),b"",0,b""),
                    7:((0,0,1,0),b"ab",0,b""),
                    8:((token,0,0,0),b"",0,b""),
                    9:((0,0,0,0),b"path",0,b""),
                    10:((0,0o700,0,0),b"path",0,b""),
                    11:((token,6,0,0),b"",0,b""),
                    12:((0,0,0,0),b"",0,struct.pack("<2Q",12,345)),
                    13:((5,6,0,0),b"",0,b""),
                    14:((7,0,0,0),b"",3,b"abc"),
                    15:((token,0,0,0),b"",0,stat),
                    16:((0,0,0,0),b"",0,b""),
                    17:((token,1,120,1),b"",0,b""),
                    18:((0,256,0,0),b"path",0,stat),
                    19:((0,7,0,0),b"path",3,b"abc"),
                    20:((8,0,0,0),b"",3,b"/x\x00"),
                    21:((token,0o600,0,0),b"",0,b""),
                    22:((0,0o600,0,0),b"path",0,b""),
                }
                args,body,raw,response=cases[operation]
                code,h,event=self.call(c,operation,*args,body=body)
                self.assertEqual((code,h[1],h[6],h[15]),(1,1,operation,2))
                if operation==1:self.assertEqual(event[256:256+h[16]],b"path\x00")
                if operation==7:self.assertEqual(event[256:256+h[16]],b"a\x00b\x00")
                if operation==3:self.assertEqual(event[256:256+h[16]],b"a\x00b")
                if token is not None:self.assertEqual(h[8],0,"FD zero must remain a real raw fd")
                if operation==17:self.assertEqual(h[8:12],(0,1,120,1))
                if operation==8:self.assertEqual(q(c["work"],9),0,"close must retire before its syscall")
                code,h,out=self.ack(c,raw,response)
                self.assertEqual((code,h[7],h[15]),(0,0,1))
                if operation in (2,14,19,20):
                    self.assertEqual((h[8],h[16],out[256:256+h[16]]),(raw,len(response),response))
                elif operation in (4,15,18):
                    self.assertEqual(h[8:14],(71,9001,0o100600,0,23,123))
                    self.assertEqual(h[24],2)
                    self.assertEqual(h[16],0 if operation==4 else 144)
                    if operation!=4:self.assertEqual(out[256:400],stat)
                elif operation==12:self.assertEqual(h[8:10],(12,345))
                elif operation in (3,16):self.assertEqual(h[8],raw)

    def test_zero_uid_and_u32_identity_are_not_unissued_markers(self):
        for value in (0,1,65534,0xffffffff):
            with self.subTest(uid=value):
                c=self.context();self.assertEqual(self.call(c,16)[0],1)
                code,h,_=self.ack(c,value)
                self.assertEqual((code,h[7],h[8]),(0,0,value))
        c=self.context();self.call(c,16)
        code,h,_=self.ack(c,1<<32)
        self.assertEqual((code,h[19]),(BAD,29));self.assert_poisoned(c,29)

    def test_partial_and_zero_io_preserve_exact_extents(self):
        for operation,count,response in ((2,0,b""),(2,9,b"x"),(14,0,b""),(14,9,b"xy"),(19,0,b""),(19,9,b"x")):
            with self.subTest(operation=operation,count=count):
                c=self.context()
                if operation==2:args=(self.opened(c),count,0)
                elif operation==14:args=(count,)
                else:args=(0,count)
                self.call(c,operation,*args,body=b"path" if operation==19 else b"")
                code,h,out=self.ack(c,len(response),response)
                self.assertEqual((code,h[8],h[16]),(0,len(response),len(response)))
                self.assertEqual(out[256:256+h[16]],response)
        c=self.context();token=self.opened(c);self.call(c,3,token,0,body=b"abc")
        self.assertEqual(self.ack(c,0)[1][8],0)

    def test_growth_precedes_syscall_and_reuses_exact_call_header(self):
        c=self.context()
        code,h,_=self.call(c,14,4096,auto_grow=False)
        self.assertEqual((code,h[5],h[15],h[17],h[18]),(2,0,3,512,4352))
        original=c["request"];before=bytes(c["work"])
        for _ in range(2):
            code,again,_=self.invoke(original,c["work"],512)
            self.assertEqual((code,again),(2,h));self.assertEqual(bytes(c["work"]),before)
        c["output"]=h[18]
        code,h,_=self.invoke(original,c["work"],c["output"])
        c["last"]=h
        self.assertEqual((code,h[4],h[5]),(1,1,1))
        self.assertEqual(self.ack(c,1,b"x")[0],0)
        c=self.context();self.call(c,14,4096,auto_grow=False)
        wrong=bytearray(c["request"]);poke(wrong,72,1)
        code,h,_=self.invoke(wrong,c["work"],512)
        self.assertEqual((code,h[19]),(BAD,13));self.assert_poisoned(c,13)
        c=self.context();self.call(c,14,4096,auto_grow=False)
        code,h,_=self.invoke(self.ack_frame(c,command=6),c["work"],512)
        self.assertEqual((code,h[19]),(BAD,18));self.assert_poisoned(c,18)

    def test_slots_grow_beyond_sixteen_without_reusing_logical_tokens(self):
        c=self.context();tokens=[self.opened(c,fd) for fd in range(20)]
        self.assertEqual(tokens,list(range(1,21)))
        self.assertEqual((q(c["work"],9),q(c["work"],10)),(20,32))
        self.call(c,8,tokens[3]);self.ack(c)
        token=self.opened(c,100)
        self.assertEqual(token,21)
        self.call(c,8,tokens[3])
        self.assertEqual(c["last"][1],BAD)

    def test_close_consumes_on_eintr_and_never_retries(self):
        c=self.context();token=self.opened(c,0)
        code,h,_=self.call(c,8,token)
        sequence=h[5]
        self.assertEqual((code,q(c["work"],9)),(1,0))
        code,h,_=self.ack(c,-4)
        self.assertEqual((code,h[7],h[5],h[20]),(0,4,sequence,0))
        code,h,_=self.call(c,8,token)
        self.assertEqual((code,h[19],h[5]),(BAD,12,sequence))
        self.assert_poisoned(c,12)

    def test_close_all_attempts_each_once_and_retains_first_errno(self):
        c=self.context()
        for fd in (0,3,7):self.opened(c,fd)
        c["call"]+=1
        source=frame(4,session=c["session"],call=c["call"])
        code,h,_=self.invoke(source,c["work"],c["output"]);c["last"]=h
        for fd,error in ((0,-4),(3,0),(7,-9)):
            self.assertEqual((code,h[6],h[8],h[23]),(1,8,fd,1))
            code,h,_=self.ack(c,error)
        self.assertEqual((code,h[6],h[7],h[15],h[20],h[23]),(0,0,4,5,0,1))
        code,h,_=self.invoke(frame(1,session=c["session"]),c["work"],c["output"])
        self.assertEqual((code,h[19]),(BAD,9));self.assert_poisoned(c,9)
        empty=self.context();empty["call"]=1
        code,h,_=self.invoke(frame(4,call=1),empty["work"])
        self.assertEqual((code,h[6],h[15],h[20],h[23]),(0,0,5,0,1))

    def test_ack_replay_cross_session_and_correlation_changes_refuse(self):
        for word in (2,3,4,5,6,8,9,10,11,13,14,31):
            with self.subTest(word=word):
                c=self.context();self.call(c,16)
                source=bytearray(self.ack_frame(c,0));poke(source,8*word,(q(source,word)+1)&MASK)
                code,h,_=self.invoke(source,c["work"],512)
                self.assertEqual(code,BAD);self.assert_poisoned(c)
        c=self.context();self.call(c,16);source=self.ack_frame(c,0)
        self.assertEqual(self.invoke(source,c["work"])[0],0)
        self.assertEqual(self.invoke(source,c["work"])[0],BAD);self.assert_poisoned(c)
        c=self.context();self.call(c,16)
        self.assertEqual(self.invoke(self.ack_frame(c,command=5),c["work"])[1][19],18)
        self.assert_poisoned(c,18)

    def test_bad_syscall_returns_and_truncated_structures_refuse_before_reads(self):
        cases=[(12,(),0,b"",32),(12,(),0,b"x"*8,32),(12,(),0,b"x"*15,32),
               (12,(),0,b"x"*17,32),(12,(),0,struct.pack("<2Q",1,1000000000),32),
               (16,(),1<<32,b"",29),(16,(),-1,b"x",23),
               (20,(4,),0,b"",26),(20,(4,),1,b"x",26)]
        for op,args,raw,body,reason in cases:
            with self.subTest(operation=op,raw=raw,body_bytes=len(body)):
                c=self.context();self.call(c,op,*args)
                code,h,_=self.ack(c,raw,body)
                self.assertEqual((code,h[19]),(BAD,reason));self.assert_poisoned(c,reason)
        for length in (0,1,143,145):
            c=self.context();token=self.opened(c);self.call(c,15,token)
            code,h,_=self.ack(c,0,bytes(length))
            self.assertEqual((code,h[19]),(BAD,31));self.assert_poisoned(c,31)
        c=self.context();self.call(c,1,0,0,0,body=b"x")
        self.assertEqual(self.ack(c,1<<31)[1][19],24)
        c=self.context();token=self.opened(c);self.call(c,2,token,1)
        self.assertEqual(self.ack(c,2,b"xx")[1][19],26)
        c=self.context();token=self.opened(c);self.call(c,6,token)
        self.assertEqual(self.ack(c,1)[1][19],30)

    def test_known_errno_is_complete_and_context_remains_usable(self):
        for error in (1,4,5,9,11,13,28,38,95,4095):
            with self.subTest(errno=error):
                c=self.context();self.call(c,1,0,0,0,body=b"x")
                code,h,_=self.ack(c,-error)
                self.assertEqual((code,h[7],h[15],h[20],h[21]),(0,error,1,0,1))
                self.call(c,16);self.assertEqual(self.ack(c,0)[0],0)

    def test_malformed_sources_short_buffers_and_first_refusal_order(self):
        for size in (0,7,8,15,255,511):
            with self.subTest(workspace=size):
                work=bytearray(size)
                self.assertEqual(self.invoke(frame(1),work)[0],BAD)
                if size>=8:
                    self.assertEqual(q(work,0),BADMAGIC)
                    work.extend(bytes(512-len(work)))
                    self.assertEqual(self.invoke(frame(1),work)[0],BAD)
        for size in (0,127,255):
            c=self.context()
            code,header,out=self.invoke(b"",c["work"],size)
            self.assertEqual((code,header,out),(BAD,None,bytes(size)))
            self.assert_poisoned(c,1)
        for raw,reason in ((b"",2),(bytes(255),2),(bytes(256),3)):
            c=self.context();code,h,_=self.invoke(raw,c["work"])
            self.assertEqual((code,h[19]),(BAD,reason));self.assert_poisoned(c,reason)
        c=self.context()
        bad=frame(2,call=1,operation=16,lease=1,reserved={0:0,31:1})
        code,h,_=self.invoke(bad,c["work"])
        self.assertEqual((code,h[19]),(BAD,3))
        for body in (b"",b"a\x00b"):
            c=self.context();self.assertEqual(self.call(c,1,0,0,0,body=body)[1][19],12)

    def test_private_workspace_inconsistency_and_counter_boundaries(self):
        for offset,value in ((0,1),(8,99),(56,1),(64,0),(72,1),(80,MASK),(88,1),(104,1),(168,1),(248,2),(256,1)):
            with self.subTest(offset=offset):
                c=self.context();poke(c["work"],offset,value)
                code,h,_=self.invoke(frame(2,call=1,operation=16,lease=1),c["work"],steps=200000)
                self.assertEqual((code,h[19]),(BAD,7));self.assert_poisoned(c,7)
        c=self.context();poke(c["work"],40,MASK)
        code,h,_=self.call(c,16)
        self.assertEqual((code,h[19],h[5]),(BAD,22,MASK))
        c=self.context();poke(c["work"],64,MASK)
        code,h,_=self.call(c,1,0,0,0,body=b"x")
        self.assertEqual((code,h[19],h[5]),(BAD,20,0))
        c=self.context();poke(c["work"],32,MASK-1);c["call"]=MASK-1
        self.assertEqual(self.call(c,16)[0],1);self.assertEqual(self.ack(c,0)[0],0)
        code,h,_=self.invoke(frame(2,call=0,operation=16,lease=1),c["work"],512)
        self.assertEqual((code,h[19]),(BAD,10))

    def test_duplicate_raw_fd_refuses_without_reissuing_a_token(self):
        c=self.context();self.assertEqual(self.opened(c,0),1)
        self.call(c,1,0,0,0,body=b"again")
        code,h,_=self.ack(c,0)
        self.assertEqual((code,h[19],h[20],h[21]),(BAD,25,1,2))
        self.assert_poisoned(c,25)

    def test_getlk_full_raw_flock_and_typed_fields_are_lossless(self):
        for locktype,whence,start,count,pid in (
            (0,0,128,1,123),(1,0,120,8,0xffffffff),(2,0,0,0,0),
            (2,2,MASK,MASK-1,0x80000000),
        ):
            with self.subTest(locktype=locktype,whence=whence,pid=pid):
                c=self.context();token=self.opened(c,0)
                code,h,_=self.call(c,23,token,1,128,1)
                self.assertEqual((code,h[6],h[8:12],h[16]),(1,23,(0,1,128,1),0))
                payload=struct.pack("<HHIQQII",locktype,whence,0x12345678,start,count,pid,0xabcdef01)
                code,h,out=self.ack(c,0,payload)
                self.assertEqual((code,h[7],h[8:13],h[16]),(0,0,(locktype,whence,start,count,pid),32))
                self.assertEqual(out[256:288],payload)
                self.assertEqual((h[20],h[21]),(1,2))

    def test_getlk_truncation_positive_result_errno_and_unknown(self):
        for length in (0,1,15,16,31,33):
            with self.subTest(length=length):
                c=self.context();token=self.opened(c);self.call(c,23,token,1,128,1)
                code,h,_=self.ack(c,0,bytes(length))
                self.assertEqual((code,h[19]),(BAD,34));self.assert_poisoned(c,34)
        c=self.context();token=self.opened(c);self.call(c,23,token,1,128,1)
        self.assertEqual(self.ack(c,1,bytes(32))[1][19],30)
        for error in (1,4,5,9,11,22,38,4095):
            with self.subTest(errno=error):
                c=self.context();token=self.opened(c);self.call(c,23,token,1,128,1)
                code,h,_=self.ack(c,-error)
                self.assertEqual((code,h[7],h[15],h[20]),(0,error,1,1))
                self.call(c,16);self.assertEqual(self.ack(c,0)[0],0)
        c=self.context();token=self.opened(c);self.call(c,23,token,1,128,1)
        code,h,_=self.ack(c,-4,bytes(32))
        self.assertEqual((code,h[19]),(BAD,23))
        c=self.context();token=self.opened(c);self.call(c,23,token,1,128,1)
        code,h,_=self.invoke(self.ack_frame(c,command=5),c["work"],c["output"])
        self.assertEqual((code,h[19]),(BAD,18));self.assert_poisoned(c,18)

    def test_getlk_growth_is_before_actual_query_and_exact_source(self):
        c=self.context();token=self.opened(c);c["output"]=256
        code,h,_=self.call(c,23,token,1,128,1,auto_grow=False)
        sequence=q(c["work"],5)
        self.assertEqual((code,h[15],h[18],h[5]),(2,3,288,sequence))
        raw=c["request"];before=bytes(c["work"])
        again=self.invoke(raw,c["work"],256)
        self.assertEqual(again[0:2],(2,h));self.assertEqual(bytes(c["work"]),before)
        c["output"]=288;code,h,_=self.invoke(raw,c["work"],288);c["last"]=h
        self.assertEqual((code,h[5]),(1,sequence+1))
        payload=struct.pack("<HHIQQII",2,0,0,128,1,0,0)
        code,h,out=self.ack(c,0,payload)
        self.assertEqual((code,h[16],out[256:288]),(0,32,payload))
        c=self.context();token=self.opened(c);c["output"]=256
        self.call(c,23,token,1,128,1,auto_grow=False)
        changed=bytearray(c["request"]);poke(changed,80,129)
        self.assertEqual(self.invoke(changed,c["work"],256)[1][19],13)
        c=self.context();token=self.opened(c);self.call(c,23,token,1,128,1)
        code,h,_=self.invoke(self.ack_frame(c,0,payload),c["work"],287)
        self.assertEqual((code,h[19]),(BAD,27));self.assert_poisoned(c,27)

    def test_getlk_queries_do_not_acquire_close_or_reissue_handles(self):
        c=self.context();token=self.opened(c,0)
        original_rows=bytes(c["work"][512:])
        for kind in (0,1,2):
            code,h,_=self.call(c,23,token,kind,128,1)
            self.assertEqual((code,h[8:12],h[20],h[21]),(1,(0,kind,128,1),1,2))
            self.assertEqual(bytes(c["work"][512:]),original_rows)
            payload=struct.pack("<HHIQQII",2,0,0,128,1,0,0)
            code,h,_=self.ack(c,0,payload)
            self.assertEqual((code,h[7],h[20],h[21]),(0,0,1,2))
            self.assertEqual(bytes(c["work"][512:]),original_rows)
        self.call(c,8,token);self.ack(c)
        code,h,_=self.call(c,23,token,1,128,1)
        self.assertEqual((code,h[19]),(BAD,12));self.assert_poisoned(c,12)

if __name__=="__main__":
    unittest.main(verbosity=2)
