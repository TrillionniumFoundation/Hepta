"""NEW inode/WAL-owner fixtures; synthetic FS packets are private protocol controls.

The same methods can run on retained CoreVM and paired actual B3-produced image.
No synthetic packet is evidence of actual filesystem provenance or migration.
Real FS-provider/fcntl integration is a separate required group.
"""
import struct,unittest
from pathlib import Path
from hepta.hia_agent_assembly import assemble_program,render_assembly
from hepta.hia_program_runtime import _Machine,_Owner,_View
from tools.generate_hia_agent_namespace_inode import document,MAGIC,BAD,FS_MAGIC
ROOT=Path(__file__).resolve().parents[1]
REFUSED=0xfffffffd
MASK=(1<<64)-1
def q(raw,index):return struct.unpack_from("<Q",raw,index*8)[0]
def put(raw,index,value):struct.pack_into("<Q",raw,index*8,value)
def frame(command,session=(0,1),call=0,action=0,handle=0,operation=0,
          value=0,offset=0,count=0,lease=0,body=b"",fs=(17,29),watermarks=(0,0)):
    values=[MAGIC,command,*session,call,action,handle,operation,0,value,0,0,0,offset,count,lease,len(body)]+[0]*15
    if command==1:values[9:13]=[*fs,*watermarks]
    return struct.pack("<32Q",*values)+body

class NamespaceInodeOwnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source=(ROOT/"examples/hia_bootstrap/agent_namespace_inode_r2.hiaasm").read_bytes()
        cls.program=assemble_program(cls.source)
        cls.entry=cls.program.as_dict()["functions"][0]
    def invoke(self,raw,work,capacity=256,steps=4000000):
        raw=bytes(raw);out=bytearray(capacity)
        owners=[_Owner(-1,bytearray(raw)),_Owner(-2,out),_Owner(-3,work)]
        machine=_Machine(self.program,steps,16<<20,None,64)
        result=machine.invoke(self.entry,[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
        self.assertEqual(bytes(owners[0].data),raw)
        result_bytes=bytes(out)
        return result,struct.unpack_from("<32Q",result_bytes) if capacity>=256 else None,result_bytes
    def context(self,size=512):
        c=dict(work=bytearray(size),call=0,session=(0,1),fs=(17,29),fscall=0,fsseq=0,peers=0,grows=0)
        code,h,raw=self.invoke(frame(1,session=c["session"],fs=c["fs"]),c["work"])
        self.assertEqual((code,h[14],h[13],h[22]),(0,1,1,1))
        c.update(last=h,last_bytes=raw)
        return c
    def start(self,c,command,handle=0,*,value=0,offset=0,count=0,grow=True):
        c["call"]+=1
        raw=frame(command,session=c["session"],call=c["call"],handle=handle,value=value,
                  offset=offset,count=count,lease=((5000+c["call"])&MASK) or 1)
        c["original"]=raw
        code,h,out=self.invoke(raw,c["work"])
        if code==2 and grow:
            self.assertEqual(command,2)
            self.assertGreater(h[15],len(c["work"]))
            self.assertLessEqual(h[15],16<<20,"finite fixture allocation guard, not language quota")
            old=bytes(c["work"]);c["work"].extend(bytes(h[15]-len(c["work"])))
            self.assertEqual(bytes(c["work"][:len(old)]),old)
            c["grows"]+=1
            code,h,out=self.invoke(raw,c["work"])
            self.assertNotEqual(code,2)
        c.update(last=h,last_bytes=out)
        return code,h,out
    def ack_source(self,c,*,error=0,device=71,inode=9001,mode=0o100600,uid=0,gid=23,size=123,command=6):
        h=c["last"]
        if command==7:
            return frame(7,session=c["session"],call=h[4],action=h[5],handle=h[6],
                         operation=h[7],lease=h[11])
        c["fscall"]+=1;c["fsseq"]+=1
        args=[h[16],0,0,0]
        if h[7]==17:args=[h[16],h[17],h[18],h[19]]
        request=struct.pack("<32Q",FS_MAGIC,2,*c["fs"],c["fscall"],0,h[7],0,*args,0,h[5],*([0]*18))
        words=[0]*32
        words[:8]=[FS_MAGIC,0,*c["fs"],c["fscall"],c["fsseq"],h[7],error]
        words[14]=h[5];words[15]=1;words[20]=100;words[21]=1000;words[22]=3
        payload=b""
        if h[7]==15 and error==0:
            payload=bytearray(144)
            struct.pack_into("<QQQIIIIQqqq",payload,0,device,inode,1,mode,uid,gid,0,0,size,4096,8)
            words[8:14]=[device,inode,mode,uid,gid,size&MASK]
            words[16]=144;words[24]=1
        output=struct.pack("<32Q",*words)+bytes(payload)
        output+=bytes(512-len(output))
        return frame(6,session=c["session"],call=h[4],action=h[5],handle=h[6],
                     operation=h[7],lease=h[11],body=request+output)
    def ack(self,c,**kw):
        raw=self.ack_source(c,**kw);c["ack_source"]=raw
        code,h,out=self.invoke(raw,c["work"]);c["peers"]+=1
        c.update(last=h,last_bytes=out)
        return code,h,out
    def register(self,c,token,device=71,inode=9001,uid=0):
        code,h,_=self.start(c,2,value=token)
        self.assertEqual((code,h[7],h[16]),(1,15,token))
        code,h,_=self.ack(c,device=device,inode=inode,uid=uid)
        self.assertEqual((code,h[8],h[9]),(0,0,0))
        return h[10]
    def locked(self,c,handle,kind=2,offset=0,count=1):
        code,h,_=self.start(c,3,handle,value=kind,offset=offset,count=count)
        self.assertEqual((code,h[7],h[17],h[18],h[19]),(1,17,kind-1,120+offset,count))
        code,h,_=self.ack(c);self.assertEqual((code,h[8]),(0,0))
    def poison(self,c,raw=None,reason=None):
        if raw is not None:
            code,h,_=self.invoke(raw,c["work"]);self.assertEqual(code,REFUSED)
            if reason is not None:self.assertEqual(h[23],reason)
        frozen=bytes(c["work"])
        code,h,_=self.invoke(frame(1,session=(5,6)),c["work"])
        self.assertEqual(code,REFUSED);self.assertEqual(q(c["work"],0),BAD)
        self.assertEqual(bytes(c["work"]),frozen)
    def test_01_source_profile_and_exact_regeneration(self):
        d=document()
        self.assertEqual(render_assembly(d).encode(),self.source)
        self.assertLessEqual(len(d["functions"]),128)
        self.assertLessEqual(sum(len(f["blocks"]) for f in d["functions"]),1536)
        self.assertLessEqual(max(len(f["blocks"]) for f in d["functions"]),256)
        self.assertLessEqual(sum(len(b["ops"]) for f in d["functions"] for b in f["blocks"]),8192)
        self.assertLessEqual(max(len(b["params"]) for f in d["functions"] for b in f["blocks"]),16)
    def test_02_stat_first_registration_zero_uid_device_and_monotonic_handles(self):
        c=self.context()
        a=self.register(c,1,device=0,inode=0,uid=0)
        b=self.register(c,2,device=0,inode=0,uid=0)
        self.assertEqual((a,b,c["grows"],q(c["work"],8)),(1,2,1,2))
        self.assertEqual((q(c["work"],(512+72)//8),q(c["work"],(512+80)//8)),(0o100600,0))
        code,h,_=self.start(c,5,a)
        self.assertEqual((code,h[7],h[16]),(1,8,1))
        self.assertEqual(self.ack(c)[0],0)
        d=self.register(c,3,device=0,inode=0)
        self.assertEqual(d,3)
    def test_03_shared_refcounts_and_no_os_redundancy(self):
        c=self.context();a=self.register(c,11);b=self.register(c,22)
        self.locked(c,a,kind=1)
        peers=c["peers"];action=c["last"][5]
        self.assertEqual(self.start(c,3,b,value=1,count=1)[0],0)
        self.assertEqual(self.start(c,3,a,value=1,count=1)[0],0)
        self.assertEqual(self.start(c,4,a,value=1,count=1)[0],0)
        self.assertEqual((c["peers"],c["last"][5]),(peers,action))
        code,h,_=self.start(c,4,b,value=1,count=1)
        self.assertEqual((code,h[7],h[17]),(1,17,2))
        self.assertEqual(self.ack(c)[0],0)
    def test_04_exclusive_conflicts_are_busy_without_physical_request(self):
        c=self.context();a=self.register(c,11);b=self.register(c,22)
        self.locked(c,a)
        before=c["peers"];action=c["last"][5]
        for kind in (1,2):
            code,h,_=self.start(c,3,b,value=kind,count=1)
            self.assertEqual((code,h[8],h[9],h[5]),(0,5,0,action))
        self.assertEqual(c["peers"],before)
        self.assertEqual(self.start(c,4,a,value=2,count=1)[0],1)
        self.ack(c)
        self.locked(c,b)
    def test_05_deferred_alias_close_lifo_and_known_close_errors_not_retried(self):
        c=self.context();a=self.register(c,11);b=self.register(c,22);d=self.register(c,33)
        self.locked(c,a)
        peers=c["peers"]
        self.assertEqual(self.start(c,5,b)[0],0)
        self.assertEqual(self.start(c,5,d)[0],0)
        self.assertEqual(c["peers"],peers)
        self.assertEqual(self.start(c,4,a,value=2,count=1)[0],1)
        code,h,_=self.ack(c)
        self.assertEqual((code,h[7],h[16],h[21]),(1,8,33,d))
        code,h,_=self.ack(c,error=4)
        self.assertEqual((code,h[7],h[16],h[21]),(1,8,22,b))
        code,h,_=self.ack(c,error=9)
        self.assertEqual((code,h[8],h[9],h[20],h[12]),(0,0,0,4,1))
        self.assertEqual(c["peers"],peers+3)
    def test_06_all_selected_lock_errnos_remain_busy_with_masks_unchanged(self):
        for error in (1,4,5,9,11,13,22,28,95,110,4095):
            with self.subTest(errno=error):
                c=self.context();a=self.register(c,11);self.locked(c,a)
                rows=bytes(c["work"][512:])
                self.assertEqual(self.start(c,4,a,value=2,count=1)[0],1)
                code,h,_=self.ack(c,error=error)
                self.assertEqual((code,h[8],h[9]),(0,5,error))
                self.assertEqual(bytes(c["work"][512:]),rows)
                self.assertEqual(self.start(c,4,a,value=2,count=1)[0],1)
                self.assertEqual(self.ack(c)[0],0)
    def test_07_independent_inodes_do_not_share_lock_masks(self):
        c=self.context();a=self.register(c,11,inode=1);b=self.register(c,22,inode=2)
        self.locked(c,a,offset=0,count=8);self.locked(c,b,offset=0,count=8)
        self.assertEqual(self.start(c,4,a,value=2,count=8)[0],1);self.ack(c)
        self.assertEqual(self.start(c,5,a)[0],1);self.ack(c)
        self.assertEqual(q(c["work"],(512+96+40)//8),255)
    def test_08_registration_errno_and_growth_source_identity(self):
        c=self.context()
        code,h,_=self.start(c,2,value=77,grow=False)
        self.assertEqual((code,h[14],h[15]),(2,3,2048))
        old=bytes(c["work"]);c["work"].extend(bytes(h[15]-len(c["work"])))
        self.assertEqual(bytes(c["work"][:len(old)]),old)
        code,h,out=self.invoke(c["original"],c["work"]);c.update(last=h,last_bytes=out)
        self.assertEqual(code,1)
        code,h,_=self.ack(c,error=5);self.assertEqual((code,h[8],h[9],h[10]),(0,1,5,0))
        self.assertEqual(self.register(c,77),1)
        c=self.context();self.start(c,2,value=7,grow=False)
        broken=bytearray(c["original"]);put(broken,15,q(broken,15)+1)
        self.poison(c,broken,10)
    def test_09_more_than_sixteen_rows_have_no_fixed_descriptor_quota(self):
        c=self.context()
        handles=[self.register(c,100+i,inode=1000+i) for i in range(17)]
        self.assertEqual(handles,list(range(1,18)))
        self.assertEqual((c["grows"],q(c["work"],7),q(c["work"],8)),(2,32,17))
        for handle in reversed(handles):
            self.assertEqual(self.start(c,5,handle)[0],1)
            self.assertEqual(self.ack(c)[0],0)
        self.assertEqual(q(c["work"],8),0)
    def test_10_request_and_reply_corruption_are_permanent(self):
        cases=[("request_nonce",272,88),("request_call",288,0),("request_op",304,8),
               ("request_token",320,99),("request_lease",360,99),("request_reserved",368,1),
               ("reply_nonce",528,88),("reply_call",544,0),("reply_sequence",552,0),
               ("reply_op",560,8),("reply_errno",568,4096),("reply_uid_duplicate",600,99),
               ("reply_source_lease",624,99),("reply_phase",632,2),
               ("reply_extent",640,10000),("reply_version",688,4),
               ("reply_reserved",712,1),("stat_inode",776,77)]
        for label,offset,value in cases:
            with self.subTest(field=label):
                c=self.context();self.start(c,2,value=11)
                raw=bytearray(self.ack_source(c));struct.pack_into("<Q",raw,offset,value)
                self.poison(c,raw,28)
    def test_11_wrong_outer_ack_and_duplicate_ack_cannot_advance(self):
        for word in (2,4,5,6,7,15):
            with self.subTest(field=word):
                c=self.context();self.start(c,2,value=11)
                raw=bytearray(self.ack_source(c));put(raw,word,(q(raw,word)+1)&MASK)
                self.poison(c,raw)
        c=self.context();self.start(c,2,value=11);self.ack(c)
        self.poison(c,c["ack_source"])
    def test_12_unknown_result_keeps_pending_masks_and_refuses_forever(self):
        c=self.context();a=self.register(c,11);self.locked(c,a)
        self.start(c,4,a,value=2,count=1)
        rows=bytes(c["work"][512:])
        raw=self.ack_source(c,command=7)
        self.poison(c,raw,13)
        self.assertEqual(bytes(c["work"][512:]),rows)
    def test_13_stale_and_duplicate_tokens_and_locked_retirement(self):
        c=self.context();self.register(c,11)
        code,_,_=self.start(c,2,value=11);self.assertEqual(code,REFUSED);self.poison(c)
        c=self.context();a=self.register(c,11);self.locked(c,a)
        code,_,_=self.start(c,5,a);self.assertEqual(code,REFUSED);self.poison(c)
        c=self.context();a=self.register(c,11);self.start(c,5,a);self.ack(c)
        code,_,_=self.start(c,3,a,value=1,count=1);self.assertEqual(code,REFUSED);self.poison(c)
    def test_14_invalid_lock_shapes_and_owned_conversion(self):
        for kind,offset,count in ((0,0,1),(3,0,1),(1,0,2),(2,8,1),(2,0,0),(2,7,2)):
            with self.subTest(shape=(kind,offset,count)):
                c=self.context();a=self.register(c,11)
                code,_,_=self.start(c,3,a,value=kind,offset=offset,count=count)
                self.assertEqual(code,REFUSED);self.poison(c)
        c=self.context();a=self.register(c,11);self.locked(c,a,kind=1)
        self.assertEqual(self.start(c,3,a,value=2,count=1)[0],REFUSED);self.poison(c)
    def test_15_private_state_corruption_and_near_u64_boundaries(self):
        for word,value in ((7,MASK),(29,2),(25,0),(26,0)):
            with self.subTest(word=word):
                c=self.context();a=self.register(c,11)
                if word in (25,26):
                    put(c["work"],25,0);put(c["work"],26,0)
                else:put(c["work"],word,value)
                code,_,_=self.start(c,3,a,value=2,count=1)
                self.assertEqual(code,REFUSED);self.poison(c)
        c=self.context();put(c["work"],4,MASK)
        raw=frame(2,call=0,value=11,lease=1)
        self.poison(c,raw,15)
        c=self.context();put(c["work"],6,MASK)
        self.assertEqual(self.start(c,2,value=11)[0],REFUSED);self.poison(c)
        c=self.context();a=self.register(c,11);put(c["work"],5,MASK)
        self.assertEqual(self.start(c,3,a,value=2,count=1)[0],REFUSED);self.poison(c)
    def test_16_private_phase_action_and_retirement_generation_consistency(self):
        c=self.context();self.start(c,2,value=11)
        put(c["work"],264//8,5)
        self.poison(c,self.ack_source(c),7)
        c=self.context();a=self.register(c,11);self.locked(c,a)
        self.start(c,4,a,value=2,count=1);put(c["work"],160//8,0)
        self.poison(c,self.ack_source(c),7)
        c=self.context();a=self.register(c,11);b=self.register(c,22);d=self.register(c,33)
        self.locked(c,a);self.start(c,5,b);self.start(c,5,d)
        put(c["work"],(512+2*96+56)//8,q(c["work"],(512+96+56)//8))
        self.assertEqual(self.start(c,4,a,value=2,count=1)[0],REFUSED);self.poison(c)
    def test_17_short_buffers_do_not_initialize_or_reissue(self):
        for size in (0,7,8,255,511):
            with self.subTest(workspace=size):
                work=bytearray(size)
                self.assertEqual(self.invoke(frame(1),work)[0],REFUSED)
                if size>=8:self.assertEqual(q(work,0),BAD)
        for size in (0,7,255):
            with self.subTest(output=size):
                work=bytearray(512)
                self.assertEqual(self.invoke(frame(1),work,capacity=size)[0],REFUSED)
                self.assertEqual(q(work,0),BAD)
        c=self.context();self.poison(c,b"")
    def test_18_future_fs_watermark_is_recorded_but_old_complete_replay_is_refused(self):
        c=self.context();c["fscall"]=8;c["fsseq"]=15
        self.assertEqual(self.register(c,11),1)
        self.assertEqual((q(c["work"],27),q(c["work"],28)),(9,16))
        self.start(c,2,value=22)
        raw=bytearray(self.ack_source(c));struct.pack_into("<Q",raw,288,9);struct.pack_into("<Q",raw,544,9)
        self.poison(c,raw,28)

if __name__=="__main__":unittest.main()
