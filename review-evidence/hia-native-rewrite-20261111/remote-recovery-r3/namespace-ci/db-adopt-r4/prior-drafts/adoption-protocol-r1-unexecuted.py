"""New completed-FSTAT adoption controls; original forty tests are inherited.

This is a source-only fixture until independently executed. The C policy calls
receive controlled raw fstat facts and the HIA input contains that complete
completed FS-shaped receipt. It does not prove a real physical global issuer.
Every successful new adoption requires no emitted filesystem continuation.
"""
from __future__ import annotations
import struct
from tests.namespace_db_reuse_original import NamespaceDBNodeTests as Original
from tests.namespace_db_reuse_original import packet,q,setq,MAGIC,FS,BAD

class NamespaceDBAdoptionTests(Original):
    def adoption(self,c,token=5,flags=0,*,reference=False,physical_action=17):
        expected=None;events=[]
        if reference:
            start=self.oracle.lib.oracle_events()
            expected=self.oracle.call(2,0,token,flags,c["next_handle"])
            self.assertEqual(expected,(0,c["next_handle"]))
            events=self.oracle.events(start)
            self.assertEqual(len(events),1)
            self.assertEqual(events[0][1:6],(15,token,0,0,0))
            self.assertEqual(events[0][6:],(0,0))
        c["call"]+=1;c["lease"]+=1;c["fs_call"]+=3;c["fs_sys"]+=5
        request=[0]*32
        request[:14]=[FS,2,*c["fsnonce"],c["fs_call"],0,15,0,token,0,0,0,0,physical_action]
        result=[0]*32
        result[:8]=[FS,0,*c["fsnonce"],c["fs_call"],c["fs_sys"],15,0]
        result[8:14]=[c["dev"],c["ino"],c["mode"],c["uid"],c["gid"],4096]
        result[14]=physical_action;result[15]=1;result[16]=144
        result[20]=1;result[21]=1000;result[22]=3;result[24]=1
        raw_stat=bytearray(144)
        struct.pack_into("<QQQIII",raw_stat,0,c["dev"],c["ino"],1,c["mode"],c["uid"],c["gid"])
        struct.pack_into("<q",raw_stat,48,4096)
        body=struct.pack("<32Q",*request)+struct.pack("<32Q",*result)+raw_stat
        raw=packet(10,c["nonce"],c["call"],value=token,flags=flags,lease=c["lease"],payload=body)
        self.assertEqual(len(raw),912)
        self.observe(dict(kind="completed_FSTAT_adoption_source",input_hex=raw.hex(),
            reference_events=events,reference_expected=expected,controlled_FS_receipts=1,
            real_FS_syscalls=0,physical_source_issuer_claimed=False))
        return raw,expected,events

    def adopt(self,c,token=5,flags=0):
        raw,expected,events=self.adoption(c,token,flags,reference=True)
        result=self.step(c,raw)
        self.assertEqual(result[0],0)
        self.assertEqual((result[1][8],result[1][10]),expected)
        self.assertEqual((result[1][5],result[1][7]),(0,0))
        self.assertEqual(result[1][16],token)
        self.assertEqual((q(c["work"],18),q(c["work"],19)),(c["fs_call"],c["fs_sys"]))
        self.assertEqual(c["work"][512:1536],bytes(1024))
        c["next_handle"]+=1
        self.observe(dict(kind="independent_C_operation",command=10,reference_command=2,
            token=token,flags=flags,full_original_events=events,input_hex=raw.hex(),
            actual_output_hex=result[2].hex(),expected_code=expected[0],expected_result=expected[1],
            HIA_emitted_new_FS_continuations=0,actual_OS_calls=0))
        self.compare(c)
        return result[1][10]

    def mutated(self,raw,offset,value):
        result=bytearray(raw);struct.pack_into("<Q",result,offset,value)
        return bytes(result)

    def clone(self,c):
        return dict(c,work=bytearray(c["work"]))

    def test_41_adopt_first_single_fstat_uid_zero_and_zero_identity(self):
        c=self.context(dev=0,ino=0,uid=0,gid=0)
        h=self.adopt(c,5)
        self.assertEqual(h,1);self.assertEqual(self.oracle.lib.oracle_events(),1)
        self.close(c,h)

    def test_42_adopt_preserves_all_readonly_unixexcl_combinations(self):
        for flags in range(4):
            with self.subTest(flags=flags):
                c=self.context();h=self.adopt(c,5,flags)
                self.lock(c,h,1);self.unlock(c,h);self.close(c,h)

    def test_43_adopt_interleaved_global_fs_calls_and_action_gaps(self):
        c=self.context()
        a=self.adopt(c,5)
        c["fs_call"]+=101;c["fs_sys"]+=311
        b=self.adopt(c,6,1)
        self.assertGreater(b,a)
        self.close(c,a);self.close(c,b)

    def test_44_reused_fd_adopts_once_under_fresh_logical_handle(self):
        c=self.context();guard=self.adopt(c,5);self.lock(c,guard,1)
        old=self.adopt(c,6);self.close(c,old)
        self.assertEqual(self.take_unused(c,2),6)
        events=self.oracle.lib.oracle_events()
        fresh=self.adopt(c,6)
        self.assertGreater(fresh,old)
        self.assertEqual(self.oracle.lib.oracle_events()-events,1)
        self.unlock(c,guard);self.close(c,fresh);self.close(c,guard)

    def test_45_grow_keeps_all912_source_bytes_and_commits_once(self):
        c=self.context()
        raw,expected,events=self.adoption(c,5,reference=True)
        prefix=bytes(c["work"])
        r=self.invoke(c,raw);self.assertEqual(r[0],2)
        self.assertEqual(q(c["work"],1),6)
        self.assertEqual(bytes(c["work"][512:1424]),raw)
        self.assertEqual(q(c["work"],8),0)
        saved=bytes(c["work"]);need=r[1][21]
        c["work"].extend(bytes(need-len(c["work"])))
        self.assertEqual(bytes(c["work"][:len(saved)]),saved)
        r=self.invoke(c,raw);self.assertEqual(r[0],0)
        self.assertEqual((r[1][8],r[1][10]),expected)
        self.assertEqual((r[1][5],r[1][7]),(0,0))
        c["next_handle"]+=1;self.compare(c)
        self.assertEqual(bytes(c["work"][512:1536]),bytes(1024))
        self.close(c,expected[1])

    def test_46_grow_rejects_mutation_any_packet_region(self):
        c=self.context();raw,_,_=self.adoption(c)
        r=self.invoke(c,raw);self.assertEqual(r[0],2)
        c["work"].extend(bytes(r[1][21]-len(c["work"])))
        for offset in (8,32,64,120,128,256,288,360,512,576,768,904):
            with self.subTest(offset=offset):
                other=self.clone(c);bad=self.mutated(raw,offset,q(raw,offset//8)^1)
                self.poison(other,bad)

    def test_47_cross_nonce_call_and_source_lease_rejected(self):
        c=self.context();raw,_,_=self.adoption(c)
        for offset,value in ((16,999),(24,999),(32,0),(32,2),(120,0),
                             (272,1),(280,1),(528,1),(536,1)):
            with self.subTest(offset=offset,value=value):
                self.poison(self.clone(c),self.mutated(raw,offset,value))

    def test_48_actual_request_identity_operation_token_reserved(self):
        c=self.context();raw,_,_=self.adoption(c)
        changes=((256,0),(264,3),(288,0),(296,1),(304,18),(312,1),
                 (320,6),(328,1),(336,1),(344,1),(352,1),(360,0),(368,1),(504,1))
        for offset,value in changes:
            with self.subTest(offset=offset,value=value):
                self.poison(self.clone(c),self.mutated(raw,offset,value))

    def test_49_actual_result_completion_error_phase_and_extent(self):
        c=self.context();raw,_,_=self.adoption(c)
        changes=((512,0),(520,1),(544,c["fs_call"]+1),(552,0),(560,18),
                 (568,5),(624,18),(632,2),(640,143),(640,145),
                 (648,1),(656,1),(664,1),(680,0),(688,2),(696,1),(712,1),(760,1))
        for offset,value in changes:
            with self.subTest(offset=offset,value=value):
                self.poison(self.clone(c),self.mutated(raw,offset,value))

    def test_50_stat_duplicate_fields_all_compared(self):
        c=self.context();raw,_,_=self.adoption(c)
        for offset in (576,584,592,600,608,616,704,768,776,784,792,800,816):
            with self.subTest(offset=offset):
                self.poison(self.clone(c),self.mutated(raw,offset,q(raw,offset//8)^1))

    def test_51_exact_logical_packet_extent_and_padding(self):
        c=self.context();raw,_,_=self.adoption(c)
        for n in (0,7,255,256,767,768,911):
            with self.subTest(length=n):self.poison(self.clone(c),raw[:n])
        longer=bytearray(raw+bytes(8));struct.pack_into("<Q",longer,128,664)
        self.poison(self.clone(c),bytes(longer))
        self.poison(self.clone(c),self.mutated(raw,128,655))

    def test_52_real_watermarks_accept_max_once_and_never_wrap(self):
        c=self.context();c["fs_call"]=(1<<64)-4;c["fs_sys"]=(1<<64)-6
        raw,expected,_=self.adoption(c,5,reference=True)
        self.assertEqual((c["fs_call"],c["fs_sys"]),((1<<64)-1,(1<<64)-1))
        result=self.step(c,raw);self.assertEqual(result[0],0)
        c["next_handle"]+=1;self.compare(c)
        replay=bytearray(raw);struct.pack_into("<Q",replay,32,c["call"]+1)
        struct.pack_into("<Q",replay,64,6);struct.pack_into("<Q",replay,320,6)
        self.poison(self.clone(c),bytes(replay))

    def test_53_duplicate_live_or_deferred_fs_token_is_rejected(self):
        c=self.context();guard=self.adopt(c,5);other=self.adopt(c,6)
        raw,_,_=self.adoption(c,5)
        self.poison(self.clone(c),raw)
        self.lock(c,guard,1);self.close(c,other)
        raw,_,_=self.adoption(c,6)
        self.poison(self.clone(c),raw)

    def test_54_consistent_wrong_inode_cannot_enter_selected_node(self):
        c=self.context();self.adopt(c,5)
        raw,_,_=self.adoption(c,6)
        for header,data in ((576,768),(584,776)):
            bad=bytearray(raw)
            struct.pack_into("<Q",bad,header,q(raw,header//8)+1)
            struct.pack_into("<Q",bad,data,q(raw,data//8)+1)
            self.poison(self.clone(c),bytes(bad))

    def test_55_grow_valid_but_changed_stat_still_refused(self):
        c=self.context();raw,_,_=self.adoption(c)
        r=self.invoke(c,raw);self.assertEqual(r[0],2)
        c["work"].extend(bytes(r[1][21]-len(c["work"])))
        bad=bytearray(raw)
        struct.pack_into("<Q",bad,576,c["dev"]+1)
        struct.pack_into("<Q",bad,768,c["dev"]+1)
        self.poison(c,bytes(bad))

    def test_56_pending_workspace_shape_and_first_poison_remain_sticky(self):
        c=self.context();raw,_,_=self.adoption(c)
        r=self.invoke(c,raw);self.assertEqual(r[0],2)
        c["work"].extend(bytes(r[1][21]-len(c["work"])))
        for offset,value in ((8,5),(168,2),(192,15),(40,1),(296,0),(640,655),
                             (200,6),(1424,1),(384,1)):
            with self.subTest(offset=offset):
                other=self.clone(c);struct.pack_into("<Q",other["work"],offset,value)
                self.poison(other,raw)

    def test_57_short_output_and_workspace_do_not_escape_bounds(self):
        c=self.context();raw,_,_=self.adoption(c)
        for capacity in (0,1,7,8,127,255):
            with self.subTest(capacity=capacity):
                self.poison(self.clone(c),raw,capacity=capacity)
        for length in (0,1,7,8,511,1023,1423,1535):
            with self.subTest(workspace=length):
                other=self.clone(c);other["work"]=bytearray(length)
                self.poison(other,raw)

    def test_58_success_cannot_be_replayed_or_reentered_as_fs_pending(self):
        c=self.context();raw,expected,_=self.adoption(c,5,reference=True)
        r=self.step(c,raw);self.assertEqual(r[0],0);c["next_handle"]+=1
        self.compare(c);self.poison(self.clone(c),raw)
        other=self.clone(c);forged=self.mutated(raw,8,7)
        self.poison(other,forged)

    def test_59_repeated_adoption_grows_without_a_new_row_quota(self):
        c=self.context();handles=[]
        for i in range(20):handles.append(self.adopt(c,100+i,i%4))
        self.assertEqual(q(c["work"],8),20)
        self.assertGreaterEqual(q(c["work"],7),32)
        for h in reversed(handles):self.close(c,h)

    def test_60_adopted_and_original_register_share_exact_inode_policy(self):
        c=self.context();a=self.adopt(c,5);b=self.register(c,6)
        self.lock(c,a,1);self.lock(c,b,1)
        self.assertEqual(self.lock(c,a,4)[8],5)
        self.unlock(c,b);self.assertEqual(self.lock(c,a,4)[8],0)
        self.unlock(c,a);self.close(c,b);self.close(c,a)

EXPECTED_TESTS=60
LEGACY_TESTS=40
NEW_ADOPTION_TESTS=20
