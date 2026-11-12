"""Complete deterministic foreign-effect scenarios for the new unixOpen owner.

These fixtures do not perform filesystem operations and do not claim issuer
authority. Their job is to compare the parent with original selected C control
flow; a later fixed physical join must replace every foreign effect.
"""
from __future__ import annotations
import copy,random,struct
MASK=(1<<64)-1
MAGIC=int.from_bytes(b"HIANUO01","little")
REQUEST=int.from_bytes(b"HIANUQ01","little")
def q(raw,offset):return struct.unpack_from("<Q",raw,offset)[0]
def put(raw,offset,value):struct.pack_into("<Q",raw,offset,value&MASK)
def begin(case,*,call=1,random_pid=17,counter=7,fsseq=100,sysseq=200):
    path=case.get("path",b"/tmp/hia-db\0\0")
    absent=path is None
    if absent:path=b""
    data=bytearray(512+len(path))
    fields={0:MAGIC,8:1,16:11,24:12,32:call,40:1001,48:case.get("flags",256|2|4),
        56:int(absent),64:len(path),72:case.get("want_out",1),80:31,
        88:case.get("exclusive_vfs",0),96:case.get("mmap_max",1<<20),
        104:case.get("psow_default",1),112:case.get("initial_errno",28),
        120:random_pid,128:512,136:55,144:counter,152:21,160:22,
        168:fsseq,176:sysseq,184:777,192:case.get("path_offset",0),
        200:case.get("initial_out",0xfeedbeef) if case.get("want_out",1) else 0}
    for offset,value in fields.items():put(data,offset,value)
    data[512:]=path;return bytes(data)
def default_values(request):
    op=request["op"];args=request["args"]
    rows={1:[17,0,0,0,0,0],2:[0,0,0,0,0,0],3:[0,0,0,0,0,0],
        4:[1,100,0,0,0,0],5:[0,0,0,0,0,0],6:[0,0,0,0,0,0],
        7:[51,3,0,0,0,0],8:[0,0,0,0,0,0],9:[0,0,0,0,0,0],
        10:[0,0,0,0,0,0],11:[0,0,0,0,0,0],12:[args[2],0,0,0,0,0],
        13:[0,301,401,19,23,0],14:[0,0,0,0,0,0],15:[0,23,1,0,0,0],
        16:[0,23,1,0,0,0],17:[args[0],0,0,0,0,0],18:[0,0,0,0,0,0]}
    return list(rows[op])
class Provider:
    def __init__(self,case,wire):
        self.case=case;self.seq=q(wire,168);self.sys=q(wire,176)
        self.count=0;self.peer_serials={}
    def __call__(self,request):
        op=request["op"];stage=request["stage"];self.count+=1
        row=copy.deepcopy(self.case.get("effects",{}).get(stage,{}))
        values=list(row.get("values",default_values(request)));assert len(values)==6
        if op==3 and values[0] and values[3]==MASK:values[3]=request["args"][0]&3
        error=row.get("errno",request["state_before"][19])
        if op in (8,10,11,14,15,16) and values[0] and "errno" not in row:error=values[0]
        payload=row.get("payload",b"/tmp/etilqs_1234\0\0" if op==5 and values[0]==0 else b"")
        assert isinstance(payload,bytes)
        if op==1 or 8<=op<=11 or 14<=op<=16:delta=1
        elif op in (2,4,12,17,18):delta=0
        elif op==3:delta=self.case.get("reuse_stat",0)
        elif op==6:delta=self.case.get("create_stat",0)
        elif op==7:delta=1
        elif op==13:delta=1
        else:delta=0
        delta=row.get("fs_delta",delta);self.seq+=delta;self.sys+=delta
        peer={2:10,4:11,18:11,5:12,6:8,12:8,7:7,17:13}.get(op,6)
        self.peer_serials[peer]=self.peer_serials.get(peer,0)+1
        return {"errno":error,"values":values,"payload":payload,
            "fs_sequence":self.seq,"syscall_sequence":self.sys,
            "peer":peer,"peer_context":1000+peer,"generation":1,
            "entry_serial":self.peer_serials[peer],"source_lease":2000+self.count,
            "scope":"EXPLICIT_FOREIGN_TEST_EFFECT_NO_NAMESPACE_AUTHORITY"}
def ack(request_bytes,reply):
    assert len(request_bytes)>=256 and q(request_bytes,0)==REQUEST
    data=bytearray(512+len(reply["payload"]))
    fields={0:MAGIC,8:2,16:q(request_bytes,16),24:q(request_bytes,24),
        32:q(request_bytes,32),40:q(request_bytes,40),48:q(request_bytes,48),
        56:q(request_bytes,56),64:reply["errno"],120:reply["fs_sequence"],
        128:reply["syscall_sequence"],136:len(reply["payload"]),144:reply["peer"],
        152:reply["peer_context"],160:reply["generation"],168:reply["entry_serial"],
        176:reply["source_lease"]}
    for i,value in enumerate(reply["values"]):fields[72+8*i]=value
    for offset,value in fields.items():put(data,offset,value)
    data[256:512]=request_bytes[:256];data[512:]=reply["payload"]
    return bytes(data)
def cases():
    result=[]
    def add(name,**kw):
        assert name not in {x["name"] for x in result}
        result.append(dict(name=name,**kw))
    def effect(values,errno=None,**kw):
        row=dict(values=values,**kw)
        if errno is not None:row["errno"]=errno
        return row
    rofail=effect([0,MASK,0,0,0,0],13)
    add("main_new")
    add("main_readonly",flags=256|1)
    add("main_no_output",want_out=0)
    add("main_initial_output_same_as_final",initial_out=256|2|4)
    add("main_reuse",effects={20:effect([71,51,3,MASK,0,0])},reuse_stat=1)
    add("main_reuse_fd_zero",effects={20:effect([71,51,0,MASK,0,0])},reuse_stat=1)
    add("pid_changes_twice",effects={10:effect([81,0,0,0,0,0]),11:effect([82,0,0,0,0,0])})
    add("malloc_oom_immediate",effects={21:effect([0,0,0,0,0,0],12)})
    add("fallback_second_open",effects={31:rofail})
    add("fallback_reuse",effects={31:rofail,33:effect([81,61,8,MASK,0,0])},reuse_stat=1)
    add("both_opens_fail",effects={31:rofail,35:effect([0,MASK,0,0,0,0],2)})
    add("directory_error_no_fallback",effects={31:effect([0,MASK,0,0,0,0],21)})
    add("readonly_error_no_fallback",flags=256|1,effects={31:rofail})
    add("preallocation_freed_with_errno_change",effects={31:effect([0,MASK,0,0,0,0],21),
        36:effect([14,0,0,0,0,0],5),80:effect([0,0,0,0,0,0],6)})
    add("journal_directory_not_writable",flags=2048|2|4,effects={31:rofail,32:effect([2,0,0,0,0,0],2)})
    add("journal_access_success_fallback",flags=2048|2|4,effects={31:rofail})
    add("journal_existing_ro_fallback",flags=2048|2,effects={31:rofail})
    add("journal_create_stat_error",flags=2048|2|4,create_stat=1,effects={30:effect([1802,0,0,0,0,0],2)})
    add("main_uri_create_stat_error_direct_return",flags=256|2|4|64,create_stat=1,
        effects={30:effect([1802,0,0,0,0,0],13)})
    add("journal_chown_root",flags=2048|2|4,create_stat=1,effects={30:effect([0,420,1001,1002,0,0])})
    add("journal_chown_nonroot",flags=2048|2|4,create_stat=1,
        effects={30:effect([0,420,1001,1002,0,0]),40:effect([1001,0,0,0,0,0])})
    add("wal_chown_failure_ignored",flags=524288|2|4,create_stat=1,
        effects={30:effect([0,384,1,2,0,0]),41:effect([1,0,0,0,0,0],1)})
    add("wal_zero_mode_skips_chown",flags=524288|2|4)
    add("temp_success_original_path_stays_null",flags=512|2|4|8,path=None)
    add("temp_failure_ERROR",flags=512|2|4|8,path=None,effects={22:effect([1,0,0,0,0,0])})
    add("temp_failure_IOERR",flags=512|2|4|8,path=None,effects={22:effect([10,0,0,0,0,0])})
    add("temp_failure_GETTEMPPATH",flags=512|2|4|8,path=None,effects={22:effect([6410,0,0,0,0,0])})
    add("temp_max512_filename",flags=512|2|4|8,path=None,
        effects={22:effect([0,0,0,0,0,0],payload=b"/"+b"x"*509+b"\0\0")})
    add("delete_unlink_failure_ignored",flags=512|2|4|8,path=b"/tmp/private-temp\0\0",
        effects={50:effect([13,0,0,0,0,0],13)})
    add("exclusive_POSIX_flags",flags=512|2|4|16)
    add("unix_excl_psow_false",exclusive_vfs=1,psow_default=0)
    add("URI_psow_off",flags=256|2|4|64,path=b"/tmp/db\0psow\0off\0\0",
        effects={60:effect([0,0,0,0,0,0])})
    add("URI_allocation_offset",flags=256|2|4|64,path=b"\0"*6+b"/tmp/db\0psow\0true\0\0",path_offset=6)
    add("NULL_URI_uses_default",flags=512|2|4|8|64,path=None)
    add("inode_fstat_failure_cleanup",effects={61:effect([10,0,0,0,0,0],5)})
    add("inode_oom_cleanup",effects={61:effect([7,0,0,0,0,0],12)})
    add("inode_failure_close_failure_log_inside_mutex",
        effects={61:effect([10,0,0,0,0,0],5),62:effect([4,0,0,0,0,0],4),
                 63:effect([4106,0,0,0,0,0],9)})
    add("inode_oom_close_failure",effects={61:effect([7,0,0,0,0,0],12),62:effect([9,0,0,0,0,0],9)})
    add("verify_fstat_failure_warning",effects={70:effect([5,0,0,0,0,0],5)})
    add("verify_nlink_zero_warning",effects={70:effect([0,23,0,0,0,0])})
    add("verify_nlink_multiple_warning",effects={70:effect([0,23,2,0,0,0])})
    add("verify_stat_failure_warning",effects={71:effect([2,0,0,0,0,0],2)})
    add("verify_inode_moved_warning",effects={71:effect([0,24,1,0,0,0])})
    add("verify_warning_preserves_success_and_latest_errno",
        effects={70:effect([0,23,0,0,0,0]),72:effect([28,0,0,0,0,0],13)})
    add("long_nonnull_path_no_new_512_quota",path=b"/"+b"x"*8192+b"\0\0")
    add("non_UTF8_path_is_raw_POSIX",path=b"/tmp/\xff\x80\xfe\0\0")
    add("all_u64_mmap_config_bits",mmap_max=MASK)
    for kind in (512,1024,4096,8192,16384,524288):
        add("file_kind_"+str(kind),flags=kind|2|4)
    rng=random.Random(0x9ACDFA)
    for i in range(32):
        kind=rng.choice((256,512,1024,2048,4096,8192,16384,524288))
        access=rng.choice((1,2));flags=kind|access
        if access==2 and rng.randrange(2):flags|=4
        overrides={}
        if rng.randrange(3)==0:
            overrides[31]=effect([0,MASK,0,0,0,0],rng.choice((2,13,21)))
            if rng.randrange(2):overrides[35]=effect([0,MASK,0,0,0,0],rng.choice((2,13)))
        if kind==256 and rng.randrange(3)==0:
            overrides[61]=effect([rng.choice((7,10)),0,0,0,0,0],rng.choice((5,12)))
        if rng.randrange(3)==0:overrides[70]=effect([0,23,rng.choice((0,1,2)),0,0,0])
        add("fixed_seed_"+str(i),flags=flags,effects=overrides,
            want_out=rng.randrange(2),exclusive_vfs=rng.randrange(2),psow_default=rng.randrange(2),
            initial_errno=rng.choice((0,2,4,13,28)),path=b"/tmp/db-"+str(i).encode()+b"\0\0")
    assert len(result)==85,len(result)
    return result
