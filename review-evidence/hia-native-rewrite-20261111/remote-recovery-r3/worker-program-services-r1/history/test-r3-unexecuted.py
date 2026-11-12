"""Independent public-oracle tests for the new fixed Worker program service.

No old component count is inherited. References are prepared before each
native group. During native execution the only application process is the
source-bound static ELF; Python only owns files, wait/cleanup and evidence.
"""
from __future__ import annotations
import argparse,copy,ctypes,importlib.util,json,os,resource,signal,stat,struct,subprocess,sys,time,traceback,zlib
from hashlib import sha256
from pathlib import Path
sys.dont_write_bytecode=True
p=argparse.ArgumentParser()
p.add_argument("--bundle",type=Path,required=True);p.add_argument("--reference",type=Path,required=True)
p.add_argument("--out",type=Path,required=True)
p.add_argument("--group",required=True,choices=("semantic","assembly-boundary","object-boundary","private-protocol","example-chain"))
a=p.parse_args();OUT=a.out.resolve();OUT.mkdir(parents=True,exist_ok=False)
REF=a.reference.resolve();bundle_raw=a.bundle.read_bytes();bundle=json.loads(bundle_raw)
EXE=Path(bundle["executable_path"]);exe_raw=EXE.read_bytes()
assert len(exe_raw)==bundle["executable_bytes"] and sha256(exe_raw).hexdigest()==bundle["executable_sha256"]
assert bundle["compiler_sha256"]=="0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
assert bundle["fresh_compiles"]==6 and bundle["nonzero_images"]==41
resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
libc=ctypes.CDLL(None,use_errno=True)
libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
assert libc.prctl(4,0,0,0,0)==0 and libc.prctl(3,0,0,0,0)==0
SELF_PARENT=os.getpid();START=time.monotonic_ns()
PINS={a.bundle.resolve():(bundle_raw,stat.S_IMODE(a.bundle.stat().st_mode)),
      EXE.resolve():(exe_raw,stat.S_IMODE(EXE.stat().st_mode)),
      Path(__file__).resolve():(Path(__file__).read_bytes(),stat.S_IMODE(Path(__file__).stat().st_mode))}
ROWS=[];NATIVE=0;KERNEL_ENTRIES=0;FAILED=None;STATUS="FAIL";PLAN=[]
INITIAL_CPU=resource.getrusage(resource.RUSAGE_SELF);INITIAL_CHILD=resource.getrusage(resource.RUSAGE_CHILDREN)
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def cas(raw):
    raw=bytes(raw);h=digest(raw);dest=OUT/"cas"/(h+".zlib");dest.parent.mkdir(exist_ok=True)
    if not dest.exists():dest.write_bytes(zlib.compress(raw,1))
    assert zlib.decompress(dest.read_bytes())==raw
    return dict(bytes=len(raw),sha256=h,path="cas/"+dest.name,compression="zlib")
def pin(path):
    path=Path(path).resolve();value=(path.read_bytes(),stat.S_IMODE(path.stat().st_mode))
    if path in PINS:assert PINS[path]==value,path
    PINS[path]=value;return value[0]
def unchanged():
    return all(p.is_file() and p.read_bytes()==raw and stat.S_IMODE(p.stat().st_mode)==mode
               for p,(raw,mode) in PINS.items())
def canonical(value):return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode("utf-8")
def transport(value):return json.dumps(value,sort_keys=False,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode("utf-8")
def header(raw,mode,lease=0x57500001,request=1,digits=4300,tree=0):
    return struct.pack("<8Q",int.from_bytes(b"HIAWPI01","little"),lease,request,digits,len(raw),mode,tree,0)
def primitive(version=6,functions=1):
    result={"schema":"hepta.hia.program.v"+str(version),"module":"worker_native_example","functions":[]}
    for index in range(functions):
        params=[{"name":"value","type":"u8"}]
        result["functions"].append({"name":"identity" if functions==1 else "f"+str(index),
          "params":params,"returns":["u8"],"effects":[],"entry":"entry",
          "blocks":[{"id":"entry","params":params,"ops":[],"term":{"op":"ret","values":["value"]}}]})
    return result
def composite(version):
    result=primitive(6);result["schema"]="hepta.hia.composite.v"+str(version)
    result["types"]=[]
    return result
def assembly_text(functions=1,version=6):
    raw="hia-asm.v1 hepta.hia.program.v"+str(version)+" worker_native_example\n"
    for i in range(functions):
        name="identity" if functions==1 else "f"+str(i)
        raw+="fn "+name+"(value:u8) -> (u8) effects() entry(entry)\nblock entry(value:u8)\n  ret(value)\nend\n"
    return raw.encode()
def child_setup():
    resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    if libc.prctl(4,0,0,0,0)!=0 or libc.prctl(3,0,0,0,0)!=0:os._exit(125)
    if libc.prctl(1,signal.SIGKILL,0,0,0)!=0:os._exit(125)
    if os.getppid()!=SELF_PARENT:os._exit(125)
def actual(label,packet,extra=()):
    global NATIVE
    root=OUT/"cases"/label;root.mkdir(parents=True,exist_ok=False)
    (root/"input.bin").write_bytes(packet)
    save(OUT/"pending-process.json",dict(label=label,input=cas(packet),executable_sha256=digest(exe_raw),
        budget=dict(cpu=90,wall=180,address=1<<30)))
    process=None;timed=False;started=time.monotonic_ns();before=resource.getrusage(resource.RUSAGE_CHILDREN)
    try:
        with (root/"input.bin").open("rb") as fi,(root/"stdout.bin").open("wb") as fo,(root/"stderr.bin").open("wb") as fe:
            env={"PATH":"/nonexistent","HOME":"/nonexistent","LANG":"C.UTF-8","LC_ALL":"C.UTF-8"}
            process=subprocess.Popen([str(EXE),*extra],stdin=fi,stdout=fo,stderr=fe,env=env,
                                     close_fds=True,start_new_session=True,preexec_fn=child_setup)
            NATIVE+=1
            try:rc=process.wait(timeout=180)
            except subprocess.TimeoutExpired:
                timed=True;os.killpg(process.pid,signal.SIGKILL);rc=process.wait()
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid,signal.SIGKILL);process.wait()
    after=resource.getrusage(resource.RUSAGE_CHILDREN)
    stdout=(root/"stdout.bin").read_bytes();stderr=(root/"stderr.bin").read_bytes()
    row=dict(label=label,returncode=rc,timed_out=timed,wall_ns=time.monotonic_ns()-started,
      user_cpu=after.ru_utime-before.ru_utime,system_cpu=after.ru_stime-before.ru_stime,
      stdout=cas(stdout),stderr=cas(stderr),input=cas(packet),parent_cleanup_complete=True,
      empty_PATH_and_HOME=True,no_runtime_python_or_oracle_callback=True)
    save(root/"process.json",row)
    assert not timed,row
    return row,stdout,stderr
def receipt_expected(checked,raw):
    core=checked.canonical_bytes
    original=checked.structured_bytes if checked.structured_bytes is not None else core
    data=json.loads(core);input_data=json.loads(original)
    return dict(core=core,input_sha256=checked.input_sha256,core_sha256=checked.sha256,
        input_bytes=len(original),kind=int(checked.structured_bytes is not None),
        version=int(input_data["schema"].rsplit("v",1)[1]),
        core_version=int(data["schema"].rsplit("v",1)[1]))
def reference(mode,raw,tree):
    value=json.loads(raw) if tree else raw
    try:
        if mode==1:
            checked=verify_program(value);info=receipt_expected(checked,raw)
            return dict(kind=1,domain=0,phase=0,line=0,payload=info["core"],program=info)
        if mode==2:
            # The public renderer performs its own verify. This separately
            # obtained reference is only for validating the actual receipt.
            checked=verify_program(value)
            text=render_assembly(value).encode("utf-8");info=receipt_expected(checked,raw)
            return dict(kind=2,domain=0,phase=0,line=0,payload=text,program=info)
        if mode==3:
            checked=assemble_program(raw);info=receipt_expected(checked,raw)
            return dict(kind=1,domain=0,phase=0,line=0,payload=info["core"],program=info)
        result=diagnose_assembly(raw)
        info=receipt_expected(assemble_program(raw),raw) if result["accepted"] else None
        return dict(kind=3,domain=0,phase=0,line=0,payload=canonical(result),program=info)
    except HIAProgramRejected as exc:
        asm=isinstance(exc,HIAAssemblyRejected)
        phase=0 if not asm else {"syntax":1,"core_verification":2,"representation":3}[exc.phase]
        return dict(kind=4,domain=2 if asm else 1,phase=phase,line=getattr(exc,"line",None) or 0,
                    code=exc.code,payload=str(exc).encode("utf-8"),program=None)
def add(label,mode,value,tree=0,accept=None,raw=False):
    source=bytes(value) if raw else transport(value)
    expected=reference(mode,source,tree)
    if accept is not None:assert (expected["kind"]!=4)==accept,(label,expected)
    PLAN.append(dict(label=label,mode=mode,tree=tree,source=source,expected=expected))
def parse_result(row,stdout,stderr,planned,lease,request):
    expected=planned["expected"];mode=planned["mode"]
    assert len(stderr)>=128,(row,len(stderr))
    terminal=struct.unpack("<16Q",stderr[:128])
    assert terminal[0]==int.from_bytes(b"HIACDE01","little") and terminal[1]==7
    assert terminal[2]==lease and terminal[3]>0
    if expected["kind"]==4:
        assert row["returncode"]==2 and not stdout
        result=stderr[128:]
        assert terminal[4:7]==(1,expected["domain"],30)
    else:
        assert row["returncode"]==0 and len(stderr)==128
        result=stdout
        assert terminal[4:7]==(0,0,30)
    assert len(result)>=256 and terminal[7]==0 and terminal[8]==len(result)
    assert terminal[9]==expected["kind"] and terminal[10]==expected["domain"]
    assert terminal[11]==len(result) and terminal[12:]==(0,0,0,0)
    words=struct.unpack_from("<32Q",result)
    assert words[:9]==(int.from_bytes(b"HIAWPE01","little"),1,lease,request,mode,
                       expected["kind"],expected["domain"],expected["phase"],expected["line"])
    assert words[9]==len(result) and words[18:]==(0,)*14
    receipt_at,receipt_n,core_at,core_n,payload_at,payload_n,code_at,code_n=words[10:18]
    for start,size in ((receipt_at,receipt_n),(core_at,core_n),(payload_at,payload_n),(code_at,code_n)):
        assert start<=len(result) and size<=len(result)-start
    assert result[payload_at:payload_at+payload_n]==expected["payload"]
    if expected["kind"]==4:
        assert (receipt_at,receipt_n,core_at,core_n)==(0,0,0,0)
        assert (payload_at,len(result))==(256,256+payload_n)
        assert code_at==payload_at and result[code_at:code_at+code_n]==expected["code"].encode("ascii")
    else:
        assert (code_at,code_n)==(0,0)
        program=expected["program"]
        if program is None:
            assert (receipt_at,receipt_n,core_at,core_n)==(0,0,0,0)
            assert (payload_at,len(result))==(256,256+payload_n)
        else:
            assert (receipt_at,receipt_n,core_at,core_n)==(256,256,512,len(program["core"]))
            assert result[core_at:core_at+core_n]==program["core"]
            receipt=struct.unpack_from("<32Q",result,256)
            assert receipt[0]==int.from_bytes(b"HIAPRV01","little") and receipt[1]==1
            assert receipt[2]==lease+2 and receipt[3]>0
            assert receipt[4:9]==(program["kind"],program["version"],program["core_version"],
                                  program["input_bytes"],len(program["core"]))
            assert receipt[9]==(program["input_bytes"] if program["kind"] else 0)
            assert result[256+80:256+112].hex()==program["input_sha256"]
            assert result[256+112:256+144].hex()==program["core_sha256"]
            assert receipt[18:24]==(45,52 if program["kind"] else 0,56,256,1,program["kind"])
            assert receipt[24:]==(0,)*8
            if expected["kind"]==1:
                assert payload_at==core_at and payload_n==core_n and len(result)==512+core_n
            else:
                assert payload_at==512+core_n and len(result)==payload_at+payload_n
    return result
def record_plan():
    rows=[]
    for row in PLAN:
        expected=row["expected"];program=expected["program"]
        ref=dict(expected)
        ref["payload"]=cas(expected["payload"])
        if program is not None:
            ref["program"]=dict(program,core=cas(program["core"]))
        rows.append(dict(label=row["label"],mode=row["mode"],tree=row["tree"],
                         input=cas(row["source"]),expected=ref))
    save(OUT/"planned-corpus.json",rows)
def semantic_plan():
    for version in range(1,9):add("verify-v"+str(version),1,primitive(version),accept=True)
    for version in (6,7,8):add("verify-tree-v"+str(version),1,primitive(version),tree=1,accept=True)
    for version in range(1,5):
        add("verify-composite-v"+str(version),1,composite(version),accept=True)
        add("render-composite-v"+str(version),2,composite(version),accept=False)
    for version in range(1,9):
        add("render-v"+str(version),2,primitive(version),accept=version>=6)
    for version in (6,7,8):
        text=assembly_text(version=version)
        add("assemble-v"+str(version),3,text,raw=True,accept=True)
        add("diagnose-v"+str(version),4,text,raw=True,accept=True)
    from tests.test_hia_program_composite import stored_loan_program,task_program
    for name,factory in (("stored-loan",stored_loan_program),("task-helpers",task_program)):
        add("verify-"+name,1,factory(),accept=True)
        add("render-profile-"+name,2,factory(),accept=False)
    for label,raw in (("empty",b""),("invalid-utf8",b"\xff"),("duplicate",b'{"schema":1,"schema":2}'),
                       ("float",b'{"v":1.5}'),("nonfinite",b'{"v":NaN}'),("trailing",b'{} {}')):
        add("raw-"+label,1,raw,raw=True,accept=False)
    bad=primitive();bad["functions"][0]["blocks"][0]["term"]["values"]=["missing"]
    add("core-undefined-value",1,bad,accept=False)
    bad=primitive();bad["functions"][0]["blocks"][0]["ops"]=[
      {"op":"bad_"+("λ"*60000),"args":[],"out":[],"attrs":{}}]
    add("core-complete-unicode-opcode-error",1,bad,accept=False)
def assembly_boundary_plan():
    for n in (128,129,256,257):add("functions-"+str(n),3,assembly_text(n),raw=True,accept=n<=256)
    for n in (1048576,1048577):add("assembly-source-"+str(n),3,b" "*n,raw=True,accept=False)
    for n in (16384,16385):
        add("assembly-lines-"+str(n),3,b"\n"*n,raw=True,accept=False)
        add("assembly-line-bytes-"+str(n),3,b"x"*n+b"\n",raw=True,accept=False)
    for label,raw in (("late-utf8",b"invalid grammar\n\xff"),("bom",b"\xef\xbb\xbf"+assembly_text()),
       ("nul",assembly_text()+b"\0"),("lone-cr",assembly_text()+b"\r"),("crlf",assembly_text().replace(b"\n",b"\r\n"))):
        add("source-precedence-"+label,3,raw,raw=True,accept=label=="crlf")
    for n in (4300,4301):
        raw=("hia-asm.v1 hepta.hia.program.v6 digits\nfn x() -> (u8) effects() entry(e)\nblock e()\n"
             "  v:u8 = int.const() {\"value\":"+("9"*n)+"}\n  ret(v)\nend\n").encode()
        add("assembly-integer-digits-"+str(n),3,raw,raw=True,accept=False)
    for n in (15,16,17):
        value=0
        for _ in range(n):value=[value]
        attrs=transport({"x":value}).decode()
        raw=("hia-asm.v1 hepta.hia.program.v6 nested\nfn x() -> () effects() entry(e)\nblock e()\n"
             "  _ = wrong() "+attrs+"\n  ret()\nend\n").encode()
        add("assembly-attrs-nesting-"+str(n),3,raw,raw=True,accept=False)
    for raw in (b"bad header\n",assembly_text().replace(b"ret(value)",b"ret(missing)")):
        add("diagnose-"+str(len(PLAN)),4,raw,raw=True,accept=True)
def object_boundary_plan():
    base=transport(primitive())
    for n in (8388608,8388609):
        add("raw-byte-"+str(n),1,base+b" "*(n-len(base)),raw=True,accept=n==8388608)
    # A real primitive schema keeps successful snapshot traversal on the
    # complete Core diagnostic route. Five fixed value nodes (keys do not
    # count) precede the fanout, so these total exactly 262144 and 262145.
    # The extra member is intentionally rejected by the full Core envelope
    # only after the unchanged public snapshot/structure gates.
    for total in (262144,262145):
        value={"schema":"hepta.hia.program.v6","module":"boundary","functions":[],
               "extra":[None]*(total-5)}
        add("tree-total-nodes-"+str(total),1,value,tree=1,accept=False)
    for depth in (63,64,65):
        extra=0
        for _ in range(depth-1):extra=[extra]
        value={"schema":"hepta.hia.program.v6","module":"boundary","functions":[],"extra":extra}
        add("tree-leaf-depth-"+str(depth),1,value,tree=1,accept=False)
    add("render-tree-complete-roundtrip",2,primitive(),tree=1,accept=True)

def native_planned():
    for index,row in enumerate(PLAN):
        lease=0x57500001+index*8;request=index+1
        packet=header(row["source"],row["mode"],lease,request,tree=row["tree"])+row["source"]
        process,stdout,stderr=actual(row["label"],packet)
        result=parse_result(process,stdout,stderr,row,lease,request)
        ROWS.append(dict(label=row["label"],status="PASS",process=process,result=cas(result),
            complete_payload_and_Core_bytes_equal=True,actual_receipt_digests_equal=True))
        save(OUT/"cases-completed.json",ROWS)
def private_protocol():
    global KERNEL_ENTRIES
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    root=Path(bundle["role_bindings"]["56"]["image_path"])
    image=NativeHiaJsonImage(pin(root),expected_sha256=bundle["role_bindings"]["56"]["image_sha256"])
    guardbytes=bytes(range(32))
    def buffer(raw,size):
        backing=ctypes.create_string_buffer(max(1,size)+64);at=ctypes.addressof(backing)+32
        ctypes.memmove(at-32,guardbytes,32);ctypes.memset(at,0,max(1,size))
        if raw:ctypes.memmove(at,raw,len(raw))
        ctypes.memmove(at+max(1,size),guardbytes,32)
        return backing,at,size
    def invoke(command,state,output_n=128,advertised=None):
        global KERNEL_ENTRIES
        src=buffer(command,len(command));dst=buffer(b"",128);work=buffer(state,len(state))
        before=dict(command=cas(command),workspace=cas(state),output=cas(bytes(128)))
        save(OUT/"pending-native-entry.json",dict(entry=KERNEL_ENTRIES+1,before=before,
             advertised_workspace=len(state) if advertised is None else advertised,advertised_output=output_n))
        ret=int(image._entry(src[1],src[2],dst[1],output_n,work[1],len(state) if advertised is None else advertised))
        KERNEL_ENTRIES+=1
        for b,at,n in (src,dst,work):
            assert ctypes.string_at(at-32,32)==guardbytes and ctypes.string_at(at+max(1,n),32)==guardbytes
        after=ctypes.string_at(work[1],work[2]);out=ctypes.string_at(dst[1],128)
        assert ctypes.string_at(src[1],src[2])==command
        row=dict(entry=KERNEL_ENTRIES,returned=ret,before=before,workspace_after=cas(after),output=cas(out),
                 complete_inputs_and_canaries_unchanged=True)
        save(OUT/"entries"/(str(KERNEL_ENTRIES).zfill(4)+".json"),row)
        return ret,after,out
    state=bytearray(1<<20);struct.pack_into("<Q",state,4096,1)
    struct.pack_into("<Q",state,4096+8,2);struct.pack_into("<Q",state,4096+16,1<<20)
    command=header(b"{}",1)
    invalid=[]
    for offset,value in ((0,0),(8,0),(8,(1<<64)-1),(16,0),(24,639),(24,1<<32),
                         (32,1),(40,0),(40,5),(48,2),(56,1)):
        raw=bytearray(command);struct.pack_into("<Q",raw,offset,value)
        invalid.append(("header-"+str(offset)+"-"+str(value),bytes(raw),bytes(state),128,None))
    invalid.append(("tree-with-assembly",header(b"{}",3,tree=1),bytes(state),128,None))
    for n in (0,63,65):
        raw=(command+b"\0")[:n]
        invalid.append(("header-extent-"+str(n),raw,bytes(state),128,None))
    for at,value in ((4096,0),(4096+16,1),(4096+24,1),(4096+63*8,1),(73728,1),(1048575,1)):
        work=bytearray(state)
        if at==1048575:work[at]=value
        else:struct.pack_into("<Q",work,at,value)
        invalid.append(("initial-workspace-"+str(at),command,bytes(work),128,None))
    invalid.append(("short-output",command,bytes(state),127,None))
    invalid.append(("short-workspace",command,bytes(state),128,(1<<20)-1))
    for label,cmd,work,out_n,advertised in invalid:
        ret,after,out=invoke(cmd,work,out_n,advertised);assert ret==0xfffffffd,label
        ROWS.append(dict(label=label,status="PASS",classification="PRIVATE_ABI_REFUSAL",
                         native_entry=KERNEL_ENTRIES,short_workspace_requires_outer_lease_discard=advertised is not None))
    ret,waiting,event=invoke(command,bytes(state));assert ret==128
    e=struct.unpack("<16Q",event);assert e[1]==15
    ack=struct.pack("<8Q",int.from_bytes(b"HIACDA01","little"),e[2],e[3],15,0,128,160,0)+bytes(160)
    for offset,value in ((0,0),(8,e[2]+1),(16,e[3]+1),(24,1),(32,1),(48,159),(56,1)):
        raw=bytearray(ack);struct.pack_into("<Q",raw,offset,value)
        ret,poison,out=invoke(bytes(raw),waiting);assert ret==0xfffffffd
        ret2,after,out=invoke(command,poison);assert ret2==0xfffffffd
        ROWS.append(dict(label="bad-ACK-"+str(offset),status="PASS",native_entries=[KERNEL_ENTRIES-1,KERNEL_ENTRIES],
                         permanent_refusal_verified=True,foreign_private_ACK=True))
    image._mapping.close()
    for label,packet,extra in (("fixed-bad-magic",bytes(64),()),("fixed-short-header",b"x",()),
        ("fixed-truncated-input",header(b"{}",1)+b"{",()),("fixed-trailing",header(b"{}",1)+b"{}x",()),
        ("fixed-argc",header(b"{}",1)+b"{}",("unexpected",))):
        process,stdout,stderr=actual(label,packet,extra)
        assert not stdout and process["returncode"]==(64 if extra else 3)
        if not extra:
            assert len(stderr)==32 and stderr[:8]==b"HIAXER01"
        ROWS.append(dict(label=label,status="PASS",classification="FIXED_MECHANICAL_REFUSAL",process=process))
    save(OUT/"cases-completed.json",ROWS)

def example_chain():
    document=primitive();document["module"]="discovery_identity"
    # All oracle calls and expected three outputs happen before the first ELF.
    first=reference(1,transport(document),1)
    middle=reference(2,first["program"]["core"],0)
    last=reference(3,middle["payload"],0)
    assert first["program"]["core"]==last["program"]["core"]
    plan=[dict(label="example-P16",mode=1,tree=1,source=transport(document),expected=first),
          dict(label="example-P17",mode=2,tree=0,source=first["program"]["core"],expected=middle),
          dict(label="example-P18",mode=3,tree=0,source=middle["payload"],expected=last)]
    PLAN.extend(plan);record_plan()
    for module in tuple(sys.modules.values()):
        filename=getattr(module,"__file__",None)
        if filename and Path(filename).resolve().is_relative_to(REF) and Path(filename).suffix==".py":pin(filename)
    actual_input=plan[0]["source"];last_core=None
    for index,row in enumerate(plan):
        lease=0x57510001+index*8;request=index+1
        process,stdout,stderr=actual(row["label"],header(actual_input,row["mode"],lease,request,tree=row["tree"])+actual_input)
        result=parse_result(process,stdout,stderr,row,lease,request)
        words=struct.unpack_from("<32Q",result)
        core=result[words[12]:words[12]+words[13]]
        payload=result[words[14]:words[14]+words[15]]
        if index==0:last_core=core
        if index==2:assert core==last_core
        actual_input=payload
        ROWS.append(dict(label=row["label"],status="PASS",process=process,result=cas(result),
            successor_input_from_actual_native_payload=True,complete_roundtrip_Core_bytes_equal=index==2))
        save(OUT/"cases-completed.json",ROWS)

try:
    sys.path.insert(0,str(REF))
    from hepta.hia_program import HIAProgramRejected,verify_program
    from hepta.hia_agent_assembly import HIAAssemblyRejected,render_assembly,assemble_program,diagnose_assembly
    for row in bundle["role_bindings"].values():
        for key,sha,size in (("source_path","source_sha256","source_bytes"),("image_path","image_sha256","image_bytes")):
            raw=pin(row[key]);assert (len(raw),digest(raw))==(row[size],row[sha])
    if a.group=="semantic":semantic_plan()
    elif a.group=="assembly-boundary":assembly_boundary_plan()
    elif a.group=="object-boundary":object_boundary_plan()
    expected_planned={"semantic":45,"assembly-boundary":22,"object-boundary":8}
    if a.group in expected_planned:assert len(PLAN)==expected_planned[a.group]
    # Preserve all imported exact reference source files before native execution.
    for module in tuple(sys.modules.values()):
        filename=getattr(module,"__file__",None)
        if filename and Path(filename).resolve().is_relative_to(REF) and Path(filename).suffix==".py":pin(filename)
    if a.group=="private-protocol":
        private_protocol()
    elif a.group=="example-chain":
        example_chain()
    else:
        record_plan()
        native_planned()
        assert len(ROWS)==len(PLAN) and all(x["status"]=="PASS" for x in ROWS)
    expected_completed={"semantic":45,"assembly-boundary":22,"object-boundary":8,
                        "private-protocol":35,"example-chain":3}
    assert len(ROWS)==expected_completed[a.group]
    if a.group=="private-protocol":assert KERNEL_ENTRIES==38 and NATIVE==5
    assert unchanged();STATUS="PASS"
except BaseException as exc:
    FAILED=dict(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
    traceback.print_exc()
finally:
    same=unchanged()
    if not same:STATUS="FAIL"
    current=resource.getrusage(resource.RUSAGE_SELF);children=resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu=(current.ru_utime+current.ru_stime-INITIAL_CPU.ru_utime-INITIAL_CPU.ru_stime+
         children.ru_utime+children.ru_stime-INITIAL_CHILD.ru_utime-INITIAL_CHILD.ru_stime)
    if cpu>=90:
        STATUS="FAIL"
        FAILED=dict(error_class="AggregateCpuBudgetObservation",actual_cpu_seconds=cpu,earlier_failure=FAILED)
    save(OUT/"source-pins.json",[dict(path=str(path),bytes=len(raw),sha256=digest(raw),mode=mode)
         for path,(raw,mode) in PINS.items()])
    report=dict(schema="hia-worker-program-fixed-actual-r1",status=STATUS,group=a.group,
        planned_semantic_cases=len(PLAN),completed_cases=len(ROWS),actual_native_processes=NATIVE,
        actual_private_kernel_entries=KERNEL_ENTRIES,aggregate_cpu_seconds=cpu,
        elapsed_ns=time.monotonic_ns()-START,failure=FAILED,
        completed_full_payload_comparisons=sum(int("result" in row) for row in ROWS),
        completed_private_controls=sum(int("classification" in row or "foreign_private_ACK" in row) for row in ROWS),
        full_payload_and_actual_receipt_checks_required=True,
        source_image_executable_before_after_equal=same,
        old_case_counts_inherited=False,old_completed_groups_rerun=False,
        original_limits=dict(cpu=90,wall=180,address=1<<30),
        program_bridge_to_live_initializer_registry=False,
        inherited_composite_refusal_text_missing_groups=[1,2,3,4,5,6,9],
        namespace_issued=False,whole_worker_closed=False,installed_activation=False,cold_qualified=False)
    save(OUT/"summary.json",report)
    print("HIA_WORKER_PROGRAM_GROUP "+json.dumps(report,sort_keys=True),flush=True)
if STATUS!="PASS":raise SystemExit(1)
