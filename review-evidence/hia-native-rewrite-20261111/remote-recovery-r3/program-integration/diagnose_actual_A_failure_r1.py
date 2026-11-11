"""Exact original A-carrier failure reproduction and terminal-only instrumentation.
No semantic HIA image is regenerated or edited; no passing qualification is claimed.
"""
from pathlib import Path,PurePosixPath
from hashlib import sha256
import argparse,ctypes,json,os,re,resource,signal,stat,struct,subprocess,sys,tarfile,time,traceback,zlib
PIN=dict(bytes=36656892,sha256="9f78f1cf62c344e36a5c7132e675ae7bfb9fbb4db2f9d9e3c08ab88964948df6",
    members=386,original_bytes=109970733,member_index_bytes=171183,
    member_index_sha256="baa17788887a80618cdd187b8598cc6c0148e51368dbe7031046b1dcb0c0f67a",
    scope="real-A-service-fixed-carrier-integration",status="FAIL")
BASE="program-integration/workspace/native-cli-program-service-integration-r1/development/actual-r1/"
def h(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--download",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    a=parser.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    assert os.environ.get("GITHUB_ACTIONS")=="true" and sys.version_info[:3]==(3,12,14)
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    downloaded=list(a.download.rglob("evidence.tar.xz"));assert len(downloaded)==1,downloaded
    archive=downloaded[0];index=archive.with_name("evidence-members.json");custody=archive.with_name("custody.json")
    before={p:p.read_bytes() for p in (archive,index,custody)}
    assert (len(before[archive]),h(before[archive]))==(PIN["bytes"],PIN["sha256"])
    assert (len(before[index]),h(before[index]))==(PIN["member_index_bytes"],PIN["member_index_sha256"])
    outer=json.loads(before[custody])
    assert all(outer[k]==v for k,v in PIN.items())
    ledger=json.loads(before[index]);wanted={r["name"]:r for r in ledger}
    assert len(ledger)==len(wanted)==PIN["members"]
    seen=set();original={};total=0;verified=[]
    with tarfile.open(archive,"r:xz") as tf:
        for member in tf:
            path=PurePosixPath(member.name)
            assert member.isfile() and not member.issym() and not member.islnk()
            assert not path.is_absolute() and ".." not in path.parts and member.name not in seen
            raw=tf.extractfile(member).read();row=wanted[member.name]
            assert (len(raw),h(raw),stat.S_IMODE(member.mode))==(row["bytes"],row["sha256"],row["mode"])
            seen.add(member.name);total+=len(raw);verified.append(row)
            if member.name.startswith(BASE):original[member.name[len(BASE):]]=raw
    assert seen==set(wanted) and total==PIN["original_bytes"]
    save(out/"verified-original-members.json",verified)
    def take(name):
        raw=original[name];dest=out/"original"/name;dest.parent.mkdir(parents=True,exist_ok=True)
        if not dest.exists():dest.write_bytes(raw)
        assert dest.read_bytes()==raw
        return raw
    def cas(row):
        raw=zlib.decompress(take(row["path"]))
        assert (len(raw),h(raw))==(row["bytes"],row["sha256"])
        return raw
    case="cases/core-v1-action-6/"
    previous=json.loads(take(case+"process.json"))
    assert previous["exit"]==126 and previous["timed_out"] is False
    assert previous["stdout"]["bytes"]==0 and previous["stderr"]["bytes"]==0
    pack=json.loads(take(case+"pack.json"));packet=cas(pack["input"]);executable=cas(pack["output"])
    assert take(case+"native-fixture")==executable
    assert cas(previous["stdout"])==b"" and cas(previous["stderr"])==b""
    words=struct.unpack_from("<8Q",packet)
    assert words==(int.from_bytes(b"HIACBP01","little"),1,3,133,len(packet),1128,64,0)
    sizes=struct.unpack_from("<133Q",packet,64);parts=[];at=1128
    for size in sizes:parts.append(packet[at:at+size]);at+=size
    assert at==len(packet) and all(len(r)==n for r,n in zip(parts,sizes))
    original_prefix=take("prefix.bin");layout=json.loads(take("layout.json"))
    assert layout["prefix_bytes"]==len(original_prefix) and layout["prefix_sha256"]==h(original_prefix)
    def packed(prefix,tables):
        data=bytearray(prefix)
        for idx,raw in enumerate(parts):
            if not raw:continue
            data+=bytes((-len(data))&15)
            table=0 if idx<7 else 1 if idx<70 else 2
            role=idx+1 if table==0 else idx-6 if table==1 else idx-69
            struct.pack_into("<Q",data,tables[table]+role*8,0x400000+len(data))
            data+=raw
        struct.pack_into("<Q",data,96,len(data));struct.pack_into("<Q",data,104,len(data))
        return bytes(data)
    assert packed(original_prefix,layout["tables"])==executable
    asm=take("template/source.S")
    assert h(asm)=="f06b915cdfb415894e05c8c4a3e7bbdba9fe9c0bc5b8791878516f91cdfa66de"
    sites=[]
    def instrument(match):
        number=len(sites)+1
        sites.append(dict(index=number,line=asm[:match.start()].count(b"\n")+1,
            instruction=match.group(0).decode(),target=match.group(3).decode()))
        return match.group(1)+match.group(2)+b" diag_fail_"+str(number).encode()
    source=re.sub(rb"(?m)^([ \t]+)(j[a-z]+)[ \t]+((?:svc_)?abi_error)[ \t]*$",instrument,asm)
    assert sites and len(sites)<2000
    labels=b"".join((f"diag_fail_{r['index']}:\n"
        f"    mov qword ptr [r15+3008],{r['index']}\n"
        "    mov [r15+3016],rax\n"
        "    jmp diag_capture\n").encode() for r in sites)
    handler=b"""diag_capture:
    mov rax,0x3130474244414948
    push rax
    mov rsi,rsp
    mov edx,8
    call diag_write
    add rsp,8
    mov rsi,r15
    mov edx,4096
    call diag_write
    mov rsi,r12
    mov edx,128
    call diag_write
    mov rsi,r13
    mov edx,4096
    call diag_write
    xor ebx,ebx
diag_slot_loop:
    mov rax,rbx
    shl rax,5
    lea rbp,[r15+rax]
    sub rsp,32
    mov [rsp],rbx
    mov rax,[rbp+8]
    mov [rsp+8],rax
    mov rax,[rbp+16]
    mov [rsp+16],rax
    mov rax,[rbp+24]
    mov [rsp+24],rax
    mov rsi,rsp
    mov edx,32
    call diag_write
    add rsp,32
    mov rsi,[rbp]
    mov rdx,[rbp+8]
    test rsi,rsi
    jz diag_slot_done
    call diag_write
diag_slot_done:
    inc ebx
    cmp ebx,64
    jb diag_slot_loop
    mov edi,126
    jmp terminate
diag_write:
    test rdx,rdx
    jz diag_write_done
    mov edi,2
    mov eax,1
    syscall
    cmp rax,-4
    je diag_write
    test rax,rax
    jle diag_write_failed
    cmp rax,rdx
    ja diag_write_failed
    add rsi,rax
    sub rdx,rax
    jmp diag_write
diag_write_done:
    ret
diag_write_failed:
    mov edi,127
    jmp terminate
"""
    marker=b"\nimage_table:\n";assert source.count(marker)==1
    source=source.replace(marker,b"\n"+labels+handler+b"\n    .p2align 3\nimage_table:\n",1)
    (out/"diagnostic.S").write_bytes(source);save(out/"branch-sites.json",sites)
    def tool(label,argv):
        done=subprocess.run(list(map(str,argv)),capture_output=True,timeout=30)
        (out/(label+".stdout")).write_bytes(done.stdout);(out/(label+".stderr")).write_bytes(done.stderr)
        save(out/(label+".process.json"),dict(argv=list(map(str,argv)),returncode=done.returncode))
        if done.returncode:
            sys.stderr.buffer.write(done.stderr);sys.stderr.buffer.flush()
        done.check_returncode();return done.stdout
    obj=out/"diagnostic.o";binary=out/"diagnostic.bin"
    tool("as",["as","--64",out/"diagnostic.S","-o",obj])
    tool("objcopy",["objcopy","-O","binary","-j",".text",obj,binary])
    assert b"R_X86_64" not in tool("objdump",["objdump","-r",obj])
    symbols=tool("nm",["nm","-n",obj]).decode()
    syms={name:int(at,16) for at,_,name in (line.split() for line in symbols.splitlines())}
    code=binary.read_bytes();assert syms["executor_start"]==0 and syms["executor_end"]==len(code)
    tables=[176+syms[n] for n in ("image_table","service_image_table_1","service_image_table_2")]
    diagnostic=packed(original_prefix[:176]+code,tables)
    original_exe=out/"exact-original-elf";original_exe.write_bytes(executable);original_exe.chmod(0o700)
    diag_exe=out/"diagnostic-elf";diag_exe.write_bytes(diagnostic);diag_exe.chmod(0o700)
    argv=previous["argv"];assert len(argv)==1 and argv[0].endswith("/cases/core-v1-action-6/native-fixture")
    cwd=Path(argv[0]).parent;assert not cwd.exists();cwd.mkdir(parents=True)
    env=dict(PATH="",HOME="",LANG="C.UTF-8",LC_ALL="C.UTF-8")
    libc=ctypes.CDLL(None,use_errno=True)
    def run(label,exe):
        where=out/label;where.mkdir();process=None;status=None;usage=None;timeout=False
        parent=os.getpid();start=time.monotonic_ns()
        def limits():
            if libc.prctl(1,signal.SIGKILL,0,0,0):os._exit(127)
            if os.getppid()!=parent:os._exit(127)
            resource.setrlimit(resource.RLIMIT_CPU,(90,90))
            resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
            resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        with (where/"stdout.bin").open("wb") as stdout,(where/"stderr.bin").open("wb") as stderr:
            try:
                process=subprocess.Popen(argv,executable=str(exe),cwd=cwd,env=env,stdin=subprocess.DEVNULL,
                    stdout=stdout,stderr=stderr,start_new_session=True,preexec_fn=limits)
                while status is None:
                    pid,state,measure=os.wait4(process.pid,os.WNOHANG)
                    if pid:
                        status=state;usage=measure;process.returncode=os.waitstatus_to_exitcode(state);break
                    if time.monotonic_ns()-start>120_000_000_000:timeout=True;break
                    time.sleep(.01)
            finally:
                if process is not None and process.returncode is None:
                    try:os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    _,status,usage=os.wait4(process.pid,0);process.returncode=os.waitstatus_to_exitcode(status)
        so=(where/"stdout.bin").read_bytes();se=(where/"stderr.bin").read_bytes()
        row=dict(label=label,argv=argv,executable=str(exe),cwd=str(cwd),env=env,exit=process.returncode,
            timed_out=timeout,elapsed_ns=time.monotonic_ns()-start,CPU_seconds=90,address_bytes=1<<30,wall_seconds=120,
            child_cpu=usage.ru_utime+usage.ru_stime,stdout_bytes=len(so),stdout_sha256=h(so),
            stderr_bytes=len(se),stderr_sha256=h(se))
        save(where/"process.json",row)
        return row,so,se
    rerun,so,se=run("exact-original-reproduction",original_exe)
    assert rerun["exit"]==126 and not rerun["timed_out"] and so==se==b"",rerun
    actual,so,se=run("diagnostic-reproduction",diag_exe)
    assert actual["exit"]==126 and not actual["timed_out"] and so==b""
    assert se[:8]==b"HIADBG01"
    meta=se[8:4104];event=se[4104:4232];ack=se[4232:8328];at=8328;slots={}
    for index in range(64):
        record=struct.unpack_from("<4Q",se,at);at+=32
        assert record[0]==index
        pointer=struct.unpack_from("<Q",meta,index*32)[0]
        size=record[1] if pointer else 0
        raw=se[at:at+size];assert len(raw)==size;at+=size
        if pointer:
            target=out/"decoded"/("slot-"+str(index)+".bin");target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(raw);slots[index]=raw
    assert at==len(se)
    (out/"metadata.bin").write_bytes(meta);(out/"event.bin").write_bytes(event);(out/"ack.bin").write_bytes(ack)
    site=struct.unpack_from("<Q",meta,3008)[0];assert 1<=site<=len(sites)
    scalar=lambda raw,lo,hi:{str(i):struct.unpack_from("<Q",raw,i)[0] for i in range(lo,min(hi,len(raw))-7,8)}
    report=dict(status="PASS_DIAGNOSIS_ONLY",original_attempt_status="FAIL",original_native_cases_passed=0,
        original_tar_all_members_verified=len(seen),original_tar_all_bytes_verified=total,
        original_ELF_reproduced=True,original_images_unchanged=True,diagnostic_new_native_processes=2,
        branch=sites[site-1],rax_before_terminal=struct.unpack_from("<Q",meta,3016)[0],
        context=scalar(meta,2048,2352),event=list(struct.unpack("<16Q",event)),ack=scalar(ack,0,384),
        workspace_prefix=scalar(slots.get(2,b""),0,640),workspace_caps=scalar(slots.get(2,b""),4096,4608),
        A_state=scalar(slots.get(2,b""),32000,32320),
        raw_slot_records={str(i):dict(bytes=len(raw),sha256=h(raw)) for i,raw in slots.items()},
        original_process=previous,reproduction=rerun,diagnostic_process=actual,
        no_source_or_image_repair=True,no_qualification_claim=True,whole_stack_closed=False,
        input_download_unchanged=all(p.read_bytes()==raw for p,raw in before.items()))
    assert report["input_download_unchanged"] and original_exe.read_bytes()==executable and diag_exe.read_bytes()==diagnostic
    save(out/"summary.json",report);print("HIA_A_FAULT_DIAGNOSIS "+json.dumps(report,sort_keys=True),flush=True)
if __name__=="__main__":
    try:main()
    except BaseException:
        traceback.print_exc();raise
