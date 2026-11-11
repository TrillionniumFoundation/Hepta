"""Development-only actual ELF fault capture for the seven-image CLI.

This does not change or repair the tested runtime. It assembles an explicitly
instrumented copy of the frozen mechanics, embeds the exact already-built seven
HIA images, and runs one missing-file input. No reference result is inherited.
Every byte of each logical live slot, command, event and metadata is retained.
"""
from pathlib import Path
from hashlib import sha256
import argparse,ctypes,json,os,re,resource,signal,struct,subprocess,sys,time,traceback
EXPECTED_ASM="d44539b7bba266622d870c6065484e05030b7cce477ffb287d2ab0fd8c5d82c9"
def sha(raw):return sha256(raw).hexdigest()
def save(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--bundle",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    args=p.parse_args()
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    bundle_raw=args.bundle.read_bytes();bundle=json.loads(bundle_raw)
    build=args.bundle.parent
    frozen={}
    def read(path):
        path=Path(path).resolve();raw=path.read_bytes()
        if path in frozen:assert frozen[path]==raw
        else:frozen[path]=raw
        return raw
    read(args.bundle);read(Path(__file__))
    asm_path=build/"frozen/authoring/cli_native_executor.S"
    original=read(asm_path)
    assert sha(original)==EXPECTED_ASM
    images={}
    for role in range(1,8):
        row=bundle["components"][str(role)]
        if role<7:
            images[role]=read(row["image"]["copy"])
            assert sha(images[role])==row["image"]["sha256"]
            assert sha(read(row["source"]["copy"]))==row["source"]["sha256"]
        else:
            images[role]=read(row["image_path"])
            assert sha(images[role])==row["manifest"]["image_sha256"]
            assert sha(read(row["source"]["copy"]))==row["source"]["sha256"]
    sites=[]
    def instrument(match):
        index=len(sites)+1
        sites.append(dict(index=index,line=original[:match.start()].count(b"\n")+1,
                          instruction=match.group(0).decode()))
        return match.group(1)+match.group(2)+b" diag_fail_"+str(index).encode()
    source=re.sub(rb"(?m)^([ \t]+)(j[a-z]+)[ \t]+abi_error[ \t]*$",instrument,original)
    assert sites and source.count(b"\nabi_error:\n")==1
    # Site writes happen only after the original failure condition has fired.
    fail_labels=b"".join(
        (f"diag_fail_{row['index']}:\n"
         f"    mov qword ptr [r15+3008],{row['index']}\n"
         "    mov [r15+3016],rax\n"
         "    jmp abi_error\n").encode()
        for row in sites)
    handler=b"""abi_error:
    mov rax,0x3144494241494c43
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
diag_slots:
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
    jz diag_no_slot
    call diag_write
diag_no_slot:
    inc ebx
    cmp ebx,64
    jb diag_slots
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
    source=source.replace(b"abi_error:\n    mov edi,126\n    jmp terminate\n",handler,1)
    assert handler in source
    source=source.replace(b"    .p2align 3\nimage_table:\n",fail_labels+b"    .p2align 3\nimage_table:\n",1)
    (out/"original.S").write_bytes(original);(out/"diagnostic.S").write_bytes(source)
    save(out/"branch-sites.json",sites)
    def tool(label,command):
        result=subprocess.run(command,capture_output=True,timeout=30)
        (out/(label+".stdout")).write_bytes(result.stdout)
        (out/(label+".stderr")).write_bytes(result.stderr)
        save(out/(label+".process.json"),dict(command=list(map(str,command)),returncode=result.returncode))
        result.check_returncode()
        return result.stdout
    obj=out/"diagnostic.o";binary=out/"diagnostic.bin"
    tool("as",["as","--64",str(out/"diagnostic.S"),"-o",str(obj)])
    tool("objcopy",["objcopy","-O","binary","-j",".text",str(obj),str(binary)])
    reloc=tool("objdump",["objdump","-r",str(obj)])
    assert b"R_X86_64" not in reloc
    symbols=tool("nm",["nm","-n",str(obj)]).decode()
    syms={name:int(at,16) for at,_,name in (line.split() for line in symbols.splitlines())}
    save(out/"symbols.json",syms)
    header=(b"\x7fELF\x02\x01\x01"+bytes(9)+
            struct.pack("<HHIQQQIHHHHHH",2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)+
            struct.pack("<IIQQQQQQ",1,5,0,0x400000,0x400000,0,0,4096)+
            struct.pack("<IIQQQQQQ",0x6474e551,6,0,0,0,0,0,16))
    executable=bytearray(header+binary.read_bytes())
    table=176+syms["image_table"]
    for role in range(1,8):
        executable+=bytes((-len(executable))&15)
        struct.pack_into("<Q",executable,table+role*8,0x400000+len(executable))
        executable+=images[role]
    struct.pack_into("<Q",executable,96,len(executable))
    struct.pack_into("<Q",executable,104,len(executable))
    exe=out/"diagnostic-cli";exe.write_bytes(executable);exe.chmod(0o700)
    assert exe.read_bytes()==executable
    expected_parent=os.getpid()
    def child_setup():
        libc=ctypes.CDLL(None,use_errno=True)
        if libc.prctl(1,signal.SIGKILL,0,0,0)!=0:os._exit(127)
        if os.getppid()!=expected_parent:os._exit(127)
        resource.setrlimit(resource.RLIMIT_CPU,(10,10))
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    process=None;started=time.monotonic_ns()
    argv=[str(exe),"verify",str(out/"absent-input")]
    assert not (out/"absent-input").exists()
    with (out/"stdout.bin").open("wb") as stdout,(out/"stderr.bin").open("wb") as stderr:
        try:
            process=subprocess.Popen(argv,cwd=out,env={"PATH":"","HOME":str(out),"LC_ALL":"C.UTF-8"},
                stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,
                start_new_session=True,preexec_fn=child_setup)
            deadline=time.monotonic()+30
            while True:
                got,status,usage=os.wait4(process.pid,os.WNOHANG)
                if got:
                    process.returncode=os.waitstatus_to_exitcode(status);break
                if time.monotonic()>deadline:raise TimeoutError("CLI diagnostic child")
                time.sleep(.01)
        finally:
            original_error=sys.exc_info()[1]
            if process is not None and process.returncode is None:
                try:
                    os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except BaseException as error:
                    if original_error is None:raise
                    original_error.add_note("diagnostic kill: "+repr(error))
                try:
                    _,status,usage=os.wait4(process.pid,0)
                    process.returncode=os.waitstatus_to_exitcode(status)
                except BaseException as error:
                    if original_error is None:raise
                    original_error.add_note("diagnostic wait: "+repr(error))
    stderr=(out/"stderr.bin").read_bytes()
    record=dict(scope="INSTRUMENTED_DEVELOPMENT_FAULT_ONLY_NOT_EQUIVALENCE",
        original_assembly_sha256=sha(original),diagnostic_assembly_sha256=sha(source),
        embedded_images={str(k):sha(v) for k,v in images.items()},
        argv=argv,pid=process.pid,exit=process.returncode,wait_status=status,
        user=usage.ru_utime,system=usage.ru_stime,maxrss_kib=usage.ru_maxrss,
        elapsed_ns=time.monotonic_ns()-started,stdout_bytes=(out/"stdout.bin").stat().st_size,
        stderr_bytes=len(stderr),stderr_sha256=sha(stderr),fault=None)
    if stderr[:8]==b"CLIABID1":
        at=8
        metadata=stderr[at:at+4096];at+=4096
        frame=stderr[at:at+128];at+=128
        command=stderr[at:at+4096];at+=4096
        (out/"metadata.bin").write_bytes(metadata)
        (out/"frame.bin").write_bytes(frame)
        (out/"command.bin").write_bytes(command)
        u=lambda b,n:struct.unpack_from("<Q",b,n)[0]
        fault=dict(site=u(metadata,3008),rax=u(metadata,3016),
                   event=list(struct.unpack("<16Q",frame)),
                   command=list(struct.unpack_from("<40Q",command)),
                   slots=[])
        fault["site_source"]=sites[fault["site"]-1] if 1<=fault["site"]<=len(sites) else None
        for slot in range(64):
            assert len(stderr)-at>=32
            index,size,mapped,readonly=struct.unpack_from("<4Q",stderr,at);at+=32
            assert index==slot and size<=len(stderr)-at
            raw=stderr[at:at+size];at+=size
            (out/("slot-"+str(slot).zfill(2)+".bin")).write_bytes(raw)
            fault["slots"].append(dict(slot=slot,bytes=size,mapped=mapped,readonly=readonly,sha256=sha(raw)))
            if slot==2:
                fault["controller"]=dict(sequence=u(raw,24),phase=u(raw,32),pending=u(raw,40),
                    next=u(raw,48),returned=u(raw,56),reason=u(raw,472),status=u(raw,8200),
                    fields=list(struct.unpack_from("<24Q",raw,12288)),
                    observed=list(struct.unpack_from("<32Q",raw,512)))
            if slot==11 and size>=1024:
                fault["file_state"]=dict(words=list(struct.unpack_from("<30Q",raw)),
                    event=list(struct.unpack_from("<16Q",raw,256)))
            if slot==10 and size>=1024:
                fault["pretty_state"]=dict(words=list(struct.unpack_from("<30Q",raw)),
                    event=list(struct.unpack_from("<16Q",raw,256)))
        assert at==len(stderr),(at,len(stderr))
        record["fault"]=fault
    record["source_pins_unchanged"]=all(path.read_bytes()==raw for path,raw in frozen.items())
    save(out/"source-pins.json",{str(path):dict(bytes=len(raw),sha256=sha(raw)) for path,raw in frozen.items()})
    save(out/"summary.json",record)
    print("HIA_CLI_ACTUAL_FAULT "+json.dumps(record,sort_keys=True),flush=True)
    assert record["source_pins_unchanged"]
    assert process.returncode==126 and record["fault"] is not None
if __name__=="__main__":main()
