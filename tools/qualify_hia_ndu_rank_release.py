"""Actual native NDU stage-18 DAG fixture, independent of ordinary host construction.

This explicitly initializes the native owner at its existing stage checkpoint.
It does not grant whole cold or whole installed release qualification.
"""
from pathlib import Path
from hashlib import sha256
import argparse,ctypes,mmap,os,fcntl,struct,subprocess,json,time,sys,stat

def pin(raw): return {"bytes":len(raw),"sha256":sha256(raw).hexdigest()}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--prerequisites",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--normalizer",type=Path,required=True)
    parser.add_argument("--ordinary",type=Path,required=True)
    args=parser.parse_args()
    S,P,D=args.source,args.prerequisites,args.output
    D.mkdir(mode=0o700)
    sys.path.insert(0,str(S))
    from tools.generate_hia_release_owner import template
    from tools.generate_hia_ndu_evaluator_recipe import SOURCE_PATH as RECIPE
    from tools.hia_native_release_dependencies import read_recipe
    from tools.hia_ndu_rank_release import PRODUCTS,CONTRACT,CONTRACT_PRODUCT,checked_contract
    from tools.hia_ndu_evaluator_release import PRODUCT as LEAF,CONTRACT_PRODUCT as LEAF_RECEIPT,CONTRACT as LEAF_CONTRACT
    recipe=read_recipe((S/RECIPE).read_bytes());SOURCES=tuple(recipe["sources"]);OUTPUTS=tuple(recipe["publications"])
    assert len(OUTPUTS)==8 and set(OUTPUTS)=={LEAF,LEAF_RECEIPT,CONTRACT_PRODUCT,*PRODUCTS.values()}
    from tools.build_hia_source_build import _named_source_request
    from tools.build_hia_native_store_release import _member_with_objects
    before={name:(S/name).read_bytes() for name in (*SOURCES,RECIPE,"tools/hia_release_owner_syscalls.S","tools/generate_hia_release_owner.py")}
    normalizer=args.normalizer.read_bytes()
    contract=checked_contract(before[CONTRACT])
    assert pin(normalizer)=={k:contract["products"]["normalizer"][k]for k in("bytes","sha256")}
    ordinary={name:(args.ordinary/name).read_bytes()for name in OUTPUTS}
    rawcaps=[(P/name).read_bytes() for name in ("hia-subprocess","hia-source-build","hia-source-capture","B3.flat","original-cold.json")]
    expected=("a2d80e53","494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af","4acb5f95","acb6478d1a466d17210611c5fcbbd5aeec3109b0813e917f0bb5c8419f3c33a9","9dd1bac3a5bf88422b089f3370fd9443c376b6b322082fab6a3928c9437a2425")
    for raw,digest in zip(rawcaps,expected,strict=True):
        if not sha256(raw).hexdigest().startswith(digest): raise ValueError("original prerequisite differs")
    original=(P/"hia-release-owner").read_bytes()
    if pin(original)!={"bytes":904435,"sha256":"9cd34906ad54cb64ab0182cc882741278db2d9ed1b7bd260a665a3fc85bf4c88"}: raise ValueError("actual owner differs")
    prefix,holes=template()
    labels=("policy_hole","stage_hole","sha_hole")
    starts=[holes[n]+4+struct.unpack_from("<i",original,holes[n])[0] for n in labels]
    assert starts==sorted(starts) and starts[0]==len(prefix)
    parts=[original[a:b] for a,b in zip(starts,starts[1:]+[len(original)],strict=True)]
    report={"schema":"hepta.hia.ndu-rank-stage-native-component.v1","passed":False,
            "scope":"actual native stage18 DAG with explicitly captured prior stage2 product; final same-release stage2 plus cold/install are independent",
            "owner":pin(original),"native_parts":[pin(p) for p in parts],"inputs":{n:pin(v) for n,v in before.items()},
            "prerequisites":[pin(p) for p in rawcaps],"commands":[]}
    fds=[]
    def save():(D/"result.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    def seal(name,raw,mode=0o400):
        fd=os.memfd_create(name,os.MFD_ALLOW_SEALING);fds.append(fd)
        at=0
        while at<len(raw):at+=os.write(fd,raw[at:])
        os.fchmod(fd,mode);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15);return fd
    try:
        for name in ("stage","work","published","source-kit"):(D/name).mkdir(mode=0o700)
        dirs=[os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW) for p in (S,D/"stage",D/"work",D,D/"published")]
        fds.extend(dirs)
        caps=[seal("captured-"+str(i),raw,0o500 if i<3 else 0o400) for i,raw in enumerate(rawcaps)]
        normalizer_fd=seal("captured-prior-stage2-normalizer",normalizer,0o500)
        report["normalizer"]=pin(normalizer)
        kit_sources={alias:(S/"examples/hia_bootstrap"/name).read_bytes() for alias,name in (
            ("source_build_policy.hepta","source_release_kit.hepta"),
            ("selfhost.hepta","selfhost.hepta"),
            ("source_build_packer.hepta","source_build_packer.hepta"))}
        wire=_named_source_request(kit_sources)
        report["source_kit_calls"]=[]
        for operation in ("sources","pack"):
            argv=[f"/proc/self/fd/{caps[1]}",operation]
            started=time.monotonic()
            result=subprocess.run(argv,input=wire,pass_fds=(caps[1],),capture_output=True,
                                  env={"PATH":""},timeout=180)
            kd=D/"source-kit"
            (kd/(operation+".stdin")).write_bytes(wire)
            (kd/(operation+".stdout")).write_bytes(result.stdout)
            (kd/(operation+".stderr")).write_bytes(result.stderr)
            report["source_kit_calls"].append({"operation":operation,"input":pin(wire),
                "returncode":result.returncode,"stdout":pin(result.stdout),"stderr":pin(result.stderr),
                "seconds":time.monotonic()-started})
            save()
            if result.returncode or result.stderr or not result.stdout:
                raise ValueError("actual source-kit construction failed")
            wire=result.stdout
        if not wire.startswith(b"\x7fELF"):
            raise ValueError("actual source-kit is not an ELF")
        sourcekit=D/"source-kit"/"hia-source-release-kit"
        sourcekit.write_bytes(wire);sourcekit.chmod(0o500)
        kitfd=seal("actual-source-release-kit",wire,0o500)
        report["source_kit"]=pin(wire)
        source_pins={n:sha256(before[n]).hexdigest() for n in (*SOURCES,RECIPE)}
        inv=bytearray(struct.pack("<8sQ",b"HIASPI01",len(source_pins)))
        for name,digest in sorted(source_pins.items()):
            raw=name.encode();inv+=struct.pack("<Q",len(raw))+bytes.fromhex(digest)+raw
        name=b"published"
        request=struct.pack("<8s15Q",b"HIAOWN01",0,time.monotonic_ns()+1800_000_000_000,*dirs[:3],*caps,*dirs[3:],len(name),len(inv),0)+b"".join(sha256(raw).digest() for raw in rawcaps)+name+inv
        reqfd=seal("actual-request",request);(D/"request.bin").write_bytes(request)
        w=bytearray(4194304);o=bytearray(128)
        def put(at,v):struct.pack_into("<Q",w,at,v&((1<<64)-1))
        mapping=mmap.mmap(-1,len(parts[0]),prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC);mapping.write(parts[0])
        fn=ctypes.CFUNCTYPE(ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64)(ctypes.addressof(ctypes.c_char.from_buffer(mapping)))
        sb=ctypes.create_string_buffer(request);ob=(ctypes.c_ubyte*len(o)).from_buffer(o);wb=(ctypes.c_ubyte*len(w)).from_buffer(w)
        result=fn(ctypes.addressof(sb),len(request),ctypes.addressof(ob),len(o),ctypes.addressof(wb),len(w))
        assert result==1 and struct.unpack_from("<Q",w)[0]==1,(result,o[:64].hex())
        inventory=os.memfd_create("writable-native-inventory",os.MFD_ALLOW_SEALING);fds.append(inventory)
        os.write(inventory,struct.pack("<8s2Q",b"HIAINV01",0,0))
        graph=before[RECIPE];graphfd=seal("actual-stage18-dag",graph)
        w[2097152:2097152+len(graph)]=graph
        for at,value in {0:5002,8:0,120:kitfd,200:inventory,216:caps[1],224:caps[2],232:caps[0],256:24,
                         3000:len(rawcaps[0]),3008:len(rawcaps[1]),3016:len(rawcaps[2]),3024:len(rawcaps[3]),3032:len(rawcaps[4]),
                         1500000:graphfd,1500008:len(graph),1519984:0,1599904:0}.items():put(at,value)
        # The captured runner and capture binaries are real prior release products.
        # Reconstruct their two original product-table rows in this explicit component checkpoint.
        put(104,3)
        for index,(name,fd,raw) in enumerate((
                (b"hia-subprocess",caps[0],rawcaps[0]),
                (b"hia-source-capture",caps[2],rawcaps[2]),
                (b"hia-nominal-constructor",normalizer_fd,normalizer))):
            name_at=1900000+index*64
            w[name_at:name_at+len(name)]=name
            for offset,value in ((0,fd),(8,len(raw)),(16,name_at),(24,len(name))):
                put(294912+index*32+offset,value)
        statefd=seal("native-initial-state",w);os.dup2(statefd,1000);fds.append(1000)
        dumpfd=os.open(D/"terminal-state.bin",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.dup2(dumpfd,1001);fds.extend((dumpfd,1001))
        assembly=before["tools/hia_release_owner_syscalls.S"].decode()
        old="    lea r14,[rax+STATE_BYTES]\nadvance:"
        replacement="""    lea r14,[rax+STATE_BYTES]
    mov eax,17
    mov edi,1000
    mov rsi,r15
    mov edx,STATE_BYTES
    xor r10d,r10d
    syscall
    cmp rax,STATE_BYTES
    jne invalid
    mov eax,39
    syscall
    mov [r15+16],rax
    mov eax,102
    syscall
    mov [r15+24],rax
advance:
    cmp QWORD PTR [r15],5000
    jne diagnostic_continue
    cmp QWORD PTR [r15+1519984],1
    je diagnostic_complete
diagnostic_continue:
    mov rax,[r15]
    mov [r14+128],rax"""
        assert assembly.count(old)==1
        assembly=assembly.replace(old,replacement)
        assembly=assembly.replace("stage_action:\n","stage_action:\n    mov rax,[r15]\n    mov [r14+128],rax\n")
        assembly=assembly.replace("syscall_action:\n","syscall_action:\n    cmp QWORD PTR [r14],60\n    jne diagnostic_after_dump\n    call diagnostic_dump\ndiagnostic_after_dump:\n")
        assembly+="""
diagnostic_complete:
    call diagnostic_dump
    mov eax,60
    xor edi,edi
    syscall
    ud2
diagnostic_dump:
    mov eax,1
    mov edi,1001
    mov rsi,r15
    mov edx,STATE_BYTES+136
    syscall
    ret
"""
        asm=D/"mechanical-checkpoint.S";asm.write_text(assembly)
        obj=D/"mechanical-checkpoint.o";flat=D/"mechanical-checkpoint.bin"
        for argv in (["/usr/bin/as","--64",str(asm),"-o",str(obj)],["/usr/bin/objcopy","-O","binary","-j",".text",str(obj),str(flat)]):
            report["commands"].append(argv);subprocess.run(argv,check=True,capture_output=True,timeout=30)
        symbols={name:int(a,16) for a,_,name in (line.split() for line in subprocess.check_output(["/usr/bin/nm","-n",str(obj)],text=True).splitlines())}
        code=bytearray(prefix[:176]+flat.read_bytes())
        for name,part in zip(labels,parts,strict=True):
            at=176+symbols[name];struct.pack_into("<i",code,at,len(code)-at-4);code+=part
        struct.pack_into("<2Q",code,96,len(code),len(code))
        executable=D/"mechanical-owner";executable.write_bytes(code);executable.chmod(0o500)
        report.update(mechanical_capsule=pin(code),request=pin(request),initial_state=pin(w));save()
        argv=["/usr/bin/strace","-f","-qq","-s","120","-e","trace=process,execveat","-o",str(D/"trace.log"),str(executable)]
        report["commands"].append(argv)
        start=time.monotonic()
        result=subprocess.run(argv,stdin=reqfd,pass_fds=tuple(set(fds)),capture_output=True,
                              env={"PATH":"","TMPDIR":str(D/"work")},cwd=D,timeout=180)
        (D/"stdout").write_bytes(result.stdout);(D/"stderr").write_bytes(result.stderr)
        report.update(returncode=result.returncode,seconds=time.monotonic()-start)
        terminal=(D/"terminal-state.bin").read_bytes()
        report["terminal_state"]=pin(terminal)
        if len(terminal)==4194304+136:
            q=lambda at:struct.unpack_from("<Q",terminal,at)[0]
            report["terminal"]={"phase":q(0),"previous_phase":q(4194304+128),"dag_index":q(1519984),
                                "node_index":q(1500040),"operation":q(1500048),"plan":list(struct.unpack_from("<16Q",terminal,4194304)),
                                "published":q(1599904)}
        report["products"]={p.name:{**pin(p.read_bytes()),"mode":stat.S_IMODE(p.stat().st_mode)} for p in (D/"stage").iterdir()}
        if result.returncode==0:
            if set(report["products"])!=set(OUTPUTS):raise ValueError("native stage18 actual inventory differs")
            expected={row["resource"]:{k:row[k]for k in("bytes","sha256")}for row in contract["products"].values()}
            expected[CONTRACT_PRODUCT]=pin(before[CONTRACT])
            leaf=json.loads(before[LEAF_CONTRACT])
            expected[LEAF]={"bytes":leaf["binary_bytes"],"sha256":leaf["binary_sha256"]}
            expected[LEAF_RECEIPT]=pin(before[LEAF_CONTRACT])
            for name in OUTPUTS:
                raw=(D/"stage"/name).read_bytes()
                if pin(raw)!=expected[name]or raw!=ordinary[name]:
                    raise ValueError("native DAG and ordinary complete product differ: "+name)
                wanted=0o500 if raw.startswith(b"\x7fELF")else 0o400
                if report["products"][name]["mode"]!=wanted:
                    raise ValueError("native publication mode differs: "+name)
            report["all_eight_products_complete_byte_equal"]=True
            report["ordinary_products"]={name:pin(raw)for name,raw in ordinary.items()}
            report["recipe"]={k:recipe[k]for k in("nodes","bytes","sha256","sources","publications")}
        report["physical_inputs_unchanged"]=all((S/n).read_bytes()==raw for n,raw in before.items()) and all((P/name).read_bytes()==raw for name,raw in zip(("hia-subprocess","hia-source-build","hia-source-capture","B3.flat","original-cold.json"),rawcaps,strict=True)) and (P/"hia-release-owner").read_bytes()==original and args.normalizer.read_bytes()==normalizer and all((args.ordinary/name).read_bytes()==raw for name,raw in ordinary.items())
        report["passed"]=result.returncode==0 and report.get("terminal",{}).get("phase")==5000 and report["terminal"]["dag_index"]==1 and report.get("all_eight_products_complete_byte_equal")is True and report["physical_inputs_unchanged"]
        save();print(json.dumps(report,sort_keys=True),flush=True)
        if not report["passed"]:raise SystemExit(1)
    finally:
        save()
        for fd in set(fds):
            try:os.close(fd)
            except OSError:pass
    return 0
if __name__=="__main__":raise SystemExit(main())
