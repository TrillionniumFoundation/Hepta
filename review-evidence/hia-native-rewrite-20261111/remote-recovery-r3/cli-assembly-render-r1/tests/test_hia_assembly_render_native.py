"""Fresh complete native assembly renderer component with retained byte evidence.
Actual prior Core admission is an oracle fixture prerequisite here; this suite
does not claim that the native admission/roundtrip/CLI coordinator has run.
"""
from pathlib import Path
from hashlib import sha256
import argparse,copy,ctypes,json,random,resource,struct,sys,time,traceback,zlib
sys.dont_write_bytecode=True
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+"\n")
def public_corpus(reference,read):
    from tests.test_hia_program import arithmetic,resource_program,joined_loan_program,b,c,f,i,m,ret,jump,branch
    from tests.test_hia_returned_loans import loan_program,multiple_shared
    rows=[]
    def add(label,document):rows.append((label,document))
    def schema(document,version):
        value=copy.deepcopy(document);value["schema"]="hepta.hia.program.v"+str(version);return value
    types=["i8","u8","i16","u16","i32","u32","i64","u64","isize","usize"]
    for version in (6,7,8):
        for typ in types:
            width=64 if typ.endswith("size") else int(typ[1:])
            low=-(1<<(width-1)) if typ[0]=="i" else 0
            high=(1<<(width-1))-1 if typ[0]=="i" else (1<<width)-1
            for value in sorted({low,0,1,high}):
                add("const-v%d-%s-%d"%(version,typ,value),
                    schema(m(f("constant",[],[typ],[],[b("entry",[],[c("answer",typ,value)],ret("answer"))])),version))
            for opcode in ("int.add.checked","int.add.wrap","int.div.checked","int.shr.checked"):
                add("arithmetic-v%d-%s-%s"%(version,typ,opcode),schema(arithmetic(opcode,typ),version))
        for typ,value in (("bool",False),("bool",True),("unit",None)):
            add("noninteger-v%d-%s-%s"%(version,typ,value),
                schema(m(f("constant",[],[typ],[],[b("entry",[],[c("answer",typ,value)],ret("answer"))])),version))
        for code in ("user","overflow","division_by_zero","bounds","allocation"):
            add("trap-v%d-%s"%(version,code),
                schema(m(f("abort_here",[],[],["trap"],[b("entry",[],[],dict(op="trap",code=code))])),version))
        for mode in ("checked","wrap"):
            add("cast-v%d-%s"%(version,mode),
                schema(m(f("cast",[("input","i64")],["u8"],["trap"] if mode=="checked" else [],
                    [b("entry",[("input","i64")],[i("int.cast",["input"],[("value","u8")],mode=mode)],ret("value"))])),version))
        add("resource-v"+str(version),schema(resource_program(),version))
        add("joined-loan-v"+str(version),schema(joined_loan_program(),version))
        base=schema(arithmetic(),version)
        for name,exports in (("absent",None),("empty",[]),("explicit",["calculate"])):
            value=copy.deepcopy(base)
            if exports is not None:value["exports"]=exports
            add("exports-v%d-%s"%(version,name),value)
        callee=base["functions"][0]
        caller=f("caller",[("x","i32"),("y","i32")],["i32"],["trap"],[
            b("start",[("x","i32"),("y","i32")],
                [i("call",["x","y"],[("result","i32")],function="calculate")],ret("result"))])
        add("call-v"+str(version),schema(m(callee,caller),version))
        params=[("x","bool")]
        add("branch-distinct-v"+str(version),schema(m(f("choose",params,["u8"],[],[
            b("entry",params,[],branch("x",("yes",),("no",))),
            b("yes",[],[c("one","u8",1)],jump("join","one")),
            b("no",[],[c("two","u8",2)],jump("join","two")),
            b("join",[("result","u8")],[],ret("result"))])),version))
    for version in range(1,6):
        add("historical-profile-v"+str(version),schema(arithmetic(),version))
    for mode in ("read","mut"):
        for construction in ("forward","child","cfg","recursive"):
            add("returned-loan-"+mode+"-"+construction,loan_program(mode,construction))
    for construction in ("forward","children","mixed"):
        add("multiple-shared-"+construction,multiple_shared(construction))
    p=m(f("explicit_none",[],["unit"],[],[b("entry",[],[c("value","unit",None)],ret("value"))]))
    p=schema(p,8);p["functions"][0]["return_loans"]=[None];add("explicit-null-loan",p)
    fixtures=[
        ("recursive-v7","examples/hia_recursive_chain/core_v7.json"),
        ("returned-v8","examples/hia_returned_loans/core_v8.json"),
        ("structured-v2","examples/hia_recursive_chain/composite_v2.json"),
        ("structured-returned","examples/hia_returned_loans/returned_nested_field.json"),
    ]
    for label,path in fixtures:add(label,read(reference/path))
    for count in (255,256,257,1024):
        functions=[f("f"+str(n),[],[],[],[b("entry",[],[],ret())]) for n in range(count)]
        add("function-count-"+str(count),schema(m(*functions),8))
    for count in (255,256,257):
        params=[("value"+str(n),"u8") for n in range(count)]
        values=[name for name,_ in params]
        add("list-count-"+str(count),schema(m(f("values",params,["u8"]*count,[],
            [b("entry",params,[],ret(*values))])),8))
    # All names are legitimate Core ASCII identifiers; only the later assembly
    # line budget can reject the complete produced header.
    for width in (127,128):
        params=[("v"+str(n).zfill(3)+"x"*(width-4),"u8") for n in range(128)]
        add("line-budget-width-"+str(width),schema(m(f("wide",params,[],[],
            [b("entry",params,[],ret())])),8))
    for count in (4096,4097):
        first=min(count,4096)
        blocks=[b("b"+str(n),[],[],jump("b"+str(n+1)) if n+1<first else ret()) for n in range(first)]
        funcs=[f("main",[],[],[],blocks)]
        if count>4096:funcs.append(f("extra",[],[],[],[b("entry",[],[],ret())]))
        add("global-blocks-"+str(count),schema(m(*funcs),8))
    large_ops=[c("v"+str(n).zfill(6)+"x"*121,"u8",n&255) for n in range(8192)]
    add("complete-render-exceeds-one-MiB",schema(m(f("large",[],[],[],[b("entry",[],large_ops,ret())])),8))
    assert len({label for label,_ in rows})==len(rows)
    return rows
def private_constructions():
    """These shape-correct JSON trees deliberately have no Core authority."""
    def doc(attrs):
        return dict(schema="hepta.hia.program.v8",module="private",
            functions=[dict(name="fixture",params=[],returns=[],effects=[],entry="e",
                blocks=[dict(id="e",params=[],ops=[dict(op="private_unissued",args=[],out=[],attrs=attrs)],
                    term=dict(op="ret",values=[]))])])
    rows=[]
    values=[None,False,True,0,-1,2**64-1,-(2**63),2**127,
        "",'"\\/\b\t\n\f\r\0\x1f',"éλ中文😀\u2028\u2029\ufeff",[],{},
        [None,False,True,-1,"é",[],{}],{"z":[1,2],"a":{"y":3,"x":4}}]
    for n,value in enumerate(values):rows.append(("private-value-"+str(n),doc({"x":value})))
    keys=["z","a","aa","","a\0","\0","a\n","a\"","a\\","é","λ","中","😀","\U00010000","\uffff"]
    for rotation in range(len(keys)):
        names=keys[rotation:]+keys[:rotation]
        rows.append(("private-sort-"+str(rotation),doc({key:index for index,key in enumerate(names)})))
    for count in (0,1,2,3,7,16,33,128,513):
        rows.append(("private-many-keys-"+str(count),doc({"k"+str(i).zfill(4):{"z":i,"a":[i,False,None]} for i in reversed(range(count))})))
    for depth in (1,2,8,16,32,54):
        value=0
        for n in range(depth):value={"z":value} if n&1 else [value]
        rows.append(("private-depth-"+str(depth),doc({"nested":value})))
    rng=random.Random(0x484941415245)
    for n in range(24):
        names=keys.copy();rng.shuffle(names)
        rows.append(("private-random-"+str(n),doc({key:[rng.randrange(-100000,100000),False,None,"é"] for key in names[:rng.randrange(1,len(names)+1)]})))
    assert len({label for label,_ in rows})==len(rows)
    return rows
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--reference",type=Path,required=True)
    ap.add_argument("--compiler",type=Path,required=True);ap.add_argument("--out",type=Path,required=True)
    a=ap.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    assert sys.version_info[:3]==(3,12,14),sys.version
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CPU,(90,90))
    project=Path(__file__).resolve().parents[1];reference=a.reference.resolve()
    sys.path[:0]=[str(project/"tools"),str(project.parent/"Hepta-agent-edit-native"),str(reference)]
    pins={};rows=[];private_rows=[];controls=[];entries=0;started=time.monotonic_ns()
    summary=dict(status="INCOMPLETE",scope="NATIVE_COMPLETE_ASSEMBLY_TEXT_COMPONENT",
        actual_prior_admission_is_reference_fixture=True,native_Core_admission_qualified=False,
        native_roundtrip_qualified=False,public_cli_qualified=False,installed_activated=False,
        cold_qualified=False,old_counts_inherited=False,host_runtime_render_fallback=False,
        private_constructed_values_grant_no_Core_authority=True)
    def read(path):
        path=Path(path).resolve();raw=path.read_bytes()
        if path in pins:assert pins[path]==(len(raw),digest(raw)),path
        pins[path]=(len(raw),digest(raw));return raw
    def cas(raw):
        raw=bytes(raw);h=digest(raw);path=out/"cas"/(h+".zlib");path.parent.mkdir(exist_ok=True)
        if not path.exists():path.write_bytes(zlib.compress(raw,6))
        assert zlib.decompress(path.read_bytes())==raw
        return dict(bytes=len(raw),sha256=h,path="cas/"+path.name,compression="zlib")
    try:
        assert digest(read(reference/"hepta/hia_agent_assembly.py"))=="e37095496bf159ad573a31214d4d73e916648b4f0664edb541014f54681fbc03"
        assert digest(read(reference/"tools/generate_hia_json_preflight.py"))=="293e22e217cba119dad1c7a4e04b5a9cd714cbeafdfdc4c9b15f4f716557896c"
        assert digest(read(reference/"tools/generate_hia_json_decode.py"))=="fffc97c704cc75ad88239fe79d7b7f83418199a732364f834e006ebfd5f8548f"
        assert digest(read(reference/"tools/qualify_hia_selfhost.py"))=="2674bbc29a67214c16595a226a0dfb28d3dcf56e238058d45e618dd42925cb76"
        assert (len(read(a.compiler)),digest(read(a.compiler)))==(669556,"35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b")
        for path in sorted((project/"tools").glob("*.py")):read(path)
        for path in ("hepta/hia_program.py","tests/test_hia_program.py","tests/test_hia_returned_loans.py"):read(reference/path)
        read(__file__)
        from hepta.hia_agent_assembly import render_assembly,assemble_program,_render_assembly_document,HIAAssemblyRejected
        from hepta.hia_program import verify_program
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        from tools.qualify_hia_selfhost import compile_stage
        import cli_authoring,assembly_render_owner as owner
        body,constants,contract=owner.source();save(out/"owner-contract.json",contract)
        expanded=cli_authoring.expanded(body,constants);(out/"expanded.py").write_text(expanded)
        document=cli_authoring.document(expanded,"complete_assembly_render")
        profile=cli_authoring.profile(document);save(out/"profile.json",profile)
        assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["ops"]<=8192 and profile["max_params"]<=16,profile
        hia=render_assembly(document).encode();(out/"source.hiaasm").write_bytes(hia);assemble_program(hia)
        (out/"compile").mkdir()
        image_path,receipt=compile_stage(out/"compile","assembly-render",a.compiler,hia)
        image_raw=read(image_path)
        assert receipt["status"]=="returned" and receipt["abi_status"]==0
        assert receipt["artifact_sha256"]==digest(read(a.compiler)) and receipt["input_sha256"]==digest(hia)
        assert receipt["produced_sha256"]==digest(image_raw)
        assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
        manifest=dict(schema="hia.public-assembly-render.development.v1",source_sha256=digest(hia),
            source_bytes=len(hia),image_sha256=digest(image_raw),image_bytes=len(image_raw),profile=profile,receipt=receipt)
        save(out/"manifest.json",manifest)
        for path in (out/"source.hiaasm",out/"manifest.json"):read(path)
        image=NativeHiaJsonImage(image_raw,expected_sha256=digest(image_raw))
        guard=b"ASSEMBLY-NATIVE-EXACT-CANARY-32!";assert len(guard)==32
        def buffer(raw=b"",size=None):
            size=len(raw) if size is None else size;assert len(raw)<=size
            value=ctypes.create_string_buffer(max(size,1)+64);address=ctypes.addressof(value)+32
            ctypes.memmove(address-32,guard,32);ctypes.memmove(address,raw,len(raw))
            ctypes.memmove(address+max(size,1),guard,32);return [value,address,size]
        def guards(value):return ctypes.string_at(value[1]-32,32)+ctypes.string_at(value[1]+max(value[2],1),32)
        def invoke(label,s,r,w):
            nonlocal entries
            source=ctypes.string_at(s[1],s[2]);command=ctypes.string_at(r[1],r[2])
            before=ctypes.string_at(w[1],w[2]);path=out/"entries"/(str(entries).zfill(6)+".json")
            row=dict(label=label,status="ENTERING",source=cas(source),command=cas(command),before=cas(before),
                guards_before=[cas(guards(v)) for v in (s,r,w)])
            save(path,row)
            returned=int(image._entry(s[1],s[2],r[1],r[2],w[1],w[2]));entries+=1
            after=ctypes.string_at(w[1],w[2])
            row.update(status="RETURNED",returned=returned,after=cas(after),
                source_after=cas(ctypes.string_at(s[1],s[2])),command_after=cas(ctypes.string_at(r[1],r[2])),
                guards_after=[cas(guards(v)) for v in (s,r,w)])
            if w[2]>=384:row["event"]=list(struct.unpack_from("<16Q",after,256))
            save(path,row)
            assert ctypes.string_at(s[1],s[2])==source and ctypes.string_at(r[1],r[2])==command
            assert all(guards(v)==guard+guard for v in (s,r,w))
            return returned,after,row
        def command(raw,structured=0):return struct.pack("<12Q",constants["COMMAND"],1,71,19,len(raw),structured,*([0]*6))
        def native(label,raw,structured):
            s=buffer(raw);r=buffer(command(raw,structured));w=buffer(size=constants["BASE"]);count=0
            for _ in range(8):
                returned,after,row=invoke(label,s,r,w);count+=1
                event=struct.unpack_from("<16Q",after,256)
                assert event[0]==constants["EVENT"] and event[2:4]==(71,19) and event[10]==len(raw)
                assert event[5:7]==(0,0) and event[9]==0 and event[12:]==(0,0,0,0)
                if returned==0xfffffffe:
                    assert event[1]==1 and event[11]>w[2]
                    w=buffer(after,size=event[11]);continue
                assert returned==128 and event[1] in (0,2),(label,returned,event)
                assert event[7]<=len(after) and event[8]<=len(after)-event[7]
                return event,after[event[7]:event[7]+event[8]],count
            raise AssertionError("unbounded renderer GROW")
        cases=public_corpus(reference,read);private=private_constructions()
        save(out/"expected-inventory.json",dict(public=[label for label,_ in cases],private=[label for label,_ in private]))
        summary.update(expected_public_cases=len(cases),expected_private_constructions=len(private))
        for index,(label,input_value) in enumerate(cases):
            checked=verify_program(input_value);raw=checked.canonical_bytes;data=checked.as_dict()
            structured=int(checked.structured_bytes is not None)
            original=dict(canonical=cas(raw),structured=structured,
                original_structured=cas(checked.structured_bytes) if structured else None)
            compatible=not structured and data["schema"] in {"hepta.hia.program.v6","hepta.hia.program.v7","hepta.hia.program.v8"}
            if compatible:
                expected=_render_assembly_document(data).encode("utf-8")
                original["expected_text"]=cas(expected)
                try:
                    public_text=render_assembly(checked)
                    assert public_text.encode()==expected
                    original["public_roundtrip"]=dict(accepted=True)
                except HIAAssemblyRejected as error:
                    original["public_roundtrip"]=dict(accepted=False,code=error.code,message=str(error),
                        phase=error.phase,line=error.line)
            else:
                try:render_assembly(checked)
                except HIAAssemblyRejected as error:
                    assert error.code=="E_HIA_ASSEMBLY_PROFILE"
                    expected=str(error).encode();original["public_roundtrip"]=dict(accepted=False,code=error.code,
                        message=str(error),phase=error.phase,line=error.line)
                else:raise AssertionError("reference profile fixture unexpectedly accepted")
            save(out/"cases"/(str(index).zfill(4)+".input.json"),dict(label=label,**original))
            event,payload,count=native(label,raw,structured)
            assert event[1]==(0 if compatible else 2) and event[4]==(0 if compatible else 1),(label,event)
            assert payload==expected,(label,payload[:512],expected[:512],len(payload),len(expected))
            row=dict(index=index,label=label,status="PASS",entries=count,compatible=compatible,
                text=cas(payload),public_roundtrip=original["public_roundtrip"],canonical=original["canonical"])
            rows.append(row);save(out/"cases"/(str(index).zfill(4)+".result.json"),row)
            if index%25==0:print("HIA_ASSEMBLY_RENDER_PROGRESS "+json.dumps(dict(completed=index+1,total=len(cases),actual_entries=entries)),flush=True)
        for index,(label,value) in enumerate(private):
            raw=json.dumps(value,ensure_ascii=False,separators=(",",":"),allow_nan=False).encode()
            expected=_render_assembly_document(value).encode()
            save(out/"private"/(str(index).zfill(4)+".input.json"),dict(label=label,input=cas(raw),
                expected=cas(expected),admitted=False,authority="PRIVATE_CONSTRUCTION_ONLY"))
            event,payload,count=native(label,raw,0)
            assert event[1]==0 and payload==expected,(label,payload[:512],expected[:512])
            row=dict(label=label,status="PASS",entries=count,admitted=False,text=cas(payload))
            private_rows.append(row);save(out/"private"/(str(index).zfill(4)+".result.json"),row)
        good_source=verify_program(cases[0][1]).canonical_bytes;good_command=command(good_source)
        def bad(label,raw=good_source,request=good_command,workspace=None,persistent=True):
            s=buffer(raw);r=buffer(request);w=buffer(size=constants["BASE"]) if workspace is None else workspace
            returned,after,row=invoke(label,s,r,w);assert returned==0xfffffffd,(label,returned,row.get("event"))
            if persistent:
                returned,after,row=invoke(label+"-permanent",buffer(good_source),buffer(good_command),w)
                assert returned==0xfffffffd
            controls.append(dict(label=label,status="PASS",persistent_poison_claim=persistent))
        head=list(struct.unpack("<12Q",good_command))
        for field,value in [(0,0),(1,2),(2,0),(3,0),(4,len(good_source)+1),(5,2)]+[(i,1) for i in range(6,12)]:
            changed=head.copy();changed[field]=value
            bad("header-"+str(field),request=struct.pack("<12Q",*changed))
        for n in (0,8,95,97):bad("command-length-"+str(n),request=good_command[:n] if n<=96 else good_command+b"x")
        for length in (0,1,8,255,constants["BASE"]-1):
            bad("short-work-"+str(length),workspace=buffer(size=length),persistent=False)
        # Protocol-invalid source is not an alternate public Core rejection.
        for label,raw in (("empty",b""),("oversized",b" "*(8388608+1))):
            bad("source-"+label,raw,command(raw))
        for field,value in ((0,123),(8,1),(16,0),(16,3)):
            work=bytearray(constants["BASE"]);struct.pack_into("<Q",work,0,constants["STATE"])
            struct.pack_into("<Q",work,field,value)
            bad("state-%d-%d"%(field,value),workspace=buffer(work))
        for label,raw,structured in (("success-terminal",good_source,0),("profile-terminal",good_source,1)):
            s=buffer(raw);r=buffer(command(raw,structured));w=buffer(size=constants["BASE"])
            for _ in range(8):
                returned,after,row=invoke(label,s,r,w)
                if returned==0xfffffffe:w=buffer(after,size=struct.unpack_from("<Q",after,344)[0]);continue
                assert returned==128;break
            bad(label+"-reuse",raw,command(raw,structured),w)
        for mutation in ("source","header","needed","count","nodes","arena","scratch"):
            s=buffer(good_source);r=buffer(good_command);w=buffer(size=constants["BASE"])
            returned,after,row=invoke("grow-"+mutation+"-initial",s,r,w);assert returned==0xfffffffe
            w=buffer(after,size=struct.unpack_from("<Q",after,344)[0])
            returned,after,row=invoke("grow-"+mutation+"-count",s,r,w);assert returned==0xfffffffe
            event=struct.unpack_from("<16Q",after,256);w=buffer(after,size=event[11])
            raw=good_source;request=good_command
            if mutation=="source":raw=b" "+raw[1:]
            elif mutation=="header":
                change=bytearray(good_command);struct.pack_into("<Q",change,16,72);request=bytes(change)
            else:
                key={"needed":"NEEDED","count":"OUTPUT_N","nodes":"ACTUAL_NODES","arena":"ARENA","scratch":"SCRATCH"}[mutation]
                ctypes.memmove(w[1]+constants[key],struct.pack("<Q",0),8)
            bad("grow-"+mutation,raw,request,w)
        # Full malformed JSON and duplicate keys reach the retained strict
        # native decoder after mechanical allocation; fixed source is unchanged.
        for index,raw in enumerate((b"{",b"{}",b'{"schema":"hepta.hia.program.v8","schema":"x"}',
                b'{"schema":"hepta.hia.program.v8","module":"m","functions":NaN}',
                b'{"schema":"hepta.hia.program.v8","module":"\\ud800","functions":[]}')):
            s=buffer(raw);r=buffer(command(raw));w=buffer(size=constants["BASE"])
            for _ in range(8):
                returned,after,row=invoke("private-malformed-"+str(index),s,r,w)
                if returned==0xfffffffe:w=buffer(after,size=struct.unpack_from("<Q",after,344)[0]);continue
                assert returned==0xfffffffd;break
            else:raise AssertionError("malformed input never terminated")
            bad("private-malformed-"+str(index)+"-permanent",raw,command(raw),w)
        assert len(rows)==len(cases) and len(private_rows)==len(private)
        assert any(r["text"]["bytes"]>1048576 for r in rows if r["compatible"])
        late=[r for r in rows if r["compatible"] and not r["public_roundtrip"]["accepted"]]
        assert any(r["label"]=="function-count-257" for r in late)
        assert any(r["label"]=="function-count-1024" for r in late)
        assert any(r["label"]=="complete-render-exceeds-one-MiB" for r in late)
        assert all(r["public_roundtrip"]["code"]=="E_HIA_ASSEMBLY_LIMIT" for r in late),late
        unchanged=all((len(p.read_bytes()),digest(p.read_bytes()))==v for p,v in pins.items())
        assert unchanged
        summary.update(status="PASS",actual_public_cases=len(rows),private_constructions=len(private_rows),
            private_controls=len(controls),native_entries=entries,profile=profile,manifest=manifest,
            native_full_texts=sum(r["compatible"] for r in rows),native_profile_refusals=sum(not r["compatible"] for r in rows),
            reference_late_roundtrip_refusals=len(late),maximum_text_bytes=max(r["text"]["bytes"] for r in rows),
            source_image_before_after=unchanged,complete_native_text_bytes_compared=True,
            all_reference_admissions_recorded=True,private_constructions_separate=True)
    except BaseException as error:
        summary.update(status="FAIL",error=dict(type=type(error).__name__,text=str(error),traceback=traceback.format_exc()),
            completed_public_cases=len(rows),completed_private_constructions=len(private_rows),
            completed_controls=len(controls),native_entries=entries)
        raise
    finally:
        summary["elapsed_ns"]=time.monotonic_ns()-started
        save(out/"cases.json",rows);save(out/"private-constructions.json",private_rows);save(out/"controls.json",controls)
        save(out/"source-pins.json",[dict(path=str(p),bytes=n,sha256=h) for p,(n,h) in pins.items()])
        summary["cas_objects"]=len(list((out/"cas").glob("*.zlib"))) if (out/"cas").exists() else 0
        save(out/"summary.json",summary)
        print("HIA_ASSEMBLY_RENDER_SUMMARY "+json.dumps(summary,sort_keys=True),flush=True)
if __name__=="__main__":main()
