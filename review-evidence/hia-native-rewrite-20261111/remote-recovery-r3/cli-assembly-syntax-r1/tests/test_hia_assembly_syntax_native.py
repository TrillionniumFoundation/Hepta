"""Fresh actual-HIA full public assembly syntax differential.
This suite proves syntax construction and exact refusal only. It does not grant
Core verification, public three-action CLI, renderer or installed authority.
"""
from pathlib import Path
from hashlib import sha256
import argparse,ctypes,json,os,random,resource,struct,sys,time,traceback,zlib
sys.dont_write_bytecode=True
def digest(b):return sha256(b).hexdigest()
def save(p,v):
    p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(v,sort_keys=True,indent=2,ensure_ascii=True)+"\n")
def source_text():
    return ("hia-asm.v1 hepta.hia.program.v8 sums\nexports(total)\n"
        "fn total(a:u32,b:u32) -> (u64) effects() entry(entry)\n"
        "block entry(a:u32,b:u32)\n"
        '  a64:u64 = int.cast(a) {"mode":"wrap"}\n'
        '  b64:u64 = int.cast(b) {"mode":"wrap"}\n'
        "  answer:u64 = int.add.wrap(a64,b64)\n  ret(answer)\nend\n")
def corpus():
    cases=[]
    def add(label,value,digits=4300):cases.append((label,value,digits))
    seed=source_text()
    for schema in ("v6","v7","v8"):
        p=seed.replace("program.v8","program."+schema)
        add("basic-"+schema,p);add("basic-"+schema+"-bytes",p.encode())
        add("crlf-"+schema,p.replace("\n","\r\n"))
        add("empty-exports-"+schema,p.replace("exports(total)","exports()"))
        add("absent-exports-"+schema,p.replace("exports(total)\n",""))
        add("no-final-lf-"+schema,p.rstrip("\n"))
    for value in (None,True,1,[],{},bytearray(b"abc")):add("unsupported-"+type(value).__name__,value)
    for i,value in enumerate(("",b"", " \t\r\n", "\n" * 30, b"\xff", b"\xc0\x80", b"\xed\xa0\x80",
          b"\xf4\x90\x80\x80",b"\xf0\x80\x80\x80",b"\xc2",b"\xe2\x82", "\ud800","\udfff",
          "\ud800" + seed,seed+"\udc80",seed+"\ufeff",seed+"\x00",seed+"\rjunk\n")):add("source-"+str(i),value)
    for cp in list(range(9))+[11,12]+list(range(14,32))+[0xfeff]:
        add("control-"+str(cp),seed+chr(cp))
        add("control-before-earlier-syntax-"+str(cp),"bad\n"+chr(cp))
    whitespace=[9,10,11,12,13,28,29,30,31,32,133,160,5760,*range(8192,8203),8232,8233,8239,8287,12288]
    for cp in whitespace:
        char=chr(cp)
        for place,old,new in (
            ("header","hia-asm.v1 ","hia-asm.v1"+char),
            ("fn","fn total","fn"+char+"total"),
            ("arrow"," -> ",""+char+"->"+char),
            ("effects",") effects(",")"+char+"effects("),
            ("entry",") entry(",")"+char+"entry("),
            ("params","a:u32,b:u32",""+char+"a"+char+":"+char+"u32"+char+","+char+"b:u32"+char),
            ("exports","exports(total)","exports("+char+"total"+char+")"),
            ("instruction"," = ",""+char+"="+char),
            ("attrs",') {"mode":"wrap"}',')'+char+'{"mode":"wrap"}'),
        ):add("unicode-space-"+str(cp)+"-"+place,seed.replace(old,new,1))
        add("unicode-leading-"+str(cp),char+seed)
        add("unicode-trailing-"+str(cp),seed.replace("exports(total)","exports(total)"+char))
    bad_headers=["hia-asm.v0 hepta.hia.program.v8 m","hia-asm.v1 hepta.hia.program.v2 m",
        "hia-asm.v1 hepta.hia.composite.v1 m","hia-asm.v1 hepta.hia.program.v9 m",
        "hia-asm.v1 hepta.hia.program.v8 0m","hia-asm.v1 hepta.hia.program.v8 "+("a"*129),
        "hia-asm.v1 hepta.hia.program.v8 m extra","hia-asm.v1\nhepta.hia.program.v8 m",
        "\u0085hia-asm.v1 hepta.hia.program.v8 m","hia-asm.v1 hepta.hia.program.v8 m\u0085"]
    for i,value in enumerate(bad_headers):add("header-"+str(i),value+"\n")
    changes=[
        ("duplicate-exports","exports(total)","exports(total)\nexports(total)"),
        ("late-exports","end\n","end\nexports(total)\n"),
        ("invalid-fn","fn total","function total"),
        ("fn-name-long","fn total","fn "+("x"*129)),
        ("fn-empty","fn total","fn "),
        ("fn-bad-param","a:u32,b:u32","a,u32"),
        ("fn-empty-item","a:u32,b:u32","a:u32,"),
        ("fn-empty-before-bad-name","a:u32,b:u32","!:u32,"),
        ("fn-bad-out","-> (u64)","-> (bad!)"),
        ("fn-bad-effect","effects()","effects(bad!)"),
        ("fn-bad-entry","entry(entry)","entry(bad!)"),
        ("fn-loans-v7",") entry(entry)",') entry(entry) return_loans(["a"])'),
        ("fn-loans-parenthesis",") entry(entry)",') entry(entry) return_loans(["a("])'),
        ("block-bad-param","block entry(a:u32,b:u32)","block entry(a)"),
        ("block-space-before-paren","block entry(","block entry ("),
        ("block-before-term","  ret(answer)\n","block later()\n  ret(answer)\n"),
        ("end-before-term","  ret(answer)\n",""),
        ("missing-end","end\n",""),
        ("double-term","  ret(answer)\n","  ret(answer)\n  ret(answer)\n"),
        ("missing-block","block entry(a:u32,b:u32)\n",""),
        ("extra-line","end\n","end\njunk\n"),
        ("op-bad-name","int.cast(a)","int.!cast(a)"),
        ("op-empty-arg","int.cast(a)","int.cast(a,)"),
        ("op-args-before-outs","a64:u64 = int.cast(a)","bad-out = int.cast(bad!)"),
        ("op-output-empty-item","a64:u64 = ","a64:u64, = "),
        ("op-underscore","a64:u64 = ","_ = "),
        ("op-unicode-only-output","a64:u64 = ","\u00a0 = "),
        ("op-equals","a64:u64 = ","a64:u64 == "),
        ("ret-space","ret(answer)","ret (answer)"),
        ("ret-bad-list","ret(answer)","ret(answer,)"),
        ("ret-empty-before-bad","ret(answer)","ret(!,)"),
    ]
    for label,old,new in changes:
        value=seed.replace(old,new,1)
        if label=="fn-loans-v7":value=value.replace("program.v8","program.v7")
        add(label,value)
    attrs=['{}','{"mode":"wrap"}','{"x":0}','{"x":-0}','{"x":-1}','{"x":true}','{"x":null}',
        '{"x":"\\u0061"}','{"x":"\\ud83d\\ude00"}','{"x":"\\ud800"}','{"x":"\\udfff"}',
        '{"x":"é"}','{"x":"\\n"}','{"x":1,"\\u0078":2}','{"x":0,"x":1}',
        '{"x":NaN}','{"x":Infinity}','{"x":-Infinity}','{"x":1.0}','{"x":1e2}',
        '[]','null','true','1','"x"','', ' ', '{"x":}', '{"x":01}', '{"x":-}', '{"x":+1}',
        '{"x":[],"y":[null,true,false,{"z":4}]}','{"x":{"a":1},"y":{"a":2}}']
    for i,attr in enumerate(attrs):add("attrs-"+str(i),seed.replace('{"mode":"wrap"}',attr,1))
    for n in (2045,2046,2047,2048):
        add("attrs-nodes-"+str(n),seed.replace('{"mode":"wrap"}','{"x":['+','.join("0" for _ in range(n))+']}',1))
    for n in (14,15,16,17):
        add("attrs-depth-"+str(n),seed.replace('{"mode":"wrap"}','{"x":'+'['*n+'0'+']'*n+'}',1))
    for n,digits in ((639,640),(640,640),(641,640),(4299,4300),(4300,4300),(4301,4300),(5000,0)):
        add("attrs-digits-"+str(n)+"-"+str(digits),seed.replace('{"mode":"wrap"}','{"x":'+('9'*n)+'}',1),digits)
    add("attrs-duplicate-before-digits",seed.replace('{"mode":"wrap"}','{"x":'+('9'*4301)+',"x":0}',1))
    loans=['[]','[null]','["a"]','["\\u0061"]','["a","b",null]','[""]','["!"]','["é"]',
        '[0]','[false]','[[null]]','{}','null','["a",]','["\\ud800"]','["a","a"]']
    for i,value in enumerate(loans):
        add("loans-"+str(i),seed.replace(" entry(entry)"," entry(entry) return_loans("+value+")",1))
    for n in (255,256,257):add("loans-count-"+str(n),seed.replace(" entry(entry)"," entry(entry) return_loans(["+','.join("null" for _ in range(n))+"])",1))
    for n in (127,128,129):
        name="n"*n
        add("name-width-"+str(n),seed.replace("total",name))
        add("opcode-width-"+str(n),seed.replace("int.cast",name,1))
    for n in (255,256,257):
        names=",".join("x"+str(i) for i in range(n))
        params=",".join("x"+str(i)+":u8" for i in range(n))
        add("exports-count-"+str(n),seed.replace("exports(total)","exports("+names+")"))
        add("params-count-"+str(n),seed.replace("fn total(a:u32,b:u32)","fn total("+params+")"))
        add("returns-count-"+str(n),seed.replace("-> (u64)","-> ("+names+")"))
        add("effects-count-"+str(n),seed.replace("effects()","effects("+names+")"))
        add("args-count-"+str(n),seed.replace("int.cast(a)","int.cast("+names+")",1))
        add("outs-count-"+str(n),seed.replace("a64:u64 =",params+" =",1))
    for n in (255,256,257):
        value="hia-asm.v1 hepta.hia.program.v8 m\n"+"".join(
            "fn f"+str(i)+"() -> () effects() entry(e)\nblock e()\nret()\nend\n" for i in range(n))
        add("function-count-"+str(n),value)
    for n in (4095,4096,4097):
        value="hia-asm.v1 hepta.hia.program.v8 m\nfn f() -> () effects() entry(b0)\n"+"".join(
            "block b"+str(i)+"()\nret()\n" for i in range(n))+"end\n"
        add("block-count-"+str(n),value)
    for n in (16377,16378,16379):
        value="hia-asm.v1 hepta.hia.program.v8 m\nfn f() -> () effects() entry(e)\nblock e()\n"+("_ = nop()\n"*n)+"ret()\nend\n"
        add("operation-line-frontier-"+str(n),value)
    for n in (16383,16384,16385):
        first="hia-asm.v1 hepta.hia.program.v8 m"
        add("line-bytes-"+str(n),first+(" "*(n-len(first)))+"\n")
    for n in (16382,16383,16384):
        add("line-count-"+str(n+1),"\n"*n)
    for n in (1048575,1048576,1048577):
        value=seed;remaining=n-len(value)
        while remaining:
            part=min(remaining,16384)
            value+=" "*(part-1)+"\n" if part==16384 else " "*part
            remaining-=part
        add("source-byte-bound-"+str(n),value.encode())
    add("str-character-bound-before-surrogate","\ud800"*(1048576+1))
    add("str-surrogate-before-encoded-byte-bound","\ud800"*400000)
    add("str-encoded-byte-bound","\U0001f600"*300000)
    add("global-control-before-line-limit","x"*17000+"\0")
    add("global-line-count-before-line-bytes","x"*17000+"\n"*16384)
    add("early-cr-before-late-long","x\ry\n"+"x"*17000)
    add("early-long-before-late-cr","x"*17000+"\nx\ry")
    add("later-cr-before-early-syntax","bad\nx\ry")
    add("later-long-before-early-list",seed.replace("a:u32,b:u32","!,")+"\n"+"x"*17000)
    for term in ("ret()","jump e()","branch a yes(x) no(y)","trap stopped"):
        add("term-"+term,seed.replace("ret(answer)",term))
        add("term-trailing-unicode-"+term,seed.replace("ret(answer)",term+"\u00a0"))
    branches=["branch a yes(x,) no(!)","branch a yes(!) no(x,)","branch a yes(x) no(y)",
        "branch a\u0085yes()\u2028no()","branch a yes()no()","branch a yes() no() extra"]
    for i,x in enumerate(branches):add("branch-"+str(i),seed.replace("ret(answer)",x))
    rng=random.Random(0x48494141534d)
    alphabet=["(",")","=",",",":"," ","\t","\r","\n","!","a","0","\u00a0","\u2028","{","}","\""]
    for i in range(256):
        p=rng.randrange(len(seed));op=i%3;ch=alphabet[rng.randrange(len(alphabet))]
        value=seed[:p]+ch+seed[p:] if op==0 else seed[:p]+(seed[p+1:] if op==1 else ch+seed[p+1:])
        add("deterministic-mutation-"+str(i),value)
    assert len({x[0] for x in cases})==len(cases)
    return cases

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--reference",type=Path,required=True)
    ap.add_argument("--compiler",type=Path,required=True);ap.add_argument("--out",type=Path,required=True)
    a=ap.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    assert sys.version_info[:3]==(3,12,14),sys.version
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CPU,(90,90))
    project=Path(__file__).resolve().parents[1];reference=a.reference.resolve()
    sys.path[:0]=[str(project/"tools"),str(project.parent/"Hepta-agent-edit-native"),str(reference)]
    pins={};case_rows=[];controls=[];native_entries=0;start=time.monotonic_ns()
    summary=dict(status="INCOMPLETE",scope="FULL_ORIGINAL_ASSEMBLY_SYNTAX_CONSTRUCTION_ONLY",
        old_results_inherited=False,core_semantics_qualified=False,renderer_qualified=False,
        public_cli_qualified=False,installed_activated=False,cold_qualified=False,
        runtime_host_syntax_fallback=False,private_issuer_required=True)
    def read(path):
        path=Path(path).resolve();raw=path.read_bytes()
        if path in pins:assert pins[path]==(len(raw),digest(raw)),path
        pins[path]=(len(raw),digest(raw));return raw
    def cas(raw):
        raw=bytes(raw);h=digest(raw);p=out/"cas"/(h+".zlib");p.parent.mkdir(exist_ok=True)
        if not p.exists():p.write_bytes(zlib.compress(raw,6))
        assert zlib.decompress(p.read_bytes())==raw
        return dict(bytes=len(raw),sha256=h,path="cas/"+p.name,compression="zlib")
    try:
        assert digest(read(reference/"hepta/hia_agent_assembly.py"))=="e37095496bf159ad573a31214d4d73e916648b4f0664edb541014f54681fbc03"
        assert digest(read(reference/"tools/generate_hia_json_preflight.py"))=="293e22e217cba119dad1c7a4e04b5a9cd714cbeafdfdc4c9b15f4f716557896c"
        assert digest(read(reference/"tools/qualify_hia_selfhost.py"))=="2674bbc29a67214c16595a226a0dfb28d3dcf56e238058d45e618dd42925cb76"
        assert (len(read(a.compiler)),digest(read(a.compiler)))==(669556,"35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b")
        for path in sorted((project/"tools").glob("*.py")):read(path)
        read(__file__)
        from hepta.hia_agent_assembly import _parse_assembly_document,_source,HIAAssemblyRejected,render_assembly,assemble_program
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        from tools.qualify_hia_selfhost import compile_stage
        import cli_authoring,assembly_syntax_owner as owner
        body,constants,meta=owner.source();save(out/"owner-contract.json",meta)
        expanded=cli_authoring.expanded(body,constants);(out/"expanded.py").write_text(expanded)
        document=cli_authoring.document(expanded,"public_assembly_syntax")
        profile=cli_authoring.profile(document);save(out/"profile.json",profile)
        assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["ops"]<=8192 and profile["max_params"]<=16,profile
        hia=render_assembly(document).encode();(out/"source.hiaasm").write_bytes(hia)
        assemble_program(hia)
        (out/"compile").mkdir()
        image_path,receipt=compile_stage(out/"compile","assembly-syntax",a.compiler,hia)
        image_bytes=read(image_path)
        assert receipt["artifact_sha256"]==digest(read(a.compiler)) and receipt["input_sha256"]==digest(hia)
        assert receipt["status"]=="returned" and receipt["abi_status"]==0 and receipt["produced_sha256"]==digest(image_bytes)
        assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
        manifest=dict(schema="hia.public-assembly-syntax.development.v1",profile=profile,source_sha256=digest(hia),
            source_bytes=len(hia),image_sha256=digest(image_bytes),image_bytes=len(image_bytes),receipt=receipt)
        save(out/"manifest.json",manifest)
        for path in (out/"source.hiaasm",out/"manifest.json"):read(path)
        image=NativeHiaJsonImage(image_bytes,expected_sha256=digest(image_bytes))
        guard=b"ASSEMBLY-NATIVE-EXACT-CANARY-32!"
        assert len(guard)==32,len(guard)
        def buffer(raw=b"",size=None):
            size=len(raw) if size is None else size;assert len(raw)<=size
            physical=max(size,1);backing=ctypes.create_string_buffer(physical+64);at=ctypes.addressof(backing)+32
            ctypes.memmove(at-32,guard,32);ctypes.memmove(at,raw,len(raw));ctypes.memmove(at+physical,guard,32)
            return [backing,at,size]
        def check(v):
            assert ctypes.string_at(v[1]-32,32)==guard and ctypes.string_at(v[1]+max(v[2],1),32)==guard
        def invoke(label,source,command,work):
            nonlocal native_entries
            sraw=ctypes.string_at(source[1],source[2]);rraw=ctypes.string_at(command[1],command[2])
            def guards(v):return ctypes.string_at(v[1]-32,32)+ctypes.string_at(v[1]+max(v[2],1),32)
            before=ctypes.string_at(work[1],work[2]);entry=dict(source=cas(sraw),command=cas(rraw),before=cas(before),
                guards_before=[cas(guards(v)) for v in (source,command,work)])
            rowpath=out/"entries"/(str(native_entries).zfill(6)+".json");save(rowpath,dict(label=label,status="ENTERING",**entry))
            returned=int(image._entry(source[1],source[2],command[1],command[2],work[1],work[2]));native_entries+=1
            after=ctypes.string_at(work[1],work[2]);entry.update(returned=returned,after=cas(after),status="RETURNED",
                source_after=cas(ctypes.string_at(source[1],source[2])),command_after=cas(ctypes.string_at(command[1],command[2])),
                guards_after=[cas(guards(v)) for v in (source,command,work)])
            if work[2]>=384:entry["event"]=list(struct.unpack_from("<16Q",after,256))
            save(rowpath,dict(label=label,**entry))
            for v in (source,command,work):check(v)
            assert ctypes.string_at(source[1],source[2])==sraw and ctypes.string_at(command[1],command[2])==rraw
            return returned,after,entry
        def cmd(raw,kind=2,digits=4300):
            return struct.pack("<12Q",constants["COMMAND"],1,17,23,kind,digits,len(raw),0,0,0,0,0)
        def native(label,raw,kind,digits):
            s=buffer(raw);r=buffer(cmd(raw,kind,digits));w=buffer(size=constants["BASE"]);entries=[]
            for _ in range(8):
                returned,after,row=invoke(label,s,r,w);entries.append(row)
                event=struct.unpack_from("<16Q",after,256)
                assert event[0]==constants["EVENT"] and event[2:4]==(17,23) and event[10]==len(raw)
                assert event[13:]==(0,0,0)
                if returned==0xfffffffe:
                    assert event[1]==1 and event[11]>w[2]
                    w=buffer(after,size=event[11]);continue
                assert returned==128 and event[1] in (0,2)
                assert event[7]<=len(after) and event[8]<=len(after)-event[7]
                return event,after[event[7]:event[7]+event[8]],entries
            raise AssertionError("unexpected unbounded syntax GROW")
        all_cases=corpus()
        inventory=[dict(index=i,label=label,type=type(value).__name__,digits=digits) for i,(label,value,digits) in enumerate(all_cases)]
        save(out/"expected-inventory.json",inventory);summary["expected_cases"]=len(all_cases)
        for i,(label,value,digits) in enumerate(all_cases):
            old=sys.get_int_max_str_digits();sys.set_int_max_str_digits(digits)
            try:
                kind=1 if type(value) is str else 2 if type(value) is bytes else 0
                raw=value.encode("utf-8","surrogatepass") if kind==1 else value if kind==2 else b""
                prefix_ok=True
                try:_source(value)
                except HIAAssemblyRejected:prefix_ok=False
                try:
                    expected=_parse_assembly_document(value)
                    expect=dict(accepted=True,value=cas(json.dumps(expected,ensure_ascii=True,separators=(",",":")).encode()))
                except HIAAssemblyRejected as e:
                    expected=None;expect=dict(accepted=False,code=e.code,line=e.line,phase=e.phase,message=str(e))
                save(out/"cases"/(str(i).zfill(4)+".input.json"),dict(label=label,input=cas(raw),kind=kind,digits=digits,expected=expect))
                event,payload,entries=native(label,raw,kind,digits)
                assert bool(event[6])==prefix_ok,(label,"prefix",event,expect)
                if expected is not None:
                    assert event[1]==0 and event[4:6]==(0,0) and event[12]==0,(label,event,expect)
                    actual=json.loads(payload.decode("utf-8"))
                    actual_canonical=json.dumps(actual,ensure_ascii=True,separators=(",",":")).encode()
                    expected_canonical=json.dumps(expected,ensure_ascii=True,separators=(",",":")).encode()
                    assert actual_canonical==expected_canonical,(label,actual_canonical[:500],expected_canonical[:500])
                    checkrow=dict(accepted=True,ordered_value=cas(actual_canonical),constructed_json=cas(payload))
                else:
                    assert event[1]==2 and event[4]!=0 and event[5]==(expect["line"] or 0),(label,event,expect)
                    code="E_HIA_ASSEMBLY_LIMIT" if event[12] else "E_HIA_ASSEMBLY"
                    assert code==expect["code"] and payload.decode("utf-8")==expect["message"],(label,event,payload,expect)
                    checkrow=dict(accepted=False,code=code,message=payload.decode("utf-8"),line=event[5] or None)
                case_rows.append(dict(index=i,label=label,status="PASS",entries=len(entries),result=checkrow))
                save(out/"cases"/(str(i).zfill(4)+".result.json"),case_rows[-1])
                if i%25==0:print("HIA_ASSEMBLY_SYNTAX_PROGRESS "+json.dumps(dict(completed=i+1,total=len(all_cases),entries=native_entries)),flush=True)
            finally:sys.set_int_max_str_digits(old)
        raw=source_text().encode();good=cmd(raw);source=buffer(raw)
        def assert_bad(label,request,work=None):
            work=buffer(size=constants["BASE"]) if work is None else work
            request=buffer(request)
            result,after,row=invoke(label,source,request,work);assert result==0xfffffffd
            result2,after2,row2=invoke(label+"-persistent",source,buffer(good),work)
            assert result2==0xfffffffd
            controls.append(dict(label=label,status="PASS",entries=2))
        header=list(struct.unpack("<12Q",good))
        for field,value in [(0,0),(1,2),(2,0),(3,0),(4,3),(5,1),(6,len(raw)+1)]+[(i,1) for i in range(7,12)]:
            bad=header.copy();bad[field]=value;assert_bad("header-"+str(field),struct.pack("<12Q",*bad))
        for field,value in ((0,123),(8,1),(16,4)):
            workspace=bytearray(constants["BASE"]);struct.pack_into("<Q",workspace,0,constants["STATE"])
            struct.pack_into("<Q",workspace,field,value);assert_bad("state-"+str(field),good,buffer(workspace))
        # A terminal result cannot be reused, including a formerly semantic refusal.
        for label,wire in (("successful-terminal",raw),("semantic-terminal",b"bad")):
            src=buffer(wire);request=buffer(cmd(wire));work=buffer(size=constants["BASE"])
            for _ in range(8):
                result,after,row=invoke(label,src,request,work)
                if result==0xfffffffe:work=buffer(after,size=struct.unpack_from("<Q",after,344)[0]);continue
                assert result==128;break
            result,after,row=invoke(label+"-reuse",src,request,work);assert result==0xfffffffd
            result,after,row=invoke(label+"-poison",src,request,work);assert result==0xfffffffd
            controls.append(dict(label=label,status="PASS"))
        # Once the counting pass has copied the source, a same-length replacement
        # on the output GROW is rejected. Before that copy the fixed issuer must
        # retain the same immutable source; a header is never authentication.
        for change in ("source","header","needed","count"):
            src=buffer(raw);request=buffer(good);work=buffer(size=constants["BASE"])
            result,after,row=invoke("grow-"+change+"-first",src,request,work);assert result==0xfffffffe
            work=buffer(after,size=struct.unpack_from("<Q",after,344)[0])
            result,after,row=invoke("grow-"+change+"-count",src,request,work);assert result==0xfffffffe
            event=struct.unpack_from("<16Q",after,256);changed=bytearray(after)
            work=buffer(changed,size=event[11])
            if change=="source":src=buffer(b"X"+raw[1:])
            elif change=="header":
                altered=bytearray(good);struct.pack_into("<Q",altered,16,18);request=buffer(altered)
            elif change=="needed":ctypes.memmove(work[1]+constants["NEEDED"],struct.pack("<Q",0),8)
            else:ctypes.memmove(work[1]+constants["OUT_N"],struct.pack("<Q",0),8)
            result,after,row=invoke("grow-"+change+"-reject",src,request,work);assert result==0xfffffffd
            result,after,row=invoke("grow-"+change+"-persistent",source,buffer(good),work);assert result==0xfffffffd
            controls.append(dict(label="grow-"+change,status="PASS"))
        for length in (0,1,8,255,constants["BASE"]-1):
            work=buffer(size=length);result,after,row=invoke("short-work-"+str(length),source,buffer(good),work)
            assert result==0xfffffffd
            controls.append(dict(label="short-work-"+str(length),status="PASS",persistent_poison_claim=False,
                fixed_caller_must_discard_invalid_borrow=True))
        assert len(case_rows)==len(all_cases)
        summary.update(status="PASS",actual_cases=len(case_rows),actual_entries=native_entries,
            private_controls=len(controls),profile=profile,manifest=manifest,
            accepted=sum(r["result"]["accepted"] for r in case_rows),rejected=sum(not r["result"]["accepted"] for r in case_rows),
            ordered_object_bytes_compared=True,full_errors_compared=True,
            integer_value_budget_native=True,entire_original_syntax_inventory_preserved=True,
            source_image_before_after=all((len(p.read_bytes()),digest(p.read_bytes()))==v for p,v in pins.items()))
        assert summary["source_image_before_after"]
    except BaseException as e:
        summary.update(status="FAIL",error=dict(type=type(e).__name__,text=str(e),traceback=traceback.format_exc()),
            completed_cases=len(case_rows),actual_entries=native_entries,completed_controls=len(controls))
        raise
    finally:
        summary["elapsed_ns"]=time.monotonic_ns()-start
        save(out/"cases.json",case_rows);save(out/"controls.json",controls)
        save(out/"source-pins.json",[dict(path=str(p),bytes=n,sha256=h) for p,(n,h) in pins.items()])
        summary["cas_objects"]=len(list((out/"cas").glob("*.zlib"))) if (out/"cas").exists() else 0
        save(out/"summary.json",summary)
        print("HIA_ASSEMBLY_SYNTAX_SUMMARY "+json.dumps(summary,sort_keys=True),flush=True)
if __name__=="__main__":main()
