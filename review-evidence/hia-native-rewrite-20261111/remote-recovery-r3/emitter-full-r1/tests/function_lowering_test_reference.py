"""Real frame -> native lowering tape -> native Code issuer -> actual x64/finalizer.
Python owns only immutable development capture, memory transport, original oracle,
and complete raw evidence. No expected command or machine byte is fed to HIA.
"""
from pathlib import Path
from hashlib import sha256
import argparse,ast,copy,ctypes,importlib.util,itertools,json,os,resource,stat,struct,sys,time,traceback,types
sys.dont_write_bytecode=True
BAD=0xfffffffd
GROW=0xfffffffe
MASK=(1<<64)-1
MIN_TAPE=12288
RECORDS=12544
def magic(s):return int.from_bytes(s.encode("ascii"),"little")
TAPE_EVENT=magic("HIAFLE01")
TAPE=magic("HIAFLT01")
ISSUER_INPUT=magic("HIAFLC01")
ISSUER_EVENT=magic("HIAFLIE1")
RESULT=magic("HIAFLR01")
FRAME_HELPER_SHA="b3d590336e647df0804ef51c62b73ca2236abdfe8774161d4fd155cf0a5fbee6"
CODE_HELPER_SHA="61dbf40a99220f2f5b6db7950ee8e3a53299530d385fee70877ade6a0e387c11"
BUILD_SHA="01ca4abf3dde0e62787f26935f16a51243a2b0ec21fd72a1faa388f50a9170dd"
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+"\n")
def q(raw,at):return struct.unpack_from("<Q",raw,at)[0]
def replace_q(raw,at,value):
    result=bytearray(raw);struct.pack_into("<Q",result,at,value);return bytes(result)
def loaded(name,path,expected):
    raw=path.read_bytes();assert digest(raw)==expected,(str(path),digest(raw),expected)
    module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
    exec(compile(raw,str(path),"exec"),module.__dict__);return module,raw
F=None
X=None

class Actual:
    def __init__(self,bundle,reference,root,out):
        global F,X
        F,fr=loaded("function_frame_test_reference",root/"tests/function_frame_test_reference.py",FRAME_HELPER_SHA)
        X,xr=loaded("function_code_test_reference",root/"tests/function_code_test_reference.py",CODE_HELPER_SHA)
        builder,br=loaded("function_lower_build",root/"tools/build_hia_function_lowering.py",BUILD_SHA)
        self.root=root;self.reference=reference;self.out=out
        self.evidence=F.Evidence(out);self.buffers=F.Buffers();self.calls=0;self.sessions=0
        self.counts={name:0 for name in ("frame","tape","issuer","encoder","finalizer")}
        self.operations=set();self.errors=set();self.cases=[];self.private_controls=0;self.validated=0;self.pressure=0
        self.code_grows=0;self.issuer_grows=0;self.tape_grows=0;self.command_count=0;self.images={};self.closed=False
        self.covered_source_ops=set();self.covered_types=set();self.frame_rejections=0;self.tape_only_cases=0
        self.evidence.pin(__file__)
        self.evidence.pin(root/"tests/function_frame_test_reference.py",FRAME_HELPER_SHA)
        self.evidence.pin(root/"tests/function_code_test_reference.py",CODE_HELPER_SHA)
        self.evidence.pin(root/"tools/build_hia_function_lowering.py",BUILD_SHA)
        for path,h in builder.PINS.items():self.evidence.pin(root/path,h)
        frozen={p.resolve():self.evidence.pin(p) for prefix in ("hepta","tools")
                for p in sorted((reference/prefix).rglob("*.py"))}
        sys.meta_path.insert(0,builder.FrozenImports(reference,frozen))
        self.original=F.Original(self.evidence,root)
        oracle_path=root/"reference/hia_machine_x64.py"
        raw=self.evidence.pin(oracle_path,X.REFERENCE_SHA)
        self.oracle=types.ModuleType("function_lower_code_oracle");self.oracle.__file__=str(oracle_path)
        exec(compile(raw,str(oracle_path),"exec"),self.oracle.__dict__)
        doc=json.loads(self.evidence.pin(bundle));self.bundle=doc
        assert doc["schema"]=="hepta.hia.function-lowering-bundle.v1"
        assert doc["source_pins"]==builder.PINS and set(doc["components"])==set(self.counts)
        loader_path=reference/"hepta/hia_json_preflight_native.py"
        raw=self.evidence.pin(loader_path)
        loader=types.ModuleType("function_lower_native_loader");loader.__file__=str(loader_path)
        exec(compile(raw,str(loader_path),"exec"),loader.__dict__)
        try:
            for name,manifest in doc["components"].items():
                assert manifest["schema"]=="hepta.hia.function-lowering-development.v1"
                assert manifest["status"]=="BUILT_ONLY" and manifest["component"]==name
                source=self.evidence.pin(manifest["source_path"],manifest["source_sha256"])
                image=self.evidence.pin(manifest["image_path"],manifest["image_sha256"])
                assert len(source)==manifest["source_bytes"] and len(image)==manifest["image_bytes"]
                receipt=manifest["compile_receipt"]
                assert receipt["source_sha256"]==receipt["input_sha256"]==digest(source)
                assert receipt["produced_sha256"]==digest(image)
                assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
                assert receipt["runner_sha256"]==builder.PINS["reference/hia_selfhost_child.py"]
                self.images[name]=loader.NativeHiaJsonImage(image,expected_sha256=digest(image))
        except BaseException:
            for image in self.images.values():image._mapping.close()
            raise
    def entry(self,component,label,buffers,keys):
        n=self.calls;self.calls+=1;self.counts[component]+=1
        before=[self.evidence.memory(b,k) for b,k in zip(buffers,keys)]
        row=dict(number=n,component=component,label=label,status="ENTERING",before=before,
            capacities=[b["size"] for b in buffers],readonly=[b["readonly"] for b in buffers])
        self.evidence.entry(row);start=time.monotonic_ns()
        a,b,w=buffers
        returned=int(self.images[component]._entry(a["address"],a["size"],b["address"],b["size"],w["address"],w["size"]))
        elapsed=time.monotonic_ns()-start
        for item in buffers:self.buffers.check(item)
        after=[self.evidence.memory(b,k) for b,k in zip(buffers,keys)]
        for index,item in enumerate(buffers):
            if item["readonly"]:assert before[index]["sha256"]==after[index]["sha256"]
        event=struct.unpack("<16Q",ctypes.string_at(w["address"],128)) if w["size"]>=128 else None
        self.evidence.entry(dict(row,status="RETURNED",returned=returned,event=event,after=after,
            elapsed_ns=elapsed,canaries_intact=True))
        return returned,event
    def pure(self,component,label,source,second,capacity):
        a=b=w=None;events=[]
        try:
            a=self.buffers.allocate(len(source),source,True)
            b=self.buffers.allocate(len(second),second,True)
            w=self.buffers.allocate(capacity,b"\xa5"*capacity)
            for attempt in range(8):
                ret,event=self.entry(component,label,(a,b,w),(label+"-first",label+"-second",label+"-work"))
                events.append(dict(returned=ret,event=event))
                if ret==GROW:
                    needed=event[7] if component=="frame" else event[6]
                    assert event[2]==1 and needed>w["size"]
                    if component=="tape":self.tape_grows+=1
                    old=w;w=None;self.buffers.close(old)
                    w=self.buffers.allocate(needed,b"\xa5"*needed);continue
                raw=ctypes.string_at(w["address"],w["size"])
                return dict(returned=ret,event=event,workspace=raw,events=events)
            raise AssertionError(("pure GROW did not terminate",component,label))
        finally:
            for item in(w,b,a):self.buffers.close(item)
    def admit(self,document,plan):return F.Actual.admit(self,document,plan)
    def record(self,label,**values):
        row=dict(label=label,**values);self.cases.append(row);self.evidence.case(row);return row
    def close(self):
        if self.closed:return None
        self.closed=True;first=None
        for image in self.images.values():
            try:image._mapping.close()
            except BaseException as error:
                if first is None:first=error
                else:first.add_note(repr(error))
        try:answer=self.evidence.finish()
        except BaseException as error:
            if first is None:first=error
            else:first.add_note(repr(error))
        if first is not None:raise first
        return answer

class TraceCode:
    def __init__(self,code,parent):
        self.code=code;self.parent=parent;self.trace=[];self.offset_values=[];self.command_offsets=[]
    @property
    def data(self):
        self.trace.append(("offset",(),self.parent.serial))
        self.offset_values.append(len(self.code.data));self.command_offsets.append(len(self.code.data))
        return self.code.data
    def __getattr__(self,name):
        value=getattr(self.code,name)
        if not callable(value):return value
        def call(*args,**kwargs):
            assert not kwargs,(name,kwargs)
            effective=args
            if name in("load","lea","load_u8") and len(args)==2:effective=args+(0,)
            self.trace.append((name,effective,self.parent.serial))
            self.command_offsets.append(len(self.code.data))
            return value(*args)
        return call

def tape_trace(raw):
    e=struct.unpack_from("<16Q",raw);assert e[:3]==(TAPE_EVENT,1,0) and e[7]==MIN_TAPE
    header=struct.unpack_from("<32Q",raw,MIN_TAPE)
    assert header[:2]==(TAPE,1) and header[18:]==(0,)*14
    assert header[5]==e[9] and header[6]==RECORDS and header[9]==e[6]
    assert header[7]==RECORDS+header[5]*128 and header[8]==header[9]-header[7]
    assert header[9]<=len(raw) and e[8]==header[9]-MIN_TAPE
    assert raw[header[12]:header[12]+header[13]].decode("ascii")
    trace=[];effects=[]
    for index in range(header[5]):
        row=struct.unpack_from("<16Q",raw,RECORDS+index*128)
        code,argc,serial,effect=row[:4]
        assert 2<=code<=44 and code!=3 and 0<=argc<=3
        args=[]
        for i in range(argc):
            kind,value,size=row[4+3*i:7+3*i]
            if kind==2:
                assert header[7]<=value<=header[9] and size<=header[9]-value
                args.append(raw[value:value+size].decode("ascii"))
            else:
                assert kind in(0,1) and size==0 and (kind==0 or value!=0)
                args.append(-value if kind else value)
        assert row[4+3*argc:]==(0,)*(12-3*argc)
        trace.append((X.OPERATIONS[code],tuple(args),serial));effects.append(effect)
    assert effects[0]==1 and effects[-1]==3 and all(v in(0,2) for v in effects[1:-1])
    return header,trace,effects

class Issued:
    def __init__(self,actual,label,tape,code,capacity=8192):
        self.actual,self.label,self.code=actual,label,code
        self.raw=tape;self.header,self.trace,self.effects=tape_trace(tape)
        self.source=actual.buffers.allocate(len(tape),tape,True)
        self.work=actual.buffers.allocate(capacity)
        self.control_seq=1;self.lease=code.lease+50000;self.request=actual.sessions+1
        self.commands=[];self.events=[];self.pending=None;self.pending_sequence=None
        self.last_code_return=128;self.closed=False
    def config(self,kind,code_seq=None,returned=None):
        h=self.header
        return struct.pack("<16Q",ISSUER_INPUT,1,self.lease,self.request,self.control_seq,kind,
            self.code.lease,self.code.seq if code_seq is None else code_seq,
            h[2],h[3],h[4],h[9],self.code.code["size"],
            self.last_code_return if returned is None else returned,0,0)
    def entry(self,kind,raw_config=None,peer=None):
        cfg=self.config(kind) if raw_config is None else raw_config
        assert len(cfg)==128 and self.work["size"]>=256
        ctypes.memmove(self.work["address"]+128,cfg,128)
        r=self.code.work if peer is None else peer
        old_readonly=r["readonly"];F.protect(self.actual.buffers,r,True)
        try:
            return self.actual.entry("issuer",self.label,(self.source,r,self.work),
                (self.label+"-tape",self.code.prefix+"-work",self.label+"-issuer"))
        finally:F.protect(self.actual.buffers,r,old_readonly)
    def raw_work(self):return ctypes.string_at(self.work["address"],self.work["size"])
    def grow_own(self,size):
        assert size>self.work["size"]
        old=self.work;new=self.actual.buffers.allocate(size)
        try:ctypes.memmove(new["address"],old["address"],old["size"])
        except BaseException:self.actual.buffers.close(new);raise
        self.work=new;self.actual.buffers.close(old);self.actual.issuer_grows+=1
    def step(self,kind,code_seq=None,returned=None):
        cfg=self.config(kind,code_seq,returned)
        for _ in range(4):
            before=self.raw_work()[256:448]
            ret,event=self.entry(kind,cfg);self.events.append(dict(returned=ret,event=event))
            assert event[:2]==(ISSUER_EVENT,1) and event[3:6]==(self.lease,self.request,self.control_seq)
            if event[2]==4:
                assert ret==GROW and event[13]>self.work["size"] and event[15]==0
                assert self.raw_work()[256:448]==before
                self.grow_own(event[13]);continue
            assert ret==128 and event[2] in(0,1,2,5) and event[15]==0,(self.label,ret,event)
            self.control_seq+=1
            return event
        raise AssertionError("issuer own GROW did not terminate")
    def run(self):
        event=self.step(1)
        for _ in range(self.header[5]*8+64):
            action=event[2]
            if action in(0,2):
                at,n=event[11:13];assert at>=4096 and at<=self.work["size"] and n<=self.work["size"]-at
                payload=ctypes.string_at(self.work["address"]+at,n)
                return dict(event=event,payload=payload,commands=self.commands,issuer_workspace=self.raw_work())
            assert action in(1,5)
            if action==1:
                at,n=event[11:13];assert at==4096 and n<=self.work["size"]-at
                raw=ctypes.string_at(self.work["address"]+at,n)
                command=struct.unpack_from("<8Q",raw)
                assert command[:2]==(X.COMMAND,1) and command[2:4]==(self.code.lease,self.code.seq+1)
                assert command[5]==len(raw)-64 and command[7]==0
                graph=F.Graph(raw[64:]);args=graph.value(command[6])
                assert type(args)is list
                observed=(X.OPERATIONS[command[4]],tuple(args),event[10])
                assert observed==self.trace[event[9]],(self.label,observed,self.trace[event[9]])
                self.commands.append(observed);self.actual.command_count+=1
                self.actual.operations.add(command[4])
                if self.pending is not None:self.actual.buffers.close(self.pending)
                self.pending=self.actual.buffers.allocate(len(raw),raw,True)
                self.pending_sequence=command[3]
            else:
                assert self.pending is not None and event[8]==self.pending_sequence
                assert event[11:13]==(4096,self.pending["size"])
                assert ctypes.string_at(self.work["address"]+4096,event[12])==ctypes.string_at(self.pending["address"],self.pending["size"])
                assert event[13]>self.code.code["size"] or event[14]>self.code.work["size"]
                for name,need in(("code",event[13]),("work",event[14])):
                    old=getattr(self.code,name)["size"]
                    if need>old:self.code.replace(name,max(need,old*2,64 if name=="code" else 4096))
                self.actual.code_grows+=1
            old_code=ctypes.string_at(self.code.code["address"],self.code.code["size"])
            old_state=ctypes.string_at(self.code.work["address"]+128,160)
            ret,code_event=self.actual.entry("encoder",self.label,(self.pending,self.code.code,self.code.work),
                (self.label+"-native-command",self.code.prefix+"-code",self.code.prefix+"-work"))
            assert code_event[:2]==(X.EVENT,1) and code_event[3:5]==(self.code.lease,self.pending_sequence)
            assert code_event[5]==q(ctypes.string_at(self.pending["address"],64),32)
            if ret==GROW:
                assert code_event[2]==1
                assert ctypes.string_at(self.code.code["address"],self.code.code["size"])==old_code
                assert ctypes.string_at(self.code.work["address"]+128,160)==old_state
            else:
                assert ret==128 and code_event[2] in(0,2) and code_event[15]==0,(ret,code_event)
                self.code.seq+=1;assert self.code.seq==self.pending_sequence
            self.last_code_return=ret
            event=self.step(2,self.pending_sequence,ret)
        raise AssertionError("finite native command continuation did not terminate")
    def close(self):
        if self.closed:return
        self.closed=True;first=None
        for buffer in(self.pending,self.work,self.source):
            try:self.actual.buffers.close(buffer)
            except BaseException as error:
                if first is None:first=error
                else:first.add_note(repr(error))
        if first is not None:raise first

def exact_function(actual,label,document,plan=None,index=0,serial=0,prefix=0,tape_only=False):
    doc,plan=actual.admit(document,plan)
    for b in doc["functions"][index]["blocks"]:
        actual.covered_source_ops.update(op["op"] for op in b["ops"])
        actual.covered_types.update(p["type"] for p in b["params"])
        actual.covered_types.update(o["type"] for op in b["ops"] for o in op["out"])
    graph=F.capture([doc,plan],17)
    frame_command=struct.pack("<12Q",F.COMMAND,1,17,1,index,serial,q(graph,24),0,0,0,0,0)
    code=X.Session(actual);issued=None
    from hepta.hia_machine_plan import code_options
    options=code_options(plan);oracle=actual.oracle.Code(**options)
    start=actual.calls
    try:
        init=code.command(0,(options.get("scratch_registers"),options.get("move_immediate","movabs"),
                    options.get("alu_immediate","imm32")),label+"-init")
        assert init["error"] is None
        if prefix:
            raw=b"\x90"*prefix
            assert code.command(3,(raw,),label+"-seed-real-code")["error"] is None
            oracle.emit(raw);del raw
        elif not tape_only:
            old=code.code;new=actual.buffers.allocate(64,ctypes.string_at(old["address"],64))
            code.code=new;actual.buffers.close(old)
        code.compare_state(oracle)
        parent,fn,constructor_error=actual.original.construct(doc,plan,index,serial)
        f=actual.pure("frame",label+"-frame",graph,frame_command,4096)
        fe=f["event"];assert f["returned"]==128 and fe[:2]==(F.EVENT,1)
        assert fe[3:6]==(17,1,index) and fe[15]==0
        if constructor_error is not None:
            assert fe[2]==2 and fe[6]==1 and fe[11]==serial
            raw=f["workspace"];at,n=fe[12:14]
            assert raw[at:at+n].decode("utf-8")==constructor_error
            assert parent.serial==serial
            code.compare_state(oracle);actual.frame_rejections+=1
            return actual.record(label,status="PASS",kind="FRAME_SEMANTIC_REFUSAL",error=constructor_error,
                code_unchanged=True,entries=actual.calls-start)
        assert fe[2]==0 and fe[10:12]==(fn.frame,parent.serial)
        trace=TraceCode(oracle,parent);parent.c=trace;fn.c=trace
        error=None;domain=0
        try:fn.render()
        except actual.oracle.MachineEncodingError as exc:error=str(exc);domain=1
        except actual.original.module.HIAProgramNativeRejected as exc:error=str(exc);domain=2
        t=actual.pure("tape",label+"-tape",graph,f["workspace"],MIN_TAPE)
        assert t["returned"]==128 and t["event"][:3]==(TAPE_EVENT,1,0),t["event"]
        th,planned,effects=tape_trace(t["workspace"])
        assert effects.count(2)==len(doc["functions"][index]["blocks"])
        assert planned[:len(trace.trace)]==trace.trace,(label,planned,trace.trace)
        if error is None:
            assert len(planned)==len(trace.trace) and th[11]==parent.serial
        trace_record=actual.evidence.raw(json.dumps(dict(original_trace=trace.trace,native_trace=planned,
            effects=effects,error=error,domain=domain),ensure_ascii=True,separators=(",",":")).encode())
        if tape_only:
            assert error is None
            actual.tape_only_cases+=1
            return actual.record(label,status="PASS",kind="COMPLETE_TAPE_ONLY",native_commands=len(planned),
                blocks=len(doc["functions"][index]["blocks"]),entries=actual.calls-start,
                original_full_Function_trace_equal=True,actual_Code_ack_chain_not_run_for_this_case=True,full_trace=trace_record)
        issued=Issued(actual,label+"-issued",t["workspace"],code)
        answer=issued.run();ie=answer["event"]
        assert answer["commands"]==trace.trace,(label,"actual-command-prefix",answer["commands"],trace.trace)
        assert ie[10]==parent.serial,(label,ie,parent.serial)
        state=code.compare_state(oracle)
        if error is not None:
            assert ie[2]==2 and ie[13]==domain and answer["payload"].decode("utf-8")==error,(label,ie,answer["payload"],error)
            assert not parent.symbols and not parent.frames
        else:
            assert ie[2]==0
            raw=answer["issuer_workspace"];h=struct.unpack_from("<32Q",answer["payload"])
            assert h[:2]==(RESULT,1) and h[2:5]==(issued.lease,issued.request,index)
            assert h[5:7]==(code.lease,code.seq) and h[7:9]==(prefix,len(oracle.data))
            assert h[9:11]==(fn.frame,parent.serial) and h[16:]==(0,)*16
            assert h[15]==len(answer["payload"])
            assert raw[h[11]:h[11]+h[12]].decode("ascii")==doc["functions"][index]["name"]
            name=raw[h[13]:h[13]+h[14]].decode("ascii")
            assert parent.symbols==[{"name":name,"offset":h[7],"size":h[8]-h[7],"global":False}]
            assert parent.frames==[(doc["functions"][index]["name"],h[9])]
            expected=oracle.finalize()
            final=code.finalize(label+"-actual-finalizer")
            assert final["error"] is None and final["value"]==expected
            state=code.compare_state(oracle)
        return actual.record(label,status="PASS",kind="ACTUAL_NATIVE_FUNCTION_CHAIN",error=error,error_domain=domain,
            native_commands=len(answer["commands"]),frame=fn.frame,serial=parent.serial,entries=actual.calls-start,
            code_state=state,complete_command_prefix_equal=True,complete_machine_bytes_equal=True,
            complete_labels_fixups_relocations_equal=True,original_Function_symbol_and_frame_equal=error is None,
            finalizer_equal=error is None,full_trace=trace_record)
    finally:
        first=None
        for obj in (issued,code):
            if obj is None:continue
            try:obj.close()
            except BaseException as exc:
                if first is None:first=exc
                else:first.add_note(repr(exc))
        if first is not None:raise first

INT_TYPES=("i8","u8","i16","u16","i32","u32","i64","u64","isize","usize")
SCALAR_TYPES=INT_TYPES+("bool","unit")
def p(name,typ):return dict(name=name,type=typ)
def ins(op,args,out,attrs=None):return dict(op=op,args=args,out=out,attrs={} if attrs is None else attrs)
def fn(name,params=(),ops=(),returns=(),term=None,effects=(),blocks=None):
    params=list(params);ops=list(ops)
    term=dict(op="ret",values=[]) if term is None else term
    blocks=[dict(id="entry",params=params,ops=ops,term=term)] if blocks is None else blocks
    return dict(name=name,params=params,returns=list(returns),effects=list(effects),
                entry=blocks[0]["id"],blocks=blocks)
def doc(*functions):
    return dict(schema="hepta.hia.program.v8",module="native_function_lowering",functions=list(functions))
def scalar_case(op,types_,result,attrs=None):
    params=[p("p"+str(i),t) for i,t in enumerate(types_)]
    return doc(fn(op.replace(".","_"),params,[ins(op,[v["name"] for v in params],[p("v",result)],attrs)],
        [result],dict(op="ret",values=["v"]),["trap"]))
def all_effect_case(name,params,operations):
    return doc(fn(name,params,operations,term=dict(op="trap",code="user"),effects=["alloc","read","trap","write"]))
def smoke(actual):
    class Adapter:
        def compare(self,label,document,plan=None,**kw):
            return exact_function(actual,"smoke-"+label,document,plan,**kw)
    F.smoke(Adapter())
    assert len(actual.cases)==25

def scalar_group(actual,variant):
    typ=INT_TYPES[variant]
    operations=[f"int.{action}.{mode}" for action in("add","sub","mul") for mode in("checked","wrap")]
    operations += [f"int.{action}.checked" for action in("div","rem","shl","shr")]
    operations += ["bit."+name for name in("and","or","xor")]
    operations += ["compare."+name for name in("eq","ne","lt","le","gt","ge")]
    operations += ["bit.not","int.neg.checked"]
    for name in operations:
        args=[typ] if name in("bit.not","int.neg.checked") else [typ,typ]
        result="bool" if name.startswith("compare.") else typ
        exact_function(actual,name+"-"+typ,scalar_case(name,args,result),serial=100+variant)
    bits=64 if typ in("isize","usize") else int(typ[1:])
    lo=-(1<<(bits-1)) if typ.startswith("i") else 0
    hi=(1<<(bits-1))-1 if typ.startswith("i") else (1<<bits)-1
    for i,value in enumerate((lo,0,hi)):
        exact_function(actual,"const-"+typ+"-"+str(i),scalar_case("const",[],typ,dict(value=value)))
    assert len(actual.cases)==24

def cast_group(actual,variant):
    source=INT_TYPES[variant]
    for target in INT_TYPES:
        for mode in ("checked","wrap"):
            exact_function(actual,"cast-"+source+"-"+target+"-"+mode,
                scalar_case("int.cast",[source],target,dict(mode=mode)),serial=999)
    assert len(actual.cases)==20

def boolean_select_group(actual):
    for name in ("bool.not","bool.and","bool.or","compare.eq","compare.ne"):
        args=["bool"] if name=="bool.not" else ["bool","bool"]
        exact_function(actual,name,scalar_case(name,args,"bool"))
    for value in (False,True):
        exact_function(actual,"boolean-"+str(value),scalar_case("const",[],"bool",dict(value=value)))
    exact_function(actual,"unit-constant",scalar_case("const",[],"unit",dict(value=None)))
    for typ in SCALAR_TYPES:
        d=scalar_case("select",["bool",typ,typ],typ)
        for selection in("branch","cmov_scalar"):
            plan=F.machine_plan(d,select=selection)
            exact_function(actual,"select-"+typ+"-"+selection,d,plan,serial=99999)
    assert len(actual.cases)==32

def resource_group(actual):
    shapes=[
        ("buffer.new",["usize"],["buffer"]),
        ("buffer.try_new",["usize"],["buffer","bool"]),
        ("buffer.len",["buffer"],["usize"]),
        ("buffer.len",["readbuf"],["usize"]),
        ("buffer.len",["mutbuf"],["usize"]),
        ("borrow.read",["buffer"],["readbuf"]),
        ("borrow.read",["readbuf"],["readbuf"]),
        ("borrow.read",["mutbuf"],["readbuf"]),
        ("borrow.mut",["buffer"],["mutbuf"]),
        ("borrow.mut",["mutbuf"],["mutbuf"]),
        ("owner.move",["buffer"],["buffer"]),
        ("owner.move",["chain"],["chain"]),
        ("owner.drop",["buffer"],[]),
        ("owner.drop",["chain"],[]),
        ("buffer.load",["readbuf","usize"],["u8"]),
        ("buffer.store",["mutbuf","usize","u8"],[]),
        ("buffer.fill",["mutbuf","u8"],[]),
        ("buffer.copy",["mutbuf","readbuf","usize"],[]),
        ("buffer.move_within",["mutbuf","usize","usize","usize"],[]),
        ("buffer.swap",["mutbuf","usize","usize"],[]),
        ("buffer.copy_range",["mutbuf","readbuf","usize","usize","usize"],[]),
        ("buffer.fill_range",["mutbuf","usize","usize","u8"],[]),
        ("chain.empty",[],["chain"]),
        ("chain.try_push",["chain","buffer"],["chain","buffer","bool"]),
        ("chain.pop",["chain"],["chain","buffer","bool"]),
        ("chain.is_empty",["chain"],["bool"]),
        ("chain.head_read",["chain"],["readbuf"]),
        ("chain.head_mut",["chain"],["mutbuf"]),
    ]
    for index,(name,args,outs) in enumerate(shapes):
        params=[p("p"+str(i),t) for i,t in enumerate(args)]
        outputs=[p("v"+str(i),t) for i,t in enumerate(outs)]
        program=all_effect_case("resource_"+str(index),params,[ins(name,[v["name"] for v in params],outputs)])
        exact_function(actual,name+"-"+str(index),program,serial=37)
    for borrow,typ in (("borrow.read","readbuf"),("borrow.mut","mutbuf")):
        program=all_effect_case("end_loan_"+typ,[p("owner","buffer")],
            [ins(borrow,["owner"],[p("view",typ)]),ins("loan.end",["view"],[])])
        exact_function(actual,"loan-end-"+typ,program,serial=37)
    assert len(actual.cases)==30

def edge_group(actual):
    class Adapter:
        def compare(self,label,document,plan=None,**kw):
            return exact_function(actual,"edges-"+label,document,plan,**kw)
    F.edges_and_registers(Adapter())
    assert len(actual.cases)==21

def call_group(actual):
    for index,types_ in enumerate(([],["u64"],["readbuf","mutbuf","u64"],["u64","bool","i8","readbuf","mutbuf"])):
        params=[p("p"+str(i),t) for i,t in enumerate(types_)]
        callee=fn("callee",params,[ins("const",[],[p("a","u64")],dict(value=7)),
            ins("const",[],[p("b","u32")],dict(value=3))],["u64","u32"],dict(op="ret",values=["a","b"]))
        caller=fn("caller",params,[ins("call",[v["name"] for v in params],[p("x","u64"),p("y","u32")],
            dict(function="callee"))],["u64","u32"],dict(op="ret",values=["x","y"]))
        program=doc(callee,caller)
        exact_function(actual,"call-"+str(index),program,index=1,serial=19)
        plan=F.machine_plan(program,registers={"caller":{"x":"rbx","y":"r15"}})
        exact_function(actual,"call-regs-"+str(index),program,plan,index=1,serial=25)
    for typ in ("buffer","chain","readbuf","mutbuf"):
        callee=fn("resource_identity",[p("item",typ)],[],[typ],dict(op="ret",values=["item"]))
        if typ in("readbuf","mutbuf"):callee["return_loans"]=["item"]
        caller=all_effect_case("caller",[p("a",typ)],[ins("call",["a"],[p("x",typ)],dict(function="resource_identity"))])["functions"][0]
        program=doc(callee,caller)
        exact_function(actual,"call-resource-"+typ,program,index=1,serial=99)
    assert len(actual.cases)==12

def code_selection_group(actual):
    params=[p("a","u64"),p("b","u64"),p("condition","bool")]
    body=[ins("const",[],[p("small","u64")],dict(value=7)),
          ins("const",[],[p("large","u64")],dict(value=(1<<63)+7)),
          ins("int.add.wrap",["a","small"],[p("sum","u64")]),
          ins("select",["condition","sum","large"],[p("result","u64")])]
    program=doc(fn("selection",params,body,["u64"],dict(op="ret",values=["result"])))
    count=0
    for swap,move,alu,select in itertools.product((False,True),("movabs","mov32_if_exact"),
            ("imm32","imm8_if_exact"),("branch","cmov_scalar")):
        plan=F.machine_plan(program,select=select)
        plan["scratch_registers"]={"r10":"r11" if swap else "r10","r11":"r10" if swap else "r11"}
        plan["instruction_selection"]["move_immediate"]=move
        plan["instruction_selection"]["alu_immediate"]=alu
        exact_function(actual,"selection-"+str(count),program,plan,serial=count*100)
        count+=1
    assert len(actual.cases)==16

def inventory_group(actual,variant):
    if variant==0:
        program=doc(*(fn("f"+str(i)) for i in range(1024)))
        exact_function(actual,"full-1024-function-index",program,index=1023,serial=1)
    elif variant in(1,3):
        count=4096 if variant==1 else 129
        blocks=[]
        for index in range(count):
            term=dict(op="jump",target="b"+str(index+1),args=[]) if index+1<count else dict(op="ret",values=[])
            blocks.append(dict(id="b"+str(index),params=[],ops=[],term=term))
        program=doc(fn("full_blocks",blocks=blocks))
        exact_function(actual,"blocks-"+str(count),program,tape_only=variant==1)
    else:
        count=8184 if variant==2 else 8185
        program=doc(fn("frame_boundary",ops=[ins("const",[],[p("v"+str(i),"u64")],dict(value=i))
            for i in range(count)]))
        exact_function(actual,"frame-"+str(count),program,tape_only=variant==2)
    assert len(actual.cases)==1

def budget_group(actual,variant):
    if variant==3:
        program=scalar_case("int.add.checked",["u64","u64"],"u64")
    elif variant==4:
        program=all_effect_case("allocate",[p("size","usize")],
            [ins("buffer.new",["size"],[p("value","buffer")])])
    else:program=doc(fn("budget"))
    checked,plan=actual.admit(program,None)
    parent,fun,error=actual.original.construct(checked,plan,0,19);assert error is None
    code=actual.oracle.Code();trace=TraceCode(code,parent);fun.c=trace;parent.c=trace;fun.render()
    if variant in(0,1):
        prefix=(16<<20)-trace.offset_values[1]+variant
    elif variant==5:
        prefix=(16<<20)-len(code.data)
    else:
        name={2:"jmp",3:"jcc",4:"call"}[variant]
        index=next(i for i,entry in enumerate(trace.trace) if entry[0]==name)
        opcode_width=2 if name=="jcc" else 1
        prefix=(64<<20)-trace.command_offsets[index]-opcode_width
    row=exact_function(actual,"actual-prefix-budget-"+str(variant),program,serial=19,prefix=prefix)
    if variant in(0,5):
        assert row["error"] is None
        expected=(16<<20)+7 if variant==0 else (16<<20)
        assert row["code_state"]["code_bytes"]==expected
    elif variant==1:
        assert row["error_domain"]==2 and row["error"]=="E_HIA_PROGRAM_LIMIT: direct code exceeds the 16 MiB text budget"
    else:
        assert row["error_domain"]==1 and row["error"]=="x86-64 image exceeds code byte limit"
        assert row["code_state"]["code_bytes"]==64<<20
        if variant in(2,3):assert row["code_state"]["fixups"]>=1
        else:assert row["code_state"]["relocations"]>=1
    assert len(actual.cases)==1

def protocol_assets(actual):
    program=doc(fn("private",params=[p("x","u64")],returns=["u64"],term=dict(op="ret",values=["x"])))
    checked,plan=actual.admit(program,None)
    graph=F.capture([checked,plan],17)
    command=struct.pack("<12Q",F.COMMAND,1,17,1,0,0,q(graph,24),0,0,0,0,0)
    frame=actual.pure("frame","protocol-source-frame",graph,command,4096)
    assert frame["returned"]==128 and frame["event"][2]==0
    tape=actual.pure("tape","protocol-source-tape",graph,frame["workspace"],MIN_TAPE)
    assert tape["returned"]==128 and tape["event"][2]==0
    return graph,frame["workspace"],tape["workspace"]

def tape_protocol(actual):
    graph,frame,tape=protocol_assets(actual);counter=0
    def bad(label,a=graph,b=frame,capacity=MIN_TAPE):
        nonlocal counter
        result=actual.pure("tape","bad-tape-"+label,a,b,capacity)
        assert result["returned"]==BAD,(label,result["returned"],result["event"])
        if capacity>=MIN_TAPE:
            assert result["event"][:3]==(TAPE_EVENT,1,3) and result["event"][15]!=0
        counter+=1;actual.private_controls+=1
        actual.record("bad-tape-"+label,status="PASS",kind="PRIVATE_ABI_REJECTION",
            source=actual.evidence.raw(a),frame=actual.evidence.raw(b),capacity=capacity)
    for n in(0,1,63,127):bad("graph-short-"+str(n),a=graph[:n])
    for n in(0,127,4095,4607):bad("frame-short-"+str(n),b=frame[:n])
    for n in(0,1,127,4096,MIN_TAPE-1):bad("work-short-"+str(n),capacity=n)
    changes=[
        (0,0),(8,2),(16,1),(24,18),(32,0),(48,1),(56,len(frame)+1),(56,4096),
        (64,0),(72,q(frame,72)+8),(80,65552),(88,q(frame,88)+1),(96,1),(104,1),
        (112,0),(120,1),(4096,0),(4104,2),(4112,18),(4120,2),(4128,1),
        (4136,0),(4144,0),(4152,0),(4168,MASK),(4176,0),(4184,2),
        (4240,4607),(4296,0),(4296,3),(4392,6),(4424,len(frame)+1),
        (4432,0),(4440,q(frame,4440)+1),(4448,len(graph)+1),(4456,0),(4488,1),
    ]
    for index,(at,value) in enumerate(changes):bad("frame-field-"+str(index),b=replace_q(frame,at,value))
    for index,(at,value) in enumerate(((0,0),(8,0),(16,0),(24,0),(32,MASK),(40,0),(48,len(graph)-1),(56,1))):
        bad("graph-field-"+str(index),a=replace_q(graph,at,value))
    # A new invocation is a new private pure input. No header authenticates it.
    baseline=actual.pure("tape","repeat-same-issued-input",graph,frame,len(tape))
    assert baseline["returned"]==128 and baseline["workspace"]==tape
    actual.record("pure-repetition",status="PASS",kind="PURE_SAME_INPUT",complete_workspace_equal=True)
    assert counter==13+len(changes)+8

def make_code(actual,label):
    session=X.Session(actual)
    answer=session.command(0,(None,"movabs","imm32"),label+"-actual-init")
    assert answer["error"] is None
    return session

def one_code_command(actual,issued,event):
    assert event[2]==1
    raw=ctypes.string_at(issued.work["address"]+event[11],event[12])
    source=actual.buffers.allocate(len(raw),raw,True)
    try:
        for _ in range(8):
            ret,reply=actual.entry("encoder",issued.label+"-control",(source,issued.code.code,issued.code.work),
                (issued.label+"-native-command",issued.code.prefix+"-code",issued.code.prefix+"-work"))
            if ret==GROW:
                # This preparation helper keeps the same actual pending packet.
                # The full semantic corpus separately sends every GROW to issuer.
                assert reply[2]==1
                for name,need in(("code",reply[7]),("work",reply[8])):
                    old=getattr(issued.code,name)["size"]
                    if need>old:issued.code.replace(name,max(need,old*2,64 if name=="code" else 4096))
                continue
            assert ret==128 and reply[2]==0 and reply[3:5]==(issued.code.lease,issued.code.seq+1)
            issued.code.seq+=1;issued.last_code_return=ret
            return ret,reply
        raise AssertionError("private fixture actual Code GROW did not terminate")
    finally:actual.buffers.close(source)

def issuer_protocol(actual):
    graph,frame,tape=protocol_assets(actual);counter=0
    config_cases=[
        (0,0),(8,2),(16,0),(24,0),(32,0),(32,2),(40,0),(40,3),
        (48,0),(56,0),(64,0),(72,0),(80,1),(88,len(tape)+1),(96,0),
        (96,63),(104,BAD),(112,1),(120,1),
    ]
    def initial_bad(label,config_change=None,tape_change=None,state_change=None):
        nonlocal counter
        code=make_code(actual,label);issued=None
        try:
            issued=Issued(actual,label,tape,code)
            if tape_change is not None:
                old=issued.source
                issued.source=actual.buffers.allocate(len(tape_change),tape_change,True);actual.buffers.close(old)
            cfg=issued.config(1)
            if config_change is not None:cfg=replace_q(cfg,*config_change)
            if state_change is not None:
                at,value=state_change
                ctypes.memmove(issued.work["address"]+at,struct.pack("<Q",value),8)
            ret,event=issued.entry(1,cfg)
            assert ret==BAD and event[:3]==(ISSUER_EVENT,1,3) and event[15]!=0,(label,ret,event)
            assert q(issued.raw_work(),440)==1
            ret2,event2=issued.entry(1,issued.config(1))
            assert ret2==BAD and event2[2]==3 and event2[15]!=0
            actual.private_controls+=1;counter+=1
            actual.record(label,status="PASS",kind="ISSUER_PRIVATE_INITIAL_BAD",permanent_poison=True)
        finally:
            try:
                if issued is not None:issued.close()
            finally:code.close()
    for index,change in enumerate(config_cases):
        initial_bad("issuer-config-"+str(index),config_change=change)
    for at in(256,280,432,440):
        initial_bad("issuer-nonzero-state-"+str(at),state_change=(at,1))
    mutations=[(0,0),(8,2),(16,1),(24,18),(32,2),(40,1),(48,len(tape)+1),(56,0),
        (64,0),(72,0),(80,0),(96,1),(120,1),(MIN_TAPE,0),(MIN_TAPE+8,2),
        (MIN_TAPE+40,0),(MIN_TAPE+48,0),(MIN_TAPE+56,0),(MIN_TAPE+64,0),
        (MIN_TAPE+72,0),(MIN_TAPE+80,0),(MIN_TAPE+96,0),(MIN_TAPE+144,1),
        (RECORDS,3),(RECORDS+8,1),(RECORDS+16,0),(RECORDS+24,0),(RECORDS+32,1)]
    for index,(at,value) in enumerate(mutations):
        initial_bad("issuer-tape-"+str(index),tape_change=replace_q(tape,at,value))
    # Each mutated ACK starts from an actually executed initialized Code and an
    # actual outstanding native packet. Only the copied private ACK is corrupted.
    ack_fields=[(0,0),(8,2),(16,3),(24,0),(32,0),(40,0),(48,1),
        (56,1<<40),(64,1<<40),(72,1<<40),(104,1),(112,1),(120,1)]
    for index,change in enumerate(ack_fields):
        code=make_code(actual,"ack-"+str(index));issued=peer=None
        try:
            issued=Issued(actual,"ack-"+str(index),tape,code)
            event=issued.step(1);one_code_command(actual,issued,event)
            original=ctypes.string_at(code.work["address"],code.work["size"])
            changed=replace_q(original,*change);peer=actual.buffers.allocate(len(changed),changed,True)
            ret,answer=issued.entry(2,issued.config(2),peer)
            assert ret==BAD and answer[2]==3 and answer[15]!=0,(index,ret,answer)
            ret2,answer2=issued.entry(2,issued.config(2))
            assert ret2==BAD and answer2[2]==3
            actual.private_controls+=1;counter+=1
            actual.record("issuer-ack-"+str(index),status="PASS",kind="ISSUER_PRIVATE_ACK_BAD",
                actual_origin_sha256=digest(original),mutated_ack=actual.evidence.raw(changed),permanent_poison=True)
        finally:
            try:
                actual.buffers.close(peer)
                if issued is not None:issued.close()
            finally:code.close()
    # A too-short workspace cannot publish a complete event. It poisons only
    # when the fixed persistent poison word is physically present; the driver
    # discards every BAD lease regardless of that in-buffer persistence.
    for capacity in (0,127,255,511,512,8191):
        code=make_code(actual,"issuer-short-"+str(capacity));source=work=None
        try:
            source=actual.buffers.allocate(len(tape),tape,True)
            work=actual.buffers.allocate(capacity)
            old_readonly=code.work["readonly"];F.protect(actual.buffers,code.work,True)
            try:
                ret,event=actual.entry("issuer","issuer-short-"+str(capacity),(source,code.work,work),
                    ("short-tape-"+str(capacity),code.prefix+"-work","short-issuer-"+str(capacity)))
            finally:F.protect(actual.buffers,code.work,old_readonly)
            assert ret==BAD
            if capacity>=512:assert q(ctypes.string_at(work["address"],capacity),440)==1
            actual.private_controls+=1;counter+=1
            actual.record("issuer-short-"+str(capacity),status="PASS",kind="ISSUER_PRIVATE_SHORT_WORK",
                capacity=capacity,in_buffer_poison_available=capacity>=512,caller_discards_BAD_lease=True)
        finally:
            try:
                actual.buffers.close(work);actual.buffers.close(source)
            finally:code.close()
    # A protocol-only enlarged ASCII operand exercises issuer GROW before an ACK
    # is consumed. It is explicitly outside the admitted Core producer domain.
    raw=bytearray(tape);h,trace,effects=tape_trace(tape)
    record=RECORDS+128
    assert q(tape,record)==40 and q(tape,record+8)==1 and q(tape,record+32)==2
    string=b"r"*6000
    old_used=h[9];new_used=old_used+len(string)
    raw.extend(string)
    for at,value in((48,new_used),(64,new_used-MIN_TAPE),(MIN_TAPE+64,h[8]+len(string)),
        (MIN_TAPE+72,new_used),(record+40,old_used),(record+48,len(string))):
        struct.pack_into("<Q",raw,at,value)
    code=make_code(actual,"issuer-grow-pressure");issued=None
    try:
        issued=Issued(actual,"issuer-grow-pressure",bytes(raw),code)
        before=actual.issuer_grows;result=issued.run()
        assert actual.issuer_grows>before and result["event"][2]==2 and result["event"][13]==1
        oracle=actual.oracle.Code()
        try:oracle.push("r"*6000)
        except actual.oracle.MachineEncodingError as error:expected=str(error)
        else:raise AssertionError("oracle pressure did not fail")
        assert result["payload"].decode()==expected=="unknown x86-64 register"
        code.compare_state(oracle)
        actual.record("issuer-grow-pressure",status="PASS",kind="PRIVATE_FORMAT_PRESSURE_ONLY",
            actual_upstream_tape_authenticity_claim=False,own_growth_before_commit=True,
            actual_Code_error_preserved=True,error=expected)
        ret,event=issued.entry(2,issued.config(2))
        assert ret==BAD and event[2]==3
        actual.private_controls+=1;counter+=1
        actual.record("issuer-after-error-poison",status="PASS",kind="ISSUER_PRIVATE_ACK_BAD",permanent_poison=True)
    finally:
        try:
            if issued is not None:issued.close()
        finally:code.close()
    assert counter==len(config_cases)+4+len(mutations)+len(ack_fields)+6+1

GROUPS=("smoke","scalars","casts","booleans","resources","edges","calls","selection","inventory","budget","tape-protocol","issuer-protocol")
def main():
    parser=argparse.ArgumentParser()
    for name in("bundle","reference","out"):parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--group",choices=GROUPS,required=True);parser.add_argument("--variant",type=int,default=0)
    args=parser.parse_args();root=Path(__file__).resolve().parents[1]
    args.out.mkdir(parents=True,exist_ok=False)
    resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    actual=None;summary=dict(status="INCOMPLETE",group=args.group,variant=args.variant,
        scope="PRIVATE_NATIVE_FUNCTION_LOWERING_AND_ACTUAL_CODE_ACK",
        upstream_admitted_Core_checked_plan_and_configured_Code_required=True,
        development_memory_transport_only=True,runtime_host_instruction_selection=False,
        whole_emitter=False,whole_backend=False,installed=False,cold=False)
    started=time.monotonic_ns()
    try:
        assert sys.version_info[:3]==(3,12,14)
        actual=Actual(args.bundle,args.reference.resolve(),root,args.out)
        mapping=dict(smoke=smoke,scalars=lambda a:scalar_group(a,args.variant),
            casts=lambda a:cast_group(a,args.variant),booleans=boolean_select_group,
            resources=resource_group,edges=edge_group,calls=call_group,selection=code_selection_group,
            inventory=lambda a:inventory_group(a,args.variant),budget=lambda a:budget_group(a,args.variant))
        mapping["tape-protocol"]=tape_protocol;mapping["issuer-protocol"]=issuer_protocol
        mapping[args.group](actual)
        summary["status"]="PASS"
    except BaseException as error:
        summary.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        if actual is not None:
            summary.update(cases=len(actual.cases),native_entries=actual.calls,by_component=actual.counts,
                admitted_Core_inputs=actual.validated,private_controls=actual.private_controls,
                code_GROW=actual.code_grows,issuer_GROW=actual.issuer_grows,tape_GROW=actual.tape_grows,
                actual_native_commands=actual.command_count,source_opcodes=sorted(actual.covered_source_ops),
                source_types=sorted(actual.covered_types),Code_operations=sorted(actual.operations),
                original_frame_semantic_refusals=actual.frame_rejections,tape_only_cases=actual.tape_only_cases)
            try:summary["custody"]=actual.close()
            except BaseException as error:
                summary.update(status="FAIL",cleanup_error=repr(error),cleanup_traceback=traceback.format_exc());traceback.print_exc()
        summary.update(elapsed_ns=time.monotonic_ns()-started,
            limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),
                address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE))))
        save(args.out/"summary.json",summary);print(json.dumps(summary,sort_keys=True),flush=True)
    if summary["status"]!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
