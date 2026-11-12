"""Fresh actual HIA scalar / borrowed-byte wrappers and exact original Code.
Only the immutable fixture capture and independent oracle use Python semantics.
Every production Code command is copied from the actual HIA issuer's view.
"""
from pathlib import Path
from hashlib import sha256
import argparse,ast,copy,ctypes,importlib.util,itertools,json,resource,stat,struct,sys,time,traceback,types
sys.dont_write_bytecode=True
BAD=0xfffffffd
GROW=0xfffffffe
MASK=(1<<64)-1
def magic(s):return int.from_bytes(s.encode("ascii"),"little")
EVENT=magic("HIAWRE01")
COMMAND=magic("HIAWRC01")
TAPE=magic("HIAWRT01")
ISSUER_INPUT=magic("HIAWIC01")
ISSUER_EVENT=magic("HIAWIE01")
RESULT=magic("HIAWIR01")
BUILD_SHA="3877b042793ef9c15b140d70b83fec085d22efc9b7102ad18fcb846eb1846daf"
FRAME_HELPER_SHA="b3d590336e647df0804ef51c62b73ca2236abdfe8774161d4fd155cf0a5fbee6"
CODE_HELPER_SHA="61dbf40a99220f2f5b6db7950ee8e3a53299530d385fee70877ade6a0e387c11"
LOWER_HELPER_SHA="e08023ddab7501313a45825e5e2cdbba40d3524fee3e4a0f9ad33ba65335bc17"
BYTE_SHA="0bb40a17f76c27146a48a6d3d229228c9a89bfd96d4b9d65b3b9c70215a3edd6"
SCALARS=("bool","i8","u8","i16","u16","i32","u32","i64","u64","isize","usize")
LIMITS=dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
F=X=M=None
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+"\n")
def q(raw,at):return struct.unpack_from("<Q",raw,at)[0]
def changed(raw,at,value):
    out=bytearray(raw);struct.pack_into("<Q",out,at,value);return bytes(out)
def load(name,path,expected):
    raw=path.read_bytes();assert digest(raw)==expected,(str(path),digest(raw),expected)
    module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
    exec(compile(raw,str(path),"exec"),module.__dict__);return module

def tape_trace(raw):
    event=struct.unpack_from("<16Q",raw)
    assert event[:3]==(EVENT,1,0) and event[7]==12288 and event[12:]==(0,0,0,0)
    head=struct.unpack_from("<32Q",raw,12288)
    assert head[:2]==(TAPE,1) and head[5]==event[9] and head[6]==12544
    assert head[7]==12544+head[5]*128 and head[8]==head[9]-head[7]
    assert head[9]<=len(raw) and head[9]==event[6] and event[8]==head[9]-12288
    assert head[10]<=head[11] and head[11]==event[10]
    assert head[14]==event[11] and head[17]==96 and head[18] in(1,2)
    assert (head[19]==0 if head[18]==1 else 1<=head[19]<=1<<20)
    assert head[20:]==(0,)*12
    assert head[7]<=head[12]<=head[9] and head[13]<=head[9]-head[12]
    trace=[];effects=[]
    for index in range(head[5]):
        row=struct.unpack_from("<16Q",raw,12544+index*128)
        opcode,argc,serial,effect=row[:4]
        assert 2<=opcode<=44 and opcode!=3 and 0<=argc<=3
        arguments=[]
        for j in range(argc):
            kind,value,size=row[4+j*3:7+j*3]
            if kind==2:
                assert head[7]<=value<=head[9] and size<=head[9]-value
                arguments.append(raw[value:value+size].decode("ascii"))
            else:
                assert kind in(0,1) and size==0 and (kind==0 or value>0)
                arguments.append(-value if kind else value)
        assert row[4+argc*3:]==(0,)*(12-argc*3)
        trace.append((X.OPERATIONS[opcode],tuple(arguments),serial));effects.append(effect)
    assert effects[0]==1 and effects[-1]==3 and all(x==0 for x in effects[1:-1])
    return head,trace,effects

class Actual:
    def __init__(self,bundle,reference,root,out):
        global F,X,M
        self.root,self.reference,self.out=root,reference,out
        F=load("wrapper_frame_helpers",root/"tests/function_frame_test_reference.py",FRAME_HELPER_SHA)
        X=load("wrapper_code_helpers",root/"tests/function_code_test_reference.py",CODE_HELPER_SHA)
        M=load("wrapper_lower_helpers",root/"tests/function_lowering_test_reference.py",LOWER_HELPER_SHA)
        builder=load("wrapper_build",root/"tools/build_hia_emitter_wrappers.py",BUILD_SHA)
        self.evidence=F.Evidence(out);self.buffers=F.Buffers();self.calls=0;self.sessions=0
        self.counts={name:0 for name in("tape","issuer","encoder","finalizer")}
        self.operations=set();self.errors=set();self.cases=[];self.private_controls=0
        self.validated=0;self.pressure=0;self.code_grows=0;self.issuer_grows=0
        self.tape_grows=0;self.command_count=0;self.images={};self.closed=False
        for path,h in builder.PINS.items():self.evidence.pin(root/path,h)
        self.evidence.pin(__file__)
        self.evidence.pin(root/"tools/build_hia_emitter_wrappers.py",BUILD_SHA)
        for p,h in (("function_frame_test_reference.py",FRAME_HELPER_SHA),
                    ("function_code_test_reference.py",CODE_HELPER_SHA),
                    ("function_lowering_test_reference.py",LOWER_HELPER_SHA)):
            self.evidence.pin(root/"tests"/p,h)
        frozen={p.resolve():self.evidence.pin(p) for prefix in("hepta","tools")
                for p in sorted((reference/prefix).rglob("*.py"))}
        sys.meta_path.insert(0,builder.FrozenImports(reference,frozen))
        self.original=F.Original(self.evidence,root)
        raw=self.evidence.pin(root/"reference/hia_machine_x64.py",X.REFERENCE_SHA)
        self.oracle=types.ModuleType("wrapper_Code_original");self.oracle.__file__=str(root/"reference/hia_machine_x64.py")
        exec(compile(raw,self.oracle.__file__,"exec"),self.oracle.__dict__)
        native=self.original.module
        raw=self.evidence.pin(root/"reference/hia_program_native.py",F.REFERENCE_SHA)
        names={"IMPORTS","_LOADER_HOOKS","_ARG_REGS","CORE_SCHEMAS","SUPPORTED_OPCODES"}
        nodes=[n for n in ast.parse(raw).body if isinstance(n,ast.Assign)
               and any(isinstance(t,ast.Name) and t.id in names for t in n.targets)]
        assert {t.id for n in nodes for t in n.targets if isinstance(t,ast.Name)}==names
        exec(compile(ast.Module(body=nodes,type_ignores=[]),native.__file__,"exec"),native.__dict__)
        native.Code=self.oracle.Code
        package=native.__package__
        sys.modules[package+".hia_program_native"]=native
        br=self.evidence.pin(root/"reference/hia_native_byte_abi.py",BYTE_SHA)
        byte_module=types.ModuleType(package+".hia_native_byte_abi")
        byte_module.__file__=str(root/"reference/hia_native_byte_abi.py");byte_module.__package__=package
        sys.modules[byte_module.__name__]=byte_module;exec(compile(br,byte_module.__file__,"exec"),byte_module.__dict__)
        self.byte_original=byte_module
        sys.path.insert(0,str(reference))
        from hepta import hia_program
        sys.modules[package+".hia_program"]=hia_program
        self.program_original=hia_program
        M.F,M.X=F,X
        M.tape_trace=tape_trace
        M.ISSUER_INPUT,M.ISSUER_EVENT,M.RESULT=ISSUER_INPUT,ISSUER_EVENT,RESULT
        self.Issued=M.Issued
        for name in("entry","pure","record","close"):
            setattr(self,name,types.MethodType(getattr(M.Actual,name),self))
        self.admit=types.MethodType(F.Actual.admit,self)
        raw=self.evidence.pin(bundle);doc=json.loads(raw)
        assert doc["schema"]=="hepta.hia.emitter-wrapper-bundle.v1" and doc["source_pins"]==builder.PINS
        assert set(doc["components"])==set(self.counts)
        loader_path=reference/"hepta/hia_json_preflight_native.py"
        raw=self.evidence.pin(loader_path)
        loader=types.ModuleType("wrapper_native_loader");loader.__file__=str(loader_path)
        exec(compile(raw,str(loader_path),"exec"),loader.__dict__)
        try:
            for name,manifest in doc["components"].items():
                assert manifest["schema"]=="hepta.hia.emitter-wrapper-development.v1"
                assert manifest["component"]==name and manifest["status"]=="BUILT_ONLY"
                source=self.evidence.pin(manifest["source_path"],manifest["source_sha256"])
                image=self.evidence.pin(manifest["image_path"],manifest["image_sha256"])
                assert len(source)==manifest["source_bytes"] and len(image)==manifest["image_bytes"]
                receipt=manifest["compile_receipt"]
                assert receipt["input_sha256"]==receipt["source_sha256"]==digest(source)
                assert receipt["produced_sha256"]==digest(image) and receipt["produced_bytes"]==len(image)
                assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
                self.images[name]=loader.NativeHiaJsonImage(image,expected_sha256=digest(image))
        except BaseException:
            for image in self.images.values():image._mapping.close()
            raise
    def original_wrapper(self,doc,plan,index,serial,kind,extent,prefix=0):
        original=self.original.module
        proxy=types.SimpleNamespace(as_dict=lambda:doc,structured_bytes=None)
        allowed=self.program_original.VerifiedProgram.scalar_entrypoints.fget(proxy)
        foreign=()
        if kind==2:foreign=self.byte_original.normalize_exports(((doc["functions"][index]["name"],extent),),proxy)
        parent=original._Emitter(doc,allowed,foreign_buffer_exports=foreign,machine_plan=plan)
        parent.serial=serial
        code=parent.c
        if prefix:code.emit(b"\x90"*prefix)
        parent.c=M.TraceCode(code,parent)
        error=None;domain=None
        try:parent.wrapper(doc["functions"][index])
        except original.HIAProgramNativeRejected as exc:error=str(exc);domain="HIAProgramNativeRejected"
        except self.oracle.MachineEncodingError as exc:error=str(exc);domain="MachineEncodingError"
        return parent,code,error,domain

def fixture(types_,returns=None,name="entry"):
    params=[dict(name="v"+str(i),type=t) for i,t in enumerate(types_)]
    returns=[] if returns is None else list(returns)
    # A trap is valid for every well-formed signature and does not manufacture
    # foreign values. Byte-loan test functions have their exact read/write sets.
    effects=["trap"]
    if "readbuf" in types_:effects.append("read")
    if "mutbuf" in types_:effects.extend(("read","write"))
    effects=sorted(set(effects))
    block=dict(id="b0",params=copy.deepcopy(params),ops=[],term=dict(op="trap"))
    fn=dict(name=name,params=params,returns=returns,effects=effects,entry="b0",blocks=[block])
    return dict(schema="hepta.hia.program.v8",module="wrapper_fixture",functions=[fn])

def exact(actual,label,doc,*,kind=1,extent=0,index=0,serial=0,plan=None,prefix=0,admitted=True,tape_only=False):
    if admitted:doc,plan=actual.admit(doc,plan)
    else:actual.pressure+=1
    graph=F.capture([doc,plan],17)
    command=struct.pack("<12Q",COMMAND,1,17,1,index,serial,q(graph,24),kind,extent,0,0,0)
    start=actual.calls
    expected,planned_code,plan_error,plan_domain=actual.original_wrapper(doc,plan,index,serial,kind,extent)
    result=actual.pure("tape",label+"-tape",graph,command,12288)
    event=result["event"];assert result["returned"]==128 and event[:2]==(EVENT,1)
    assert event[3:6]==(17,1,index) and event[15]==0
    if plan_error is not None:
        assert plan_domain=="HIAProgramNativeRejected" and event[2]==2 and not expected.c.trace
        at,n=event[12:14];observed=result["workspace"][at:at+n].decode("ascii")
        assert observed==plan_error and event[10]==serial,(label,observed,plan_error)
        return actual.record(label,status="PASS",kind="ORIGINAL_WRAPPER_SEMANTIC_REFUSAL",error=observed,
                             native_entries=actual.calls-start,admitted=admitted)
    if not expected.exports:
        assert event[2]==4 and event[7:10]==(0,0,0) and event[10]==serial
        assert not expected.c.trace
        return actual.record(label,status="PASS",kind="ORIGINAL_WRAPPER_SKIPPED",
                             native_entries=actual.calls-start,admitted=admitted)
    assert event[2]==0
    header,trace,effects=tape_trace(result["workspace"])
    assert trace==expected.c.trace,(label,next(((a,b) for a,b in itertools.zip_longest(trace,expected.c.trace) if a!=b),None))
    assert header[11]==expected.serial and header[18:20]==(kind,extent)
    words=sum(2 if p["type"] in("readbuf","mutbuf") else 1 for p in doc["functions"][index]["params"])
    expected_frame=((words+1)*8+15)&~15
    assert header[14]==expected_frame
    if tape_only:
        return actual.record(label,status="PASS",kind="COMPLETE_NATIVE_WRAPPER_TAPE_ONLY",
            tape_commands=len(trace),serial=expected.serial,frame=header[14],
            full_original_Code_trace_equal=True,native_entries=actual.calls-start,admitted=admitted)
    reference,oracle,error,domain=actual.original_wrapper(doc,plan,index,serial,kind,extent,prefix)
    code=X.Session(actual);issued=None
    try:
        from hepta.hia_machine_plan import code_options
        options=code_options(plan)
        init=code.command(0,(options.get("scratch_registers"),options.get("move_immediate","movabs"),
                            options.get("alu_immediate","imm32")),label+"-native-init")
        assert init["error"] is None
        if prefix:
            assert code.command(3,(b"\x90"*prefix,),label+"-fixture-prefix")["error"] is None
        else:
            old=code.code;new=actual.buffers.allocate(64,ctypes.string_at(old["address"],64))
            code.code=new;actual.buffers.close(old)
        issued=actual.Issued(actual,label,result["workspace"],code)
        answer=issued.run();last=answer["event"];payload=answer["payload"]
        assert issued.commands==reference.c.trace,(label,len(issued.commands),len(reference.c.trace))
        assert last[10]==reference.serial
        state=code.compare_state(oracle)
        if error is not None:
            assert domain=="MachineEncodingError" and last[2]==2 and last[13]==1
            assert payload.decode("ascii")==error,(label,error,payload)
        else:
            assert last[2]==0
            words=struct.unpack_from("<32Q",payload)
            assert words[:2]==(RESULT,1) and words[2:5]==(issued.lease,issued.request,index)
            assert words[5:8]==(code.lease,code.seq,prefix)
            assert words[8]==len(oracle.data) and words[9]==header[14] and words[10]==reference.serial
            assert words[15]==len(payload) and words[16:19]==(kind,extent,1) and words[19:]==(0,)*13
            fn_name=doc["functions"][index]["name"].encode("ascii")
            assert words[11:15]==(4096+256,len(fn_name),4096+256,len(fn_name))
            assert payload[256:]==fn_name
            symbol=dict(name=fn_name.decode(),offset=words[7],size=words[8]-words[7],global_=True)
            expected_symbol=reference.symbols[0]
            assert (symbol["name"],symbol["offset"],symbol["size"],symbol["global_"])==(
                expected_symbol["name"],expected_symbol["offset"],expected_symbol["size"],expected_symbol["global"])
            finalized=code.finalize(label+"-final")
            original_final=oracle.finalize()
            assert finalized["error"] is None and finalized["value"]==original_final
            state=code.compare_state(oracle)
        return actual.record(label,status="PASS",kind="ACTUAL_NATIVE_WRAPPER_CODE_CHAIN",
            wrapper_kind=kind,admitted=admitted,commands=len(issued.commands),frame=header[14],
            serial=reference.serial,error=error,domain=domain,state=state,
            native_entries=actual.calls-start,full_original_trace_equal=True,
            full_machine_bytes_and_registries_equal=True,whole_Emitter=False)
    finally:
        if issued is not None:issued.close()
        code.close()


def scalar_cases(actual,variant):
    typ=SCALARS[variant]
    returns=[[],["unit"]]+[[t] for t in SCALARS]
    for count in(1,7):
        for n,result in enumerate(returns):
            exact(actual,"scalar-"+str(variant)+"-"+str(count)+"-"+str(n),
                  fixture([typ]*count,result),serial=n*29)

def borrowed_cases(actual,variant):
    count=variant+1
    for pattern in range(3):
        loans=[("readbuf" if pattern==0 or (pattern==2 and i%2==0) else "mutbuf") for i in range(count)]
        for arrangement in range(3):
            params=list(loans)
            if arrangement==1:params=list(SCALARS[:6])+params
            elif arrangement==2:
                params=[v for i,t in enumerate(loans) for v in(SCALARS[i%len(SCALARS)],t)]
            extent=(1,127,1<<20)[arrangement]
            exact(actual,"borrowed-"+str(count)+"-"+str(pattern)+"-"+str(arrangement),
                  fixture(params,["u32"]),kind=2,extent=extent,serial=count*31+pattern)

def option_cases(actual):
    for index,(swap,move,alu) in enumerate(itertools.product((False,True),("movabs","mov32_if_exact"),("imm32","imm8_if_exact"))):
        for kind in(1,2):
            types_=list(SCALARS)+(["readbuf","u64","mutbuf"] if kind==2 else [])
            document=fixture(types_,["u32"])
            checked=actual.program_original.verify_program(document)
            # The exact checked machine-plan fixture is taken through the
            # unchanged original validator before the HIA private input.
            plan=dict(schema="hepta.hia.agent.machine-plan.v2",core_sha256=checked.sha256,
                block_order={"entry":["b0"]},function_order=["entry"],function_alignment=1,scratch_registers={"r10":"r11","r11":"r10"} if swap else {"r10":"r10","r11":"r11"},
                instruction_selection=dict(move_immediate=move,alu_immediate=alu))
            exact(actual,"options-"+str(index)+"-"+str(kind),document,plan=plan,kind=kind,
                  extent=(1<<20) if kind==2 else 0,serial=17)

def reserved_cases(actual):
    names=sorted(actual.original.module.IMPORTS|actual.original.module._LOADER_HOOKS)+["__hia_","__hia_custom"]
    assert len(names)==16
    for name in names:
        exact(actual,"reserved-public-"+name,fixture(["u32"],["u32"],name),admitted=False)
        doc=fixture(["u32"],["u32"],name);doc["exports"]=[]
        exact(actual,"reserved-skipped-"+name,doc,admitted=False)

def skipped_cases(actual):
    inputs=[(["unit"],[]),(["buffer"],[]),(["readbuf"],[]),(["mutbuf"],[]),
            (["chain"],[]),([],["u32","u64"]),([],["buffer"]),([],["readbuf"])]
    for index,(params,returns) in enumerate(inputs):
        exact(actual,"signature-skipped-"+str(index),fixture(params,returns),admitted=False)

def stack_cases(actual):
    exact(actual,"scalar-exact-stack",fixture(["u64"]*8191,["u64"]),admitted=False,tape_only=True)
    exact(actual,"scalar-over-stack",fixture(["u64"]*8192,["u64"]),admitted=False,tape_only=True)
    exact(actual,"borrowed-exact-stack",fixture(["readbuf"]+["u64"]*8189,["u32"]),
          kind=2,extent=1,admitted=False,tape_only=True)
    exact(actual,"borrowed-over-stack",fixture(["readbuf"]+["u64"]*8190,["u32"]),
          kind=2,extent=1,admitted=False,tape_only=True)

def budget_cases(actual,variant):
    if variant==0:
        exact(actual,"wrapper-has-no-independent-16MiB-gate",fixture([],["unit"]),prefix=16<<20)
    else:
        exact(actual,"Code-budget-real-partial-wrapper",fixture([],["unit"]),prefix=(64<<20)-1)

def prepared(actual,label):
    doc,plan=actual.admit(fixture(["u32"],["u32"]),None)
    graph=F.capture([doc,plan],17)
    command=struct.pack("<12Q",COMMAND,1,17,1,0,0,q(graph,24),1,0,0,0,0)
    tape=actual.pure("tape",label,graph,command,12288)
    assert tape["returned"]==128 and tape["event"][2]==0
    return graph,command,tape["workspace"]

def reject_tape(actual,label,graph,command,capacity=12288):
    result=actual.pure("tape",label,graph,command,capacity)
    assert result["returned"]==BAD,(label,result["returned"],result["event"])
    if capacity>=12288:assert result["event"][2]==3 and result["event"][15]>0
    actual.private_controls+=1
    actual.record(label,status="PASS",kind="PRIVATE_WRAPPER_TAPE_ABI",return_value=BAD,
                  work_capacity=capacity,event=result["event"])

def fresh_issued(actual,label,tape,seed=False):
    code=X.Session(actual)
    try:
        assert code.command(0,(None,"movabs","imm32"),label+"-init")["error"] is None
        if seed:
            for opcode,args in ((4,("prior",)),(5,("later",)),(7,("abort",))):
                assert code.command(opcode,args,label+"-real-seed-"+str(opcode))["error"] is None
        return code,actual.Issued(actual,label,tape,code)
    except BaseException:code.close();raise

def reject_issuer(actual,label,tape,change,acknowledge=False):
    code,issued=fresh_issued(actual,label,tape,acknowledge)
    peer=None
    try:
        if acknowledge:
            event=issued.step(1)
            assert event[2]==1 and event[9]==0
            raw=ctypes.string_at(issued.work["address"]+event[11],event[12])
            packet=actual.buffers.allocate(len(raw),raw,True)
            try:
                ret,ce=actual.entry("encoder",label+"-first-actual-offset",(packet,code.code,code.work),
                    (label+"-packet",code.prefix+"-code",code.prefix+"-work"))
                assert ret==128 and ce[2]==0 and ce[5]==2
                code.seq+=1
            finally:actual.buffers.close(packet)
            kind=2
        else:kind=1
        config=issued.config(kind,code.seq,128)
        original_config=config
        original_peer=code.raw("work")
        config,peer_raw,work_mutator=change(config,original_peer)
        if work_mutator is not None:
            offset,value=work_mutator;ctypes.memmove(issued.work["address"]+offset,struct.pack("<Q",value),8)
        if peer_raw!=original_peer:peer=actual.buffers.allocate(len(peer_raw),peer_raw,True)
        ret,event=issued.entry(kind,config,peer)
        assert ret==BAD and event[2]==3 and event[15]>0,(label,ret,event)
        assert q(issued.raw_work(),440)==1
        again,ae=issued.entry(kind,original_config,code.work)
        assert again==BAD and ae[2]==3 and q(issued.raw_work(),440)==1
        actual.private_controls+=1
        actual.record(label,status="PASS",kind="PRIVATE_WRAPPER_ISSUER_POISON",
                      initial_or_actual_ACK="ACK" if acknowledge else "BEGIN",event=event,retry_event=ae)
    finally:
        actual.buffers.close(peer);issued.close();code.close()

def protocol_cases(actual):
    graph,command,tape=prepared(actual,"protocol-original")
    commands=[(0,0),(8,2),(16,0),(24,0),(32,1),(48,q(graph,24)+1),
              (56,0),(56,3),(64,1),(72,1),(80,1),(88,1)]
    for index,(at,value) in enumerate(commands):
        reject_tape(actual,"command-"+str(index),graph,changed(command,at,value))
    graphs=[(0,0),(8,18),(16,0),(16,MASK),(24,0),(32,MASK),(40,q(graph,40)+1),
            (48,len(graph)+1),(56,1),(64,9),(120,1)]
    for index,(at,value) in enumerate(graphs):
        reject_tape(actual,"Graph-"+str(index),changed(graph,at,value),command)
    reject_tape(actual,"truncated-command",graph,command[:-1])
    reject_tape(actual,"extra-command",graph,command+b"\0")
    reject_tape(actual,"truncated-Graph",graph[:-1],command)
    reject_tape(actual,"extra-Graph",graph+b"\0",command)
    for capacity in(0,127,511,8192,12287):
        reject_tape(actual,"short-wrapper-work-"+str(capacity),graph,command,capacity)
    for index,(at,value) in enumerate(((0,0),(8,2),(16,0),(24,0),(32,2),(40,0),(48,0),(56,0),
                                     (64,18),(72,2),(80,1),(88,len(tape)+1),(96,63),(104,BAD),(112,1),(120,1))):
        reject_issuer(actual,"issuer-BEGIN-"+str(index),tape,
                      lambda c,p,at=at,value=value:(changed(c,at,value),p,None))
    for index,(at,value) in enumerate(((0,0),(8,2),(16,3),(24,0),(32,0),(40,3),(48,1),(56,MASK),
                                     (64,MASK),(72,MASK),(80,0),(88,0),(96,0),(104,1),(112,1),(120,1))):
        reject_issuer(actual,"issuer-ACK-peer-"+str(index),tape,
                      lambda c,p,at=at,value=value:(c,changed(p,at,value),None),True)
    for index,(at,value) in enumerate(((32,1),(48,999999),(56,999999),(64,18),(72,999999),(80,1),(88,len(tape)+1),(104,BAD))):
        reject_issuer(actual,"issuer-ACK-config-"+str(index),tape,
                      lambda c,p,at=at,value=value:(changed(c,at,value),p,None),True)
    for index,(at,value) in enumerate(((256,0),(280,0),(288,0),(304,18),(352,999999),(432,2),(440,1))):
        reject_issuer(actual,"issuer-state-"+str(index),tape,
                      lambda c,p,at=at,value=value:(c,p,(at,value)),True)
    repeated=actual.pure("tape","pure-repeat",graph,command,len(tape))
    assert repeated["workspace"]==tape
    actual.record("pure-repeat",status="PASS",kind="PURE_REPEAT_EXACT_BYTES")
    exact(actual,"scalar-max-serial",fixture([],["unit"]),serial=MASK)
    # This is a private format pressure case, not an admitted public identifier:
    # it forces the issuer's result GROW without relaxing Core name limits.
    exact(actual,"issuer-result-GROW",fixture([],["unit"],"a"*6000),admitted=False)

EXPECTED={**{("scalars",i):26 for i in range(11)},
          **{("borrowed",i):9 for i in range(8)},
          ("options",0):16,("reserved",0):32,("skipped",0):8,("stack",0):4,
          ("budget",0):1,("budget",1):1,("protocol",0):82}
def main():
    resource.setrlimit(resource.RLIMIT_CPU,(90,90))
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    parser=argparse.ArgumentParser()
    for name in("bundle","reference","out"):parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--group",required=True);parser.add_argument("--variant",type=int,default=0)
    args=parser.parse_args();root=Path(__file__).resolve().parents[1]
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    started=time.monotonic_ns();actual=None
    summary=dict(status="INCOMPLETE",scope="NEW_WRAPPER_ACTUAL_CODE_CHAIN",group=args.group,
        variant=args.variant,cases=0,native_entries=0,private_controls=0,whole_Emitter=False,whole_backend=False,
        installed=False,cold=False,old_test_results_inherited=False,runtime_host_instruction_selection=False)
    try:
        assert sys.version_info[:3]==(3,12,14)
        assert (args.group,args.variant) in EXPECTED
        actual=Actual(args.bundle.resolve(),args.reference.resolve(),root,out)
        if args.group=="scalars":scalar_cases(actual,args.variant)
        elif args.group=="borrowed":borrowed_cases(actual,args.variant)
        elif args.group=="options":option_cases(actual)
        elif args.group=="reserved":reserved_cases(actual)
        elif args.group=="skipped":skipped_cases(actual)
        elif args.group=="stack":stack_cases(actual)
        elif args.group=="budget":budget_cases(actual,args.variant)
        else:protocol_cases(actual)
        assert len(actual.cases)==EXPECTED[(args.group,args.variant)],(len(actual.cases),EXPECTED[(args.group,args.variant)])
        if args.group=="protocol":
            assert actual.private_controls==79
            assert actual.issuer_grows>0
        summary["status"]="PASS"
    except BaseException as error:
        summary.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        if actual is not None:
            summary.update(cases=len(actual.cases),native_entries=actual.calls,private_controls=actual.private_controls,
                by_component=actual.counts,Code_operations=sorted(actual.operations),Code_errors=sorted(actual.errors),
                original_reference_admitted_fixtures=actual.validated,private_constructor_pressure=actual.pressure,
                Code_commands=actual.command_count,code_GROW=actual.code_grows,issuer_GROW=actual.issuer_grows,tape_GROW=actual.tape_grows,
                case_categories={name:sum(c["kind"]==name for c in actual.cases) for name in sorted({c["kind"] for c in actual.cases})})
            try:summary["custody"]=actual.close()
            except BaseException as error:
                summary.update(status="FAIL",cleanup_error=repr(error),cleanup_traceback=traceback.format_exc())
                traceback.print_exc()
        summary.update(limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),
                address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE))),
                elapsed_ns=time.monotonic_ns()-started)
        save(out/"summary.json",summary);print(json.dumps(summary,sort_keys=True),flush=True)
    if summary["status"]!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
