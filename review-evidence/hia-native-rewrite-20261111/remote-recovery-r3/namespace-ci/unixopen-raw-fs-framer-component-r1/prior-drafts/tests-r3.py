"""Fresh actual shared-FS windows paired with the complete framer CoreVM.

The original parent PENDING input is an explicit private fixture. The HIA
framer's complete lower request is executed unchanged in one actual six-role
ELF, and its response descriptor comes from that process's complete trace.
This is a component join, not the final installed native issuer or Store.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import argparse,gzip,hashlib,importlib.util,json,os,resource,signal,stat,struct,time,traceback
from pathlib import Path
SUPPORT="f60438dd82274504c0aaba827b5aea2741ae41480a816840dde7fdfb5e41a281"
CLIENT="e5cad29b23957856c3a3ae08645eb7a14a62f6b0263fe67720a9560b88e58270"
B3="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
BAD=(1<<32)-3
MASK=(1<<64)-1
EXPECTED_PROTOCOL_CONTROLS=80
CASES=[
 ("pid-first",1,10,"",0),("pid-reset",1,11,"",0),
 ("access-present",8,32,"present",0),("access-missing",8,32,"missing",2),
 ("access-empty",8,32,"empty",2),("access-nonutf8",8,32,"nonutf8",0),
 ("geteuid",9,40,"",0),("fchown-owner",10,41,"token",0),
 ("unlink-present",11,50,"present",0),("unlink-missing",11,50,"missing",2),
 ("unlink-empty",11,50,"empty",2),("close-owned",14,62,"token",0),
 ("fstat-unregistered",15,70,"token",0),("fstat-registered",15,70,"registered",0),
 ("stat-present",16,71,"present",0),("stat-missing",16,71,"missing",2),
 ("stat-empty",16,71,"empty",2),("stat-nonutf8",16,71,"nonutf8",0),
 ("stat-long-path",16,71,"long",36)]
def sha(b):return hashlib.sha256(b).hexdigest()
def save(path,value):
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    Path(path).write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def main():
    resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    def expired(*_):raise TimeoutError("raw-FS component original180wall")
    signal.signal(signal.SIGALRM,expired);signal.alarm(180)
    ap=argparse.ArgumentParser();ap.add_argument("--context",type=Path,required=True)
    ap.add_argument("--mode",choices=("physical","protocol"),required=True);ap.add_argument("--group",type=int,required=True)
    args=ap.parse_args();assert sys.version_info[:3]==(3,12,14)
    assert (args.mode=="physical" and 0<=args.group<5) or (args.mode=="protocol" and 0<=args.group<4)
    pins={}
    def pin(path,expected=None):
        path=Path(path).absolute();info=path.lstat()
        assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
        raw=path.read_bytes();row=dict(path=str(path),bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(info.st_mode))
        if expected is not None:assert row["sha256"]==expected,(path,row["sha256"],expected)
        if str(path) in pins:assert pins[str(path)]==row
        pins[str(path)]=row;return raw
    def load(name,path,expected=None):
        raw=pin(path,expected);spec=importlib.util.spec_from_file_location(name,path)
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module
        exec(compile(raw,str(path),"exec"),module.__dict__);return module
    context=json.loads(pin(args.context));evidence=Path(context["namespace_evidence"])
    ref=Path(context["reference"]);inputs=context["namespace_input_paths"]
    out=evidence/(args.mode+"-"+str(args.group));out.mkdir(parents=False,exist_ok=False)
    started=time.monotonic_ns();cpu=time.process_time_ns();image=None
    report=dict(status="INCOMPLETE",scope="PRIVATE_PENDING_FIXTURE_REAL_SHARED_FS_REQUEST_AND_RESULT",
        mode=args.mode,group=args.group,framer_VM_entries=0,framer_native_entries=0,
        fixed_native_entries=0,fixed_VM_entries=0,actual_primitive_ACKs=0,
        physical_cases=[],protocol_controls=[],processes=[],witnesses=[],inherited_counts=False,
        fixed_native_issuer_implemented=False,ordinary_unixOpen_closed=False,ordinary_Store_closed=False,
        actual_limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),
            address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE))))
    save(out/"summary.json",report)
    try:
        pin(__file__);sys.path.insert(0,str(ref))
        h=load("namespace_raw_fs_test_support",inputs["raw-fs-fixture-support.py"],SUPPORT)
        report["limits"]=h.LIMITS
        from hepta.hia_agent_assembly import render_assembly,assemble_program
        from hepta.hia_program import verify_program
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        build=json.loads(pin(evidence/"framer-build/summary.json"))
        assert build["status"]=="PASS_BUILD_ONLY" and build["fresh_B3_compiles"]==1 and build["source_pins_unchanged"]
        receipt=build["compile_receipt"]
        assert receipt["artifact_sha256"]==receipt["image_sha256"]==B3
        assert receipt["source_sha256"]==receipt["input_sha256"]==build["canonical_source"]["sha256"]
        assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
        doc=json.loads(pin(build["document"]["path"],build["document"]["sha256"]))
        source=pin(build["canonical_source"]["path"],build["canonical_source"]["sha256"])
        assert render_assembly(doc).encode()==source
        program=verify_program(doc)
        image_raw=pin(build["image"]["path"],build["image"]["sha256"])
        assert receipt["produced_sha256"]==sha(image_raw) and receipt["produced_bytes"]==len(image_raw)
        image=NativeHiaJsonImage(image_raw,sha(image_raw));assert image.image_sha256==sha(image_raw)
        cas=h.CAS(out/"cas")
        with gzip.open(out/"complete-framer-entries.jsonl.gz","wt",encoding="utf-8",compresslevel=1) as ledger:
            pair=h.Pair(program,image,report,cas,ledger,out/"frontier.json")
            def grow(label,s,r,w):
                code,w=pair.call(label,s,r,w)
                while code==2:
                    assert h.q(w,8)==1 and h.q(w,32)<h.q(s,32)
                    assert not any(w[328:384]),"GROW must not publish old or new pending custody"
                    need=h.q(w,320);assert need>len(w)
                    w=w+bytes(need-len(w))
                    code,w=pair.call(label+"-GROW",s,r,w)
                return code,w
            if args.mode=="physical":
                transport=load("raw_fs_actual_transport",inputs["namespace-db-join-r1-client.py"],CLIENT)
                inner=load("raw_fs_inner_replay",inputs["namespace-fs9-full-inner-replay.py"])
                replay=load("raw_fs_outer_replay",inputs["namespace-fs8-outer-replay.py"])
                fixed=json.loads(pin(evidence/"db-join-build-r1/summary.json"))
                assert fixed["status"]=="PASS_BUILD_ONLY" and fixed["fresh_role_compiles"]==6
                assert fixed["packer_entries"]==33 and fixed["source_pins_unchanged"]
                assert fixed["compile_receipt"]["artifact_sha256"]==B3
                executable=Path(fixed["executable"]["path"]);pin(executable,fixed["executable"]["sha256"])
                programs={}
                for role in range(1,7):
                    row=fixed["exact_roles"][str(role)]
                    raw=pin(row["source"]["path"],row["source"]["sha256"])
                    pin(row["image"]["path"],row["image"]["sha256"])
                    assert row["compile_receipt"]["source_sha256"]==sha(raw)
                    assert row["compile_receipt"]["produced_sha256"]==row["image"]["sha256"]
                    programs[role]=assemble_program(raw)
                selected=CASES[args.group*4:min(len(CASES),(args.group+1)*4)]
                assert selected
                for name,operation,stage,path_kind,expected_error in selected:
                    case=out/name;case.mkdir()
                    fixtures=Path(context["base"])/"namespace-raw-fs-framer-fixtures"/("physical-"+str(args.group))/name
                    fixtures.mkdir(parents=True,exist_ok=False)
                    ordinary=os.fsencode(fixtures/"present")
                    nonutf8=os.fsencode(fixtures)+b"/raw-\xff-\x80"
                    fd=os.open(ordinary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600)
                    try:assert os.write(fd,b"\x00full-native-FS\xff")==16
                    finally:os.close(fd)
                    fd=os.open(nonutf8,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600)
                    try:assert os.write(fd,b"nonutf8")==7
                    finally:os.close(fd)
                    paths={"present":ordinary,"nonutf8":nonutf8,"missing":os.fsencode(fixtures/"absent"),"empty":b"",
                           "long":os.fsencode(fixtures)+b"/"+b"a"*5000,"":b"","token":b"","registered":b""}
                    path=paths[path_kind];token=handle=0
                    def snapshot(label):
                        values=[]
                        for actual_path in (ordinary,nonutf8):
                            try:
                                info=os.lstat(actual_path)
                                with open(actual_path,"rb") as stream:content=stream.read()
                                values.append(dict(path_hex=actual_path.hex(),mode=stat.S_IMODE(info.st_mode),
                                    device=info.st_dev,inode=info.st_ino,nlink=info.st_nlink,
                                    uid=info.st_uid,gid=info.st_gid,size=info.st_size,content=cas.put(content)))
                            except FileNotFoundError:values.append(dict(path_hex=actual_path.hex(),exists=False))
                        save(case/(label+".json"),values)
                    snapshot("physical-before")
                    with transport.Carrier(executable,case/"native",fixtures) as carrier:
                        if path_kind in ("token","registered"):
                            opened,_=carrier.filesystem(25,b=os.O_RDWR|os.O_CLOEXEC,c=0o600,body=ordinary)
                            token=opened[8];assert token>0
                            if path_kind=="registered":
                                header,_=carrier.database(3,token=token);handle=header[14];assert handle>0
                        issuer=h.FixtureIssuer(carrier,cas)
                        peer_before,root_before,trace_before=issuer.before()
                        s=h.pending_source(root_before,issuer,operation,stage,path=path,token=token,handle=handle,
                            uid=os.geteuid(),gid=os.getegid(),lease=3001)
                        code,w=grow(name+"-BEGIN",s,peer_before,bytes(512))
                        assert code==1 and h.q(w,8)==2
                        issued=w;packet=w[h.q(w,304):h.q(w,304)+h.q(w,312)]
                        assert len(packet)==h.q(w,200)==len(s)
                        after,root_after,trace_after=issuer.execute(packet)
                        complete=bytearray(s);h.p(complete,8,2);complete=bytes(complete)
                        code,done=pair.call(name+"-COMPLETE",complete,after,w)
                        assert code==0 and h.q(done,8)==3
                        ack=done[h.q(done,304):h.q(done,304)+h.q(done,312)]
                        assert ack==h.expected_parent_ack(s,after)
                        fs=128+h.q(after,16)+256
                        assert h.q(after,fs+56)==expected_error
                        # Independent actual-OS observations; never used to select
                        # or construct the HIA-issued lower request.
                        if operation==1:assert h.q(ack,72)==carrier.owned_native_pid()
                        if operation==9:assert h.q(ack,72)==os.geteuid()
                        if operation in (15,16) and expected_error==0:
                            info=os.stat(ordinary if operation==15 else path)
                            assert (h.q(ack,80),h.q(ack,88))==(info.st_ino,info.st_nlink)
                            assert h.q(after,fs+64)==info.st_dev
                        if operation==11 and expected_error==0:assert not os.path.exists(path)
                        if operation==10:
                            info=os.stat(ordinary);assert (info.st_uid,info.st_gid)==(os.geteuid(),os.getegid())
                        assert len(trace_after["primitives"])==len(trace_before["primitives"])+1
                        assert trace_after["primitives"][-1]["header"][10]==1
                        witness=dict(name=name,source=cas.put(s),peer_before=cas.put(peer_before),
                            issued_workspace=cas.put(issued),request=cas.put(packet),
                            completion_source=cas.put(complete),peer_after=cas.put(after),done_workspace=cas.put(done),
                            expected_ack=cas.put(ack),actual_binding=issuer.binding,
                            before_entry_serial=root_before["after_header"][2],
                            after_entry_serial=root_after["after_header"][2],
                            actual_allocation_generation=root_after["after_header"][9],
                            expected_errno=expected_error,operation=operation,stage=stage)
                        report["witnesses"].append(witness);save(case/"witness.json",witness)
                        if handle:carrier.database(7,handle)
                        elif token and operation!=14:carrier.filesystem(8,a=token)
                    snapshot("physical-after")
                    result=replay.replay(carrier.output,programs,inner)
                    assert result["status"]=="PASS" and result["native_entries"]==result["vm_entries"]>0
                    assert result["no_masks"] and result["all_original_records_partitioned_exactly_once"]
                    assert result["all_input_output_workspace_return_bytes_equal"]
                    assert result["original_trace_before"]==result["original_trace_after"]
                    process=json.loads(pin(carrier.output/"process.json"))
                    assert process["returncode"]==0 and not process["wall_kill_sent"] and process["watchdog_error"] is None
                    assert process["actual_native_identity"]["actual_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
                    assert process["limits"]["wall_seconds"]==180
                    report["fixed_native_entries"]+=result["native_entries"];report["fixed_VM_entries"]+=result["vm_entries"]
                    report["actual_primitive_ACKs"]+=result["unchanged_inner_replayer"]["actual_primitive_acks"]
                    report["processes"].append(dict(path=str(carrier.output),process=process,replay=result))
                    report["physical_cases"].append(name);save(out/"summary.json",report)
                assert report["physical_cases"]==[x[0] for x in selected]
            else:
                all_witnesses={}
                for group in range(5):
                    path=evidence/("physical-"+str(group))/"summary.json";part=json.loads(pin(path))
                    assert part["status"]=="PASS" and part["source_pins_unchanged"]
                    for row in part["witnesses"]:
                        assert row["name"] not in all_witnesses
                        all_witnesses[row["name"]]=row
                assert set(all_witnesses)=={r[0] for r in CASES}
                def get(row,key):
                    item=row[key];raw=pin(item["path"],item["sha256"]);assert len(raw)==item["bytes"];return raw
                pid=all_witnesses["pid-first"]
                bs=get(pid,"source");br=get(pid,"peer_before");iw=get(pid,"issued_workspace")
                cs=get(pid,"completion_source");cr=get(pid,"peer_after")
                controls=[]
                def add(name,s,r,w):controls.append((name,bytes(s),bytes(r),bytes(w)))
                def changed(raw,at,value):
                    result=bytearray(raw);h.p(result,at,value);return bytes(result)
                for at,value in ((0,0),(8,9),(16,0),(24,0),(32,0),(48,0),(56,0),(64,1),
                    (128,0),(136,2),(160,0),(168,0),(184,32),(200,4096),(256,255),(376,0),
                    (384,0),(400,999),(512,0),(520,0),(528,0),(552,5),(560,0),(568,4096),(576,1)):
                    candidate=changed(bs,at,value)
                    if at in (16,24,520,528):
                        companion={16:24,24:16,520:528,528:520}[at];candidate=changed(candidate,companion,0)
                    add("BEGIN-field-"+str(at),candidate,br,bytes(512))
                for at,value in ((0,0),(8,2),(16,1),(24,1),(32,4095),(40,0),(48,0),(56,1),(64,0),(72,0),(80,0),(88,1)):
                    add("PEER-before-"+str(at),bs,changed(br,at,value),bytes(512))
                for size in (0,7,8,255,511):
                    add("short-workspace-"+str(size),bs,br,bytes(size))
                add("source-short",bs[:639],br,bytes(512))
                add("peer-short",bs,br[:127],bytes(512))
                bad=bytearray(512);h.p(bad,24,1);add("nonzero-initial-workspace",bs,br,bad)
                for at,value in ((40,0),(48,h.q(cr,48)+1),(48,0),(56,1),(64,0),(72,h.q(br,72)),
                    (80,0),(88,1),(128,0)):
                    add("COMPLETE-peer-"+str(at)+"-"+str(value),cs,changed(cr,at,value),iw)
                for at,value in ((16,h.q(cs,16)+1),(32,2),(48,h.q(cs,48)+1),(56,0),(640,1)):
                    if at<len(cs):add("COMPLETE-source-"+str(at),changed(cs,at,value),cr,iw)
                fs=128+h.q(cr,16)+256;outbase=fs-256
                for delta,value in ((0,0),(8,1),(16,0),(32,0),(40,0),(48,31),(56,4096),(112,0),(120,0),(128,1),(176,0),(200,1)):
                    add("COMPLETE-FS-"+str(delta),cs,changed(cr,fs+delta,value),iw)
                for delta,value in ((0,0),(8,1),(32,0),(40,0),(64,0),(104,0),(112,1),(128,0),(176,0)):
                    add("COMPLETE-outer-"+str(delta),cs,changed(cr,outbase+delta,value),iw)
                done=get(pid,"done_workspace")
                add("double-completion",cs,cr,done)
                assert len({row[0] for row in controls})==len(controls)==EXPECTED_PROTOCOL_CONTROLS
                selected=controls[args.group::4];assert selected
                for label,s,r,w in selected:
                    code,bad=pair.call(label,s,r,w);assert code==BAD,(label,"expected refusal")
                    if len(bad)>=8:assert h.q(bad,0)==h.magic(b"HIAUFB01")
                    if len(bad)>=512:
                        code,bad2=pair.call(label+"-persistent",bs,br,bad);assert code==BAD and h.q(bad2,0)==h.magic(b"HIAUFB01")
                    report["protocol_controls"].append(label);save(out/"summary.json",report)
                report["all_protocol_control_names"]=[row[0] for row in controls]
                report["protocol_total_inventory"]=len(controls)
                if args.group==0:
                    # Explicit synthetic private projection, not a forged actual
                    # OS or installed lease. Proves UID zero is representable.
                    uid=all_witnesses["geteuid"];s=get(uid,"completion_source");r=bytearray(get(uid,"peer_after"))
                    offset=128+h.q(r,16)+256;h.p(r,offset+64,0)
                    code,w=pair.call("private-UID-zero-projection",s,bytes(r),get(uid,"issued_workspace"))
                    assert code==0 and h.q(w,h.q(w,304)+72)==0
                    report["private_positive_controls"]=["UID-zero-not-actual-OS-receipt"]
            assert report["framer_VM_entries"]==report["framer_native_entries"]>0
            report.update(status="PASS",all_complete_return_peer_workspace_bytes_equal=True,
                actual_input_and_peer_mprotect_readonly=True,no_masks=True,original_42_suite_not_reexecuted=True)
        for module in tuple(sys.modules.values()):
            filename=getattr(module,"__file__",None)
            if filename:
                path=Path(filename).resolve()
                if path.is_relative_to(ref) and path.suffix==".py":pin(path)
    except BaseException as error:
        report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        if image is not None:
            try:image._mapping.close()
            except BaseException as error:
                report["status"]="FAIL";report["image_cleanup_error"]=repr(error)
        after={};changes=[]
        for path,row in pins.items():
            try:
                info=Path(path).lstat();assert stat.S_ISREG(info.st_mode) and not Path(path).is_symlink()
                raw=Path(path).read_bytes();after[path]=dict(path=path,bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(info.st_mode))
                if after[path]!=row:changes.append(path)
            except BaseException as error:changes.append(dict(path=path,error=repr(error)))
        report.update(source_before=pins,source_after=after,source_pins_unchanged=not changes,
            source_changes=changes,wall_ns=time.monotonic_ns()-started,CPU_ns=time.process_time_ns()-cpu)
        if changes:report["status"]="FAIL"
        save(out/"summary.json",report)
        print("NAMESPACE_RAW_FS_FRAMER_RESULT "+json.dumps({k:v for k,v in report.items()
            if k not in ("processes","witnesses","source_before","source_after")},sort_keys=True),flush=True)
    return 0 if report["status"]=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
