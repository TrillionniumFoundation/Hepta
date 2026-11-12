"""Read the exact failed impact41 large-valid process and complete original archive.

No subject imports, HIA generation, B3, VM, native execution, or failure relabeling.
"""
from pathlib import Path,PurePosixPath
from hashlib import sha1,sha256
import base64,io,json,lzma,os,resource,stat,struct,tarfile,time,traceback,zlib
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
REPO=Path(os.environ["GITHUB_WORKSPACE"]).resolve()
DOWNLOAD=Path(os.environ["HIA_IMPACT41_DIR"]).resolve()
OUT=Path(os.environ["HIA_CI_OUTPUT"]).resolve()
OUT.mkdir(parents=True,exist_ok=False)
CONFIG=json.loads("{\"impact\":{\"bytes\":23487708,\"sha256\":\"02a282f30d5aa4b57e070583867758022830152743131421d303bff6f90014d2\",\"index_bytes\":1376145,\"index_sha256\":\"9e63275d5f9541d69aa8bf75a0c2e2fa8f736af0fdc62374fdcfdd2ef97b4b48\",\"members\":3090,\"raw_bytes\":150697441,\"run\":43189935529,\"job\":131086386743,\"artifact\":13930443158,\"declared_outer_ZIP_bytes\":76043989,\"declared_outer_ZIP_sha256\":\"66c4f8c0c35df8816f8a50335422df5df520b7bb1b34788a0836249b96506baf\"},\"archives\":[]}")
started=time.monotonic_ns()
PINS={};originals=[];authors={};observations={}
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def identity(raw):return dict(bytes=len(raw),sha256=digest(raw),gitsha=gitsha(raw))
def pin(path,expected=None):
    path=Path(path);st=path.lstat()
    assert stat.S_ISREG(st.st_mode) and st.st_nlink==1,path
    raw=path.read_bytes();observed=(len(raw),digest(raw),stat.S_IMODE(st.st_mode))
    if path in PINS:assert PINS[path]==observed,path
    PINS[path]=observed
    if expected:
        for key,want in expected.items():
            if key in ("bytes","sha256","gitsha"):assert identity(raw)[key]==want,(str(path),key)
    return raw
def save(name,raw):
    relative=PurePosixPath(name)
    assert not relative.is_absolute() and all(p not in ("","..") for p in relative.parts),name
    target=OUT.joinpath(*relative.parts);target.parent.mkdir(parents=True,exist_ok=True)
    if target.exists():assert target.read_bytes()==raw,target
    else:target.write_bytes(raw)
    assert target.read_bytes()==raw
    return target
def emit(name,raw):
    row=dict(name=name,**identity(raw));save("originals/"+name,raw)
    originals.append(row)
    for offset in range(0,len(raw),12288):
        part=raw[offset:offset+12288]
        print("HIA_REVIEW_ORIGINAL "+json.dumps(dict(row,offset=offset,part_bytes=len(part),
            base64=base64.b64encode(part).decode()),sort_keys=True),flush=True)
    print("HIA_REVIEW_ORIGINAL_END "+json.dumps(row,sort_keys=True),flush=True)
def selected_author(name):
    p=PurePosixPath(name)
    return p.suffix==".py" and ("diagnostic" in p.name or p.name in
        ("hia_composite_lowering_driver_main.py","hia_composite_lowering_driver_stream.py",
         "generate_hia_program_admission_driver.py","generate_hia_composite_publication_driver.py",
         "generate_hia_legacy_projection.py","generate_hia_legacy_import_projection.py"))
def tar_rows(raw,index,kind):
    rows=index if kind=="array" else index["entries" if kind=="entries-extra-manifest" else "members"]
    expected={r.get("name",r.get("path")):r for r in rows};assert len(expected)==len(rows)
    seen=set();found={};directories=0
    with tarfile.open(fileobj=io.BytesIO(raw),mode="r|xz") as tf:
        for member in tf:
            name=member.name;rel=PurePosixPath(name)
            assert name and name not in seen and not rel.is_absolute() and ".." not in rel.parts
            seen.add(name);assert not member.mode&0o7000
            row=expected.get(name)
            if row is None:
                assert kind=="entries-extra-manifest" and name=="MANIFEST.json",(kind,name)
            else:
                mode=int(row["mode"],8) if isinstance(row["mode"],str) else row["mode"]
                assert member.mode==mode,(name,"mode")
            if member.isdir():
                assert row is not None and row.get("kind")=="directory"
                directories+=1;continue
            assert member.isfile(),name
            data=tf.extractfile(member).read();assert len(data)==member.size
            if row is not None:
                assert len(data)==row["bytes"] and digest(data)==row["sha256"],name
            found[name]=(data,member.mode)
    assert seen==set(expected) or (kind=="entries-extra-manifest" and seen==set(expected)|{"MANIFEST.json"})
    return found,dict(members=len(seen),files=len(found),directories=directories,
        original_bytes=sum(len(v[0]) for v in found.values()),every_indexed_byte_and_mode_verified=True)
def original_archive(spec):
    parts=[pin(REPO/r["path"],r) for r in spec["parts"]]
    raw=b"".join(parts)
    assert len(raw)==spec["bytes"] and digest(raw)==spec["sha256"]
    index_raw=pin(REPO/spec["index"]["path"],spec["index"])
    if "decompressed_sha256" in spec["index"]:
        index_raw=lzma.decompress(index_raw)
        assert len(index_raw)==spec["index"]["decompressed_bytes"] and digest(index_raw)==spec["index"]["decompressed_sha256"]
    entries,summary=tar_rows(raw,json.loads(index_raw),spec["kind"])
    assert summary["files"]==spec["files"]
    if "members" in spec:assert summary["members"]==spec["members"]
    for name,(data,mode) in entries.items():
        if selected_author(name):
            h=digest(data);row=authors.setdefault(h,dict(identity(data),origins=[],mode=mode))
            row["origins"].append(dict(archive=spec["label"],name=name))
            if len(row["origins"])==1:emit("authoring/"+h+"/"+PurePosixPath(name).name,data)
    return dict(summary,label=spec["label"],archive_sha256=spec["sha256"],subject_execution=False)
def impact_originals():
    spec=CONFIG["impact"];candidates=list(DOWNLOAD.rglob("evidence.tar.xz"))
    assert len(candidates)==1,[str(x) for x in candidates]
    archive=candidates[0];raw=pin(archive,spec)
    index_raw=pin(archive.with_name("evidence-members.json"),
        dict(bytes=spec["index_bytes"],sha256=spec["index_sha256"]))
    entries,summary=tar_rows(raw,json.loads(index_raw),"array")
    assert summary["members"]==spec["members"] and summary["original_bytes"]==spec["raw_bytes"]
    save("impact-original-member-index.json",index_raw)
    save("original-evidence.tar.xz",raw)
    for name,(data,mode) in entries.items():
        target=save("archive-originals/"+name,data)
        target.chmod(mode)
        assert stat.S_IMODE(target.stat().st_mode)==mode
    assert len(entries)==3090
    group_prefix="ordinary-impact-coordinator/development/native-"
    for name,(data,mode) in entries.items():
        if name in {group_prefix+group+"/summary.json" for group in ("large-valid","graph-long-report")}:
            emit("impact/"+name[len(group_prefix):],data)
    def record(group,kind,case):
        name=group_prefix+group+"/"+kind+"-%04d.json"%case
        data=entries[name][0];emit("impact/"+group+"/"+PurePosixPath(name).name,data)
        return json.loads(data)
    def cas(group,row):
        name=group_prefix+group+"/"+row["path"]
        data=zlib.decompress(entries[name][0])
        assert len(data)==row["bytes"] and digest(data)==row["sha256"],name
        return data
    facts=[]
    for group,case in (("large-valid",1),("graph-long-report",1)):
        pending=record(group,"pending",case);process=record(group,"process",case)
        streams={k:cas(group,process[k]) for k in ("stdin","stdout","stderr")}
        for key,data in streams.items():save("decoded/"+group+"/actual-"+key+".bin",data)
        expect=pending["expected"]
        fact=dict(group=group,case=case,returncode=process["returncode"],timed_out=process["timed_out"],
            elapsed_ns=process["elapsed_ns"],group_cpu_before=process["group_cpu_before"],
            group_cpu_after=process["group_cpu_after"],streams={k:identity(v) for k,v in streams.items()})
        if expect["kind"]=="result":
            components={k:cas(group,expect[k]) for k in ("candidate","receipt","impact")}
            for key,data in components.items():save("decoded/"+group+"/expected-"+key+".bin",data)
            wanted=struct.pack("<8Q",int.from_bytes(b"HIAEDR01","little"),1,
                *(len(components[k]) for k in ("candidate","receipt","impact")),0,0,0)+b"".join(components.values())
            actual=streams["stdout"];fact["wanted"]=identity(wanted)
            fact["complete_raw_equal"]=actual==wanted
            offset=next((i for i,(a,b) in enumerate(zip(actual,wanted)) if a!=b),min(len(actual),len(wanted)))
            fact["first_difference"]=offset if actual!=wanted else None
            fact["first_difference_actual_hex"]=actual[max(0,offset-32):offset+96].hex()
            fact["first_difference_expected_hex"]=wanted[max(0,offset-32):offset+96].hex()
            if len(actual)>=64:
                header=struct.unpack_from("<8Q",actual);fact["actual_header_decimal"]=[str(x) for x in header]
                if header[0]==int.from_bytes(b"HIAEDR01","little") and header[1]==1 and len(actual)==64+sum(header[2:5]):
                    at=64;checks={}
                    for key,length in zip(("candidate","receipt","impact"),header[2:5]):
                        value=actual[at:at+length];at+=length
                        check=dict(actual=identity(value),expected=identity(components[key]),raw_equal=value==components[key])
                        try:
                            a=json.loads(value);b=json.loads(components[key])
                            check["decoded_equal"]=a==b
                            check["actual_keys"]=list(a) if type(a) is dict else None
                            check["expected_keys"]=list(b) if type(b) is dict else None
                        except (ValueError,TypeError,UnicodeError) as exc:check["decode_error"]=str(exc)
                        checks[key]=check
                    fact["components"]=checks
            if group in ("semantic","interfaces","identity","impact-semantic"):
                for key,data in components.items():emit("impact/"+group+"/expected-"+key+".bin",data)
                for key,data in streams.items():emit("impact/"+group+"/actual-"+key+".bin",data)
        facts.append(fact)
    return dict(summary,source=spec,derived_buffer_observations=facts,
        original_qualification_status="FAIL_UNCHANGED",outer_ZIP_readback=False,subject_execution=False)
status="FAIL";result=dict(scope="READ_ONLY_COMPLETE_IMPACT41_ORIGINALS",new_HIA=0,new_B3=0,new_VM=0,new_native=0,
    whole_stack_closed=False,production_activation=False,original_failure_unchanged=True)
try:
    observations["impact"]=impact_originals()
    observations["author_archives"]=[]
    for path,(size,d,mode) in PINS.items():
        assert path.stat().st_size==size and stat.S_IMODE(path.stat().st_mode)==mode and digest(path.read_bytes())==d,path
    assert (time.monotonic_ns()-started)<180000000000
    status="PASS_READ_ONLY"
except BaseException as exc:
    result.update(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
    traceback.print_exc()
finally:
    after_errors=[]
    for path,(size,d,mode) in PINS.items():
        try:
            assert path.stat().st_size==size and stat.S_IMODE(path.stat().st_mode)==mode and digest(path.read_bytes())==d,path
        except BaseException as after_exc:
            after_errors.append(dict(path=str(path),error_class=type(after_exc).__name__,error=str(after_exc)))
    result["pinned_input_aftercheck_errors"]=after_errors
    result["pinned_inputs_before_after_equal"]=not after_errors
    if after_errors:status="FAIL"
    result.update(status=status,observations=observations,originals=originals,authors=list(authors.values()),
        pinned_inputs=len(PINS),elapsed_ns=time.monotonic_ns()-started,
        original_limits=dict(cpu_seconds=90,wall_seconds=180,address_space_bytes=1<<30))
    raw=(json.dumps(result,sort_keys=True,indent=2)+"\n").encode()
    save("summary.json",raw);print("HIA_REVIEW_SUMMARY "+json.dumps(result,sort_keys=True),flush=True)
if status!="PASS_READ_ONLY":raise SystemExit(1)
