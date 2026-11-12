"""Read exact failed impact buffers and original public diagnostic authors.

Read-only: no subject imports, generation, B3, VM, native execution or failure
reclassification. Raw originals are retained without JSON parse/re-encoding.
"""
from pathlib import Path,PurePosixPath
from hashlib import sha1,sha256
import base64,io,json,lzma,os,resource,stat,struct,tarfile,time,traceback,zlib
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
REPO=Path(os.environ["GITHUB_WORKSPACE"]).resolve()
DOWNLOAD=Path(os.environ["HIA_IMPACT39_DIR"]).resolve()
OUT=Path(os.environ["HIA_CI_OUTPUT"]).resolve()
OUT.mkdir(parents=True,exist_ok=False)
CONFIG=json.loads("{\"impact\":{\"bytes\":22964472,\"sha256\":\"b2e65dec5d4f55319342cc29fea9b83147eb2eed42f39b64ea17fe3722c5b1ed\",\"index_bytes\":603847,\"index_sha256\":\"10beaa850fd6042b85612701884e6be5829e7ea0c2718fca2826c6bce2265f23\",\"members\":1430,\"raw_bytes\":149045930,\"run\":43184755381,\"job\":131069068426,\"artifact\":13929055886},\"archives\":[{\"label\":\"lowering-main\",\"parts\":[{\"path\":\"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r3/lowering-main/main-reconstructed-r2-development.tar.xz\",\"gitsha\":\"8850d996db3d98127799092cb4c39dafb0096349\",\"bytes\":177348}],\"bytes\":177348,\"sha256\":\"480fe7ec354ecc2caced155cc35b830db406ce3988c0f33a4ee856ab8b61effc\",\"index\":{\"path\":\"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r3/lowering-main/members.json\",\"gitsha\":\"5946a7989219cf3ce0fa01c2be5f76deff42bd83\",\"bytes\":52092,\"sha256\":\"82674b5605feecc84560d0b478628e507eeec253b6ec2db559c64386bf4aaba0\"},\"files\":136,\"kind\":\"entries-extra-manifest\"},{\"label\":\"program-admission\",\"parts\":[{\"path\":\"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r10/program-admission-r1.tar.xz\",\"gitsha\":\"76b8bf2f75c3abed0564830bbf165f3571291cab\",\"bytes\":3730136}],\"bytes\":3730136,\"sha256\":\"3fcd6e2c10aacae6f84de0681a748531e3d8b130b87a29fbd34905783a0f7149\",\"index\":{\"path\":\"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r10/program-admission-original-member-manifest.json.xz\",\"gitsha\":\"a0dbd8e056621b1da26fbe202a80e96de3c53be2\",\"bytes\":73948,\"sha256\":\"f341aed5bb63943cc90dc8735922eba5209aaacdc8ce7aed710f41649ed249f0\",\"decompressed_bytes\":902052,\"decompressed_sha256\":\"8713f1e06861004374a44e70e32006f88d4dba552c9601d1e4caf0d76116562f\"},\"files\":2002,\"members\":2440,\"kind\":\"members\"},{\"label\":\"core-diagnostics\",\"parts\":[{\"bytes\":3145728,\"git_sha\":\"f04220c0ae9554d65b5edfe104eaee84892b0ab6\",\"path\":\"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r12/parts/core-diagnostics--development.tar.xz.part000\",\"sha256\":\"c0fece90af7b43900ec3f5360c55c362bffcd0b3cba86ca066b36c4f23cd53c2\",\"gitsha\":\"f04220c0ae9554d65b5edfe104eaee84892b0ab6\"},{\"bytes\":3145728,\"git_sha\":\"9ca3ea41e1a8d05a0d28750f5c79577270e3602d\",\"path\":\"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r12/parts/core-diagnostics--development.tar.xz.part001\",\"sha256\":\"ef62736ba3fb2041d3e76ae8239e29b7645150af67857d5f1589cf863e28d006\",\"gitsha\":\"9ca3ea41e1a8d05a0d28750f5c79577270e3602d\"},{\"bytes\":1283268,\"git_sha\":\"d639ce17c3c97be9d6fa3743f7f0da0f5c5a02e0\",\"path\":\"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r12/parts/core-diagnostics--development.tar.xz.part002\",\"sha256\":\"9b13d6a1b371fb4ca1ee5d9c78ead39ea2e8598d50fe3b7e2309573aede939c8\",\"gitsha\":\"d639ce17c3c97be9d6fa3743f7f0da0f5c5a02e0\"}],\"bytes\":7574724,\"sha256\":\"e4c2a842ee89971cab9b3406470cff50ef0f05fa9f1616c4ff3c140bfb352604\",\"index\":{\"path\":\"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r12/core-diagnostics/members.json\",\"gitsha\":\"966c7fb2e0fec3f80211d20de4ab1efcccebaef0\",\"bytes\":3064713,\"sha256\":\"5bc10652dda73f96a57b3a15e595a1dc476d254ed4481ea958c9aa2b4f544e81\"},\"files\":8355,\"members\":8355,\"kind\":\"array\"}]}")
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
        ("hia_composite_lowering_driver_main.py","generate_hia_program_driver.py"))
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
    group_prefix="ordinary-impact-coordinator/development/native-"
    for name,(data,mode) in entries.items():
        if name.startswith(group_prefix) and name.endswith("/summary.json"):
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
    for group,case in (("semantic",1),("interfaces",3),("identity",1),("impact-semantic",1),
                       ("graph-1024",1),("graph-dense",1),("large-valid",1),("graph-long-report",1)):
        pending=record(group,"pending",case);process=record(group,"process",case)
        streams={k:cas(group,process[k]) for k in ("stdin","stdout","stderr")}
        expect=pending["expected"]
        fact=dict(group=group,case=case,returncode=process["returncode"],timed_out=process["timed_out"],
            elapsed_ns=process["elapsed_ns"],group_cpu_before=process["group_cpu_before"],
            group_cpu_after=process["group_cpu_after"],streams={k:identity(v) for k,v in streams.items()})
        if expect["kind"]=="result":
            components={k:cas(group,expect[k]) for k in ("candidate","receipt","impact")}
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
status="FAIL";result=dict(scope="READ_ONLY_EXACT_ORIGINALS",new_HIA=0,new_B3=0,new_VM=0,new_native=0,
    whole_stack_closed=False,production_activation=False,original_failure_unchanged=True)
try:
    observations["impact"]=impact_originals()
    observations["author_archives"]=[original_archive(spec) for spec in CONFIG["archives"]]
    assert any(any(PurePosixPath(o["name"]).name=="hia_composite_lowering_driver_main.py" for o in row["origins"]) for row in authors.values())
    assert any(any(PurePosixPath(o["name"]).name=="generate_hia_program_driver.py" for o in row["origins"]) for row in authors.values())
    assert any(any("diagnostic" in PurePosixPath(o["name"]).name for o in row["origins"]) for row in authors.values())
    for path,(size,d,mode) in PINS.items():
        assert path.stat().st_size==size and stat.S_IMODE(path.stat().st_mode)==mode and digest(path.read_bytes())==d,path
    assert (time.monotonic_ns()-started)<180000000000
    status="PASS_READ_ONLY"
except BaseException as exc:
    result.update(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
    traceback.print_exc()
finally:
    result.update(status=status,observations=observations,originals=originals,authors=list(authors.values()),
        pinned_inputs=len(PINS),elapsed_ns=time.monotonic_ns()-started,
        original_limits=dict(cpu_seconds=90,wall_seconds=180,address_space_bytes=1<<30))
    raw=(json.dumps(result,sort_keys=True,indent=2)+"\n").encode()
    save("summary.json",raw);print("HIA_REVIEW_SUMMARY "+json.dumps(result,sort_keys=True),flush=True)
if status!="PASS_READ_ONLY":raise SystemExit(1)
