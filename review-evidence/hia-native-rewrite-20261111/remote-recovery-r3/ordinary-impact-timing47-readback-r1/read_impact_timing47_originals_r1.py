"""Read every original impact47 timing archive byte without target execution.

The original source/image identities, summaries and complete raw trace streams
are immutable. Lossless gzip envelopes preserve raw JSON and u64 byte spelling.
This reader does not rerun HIA, B3, VM, ELF, or replace the original FAIL.
"""
from __future__ import annotations
import base64,gzip,json,os,resource,shutil,stat,sys,tarfile,time,traceback
from hashlib import sha1,sha256
from pathlib import Path,PurePosixPath
assert sys.version_info[:3]==(3,12,14)
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
CONFIG=json.loads("{\"run\":43208616674,\"job\":131150087777,\"head\":\"58a5b2b462d312f77f9b0431aa230a7bfa1af993\",\"artifact\":13940337283,\"declared_outer_ZIP_bytes\":115966028,\"declared_outer_ZIP_sha256\":\"e433e5b792cc9eab19404be5d6d3b337d11cc86498d1da9169a3e829eb46653a\",\"archive_bytes\":60650668,\"archive_sha256\":\"401fa283da225118a76527c7115b1be058c684458136410ca2d4a01ef15894a9\",\"index_bytes\":1803551,\"index_sha256\":\"f25f4c0bf4f92a1345a5cd237098cca0c99b53321b94e0f4ea508cacf4d50787\",\"members\":3249,\"raw_bytes\":373984770,\"source_roles\":[{\"role\":2,\"bytes\":66816,\"sha256\":\"86d9f970ac45217ac16dc89422e80e8757f3c16d789baa881f054ff75cff323e\",\"original_source_path\":\"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/ordinary-impact-coordinator-original-role-readback/roles/2/source.hiaasm\",\"image_bytes\":94255,\"image_sha256\":\"1fa8e81f3ebe9cc5ae3c545d0310463e00bf884a0254c3cab6c2a6949580b9f2\"},{\"role\":22,\"bytes\":33683,\"sha256\":\"a30377e1f08a3426cfffe609ddbe35de67e87791cb0e9645c79e063f5d3d205a\",\"original_source_path\":\"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/ordinary-impact-coordinator-original-role-readback/roles/22/source.hiaasm\",\"image_bytes\":38349,\"image_sha256\":\"7bca81777197af059b1b5c48e340c0215214370fec007bb82ae5cadca81ef274\"},{\"role\":24,\"bytes\":89746,\"sha256\":\"74853c603ce8cdd4dfc910f61c728d67381391066e5757d8916c69c65448b821\",\"original_source_path\":\"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/ordinary-impact-coordinator-original-role-readback/roles/24/source.hiaasm\",\"image_bytes\":124040,\"image_sha256\":\"ee578c128bbe28cd920168aa518a05e76132c3b503ea3e941f4a2129d657e0d6\"},{\"role\":25,\"bytes\":71056,\"sha256\":\"b485f1a932e0425cd6eec733e1ba5822aef0d80a5bf846a43e1fc6571be80968\",\"original_source_path\":\"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/ordinary-impact-coordinator-original-role-readback/roles/25/source.hiaasm\",\"image_bytes\":108446,\"image_sha256\":\"499c065bfb39ae07a0602057f991d480ca5c05892122faa6dee7e09061539d48\"},{\"role\":26,\"bytes\":114065,\"sha256\":\"2ea6509f58117cdc86ef21f24adc747b3ac8cdc37ddd01c1a216d981a41b2233\",\"original_source_path\":\"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/ordinary-impact-coordinator-original-role-readback/roles/26/source.hiaasm\",\"image_bytes\":164212,\"image_sha256\":\"6636cf6974a93d21408838b3167a2860096b3ce067446a2ba9600a2971c6db7a\"},{\"role\":27,\"bytes\":406269,\"sha256\":\"96f91566f1e99a40a8cee6f5f4d479d2264411d3b19288e7b140b1e6388039b2\",\"original_source_path\":\"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/ordinary-impact-coordinator-original-role-readback/roles/27/source.hiaasm\",\"image_bytes\":595278,\"image_sha256\":\"c83de1c67a83f1fc024462eec9316b2a4af475801219cdfb6d0dc9162f26b0a9\"},{\"role\":44,\"bytes\":90625,\"sha256\":\"501dbad1ce76e26849a6052d12cdaa4f99f743f834ece5a7440001c51990256f\",\"original_source_path\":\"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/ordinary-impact-coordinator-original-role-readback/roles/44/source.hiaasm\",\"image_bytes\":132589,\"image_sha256\":\"c59823e52bc59d976d294b11995e2640b73abb051d851686ae0701b90223e1ad\"},{\"role\":46,\"bytes\":161943,\"sha256\":\"68c0ddba4e02d48ea1b205ff2f6e2ea65dbddb3aad0e35cfb19085960daf0816\",\"original_source_path\":\"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/ordinary-impact-coordinator-original-role-readback/roles/46/source.hiaasm\",\"image_bytes\":221718,\"image_sha256\":\"3b02302959d0f19503770db378360058ef81d354f856c256c4ce3d68b9731ba1\"},{\"role\":56,\"bytes\":258059,\"sha256\":\"364e131f7eb15f670b26dc6d97f75d8d9a037f7e738edf670d57c2bd1bb5645d\",\"original_source_path\":\"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/root-recovery/workspace/native-ordinary-impact-coordinator-r2/development/build-r1/compiled/ordinary-patch-coordinator/source.hiaasm\",\"image_bytes\":349395,\"image_sha256\":\"488585e00435c7519538497580e1c081d02efd42cedb34ac58a7fe4eef075100\"},{\"role\":57,\"bytes\":268976,\"sha256\":\"80c074a185e5ecaadb413df589e58fe13cd5d610332bd041f1593b4799d4e276\",\"original_source_path\":\"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/root-recovery/workspace/native-ordinary-impact-coordinator-r2/development/build-r1/compiled/ordinary-patch-prepare/source.hiaasm\",\"image_bytes\":377713,\"image_sha256\":\"8a5f5f26407cfd979615d6c937e5edabe0104ef06ea293f8b65976a09381f25b\"},{\"role\":58,\"bytes\":119278,\"sha256\":\"92e1d6da7855bad92f0bdd9004252d6013b8e21d88382f949d53cdab6bea12c2\",\"original_source_path\":\"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/ordinary-impact-coordinator-original-role-readback/roles/58/source.hiaasm\",\"image_bytes\":165054,\"image_sha256\":\"b9f0acbb937a27bb8838d4dc941fbbbb4b54c705636d86cd97f53262423176df\"},{\"role\":59,\"bytes\":229889,\"sha256\":\"e0809903daba34e3fb5392627850077c45b2d2e0e7061ee1230e6886ace78334\",\"original_source_path\":\"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/root-recovery/workspace/native-ordinary-impact-coordinator-r2/development/build-r1/compiled/ordinary-patch-receipt/source.hiaasm\",\"image_bytes\":335496,\"image_sha256\":\"a436aa64a590d1335097ceb1d7778ce7b8405eb2ed1a507ef983b5fe69cb7cd2\"},{\"role\":60,\"bytes\":272276,\"sha256\":\"9fea0c0a76787a3648e21f1c0412487005b2d2e233b796eec63a3de1eb27c67e\",\"original_source_path\":\"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/root-recovery/workspace/native-ordinary-impact-coordinator-r2/development/build-r1/compiled/ordinary-static-impact/source.hiaasm\",\"image_bytes\":384709,\"image_sha256\":\"595660331cd58fcab5e331cc9548c5b91082afa2904cdb7bb36592abec8786d9\"},{\"role\":63,\"bytes\":153786,\"sha256\":\"7362f885a9da0cc26a52e2930c02dc633ac7e50080e0ad0f622f62da53ffaf9c\",\"original_source_path\":\"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/root-recovery/workspace/native-ordinary-impact-coordinator-r2/development/build-r1/compiled/ordinary-patch-object-prefix/source.hiaasm\",\"image_bytes\":226229,\"image_sha256\":\"f6300b41f981399e5db47a98eb2e30585c61e528df610bdde7d29d1709e29255\"}],\"summary_pins\":[{\"actual_ELF_processes_started\":null,\"actual_fresh_B3\":null,\"build_status\":null,\"bytes\":10006,\"error\":null,\"error_class\":null,\"parent_CPU_seconds\":null,\"parent_plus_children_CPU_seconds\":null,\"path\":\"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/root-recovery/workspace/native-original-impact-timing-r1/original-readback/summary.json\",\"sha256\":\"32665ec0724fc95933dabdd3387ed495d043f64d773d223a59e3941f932ee15c\",\"status\":\"PASS_READ_ONLY\"},{\"actual_ELF_processes_started\":null,\"actual_fresh_B3\":1,\"build_status\":\"PASS\",\"bytes\":21468,\"error\":null,\"error_class\":null,\"parent_CPU_seconds\":null,\"parent_plus_children_CPU_seconds\":2.369033,\"path\":\"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/root-recovery/workspace/native-original-impact-timing-r1/build/summary.json\",\"sha256\":\"667657070f3b439e75639b5a5c2f1657e0754359748eba1e440dbbfce9b423db\",\"status\":\"BUILT_DIAGNOSTIC_ONLY\"},{\"actual_ELF_processes_started\":3,\"actual_fresh_B3\":null,\"build_status\":null,\"bytes\":9089,\"error\":null,\"error_class\":null,\"parent_CPU_seconds\":null,\"parent_plus_children_CPU_seconds\":86.048422,\"path\":\"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/root-recovery/workspace/native-original-impact-timing-r1/capture/summary.json\",\"sha256\":\"2284c1a6650a9c487eaaccfc3d8b8fb651cc1c8653aa259e8448f380f92b1244\",\"status\":\"PASS_DIAGNOSTIC_CAPTURE_ONLY\"},{\"actual_ELF_processes_started\":null,\"actual_fresh_B3\":null,\"build_status\":null,\"bytes\":173627,\"error\":null,\"error_class\":null,\"parent_CPU_seconds\":0.253542,\"parent_plus_children_CPU_seconds\":null,\"path\":\"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/root-recovery/workspace/native-original-impact-timing-r1/analysis/summary.json\",\"sha256\":\"86afae0c6cdbcca5169fc608955e4fa1d7e3f93a743edcf88d5492220f3af9b2\",\"status\":\"PASS_TIMING_ANALYSIS_ONLY\"}]}")
DOWNLOAD=Path(os.environ["HIA_TIMING47_ORIGINALS"]).resolve()
OUT=Path(os.environ["HIA_TIMING47_READBACK_OUTPUT"]).resolve()
OUT.mkdir(parents=True,exist_ok=False)
START=time.monotonic_ns();CPU=time.process_time();PINS={};envelopes=[];source_matches={}
details=dict(schema="hia-impact47-exact-original-timing-readback-v1",
 scope="READ_ONLY_FULL_ORIGINAL_ARCHIVE_SUMMARIES_TRACES_AND_HIA_SOURCE",
 source=CONFIG,new_HIA=0,new_B3=0,new_VM=0,new_native=0,
 semantic_qualification=False,original_large_valid_FAILURE_unchanged=True,
 whole_stack_closed=False,production_activation=False,outer_ZIP_independently_read=False)
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def identity(raw):return dict(bytes=len(raw),sha256=digest(raw),gitsha=gitsha(raw))
def file_identity(path):
    st=path.lstat()
    assert stat.S_ISREG(st.st_mode) and st.st_nlink==1,str(path)
    h=sha256();n=0
    with path.open("rb") as f:
        while True:
            raw=f.read(1<<20)
            if not raw:break
            n+=len(raw);h.update(raw)
    assert n==st.st_size,str(path)
    return dict(bytes=n,sha256=h.hexdigest(),mode=stat.S_IMODE(st.st_mode))
def pin(path,expected=None):
    path=Path(path);row=file_identity(path)
    if path in PINS:assert PINS[path]==row,str(path)
    if expected:
        for key in ("bytes","sha256"):
            if key in expected:assert row[key]==expected[key],(str(path),key)
    PINS[path]=row
    return row
def save(name,raw,mode=0o644):
    p=PurePosixPath(name)
    assert name and not p.is_absolute() and ".." not in p.parts and all(x for x in p.parts)
    path=OUT.joinpath(*p.parts);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("xb") as f:f.write(raw)
    path.chmod(mode)
    assert file_identity(path)==dict(bytes=len(raw),sha256=digest(raw),mode=mode)
    return path
def encode(label,raw,origin,mode):
    compressed=gzip.compress(raw,compresslevel=9,mtime=0)
    assert gzip.decompress(compressed)==raw
    row=dict(label=label,origin=origin,mode=mode,**identity(raw),
             gzip_bytes=len(compressed),gzip_sha256=digest(compressed),
             encoding="complete-gzip-base64",raw_JSON_never_reserialized=True)
    save("originals/"+label,raw,mode)
    save("encoded-originals/"+label+".gzip",compressed)
    record=dict(row,base64=base64.b64encode(compressed).decode("ascii"))
    save("encoded-originals/"+label+".envelope.json",
         (json.dumps(record,sort_keys=True)+"\n").encode())
    envelopes.append((row,compressed))
    return row
def exact_member_name(name):
    p=PurePosixPath(name)
    assert name and str(p)==name and not p.is_absolute() and ".." not in p.parts
    return p
def original_root(path):
    marker="/native-original-impact-timing-r1/"
    assert path.count(marker)==1,path
    return "impact-timing-complete/"+path.split(marker,1)[1]
def main():
    candidates=sorted(DOWNLOAD.rglob("evidence.tar.xz"))
    assert len(candidates)==1,[str(p) for p in candidates]
    archive=candidates[0];index_path=archive.with_name("evidence-members.json")
    pin(archive,dict(bytes=CONFIG["archive_bytes"],sha256=CONFIG["archive_sha256"]))
    pin(index_path,dict(bytes=CONFIG["index_bytes"],sha256=CONFIG["index_sha256"]))
    pin(Path(__file__).resolve())
    # The complete original archive is retained before parsing any member.
    archive_copy=OUT/"original-evidence.tar.xz"
    with archive.open("rb") as src,archive_copy.open("xb") as dst:shutil.copyfileobj(src,dst,1<<20)
    assert file_identity(archive_copy)["sha256"]==CONFIG["archive_sha256"]
    index_raw=index_path.read_bytes();save("original-member-index.json",index_raw)
    rows=json.loads(index_raw);assert isinstance(rows,list)
    indexed={r.get("name",r.get("path")):r for r in rows}
    assert len(indexed)==len(rows)==CONFIG["members"]
    by_source={}
    for row in CONFIG["source_roles"]:
        key=(row["bytes"],row["sha256"])
        assert key not in by_source
        by_source[key]=row
    exact={}
    for row in CONFIG["summary_pins"]:
        name=original_root(row["path"]);assert name not in exact
        exact[name]=dict(bytes=row["bytes"],sha256=row["sha256"])
    extra={
        "impact-timing-complete/build/manifest.json",
        "impact-timing-complete/build/mechanical-source-reverse-proof.json",
        "impact-timing-complete/build/source-and-image-pins.json",
        "impact-timing-complete/capture/captured-processes.json",
        "impact-timing-complete/capture/source-pins.json",
        "impact-timing-complete/analysis/input-pins.json",
    }
    for label in ("calibration-original","calibration-timed","large-valid-timed"):
        for suffix in ("process.json","timing.raw","stdout.bin","stderr.bin"):
            extra.add("impact-timing-complete/capture/"+label+"/"+suffix)
    wanted=set(exact)|extra
    missing=wanted-set(indexed);assert not missing,sorted(missing)
    kept={};seen=set();total=0;files=0;directories=0
    with tarfile.open(archive,mode="r|xz") as tf:
        for member in tf:
            name=member.name;exact_member_name(name)
            assert name not in seen and name in indexed,name
            seen.add(name);row=indexed[name]
            mode=int(row["mode"],8) if isinstance(row["mode"],str) else row["mode"]
            assert member.mode==mode and not member.mode&0o7000,(name,"mode")
            if member.isdir():
                assert row.get("kind")=="directory" and member.size==0,name
                directories+=1;continue
            assert member.isfile(),name
            assert member.size==row["bytes"],(name,"header size")
            h=sha256();n=0;parts=[]
            key=(row["bytes"],row["sha256"])
            keep=name in wanted or key in by_source
            stream=tf.extractfile(member);assert stream is not None,name
            while True:
                chunk=stream.read(1<<20)
                if not chunk:break
                n+=len(chunk);h.update(chunk)
                if keep:parts.append(chunk)
            assert n==member.size and h.hexdigest()==row["sha256"],(name,"bytes SHA")
            total+=n;files+=1
            if keep:
                raw=b"".join(parts);assert len(raw)==n
                if name in wanted:
                    assert name not in kept
                    kept[name]=(raw,mode)
                if key in by_source:
                    role=by_source[key]["role"]
                    matched=source_matches.setdefault(str(role),[])
                    matched.append(dict(name=name,mode=mode,**identity(raw)))
                    # Duplicate original archive aliases must be exactly equal.
                    previous=kept.get("role-source-"+str(role))
                    if previous is None:kept["role-source-"+str(role)]=(raw,mode)
                    else:assert previous[0]==raw,(role,"source alias bytes mismatch")
    assert seen==set(indexed) and len(seen)==CONFIG["members"]
    assert total==CONFIG["raw_bytes"]
    assert len(source_matches)==len(CONFIG["source_roles"])
    details["complete_archive_readback"]=dict(members=len(seen),files=files,
        directories=directories,raw_bytes=total,every_indexed_byte_and_mode_verified=True)
    details["source_matches"]=source_matches
    for name in sorted(wanted):
        raw,mode=kept[name]
        if name in exact:
            assert len(raw)==exact[name]["bytes"] and digest(raw)==exact[name]["sha256"],name
        label=name.removeprefix("impact-timing-complete/")
        encode(label,raw,name,mode)
    for row in CONFIG["source_roles"]:
        role=str(row["role"]);raw,mode=kept["role-source-"+role]
        assert len(raw)==row["bytes"] and digest(raw)==row["sha256"]
        encode("HIA-source/role-"+role+".hiaasm",raw,source_matches[role],mode)
    # Semantic observations occur only after all original archive bytes are verified.
    capture=json.loads(kept["impact-timing-complete/capture/summary.json"][0])
    analysis=json.loads(kept["impact-timing-complete/analysis/summary.json"][0])
    build=json.loads(kept["impact-timing-complete/build/summary.json"][0])
    assert capture["status"]=="PASS_DIAGNOSTIC_CAPTURE_ONLY"
    assert capture["actual_ELF_processes_started"]==capture["actual_processes_with_returned_record"]==3
    assert capture["semantic_images_changed"]==0 and not capture["semantic_qualification"]
    assert capture["source_and_image_before_after_equal"] and capture["parent_plus_children_CPU_seconds"]<90
    assert all(r["complete_calibration_returncode_stdout_stderr_equal_original"] is True
               for r in capture["processes"][:2])
    assert analysis["status"]=="PASS_TIMING_ANALYSIS_ONLY" and analysis["complete_inputs_before_after_equal"]
    assert analysis["actual_new_HIA"]==analysis["actual_new_B3"]==analysis["actual_new_VM"]==analysis["actual_new_native"]==0
    assert build["build_status"]=="PASS" and build["actual_fresh_B3"]==1
    assert build["actual_native_packer_entries"]==1 and build["retained_HIA_images"]==63
    by_label={r["label"]:r for r in capture["processes"]}
    assert set(by_label)=={"calibration-original","calibration-timed","large-valid-timed"}
    for label,record in by_label.items():
        for kind,suffix in (("trace","timing.raw"),("stdout","stdout.bin"),("stderr","stderr.bin")):
            raw=kept["impact-timing-complete/capture/"+label+"/"+suffix][0]
            row=record["streams"][kind]
            assert (len(raw),digest(raw))==(row["bytes"],row["sha256"]),(label,kind)
    details["actual_original_result"]=dict(build_status=build["status"],
        capture_status=capture["status"],analysis_status=analysis["status"],
        fresh_B3=1,actual_packer_entries=1,actual_ELF_processes=3,
        capture_parent_plus_children_CPU_seconds=capture["parent_plus_children_CPU_seconds"],
        complete_calibration_equal_original=True,
        large_returncode=by_label["large-valid-timed"]["returncode"],
        original_large_qualification_rewritten=False,semantic_qualification=False)
    details["selected_complete_originals"]=[row for row,compressed in envelopes]
    lines=[]
    for row,compressed in envelopes:
        for offset in range(0,len(compressed),12288):
            part=compressed[offset:offset+12288]
            lines.append("HIA_TIMING47_RAW_GZIP "+json.dumps(dict(row,offset=offset,
                part_bytes=len(part),base64=base64.b64encode(part).decode()),sort_keys=True))
        lines.append("HIA_TIMING47_RAW_GZIP_END "+json.dumps(row,sort_keys=True))
    console_bytes=sum(len(line.encode())+1 for line in lines)
    assert console_bytes<=900000,("original-envelope console budget",console_bytes)
    for line in lines:print(line,flush=True)
    details["complete_original_envelope_console_bytes"]=console_bytes
status="FAIL"
try:
    main()
    status="PASS_READ_ONLY"
except BaseException as exc:
    details.update(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
    traceback.print_exc()
finally:
    after=[]
    for path,row in PINS.items():
        try:assert file_identity(path)==row,str(path)
        except BaseException as exc:after.append(dict(path=str(path),error_class=type(exc).__name__,error=str(exc)))
    cpu=time.process_time()-CPU;elapsed=time.monotonic_ns()-START
    if after or cpu>=90 or elapsed>=180000000000:status="FAIL"
    details.update(status=status,pinned_input_aftercheck_errors=after,
        pinned_inputs_before_after_equal=not after,pinned_inputs=[dict(path=str(p),**r) for p,r in PINS.items()],
        parent_CPU_seconds=cpu,elapsed_ns=str(elapsed),
        limits=dict(CPU_seconds=90,wall_seconds=180,address_space_bytes=1<<30))
    save("readback-summary.json",(json.dumps(details,sort_keys=True,indent=2)+"\n").encode())
    print("HIA_TIMING47_READBACK_SUMMARY "+json.dumps(details,sort_keys=True),flush=True)
if status!="PASS_READ_ONLY":raise SystemExit(1)
