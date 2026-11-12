"""Read exact successful CI artifacts and preserve unabridged originals.
No project source, HIA image, B3 compiler, VM or native target is executed.
"""
from pathlib import Path,PurePosixPath
from hashlib import sha1,sha256
import base64,io,json,os,resource,signal,stat,sys,tarfile,time,traceback,zipfile
sys.dont_write_bytecode=True
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
def expired(*_):raise TimeoutError("readonly original artifact gate exceeded180seconds")
signal.signal(signal.SIGALRM,expired);signal.alarm(180)
START=time.monotonic_ns();SELF=Path(__file__).read_bytes()
AUDIT,CORE,OUT=map(lambda p:Path(p).resolve(),sys.argv[1:4])
OUT.mkdir(parents=True,exist_ok=False)
def ident(raw):
    return dict(bytes=len(raw),sha256=sha256(raw).hexdigest(),
        gitsha=sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest())
def file_ident(path):
    n=path.stat().st_size;h=sha256();g=sha1(b"blob "+str(n).encode()+b"\0");seen=0
    with path.open("rb") as stream:
        for raw in iter(lambda:stream.read(1<<20),b""):seen+=len(raw);h.update(raw);g.update(raw)
    assert seen==n
    return dict(bytes=n,sha256=h.hexdigest(),gitsha=g.hexdigest())
def save(name,raw):
    path=OUT/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);return path
def js(value):return (json.dumps(value,sort_keys=True,indent=2)+"\n").encode()
EXPECTED={
 "audit":dict(path=AUDIT,artifact=13926322477,run=43180758618,bytes=19269608,sha256="0423fb55eb3a22d7265b7910ad1e5d6c8cff3a4a9a17ca55cdbedf71a60fbcf8"),
 "core":dict(path=CORE,artifact=13927020426,run=43178823310,bytes=78164801,sha256="0d896692a5b35c1fce7f62f5bd44ae762c8c790b8e5d2a9e43d6a18d820136b8")}
summary=dict(status="FAIL",new_AST=0,new_B3=0,new_HIA=0,new_VM=0,new_native=0,
    whole_stack_closed=False,installed_activation=False,deleted_originals=0)
selected={};zip_rows=[];before={}
try:
    for label,pin in EXPECTED.items():
        path=pin["path"];observed=file_ident(path);before[label]=observed
        assert (observed["bytes"],observed["sha256"])==(pin["bytes"],pin["sha256"])
        members=[];seen=set()
        with zipfile.ZipFile(path) as archive:
            for item in archive.infolist():
                name=item.filename;p=PurePosixPath(name)
                assert not p.is_absolute() and ".." not in p.parts and str(p)==name.rstrip("/")
                assert name not in seen;seen.add(name)
                mode=(item.external_attr>>16)&65535
                assert stat.S_IFMT(mode) in (0,stat.S_IFREG,stat.S_IFDIR),name
                h=sha256();n=0;chunks=[]
                keep=(label=="audit" and (name.endswith("/complete-source-inventory.json") or
                    name.endswith("/complete-production-module-projection.json") or
                    name=="hia-complete-source-original-audit/summary.json"))
                keep=keep or (label=="core" and p.name in ("hia-cold.json","hia-language.json","hia-agent-journal-callers.json"))
                with archive.open(item) as stream:
                    for raw in iter(lambda:stream.read(1<<20),b""):
                        n+=len(raw);h.update(raw)
                        if keep:chunks.append(raw)
                assert n==item.file_size
                row=dict(name=name,bytes=n,sha256=h.hexdigest(),mode=mode,CRC=item.CRC,directory=item.is_dir())
                members.append(row)
                if keep:
                    key=label+"/"+p.name;assert key not in selected
                    selected[key]=b"".join(chunks);save("originals/"+key,selected[key])
        zip_rows.append(dict(label=label,artifact=pin["artifact"],run=pin["run"],original=observed,members=members))
    assert set(selected)=={"audit/complete-source-inventory.json","audit/complete-production-module-projection.json",
        "audit/summary.json","core/hia-cold.json","core/hia-language.json","core/hia-agent-journal-callers.json"},sorted(selected)
    inventory_raw=selected["audit/complete-source-inventory.json"]
    assert ident(inventory_raw)==dict(bytes=9847160,gitsha="9d8a36fcd6627abcdb02bc802f1507941da89f75",sha256="a08a7f1f3d5c9a35b7bef58987597b80e1f592b27b920c640fe4c054addaf7e9")
    inventory=json.loads(inventory_raw);audit=json.loads(selected["audit/summary.json"])
    assert inventory["git_head"]==audit["head"]=="e3ea7f33f1d7bf3350e4b54a9a8d3522746223c7"
    assert audit["status"]=="PASS_STATIC_AND_ORIGINAL_READBACK_ONLY"
    assert inventory["counts"]["files"]==5249 and inventory["counts"]["production_Python"]==156
    assert audit["original_retained_status"]=="FAIL_HOLD"
    cold=json.loads(selected["core/hia-cold.json"])
    language=json.loads(selected["core/hia-language.json"])
    callers=json.loads(selected["core/hia-agent-journal-callers.json"])
    assert cold["status"]=="COLD_SELFHOST_REPLAY_PASS" and len(cold["checks"])==11 and all(v is True for v in cold["checks"].values())
    assert language["status"]=="SELFHOST_LANGUAGE_COVERAGE_PASS"
    assert callers["status"]=="PASS"
    records=js(dict(schema="hia.exact-original-zip-members.v1",artifacts=zip_rows))
    save("complete-ZIP-member-index.json",records)
    selected["complete-ZIP-member-index.json"]=records
    archive_path=OUT/"complete-inventory-and-Core-original-reports.tar.xz"
    with tarfile.open(archive_path,mode="w:xz",preset=6) as archive:
        for name,raw in sorted(selected.items()):
            info=tarfile.TarInfo(name);info.size=len(raw);info.mode=420;info.mtime=0
            archive.addfile(info,io.BytesIO(raw))
    seen=set()
    with tarfile.open(archive_path,mode="r:xz") as archive:
        for info in archive:
            assert info.name in selected and info.name not in seen and info.isfile() and info.mode==420
            raw=archive.extractfile(info).read();assert raw==selected[info.name] and len(raw)==info.size
            seen.add(info.name)
    assert seen==set(selected)
    original_rows=[dict(path=name,**ident(raw)) for name,raw in sorted(selected.items())]
    for label,pin in EXPECTED.items():assert file_ident(pin["path"])==before[label]
    assert Path(__file__).read_bytes()==SELF
    archive_raw=archive_path.read_bytes();archive_identity=ident(archive_raw)
    for offset in range(0,len(archive_raw),12288):
        part=archive_raw[offset:offset+12288]
        print("HIA_EXACT_ORIGINAL_ARCHIVE "+json.dumps(dict(path=archive_path.name,
            offset=offset,part_bytes=len(part),base64=base64.b64encode(part).decode(),**archive_identity),sort_keys=True),flush=True)
    summary.update(status="PASS_READONLY_ORIGINALS",artifacts=[{k:v for k,v in r.items() if k!="members"} for r in zip_rows],
        every_ZIP_member_CRC_bytes_and_SHA256_verified=True,originals=original_rows,archive=archive_identity,
        archive_all_member_bytes_modes_verified=True,all_source_before_after_equal=True,
        inventory_files=5249,production_Python=156,old_4157_result_still="FAIL_HOLD",
        successful_Core_cold_status=cold["status"],successful_Core_cold_checks=11,
        successful_Core_language_status=language["status"],successful_Core_callers_status=callers["status"])
except BaseException as exc:
    summary.update(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc());traceback.print_exc()
finally:
    signal.alarm(0);summary["elapsed_ns"]=time.monotonic_ns()-START
    save("summary.json",js(summary));print("HIA_EXACT_ORIGINAL_READBACK "+json.dumps(summary,sort_keys=True),flush=True)
if summary["status"]!="PASS_READONLY_ORIGINALS":raise SystemExit(1)
