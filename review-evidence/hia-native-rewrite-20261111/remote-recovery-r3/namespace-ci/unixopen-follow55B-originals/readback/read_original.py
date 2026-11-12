#!/usr/bin/env python3
"""Read original FOLLOW55B Unix9 failure bytes only; never execute project code."""
from pathlib import Path, PurePosixPath
import hashlib, io, json, os, stat, tarfile, time, zipfile
ROOT = Path("/workspace/scratch/9acdfa9f5639/runtime-development/unix9-follow55B-original")
ZIP = ROOT / "artifact-13965680064.zip"
PREFIX = "hia-namespace-unixopen-native-parent-recovery/"
PIN = ("5b52a192a14ec4be154e65d224dfdceecbc1407dc1cc1697f1a53e8dfcceb909",69392985)
def sha(b): return hashlib.sha256(b).hexdigest()
def identity(p):
    b=p.read_bytes()
    return {"bytes":len(b),"sha256":sha(b),"mode":stat.S_IMODE(p.stat().st_mode)}
def safe(n):
    p=PurePosixPath(n)
    assert n and not p.is_absolute() and ".." not in p.parts and str(p)==n
    return p
def write(p,b,mode=0o644):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open("xb") as f: f.write(b)
    os.chmod(p,mode)
    assert p.read_bytes()==b and stat.S_IMODE(p.stat().st_mode)==mode
start=time.monotonic_ns()
before=identity(ZIP)
assert (before["sha256"],before["bytes"])==PIN
report={"schema":"namespace-unix9-follow55B-original-local-readback-v1","target_executions":0,"original_target_status":"FAIL","original_job":131336455273,"zip_before":before,"status":"RUNNING"}
try:
    outer=[]
    with zipfile.ZipFile(ZIP) as z:
        names=z.namelist()
        assert len(names)==1047 and len(set(names))==len(names)
        for info in z.infolist():
            safe(info.filename)
            assert not info.is_dir() and not info.flag_bits & 1
            b=z.read(info)
            assert len(b)==info.file_size
            outer.append({"name":info.filename,"bytes":len(b),"sha256":sha(b),"mode":stat.S_IMODE(info.external_attr>>16),"crc32":info.CRC})
        assert sum(x["bytes"] for x in outer)==68952467
        archive=z.read(PREFIX+"evidence.tar.xz")
        ledger=z.read(PREFIX+"evidence-members.jsonl")
        custody_raw=z.read(PREFIX+"custody.json")
        custody=json.loads(custody_raw)
    assert len(archive)==5600896 and sha(archive)=="89a6048ed725421a17042540c6d03d66f9bc504cbbfe471815f428137bfe060f"
    assert len(ledger)==30579 and sha(ledger)=="614c11cf71bb9baff39a6bbf9d35dbab9a87495da6a71aa2945ba6bd655ea7a2"
    assert custody["status"]=="FAIL" and custody["members"]==98 and custody["original_bytes"]==43495460
    write(ROOT/"evidence.tar.xz",archive)
    write(ROOT/"evidence-members.jsonl",ledger)
    write(ROOT/"custody.json",custody_raw)
    rows=[json.loads(x) for x in ledger.splitlines()]
    expect={r["name"]:r for r in rows}
    assert len(rows)==len(expect)==98
    seen=set(); retained=[]
    with tarfile.open(fileobj=io.BytesIO(archive),mode="r|xz") as t:
        for m in t:
            safe(m.name)
            assert m.isfile() and m.name in expect and m.name not in seen
            r=expect[m.name]; b=t.extractfile(m).read()
            assert m.size==len(b)==r["bytes"] and m.mode==r["mode"] and sha(b)==r["sha256"]
            p=ROOT/"inner-retained"/m.name
            write(p,b,m.mode)
            seen.add(m.name);retained.append({"name":m.name,**identity(p)})
    assert seen==set(expect) and sum(x["bytes"] for x in retained)==43495460
    doc=ROOT/"inner-retained/run/namespace-actual-unixopen-r1/actual-unixopen-build-r1/generation-frontier/role-4.document.json"
    assert identity(doc)["sha256"]=="a6eca09e2a03e8cc606df7a1c95ef6519089ff6d3dba1052b9943ae8576b7df1"
    write(ROOT/"outer-member-readback.json",(json.dumps(outer,sort_keys=True,indent=2)+"\n").encode())
    write(ROOT/"inner-member-readback.json",(json.dumps(retained,sort_keys=True,indent=2)+"\n").encode())
    report.update(status="PASS_READBACK_ONLY",outer_members=len(outer),outer_raw_bytes=sum(x["bytes"] for x in outer),all_outer_crc_read=True,inner_members=len(retained),inner_raw_bytes=sum(x["bytes"] for x in retained),all_inner_bytes_modes_sha256_readback=True,original_role4_document=str(doc),original_role4_document_identity=identity(doc))
except BaseException as e:
    report.update(status="FAIL_READBACK",error_type=type(e).__name__,error=str(e))
    raise
finally:
    after=identity(ZIP)
    report.update(zip_after=after,zip_before_after_equal=(before==after),wall_ns=time.monotonic_ns()-start)
    if before!=after:report["status"]="FAIL_READBACK"
    (ROOT/"readback.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print(json.dumps(report,sort_keys=True))
    assert before==after
