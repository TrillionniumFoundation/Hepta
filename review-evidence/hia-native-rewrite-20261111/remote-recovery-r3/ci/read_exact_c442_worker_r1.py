"""Verify exact c442 worker component/call artifacts and print original reports.

This reader executes no HIA, oracle or project code. ZIP and nested tar identities
are fixed independently below. Every original tar member is checked against the
producer's complete index, including byte hash, size and mode. Compressed CAS
objects additionally verify their uncompressed content-address digest.
"""
from __future__ import annotations
import argparse,base64,json,re,stat,tarfile,traceback,zipfile,zlib
from hashlib import sha256
from pathlib import Path,PurePosixPath
PINS={
 "components":dict(artifact_id=13898125721,zip_bytes=74324285,
    zip_sha256="6dfa38023a33c90de7e7f5126ed5c7636b9bdfecbf6a3938c24d4793855e0ebf",
    prefix="hia-worker-components-recovery",zip_files=16989,
    tar_bytes=8434524,tar_sha256="c18adecd3849aab97730befdbceba0abb78dba6684993d715631289b32680e1c",
    index_bytes=7317492,index_sha256="96dc539902887fd282a44a590a1002621a01be75c74a723b60bb99c4d1a25155",
    members=18355,original_bytes=64523416),
 "call":dict(artifact_id=13896474388,zip_bytes=51951420,
    zip_sha256="b9f0b8bb14e572771e07a2825cacaa74247ea1211a998e34a1489e95f5a5a352",
    prefix="hia-call-control-recovery",zip_files=72,
    tar_bytes=6596056,tar_sha256="eaf706f3d8c87e0db220c9907b6eb2296087fea96c6294db2d79d79fd6fd019b",
    index_bytes=3882603,index_sha256="c12e0312c550968af09dad63e481b20eb6aced477570a5f1388d48ffcfbed651",
    members=7774,original_bytes=45377041)}
def digest_file(path):
    h=sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1<<20),b""):h.update(chunk)
    return h.hexdigest()
def save(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(obj,indent=2,sort_keys=True)+"\n")
def safe(name):
    p=PurePosixPath(name)
    assert name and not p.is_absolute() and ".." not in p.parts and "\\" not in name and "\0" not in name,name
def emit(name,raw):
    if len(raw)>2*1024*1024:
        print(json.dumps(dict(event="EXACT_ORIGINAL_SIZE_ONLY",name=name,bytes=len(raw),
                              sha256=sha256(raw).hexdigest())),flush=True);return
    for offset in range(0,len(raw),18000):
        print(json.dumps(dict(event="EXACT_WORKER_ORIGINAL_BASE64",name=name,offset=offset,
            total_bytes=len(raw),sha256=sha256(raw).hexdigest(),
            data=base64.b64encode(raw[offset:offset+18000]).decode()),sort_keys=True),flush=True)
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--kind",choices=tuple(PINS),required=True)
    ap.add_argument("--zip",type=Path,required=True)
    ap.add_argument("--output",type=Path,required=True)
    a=ap.parse_args();pin=PINS[a.kind];a.output.mkdir(parents=True,exist_ok=False)
    summary=dict(status="FAIL",scope="READ_ONLY_EXACT_C442_WORKER_ORIGINALS",
        commit="c4424483c586a7f91f3311cae6107966cdcf4d4a",run_id=43113333444,
        kind=a.kind,pin=pin,native_entries=0,reference_calls=0,new_qualification=False,
        whole_worker_closed=False)
    zip_rows=[];tar_rows=[];cas_rows=[];reports=[]
    try:
        before=(a.zip.stat().st_size,digest_file(a.zip))
        assert before==(pin["zip_bytes"],pin["zip_sha256"]),before
        wanted={pin["prefix"]+"/"+n:n for n in ("evidence.tar.xz","evidence-members.json","summary.json","custody.json")}
        found={}
        with zipfile.ZipFile(a.zip) as z:
            seen=set()
            for item in z.infolist():
                safe(item.filename);assert item.filename not in seen;seen.add(item.filename)
                assert not stat.S_ISLNK(item.external_attr>>16)
                if item.is_dir():continue
                target=a.output/("original-"+wanted[item.filename]) if item.filename in wanted else None
                out=target.open("xb") if target else None
                h=sha256();size=0
                try:
                    with z.open(item) as f:
                        for chunk in iter(lambda:f.read(1<<20),b""):
                            h.update(chunk);size+=len(chunk)
                            if out:out.write(chunk)
                finally:
                    if out:out.close()
                assert size==item.file_size
                row=dict(name=item.filename,bytes=size,sha256=h.hexdigest(),
                         mode=item.external_attr>>16,crc32=item.CRC)
                zip_rows.append(row)
                if target:
                    assert target.stat().st_size==size and digest_file(target)==row["sha256"]
                    found[wanted[item.filename]]=target
            assert len(zip_rows)==pin["zip_files"],len(zip_rows)
        assert set(found)==set(wanted.values()),sorted(found)
        archive=found["evidence.tar.xz"];index=found["evidence-members.json"]
        assert (archive.stat().st_size,digest_file(archive))==(pin["tar_bytes"],pin["tar_sha256"])
        assert (index.stat().st_size,digest_file(index))==(pin["index_bytes"],pin["index_sha256"])
        expected=json.loads(index.read_bytes())
        assert len(expected)==pin["members"]
        by_name={r["name"]:r for r in expected};assert len(by_name)==len(expected)
        assert sum(r["bytes"] for r in expected)==pin["original_bytes"]
        checked=set()
        with tarfile.open(archive,"r:xz") as tf:
            for item in tf:
                safe(item.name);assert item.isfile() and item.name not in checked
                row=by_name[item.name];assert (item.size,item.mode)==(row["bytes"],row["mode"])
                capture=item.name.endswith(("/summary.json","/bundle.json")) or item.name in ("run/summary.json",)
                target=a.output/"original-reports"/item.name if capture else None
                if target:target.parent.mkdir(parents=True,exist_ok=True)
                out=target.open("xb") if target else None
                cas=re.fullmatch(r"([0-9a-f]{64})\.(gz|zlib)",PurePosixPath(item.name).name)
                decompressor=zlib.decompressobj(31 if cas and cas[2]=="gz" else 15) if cas else None
                decoded=sha256();logical=0;h=sha256();size=0
                try:
                    with tf.extractfile(item) as stream:
                        for chunk in iter(lambda:stream.read(1<<20),b""):
                            h.update(chunk);size+=len(chunk)
                            if out:out.write(chunk)
                            if decompressor:
                                pending=chunk
                                while pending:
                                    raw=decompressor.decompress(pending,1<<20)
                                    decoded.update(raw);logical+=len(raw)
                                    pending=decompressor.unconsumed_tail
                                while True:
                                    raw=decompressor.decompress(b"",1<<20)
                                    if not raw:break
                                    decoded.update(raw);logical+=len(raw)
                    if decompressor:
                        raw=decompressor.flush();decoded.update(raw);logical+=len(raw)
                        assert decompressor.eof and not decompressor.unused_data,item.name
                        assert decoded.hexdigest()==cas[1],item.name
                        cas_rows.append(dict(name=item.name,compressed_bytes=size,logical_bytes=logical,
                                             sha256=decoded.hexdigest()))
                finally:
                    if out:out.close()
                assert (size,h.hexdigest())==(row["bytes"],row["sha256"]),item.name
                checked.add(item.name);tar_rows.append(dict(name=item.name,bytes=size,sha256=h.hexdigest(),mode=item.mode))
                if target:
                    raw=target.read_bytes();assert (len(raw),sha256(raw).hexdigest())==(size,row["sha256"])
                    report=json.loads(raw)
                    reports.append(dict(name=item.name,bytes=size,sha256=row["sha256"],report=report))
                    if item.name.endswith("/summary.json"):emit(item.name,raw)
        assert checked==set(by_name)
        assert (a.zip.stat().st_size,digest_file(a.zip))==before
        original=json.loads(found["summary.json"].read_bytes())
        assert original["status"]=="PASS"
        assert original["whole_stack_closed"] is False and original["production_activated"] is False
        assert original["frozen_source_and_reference_before_after_equal"] is True
        assert original["submitted_script_pins_before_after_equal"] is True
        summary.update(status="PASS",original_status=original["status"],original_details=original["details"],
            all_zip_members_verified=True,all_tar_bytes_sha256_modes_verified=True,
            zip_unchanged=True,zip_members=len(zip_rows),tar_members=len(tar_rows),
            cas_objects=len(cas_rows),cas_logical_bytes=sum(r["logical_bytes"] for r in cas_rows),
            all_compressed_cas_content_addresses_verified=True,original_source_unchanged=True)
        for name in ("summary.json","custody.json"):emit(name,found[name].read_bytes())
    except BaseException as exc:
        summary.update(error_class=type(exc).__name__,error=str(exc));traceback.print_exc()
    finally:
        save(a.output/"zip-members.json",zip_rows)
        save(a.output/"verified-tar-members.json",tar_rows)
        save(a.output/"compressed-cas-readback.json",cas_rows)
        save(a.output/"original-report-index.json",reports)
        save(a.output/"summary.json",summary)
        print(json.dumps(summary,sort_keys=True),flush=True)
    if summary["status"]!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
