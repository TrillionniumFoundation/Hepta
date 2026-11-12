"""Read exact E development bytes before a new public CLI integration.

This is a read-only transport/identity gate. It starts no native process,
does not import the original project, and grants no semantic qualification.
The new artifact is selected by one immutable workflow run, head and job;
its complete ZIP must match the digest returned by GitHub for that artifact.
Every original member is independently compared with the retained R14 archive.
"""
from pathlib import Path,PurePosixPath
from hashlib import sha1,sha256
import argparse,io,json,re,stat,tarfile,traceback,zipfile

RUN=43129195254
HEAD="bfc30ce5c77fc5541cd0900015cf2e64f5568457"
JOB=130888828985
NAME="hia-edit-public-service-43129195254-1"
COMPILER="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
OLD=dict(run_id=43122922476,job_id=130867669693,artifact_id=13901534373,
 zip_bytes=60079807,zip_sha256="f35d3b639e645e27dedfab101f869d3bc7f1d927e6f11a1fc78bb4b6b75c8986",
 inner_bytes=20992744,inner_sha256="b2f7d7583655a813c8aad3735e2bde703f883bd9ae25887ac6feab716fbd3ae3",
 index_bytes=402737,index_sha256="5a8a3e1577a201b63789ff8f2d069445b8770197d7205ed8e5e8e368593d3acc",
 members=966,raw_bytes=149824283)
SUBMITTED={
 "cli_edit_service.py":("79260850291afad9297d5c2730bb788dee1d27b9",48642,
    "1077ade5a4685bfbc578b48ad89ce683dc8ee3f67e54e1766969abb60d17eb1c"),
 "ci_edit_public_service_r1.py":("63495cb8116e030b8f63bad15944b787b61daa6a",16035,
    "75809a3e4b9576fd1dba5b8148ba7cfb237a00fc1f5510ddfc6a66227da7e1c8")}
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def safe(name):
    path=PurePosixPath(name)
    assert name and not path.is_absolute() and ".." not in path.parts and "\\" not in name and "\0" not in name,name
    assert str(path)==name.rstrip("/"),name
    return path
def whole(path):
    h=sha256();n=0
    with path.open("rb") as stream:
        for chunk in iter(lambda:stream.read(1<<20),b""):h.update(chunk);n+=len(chunk)
    return n,h.hexdigest()
def main():
    ap=argparse.ArgumentParser()
    for key in ("zip","metadata","job","run","original-zip","source-dir","out"):
        ap.add_argument("--"+key,type=Path,required=True)
    a=ap.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    pins={};report=dict(status="FAIL",new_native_entries=0,old_case_counts_inherited=False,
        public_CLI_closed=False,whole_stack_closed=False,original_archive_pin=OLD)
    def read(path):
        path=path.resolve();raw=path.read_bytes();row=(len(raw),digest(raw))
        if path in pins:assert pins[path]==row
        pins[path]=row;return raw
    try:
        read(Path(__file__))
        metadata=json.loads(read(a.metadata));job=json.loads(read(a.job));run=json.loads(read(a.run))
        assert type(metadata["id"]) is int and metadata["id"]>0
        assert metadata["name"]==NAME and metadata["expired"] is False
        assert metadata["workflow_run"]["id"]==RUN and metadata["workflow_run"]["head_sha"]==HEAD
        assert run["id"]==RUN and run["head_sha"]==HEAD and run["run_attempt"]==1
        assert job["id"]==JOB and job["run_id"]==RUN and job["head_sha"]==HEAD
        assert job["status"]=="completed" and job["conclusion"]=="success"
        dg=metadata["digest"]
        assert type(dg) is str and re.fullmatch(r"sha256:[0-9a-f]{64}",dg),dg
        current=whole(a.zip);pins[a.zip.resolve()]=current
        assert current==(metadata["size_in_bytes"],dg[7:]),(current,metadata)
        for name,wanted in SUBMITTED.items():
            raw=read(a.source_dir/name)
            assert (gitsha(raw),len(raw),digest(raw))==wanted,name
            (out/"submitted").mkdir(exist_ok=True)
            (out/"submitted"/name).write_bytes(raw)
        frozen=out/"metadata";frozen.mkdir()
        for name,path in (("artifact.json",a.metadata),("job.json",a.job),("run.json",a.run)):
            (frozen/name).write_bytes(read(path))
        original_zip=read(a.original_zip)
        assert (len(original_zip),digest(original_zip))==(OLD["zip_bytes"],OLD["zip_sha256"])
        with zipfile.ZipFile(io.BytesIO(original_zip)) as z:
            assert z.testzip() is None
            names=z.namelist();assert len(names)==len(set(names))
            for name in names:safe(name)
            inner=[n for n in names if n=="evidence.tar.xz" or n.endswith("/evidence.tar.xz")]
            indexes=[n for n in names if n=="evidence-members.json" or n.endswith("/evidence-members.json")]
            assert len(inner)==len(indexes)==1
            original=z.read(inner[0]);index=z.read(indexes[0])
        assert (len(original),digest(original))==(OLD["inner_bytes"],OLD["inner_sha256"])
        assert (len(index),digest(index))==(OLD["index_bytes"],OLD["index_sha256"])
        rows=json.loads(index);expected={r["name"]:r for r in rows}
        assert len(rows)==len(expected)==OLD["members"]
        assert sum(r["bytes"] for r in rows)==OLD["raw_bytes"]
        (frozen/"original-members.json").write_bytes(index)
        development=out/"development";development.mkdir()
        prefix="hia-edit-public-service/"
        members=[];paths=set()
        with zipfile.ZipFile(a.zip) as z:
            assert z.testzip() is None
            names=z.namelist();assert len(names)==len(set(names))
            for info in z.infolist():
                p=safe(info.filename)
                mode=(info.external_attr>>16)&0xffff
                assert not stat.S_ISLNK(mode),info.filename
                if info.is_dir():continue
                raw=z.read(info)
                members.append(dict(name=info.filename,bytes=len(raw),sha256=digest(raw),
                    archive_mode=stat.S_IMODE(mode)))
                if info.filename.startswith(prefix):
                    relative=info.filename[len(prefix):];q=safe(relative)
                    assert relative not in paths;paths.add(relative)
                    target=development.joinpath(*q.parts);target.parent.mkdir(parents=True,exist_ok=True)
                    target.write_bytes(raw);target.chmod(0o444)
                elif info.filename=="hia-edit-public-service-driver.log":
                    (out/"original-driver.log").write_bytes(raw)
                else:raise AssertionError(("unexpected artifact member",info.filename))
        assert paths and "summary.json" in paths
        seen=set()
        with tarfile.open(fileobj=io.BytesIO(original),mode="r:xz") as tf:
            for item in tf:
                q=safe(item.name);assert item.isfile() and item.name not in seen
                row=expected[item.name];raw=tf.extractfile(item).read()
                assert (len(raw),digest(raw),stat.S_IMODE(item.mode))==(row["bytes"],row["sha256"],row["mode"])
                path=development/"original"/q
                assert path.is_file() and path.read_bytes()==raw,item.name
                seen.add(item.name)
        assert seen==set(expected)
        actual_original={p[len("original/"):] for p in paths if p.startswith("original/")}
        assert actual_original==seen
        summary=json.loads(read(development/"summary.json"))
        assert summary["generation"]["status"]=="PASS_GENERATION_AND_B3_ONLY"
        assert summary["all_original_bytes_sha_modes_unchanged"] is True
        generation=summary["generation"]
        assert generation["actual_compilations"]==2 and generation["actual_semantic_entries"]==0
        assert set(generation["components"])=={"56","58"}
        bindings={}
        for role,row in generation["components"].items():
            at=development/"generation"/("role-"+role)
            source=read(at/"source.hiaasm");image=read(at/"edit-service.image.bin")
            receipt=json.loads(read(at/"edit-service.receipt.json"))
            assert (len(source),digest(source))==(row["source_bytes"],row["source_sha256"])
            assert (len(image),digest(image))==(row["image_bytes"],row["image_sha256"])
            assert receipt["status"]=="returned" and type(receipt["abi_status"]) is int and receipt["abi_status"]==0
            assert receipt["source_unchanged"] is True and receipt["forbidden_compiler_modules_loaded"]==[]
            assert receipt["input_sha256"]==digest(source) and receipt["produced_sha256"]==digest(image)
            assert receipt["artifact_sha256"]==COMPILER and receipt["core_u32"]==len(image)
            assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
            bindings[role]=dict(source_bytes=len(source),source_sha256=digest(source),
                image_bytes=len(image),image_sha256=digest(image),receipt_bytes=(at/"edit-service.receipt.json").stat().st_size)
        save(out/"new-artifact-members.json",members)
        report.update(status="PASS_READBACK_ONLY",artifact_id=metadata["id"],
            artifact_bytes=current[0],artifact_sha256=current[1],new_artifact_members=len(members),
            new_artifact_raw_bytes=sum(r["bytes"] for r in members),
            original_members_verified=len(seen),original_raw_bytes=OLD["raw_bytes"],
            original_archive_modes_verified=True,
            extracted_mode=0o444,transport_mode_is_not_original_mode=True,
            new_compilation_bindings=bindings,development=str(development),
            diagnostic_status=summary.get("boundary_diagnostic",{}).get("status"))
    except BaseException as error:
        report.update(error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc();raise
    finally:
        unchanged=all(whole(path)==row for path,row in pins.items())
        report["all_inputs_unchanged"]=unchanged
        save(out/"input-pins.json",[dict(path=str(p),bytes=v[0],sha256=v[1]) for p,v in pins.items()])
        save(out/"readback.json",report)
        print("HIA_PUBLIC_E_ASSET_READBACK "+json.dumps(report,sort_keys=True),flush=True)
        assert unchanged
if __name__=="__main__":main()
