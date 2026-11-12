"""Independent exact FOLLOW55B ZIP and complete tar/JSONL readback; zero target execution.
Selective restoration retains exact 21 source/image pairs only after full member verification.
Local development output is not a new Ubuntu semantic qualification.
"""
from pathlib import Path,PurePosixPath
from hashlib import sha256,sha1
import argparse,copy,importlib.util,json,os,stat,sys,tarfile,zipfile
BASE=Path("/workspace/scratch/9acdfa9f5639")
SUBJECT=BASE/"native-checker-development/physical-after-r1/tools/bounded_physical_subject.py"
SUBJECT_SHA="386c110c77ef3b89a5f3e72c54737dff60c8b8625f3e544b0cc2acb242e7a3b3"
ZIP_BYTES=409495697
ZIP_SHA="e9de7737ab5404b937605f78c4f694ac2adbb6829fedf4da1a82a21f4349fce1"
INNER_BYTES=256387208
INNER_SHA="b9979eeb67675ae1d2f1af12a25354ec8df7b71276644e5bf84ad5121a76efb0"
INDEX_BYTES=92363032
INDEX_SHA="add2322de01d3ab31b42dfcc80172de2b6829885a2f6567e8d49d8041fb425fc"
MEMBERS=189916
ORIGINAL_BYTES=1532715986
COMPILER="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
def save(path,value):
    Path(path).write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def shape(info):
    return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns,stat.S_IMODE(info.st_mode))
def identity(path):
    path=Path(path).absolute();before=path.lstat()
    assert stat.S_ISREG(before.st_mode) and not path.is_symlink()
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:
        first=os.fstat(fd);assert shape(first)==shape(before) and stat.S_ISREG(first.st_mode)
        h=sha256();n=0
        while block:=os.read(fd,1<<20):h.update(block);n+=len(block)
        last=os.fstat(fd)
    finally:os.close(fd)
    assert shape(first)==shape(last)==shape(path.lstat()) and n==first.st_size
    return dict(path=str(path),bytes=n,sha256=h.hexdigest(),mode=stat.S_IMODE(first.st_mode))
def git_hash(path,size):
    h=sha1(b"blob "+str(size).encode()+b"\0")
    with Path(path).open("rb") as f:
        while block:=f.read(1<<20):h.update(block)
    return h.hexdigest()
def safe(name):
    parts=PurePosixPath(name).parts
    assert parts and not name.startswith("/") and "\\" not in name and all(x not in ("",".","..") for x in parts)
    return name
def main():
    parser=argparse.ArgumentParser()
    for name in ("zip","expected","out"):parser.add_argument("--"+name,type=Path,required=True)
    args=parser.parse_args()
    assert sys.version_info[:3]==(3,12,14)
    assert 6 in os.sched_getaffinity(0);os.sched_setaffinity(0,{6})
    assert sha256(SUBJECT.read_bytes()).hexdigest()==SUBJECT_SHA
    spec=importlib.util.spec_from_file_location("exact_physical_subject_originals",SUBJECT)
    sm=importlib.util.module_from_spec(spec);spec.loader.exec_module(sm)
    subject=sm.Subject(args.out,"FOLLOW55B complete original ZIP and tar readback")
    subject.report.update(native_entries_executed=0,VM_entries_executed=0,product_imports=0,
        source_run=43262275264,source_job=131336455359,artifact=13965177412,
        original_qualification_reexecuted=False,local_development_only=True)
    inputs={};restored={};full_assets=None
    try:
        subject.capture(__file__);subject.capture(SUBJECT,SUBJECT_SHA)
        expected=json.loads(subject.capture(args.expected))
        assert len(expected)==21 and [x["role"] for x in expected]==list(range(1,22))
        needed={}
        for row in expected:
            m=row["manifest"];r=m["compile_receipt"]
            assert r["status"]=="returned" and r["artifact_sha256"]==COMPILER==m["compiler_sha256"]
            assert r["source_sha256"]==r["input_sha256"]==m["source_sha256"]
            assert r["input_bytes"]==m["source_bytes"] and r["produced_sha256"]==m["image_sha256"]
            for kind in ("source","image"):
                path=m[kind+"_path"];assert path not in needed
                needed[path]=dict(role=row["role"],kind=kind,bytes=m[kind+"_bytes"],sha256=m[kind+"_sha256"])
        zident=identity(args.zip);inputs["zip"]=zident
        assert (zident["bytes"],zident["sha256"])==(ZIP_BYTES,ZIP_SHA)
        save(subject.out/"input-before.json",inputs)
        zip_rows=[];seen=set();core={}
        with zipfile.ZipFile(args.zip) as z:
            for zi in z.infolist():
                name=safe(zi.filename);assert name not in seen;seen.add(name)
                assert not zi.is_dir() and not stat.S_ISLNK(zi.external_attr>>16)
                suffix=PurePosixPath(name).name
                target=None
                if suffix in ("evidence.tar.xz","evidence-members.jsonl","custody.json"):
                    assert suffix not in core
                    target=subject.out/suffix;core[suffix]=target
                h=sha256();n=0;dest=target.open("xb") if target is not None else None
                try:
                    with z.open(zi) as f:
                        while block:=f.read(1<<20):
                            h.update(block);n+=len(block)
                            if dest is not None:dest.write(block)
                finally:
                    if dest is not None:dest.close()
                assert n==zi.file_size
                if target is not None:target.chmod((zi.external_attr>>16)&0o777 or 0o644)
                zip_rows.append(dict(name=name,bytes=n,sha256=h.hexdigest(),mode=(zi.external_attr>>16)&0o777,CRC=zi.CRC))
        save(subject.out/"ZIP-members.json",zip_rows)
        assert len(zip_rows)==1215
        archive=core["evidence.tar.xz"];ledger=core["evidence-members.jsonl"]
        inputs["archive"]=identity(archive);inputs["ledger"]=identity(ledger)
        assert (inputs["archive"]["bytes"],inputs["archive"]["sha256"])==(INNER_BYTES,INNER_SHA)
        assert (inputs["ledger"]["bytes"],inputs["ledger"]["sha256"])==(INDEX_BYTES,INDEX_SHA)
        save(subject.out/"input-before.json",inputs)
        custody=json.loads(core["custody.json"].read_bytes())
        assert custody["status"]=="PASS" and custody["members"]==MEMBERS
        assert custody["original_bytes"]==ORIGINAL_BYTES and custody["sha256"]==INNER_SHA
        assert custody["member_index_sha256"]==INDEX_SHA and custody["member_index_bytes"]==INDEX_BYTES
        count=total=0;names=set();selection=[]
        with ledger.open("r",encoding="utf-8") as table,tarfile.open(archive,"r|xz") as tf:
            for member in tf:
                line=table.readline();assert line
                row=json.loads(line);name=safe(member.name)
                assert name==row["name"] and name not in names;names.add(name)
                assert member.isfile() and (member.size,member.mode)==(row["bytes"],row["mode"])
                expected_file=needed.get(row["path"]);destination=None
                if expected_file is not None:
                    key=(expected_file["role"],expected_file["kind"]);assert key not in restored
                    destination=subject.out/"restored"/("role-"+str(key[0]))/("source.hiaasm" if key[1]=="source" else "image.bin")
                is_assets=name=="backend-join/development/runtime-assets.json"
                if is_assets:
                    assert full_assets is None
                    destination=subject.out/"original-runtime-assets.json"
                if destination is not None:
                    destination.parent.mkdir(parents=True,exist_ok=True)
                dest=destination.open("xb") if destination is not None else None
                h=sha256();n=0
                try:
                    with tf.extractfile(member) as stream:
                        while block:=stream.read(1<<20):
                            n+=len(block);h.update(block)
                            if dest is not None:dest.write(block)
                finally:
                    if dest is not None:dest.close()
                assert (n,h.hexdigest())==(row["bytes"],row["sha256"]),name
                if destination is not None:
                    destination.chmod(row["mode"])
                    observed=identity(destination)
                    assert (observed["bytes"],observed["sha256"],observed["mode"])==(n,row["sha256"],row["mode"])
                    selected=dict(original=row,restored=observed,gitsha=git_hash(destination,n))
                    selection.append(selected)
                    if expected_file is not None:
                        assert (n,row["sha256"])==(expected_file["bytes"],expected_file["sha256"])
                        restored[key]=selected
                    if is_assets:full_assets=json.loads(destination.read_bytes())
                count+=1;total+=n;tf.members.clear()
                if count%25000==0:
                    print(json.dumps(dict(read_members=count,total_expected=MEMBERS,bytes=total)),flush=True)
            assert not table.readline()
        assert (count,total)==(MEMBERS,ORIGINAL_BYTES) and len(restored)==42
        assert full_assets is not None and set(full_assets["roles"])=={str(x) for x in range(1,22)}
        translated=copy.deepcopy(full_assets)
        for e in expected:
            role=e["role"];m=full_assets["roles"][str(role)]["manifest"]
            for kind in ("source","image"):
                assert all(m[kind+"_"+k]==e["manifest"][kind+"_"+k] for k in ("bytes","sha256","path"))
                translated["roles"][str(role)]["manifest"][kind+"_path"]=restored[(role,kind)]["restored"]["path"]
        translated.update(restoration_only=True,original_runtime_assets_sha256=identity(subject.out/"original-runtime-assets.json")["sha256"],
            actual_new_compilations=0,actual_new_semantic_entries=0,source_artifact=13965177412)
        save(subject.out/"restored-runtime-assets.json",translated)
        save(subject.out/"selected-source-images.json",selection)
        subject.report.update(status="PASS",ZIP_members=len(zip_rows),tar_members=count,original_bytes=total,
            full_ZIP_bytes_SHA_and_each_CRC_read=True,complete_tar_regular_names_modes_sizes_SHA=True,
            complete_ledger_bytes_SHA_read=True,restored_source_image_pairs=21,
            original_runtime_assets_and_expected_console_pins_equal=True,
            no_other_member_extracted=True,storage_path=str(subject.out),selected=selection)
    except BaseException as error:subject.failure(error)
    finally:
        after={}
        for label,before in inputs.items():
            def check(label=label,before=before):
                now=identity(before["path"]);after[label]=now
                assert now==before
            subject.attempt("large-input-after:"+label,check)
        subject.attempt("input-after-receipt",lambda:save(subject.out/"input-after.json",after))
        subject.report["all_large_input_identities_before_after_equal"]=bool(inputs) and after==inputs
        subject.finish("PASS")
if __name__=="__main__":main()
