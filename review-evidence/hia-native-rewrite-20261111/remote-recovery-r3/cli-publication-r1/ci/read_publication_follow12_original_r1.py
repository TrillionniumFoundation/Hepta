"""Read exact follow12 publication originals without executing project code.

All ZIP, tar, mode, content-address and actual entry records are checked.  This
does not rerun the transaction, its reference oracle or any previous CLI test.
"""
from pathlib import Path,PurePosixPath
from hashlib import sha256
import argparse,base64,json,os,stat,struct,tarfile,traceback,zipfile,zlib
PIN=dict(artifact_id=13900605840,zip_bytes=45088034,
 zip_sha256="54fa2bc4dded871875ff3b01b7d5c886d4d45d09a8d032a680941d85387998bb",
 zip_files=34,prefix="hia-cli-publication-recovery",
 tar_bytes=5642596,tar_sha256="47d9a94ca9202141ef13d583ecfeb1bb604806ed03491eee555a440e1bc792b5",
 index_bytes=870167,index_sha256="716a7f4f93e4cc523935640cb8d0530695e53d3355fbc2aae0da78745b082798",
 members=1939,original_bytes=43063753)
def digest(raw):return sha256(raw).hexdigest()
def file_hash(path):
    h=sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1<<20),b""):h.update(chunk)
    return h.hexdigest()
def safe(name):
    p=PurePosixPath(name)
    assert name and not p.is_absolute() and ".." not in p.parts
    assert "\\" not in name and "\0" not in name
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def emit(name,raw):
    for at in range(0,len(raw),18000):
        print(json.dumps(dict(event="EXACT_PUBLICATION_ORIGINAL_BASE64",name=name,
            offset=at,total_bytes=len(raw),sha256=digest(raw),
            data=base64.b64encode(raw[at:at+18000]).decode()),sort_keys=True),flush=True)
def main():
    p=argparse.ArgumentParser();p.add_argument("--zip",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True);a=p.parse_args()
    a.out.mkdir(parents=True,exist_ok=False)
    report=dict(status="FAIL",scope="READ_ONLY_FOLLOW12_NATIVE_PUBLICATION_ORIGINALS",
        commit="722ebd53f80a86c527b816d60caca7a9d5faa1f9",run_id=43119383155,
        job_id=130855636695,pin=PIN,new_native_entries=0,new_reference_calls=0,
        whole_cli_publication_closed=False,actual_fixed_publication_carrier=False)
    zip_rows=[];tar_rows=[];cas_rows=[];all_raw=None
    try:
        original=(a.zip.stat().st_size,file_hash(a.zip))
        assert original==(PIN["zip_bytes"],PIN["zip_sha256"])
        selected={PIN["prefix"]+"/"+n:n for n in
            ("evidence.tar.xz","evidence-members.json","summary.json","custody.json")}
        found={}
        with zipfile.ZipFile(a.zip) as z:
            seen=set()
            for item in z.infolist():
                safe(item.filename);assert item.filename not in seen;seen.add(item.filename)
                assert not stat.S_ISLNK(item.external_attr>>16)
                if item.is_dir():continue
                target=a.out/("original-"+selected[item.filename]) if item.filename in selected else None
                output=target.open("xb") if target else None;h=sha256();size=0
                try:
                    with z.open(item) as stream:
                        for part in iter(lambda:stream.read(1<<20),b""):
                            h.update(part);size+=len(part)
                            if output:output.write(part)
                finally:
                    if output:output.close()
                assert size==item.file_size
                zip_rows.append(dict(name=item.filename,bytes=size,sha256=h.hexdigest(),
                    mode=item.external_attr>>16,crc32=item.CRC))
                if target:
                    assert (target.stat().st_size,file_hash(target))==(size,h.hexdigest())
                    found[selected[item.filename]]=target
        assert len(zip_rows)==PIN["zip_files"] and set(found)==set(selected.values())
        archive=found["evidence.tar.xz"];index=found["evidence-members.json"]
        assert (archive.stat().st_size,file_hash(archive))==(PIN["tar_bytes"],PIN["tar_sha256"])
        assert (index.stat().st_size,file_hash(index))==(PIN["index_bytes"],PIN["index_sha256"])
        expected=json.loads(index.read_bytes());by_name={r["name"]:r for r in expected}
        assert len(by_name)==len(expected)==PIN["members"]
        assert sum(r["bytes"] for r in expected)==PIN["original_bytes"]
        checked=set();summaries=[]
        all_raw=a.out/"exact-tar-members";all_raw.mkdir()
        with tarfile.open(archive,"r:xz") as tf:
            for item in tf:
                safe(item.name);assert item.isfile() and item.name not in checked
                row=by_name[item.name]
                assert (item.size,item.mode)==(row["bytes"],row["mode"])
                target=all_raw/item.name;target.parent.mkdir(parents=True,exist_ok=True)
                h=sha256();size=0
                with tf.extractfile(item) as stream,target.open("xb") as output:
                    for part in iter(lambda:stream.read(1<<20),b""):
                        h.update(part);size+=len(part);output.write(part)
                target.chmod(item.mode)
                assert (size,h.hexdigest())==(row["bytes"],row["sha256"])
                assert (target.stat().st_size,stat.S_IMODE(target.stat().st_mode),file_hash(target))==(size,item.mode,row["sha256"])
                checked.add(item.name);tar_rows.append(dict(row))
                if item.name.endswith("/summary.json"):
                    value=json.loads(target.read_bytes())
                    if value.get("scope")=="NEW_NATIVE_VERIFIED_PUBLICATION_COMPONENT":summaries.append(target)
                if target.suffix==".zlib" and len(target.stem)==64:
                    compressed=target.read_bytes()
                    d=zlib.decompressobj();raw=d.decompress(compressed)+d.flush()
                    assert d.eof and not d.unused_data and digest(raw)==target.stem
                    cas_rows.append(dict(name=item.name,compressed_bytes=len(compressed),
                        logical_bytes=len(raw),sha256=digest(raw)))
        assert checked==set(by_name) and len(summaries)==1
        summary_path=summaries[0];root=summary_path.parent
        actual_raw=summary_path.read_bytes();actual=json.loads(actual_raw)
        assert actual["status"]=="PASS" and actual["source_pins_unchanged"]
        assert actual["cases"]==29 and actual["private_controls"]==11
        assert actual["cas_readback"]["status"]=="PASS"
        assert actual["actual_fixed_publication_carrier"] is False
        assert actual["whole_cli_closed"] is False and actual["path_staging_owner_closed"] is False
        assert actual["python_chooses_transaction_order"] is False
        ledger_raw=(root/"entries.jsonl").read_bytes()
        entries=[json.loads(line) for line in ledger_raw.splitlines()]
        seen_refs={};counts={"publication":0,"sha":0};fs=0;hash_requests=0;terminals={}
        def content(ref):
            safe(ref["path"]);assert ref["compression"]=="zlib"
            key=ref["path"]
            if key not in seen_refs:
                data=zlib.decompress((root/key).read_bytes())
                assert (len(data),digest(data))==(ref["bytes"],ref["sha256"])
                seen_refs[key]=(ref["bytes"],ref["sha256"])
            else:assert seen_refs[key]==(ref["bytes"],ref["sha256"])
            return zlib.decompress((root/key).read_bytes())
        for entry in entries:
            assert entry["role"] in counts and entry["canaries_unchanged"] is True
            counts[entry["role"]]+=1
            data={key:content(entry[key]) for key in
                ("first","second_before","second_after","workspace_before","workspace_after")}
            if entry["role"]=="publication":
                assert data["second_before"]==data["second_after"]
                if entry["return_value"]==128:
                    event=struct.unpack_from("<16Q",data["workspace_after"],256)
                    assert event[0]==int.from_bytes(b"HIAPVE01","little")
                    if event[1]==2:fs+=1
                    elif event[1]==3:hash_requests+=1
                    elif event[1]==0:
                        assert entry["label"] not in terminals
                        source=data["first"] if event[8]==0 else data["workspace_after"]
                        assert event[8] in (0,1)
                        at,size=event[9:11]
                        assert at<=len(source) and size<=len(source)-at
                        terminals[entry["label"]]=(event,source[at:at+size])
                    else:raise AssertionError(("unexpected completed action",event))
                else:assert entry["return_value"] in (0xfffffffd,0xfffffffe)
        assert counts["publication"]==actual["native_publication_entries"]
        assert counts["sha"]==actual["native_hash_entries"]
        assert fs==actual["actual_filesystem_syscalls"]
        assert hash_requests>0 and counts["sha"]==hash_requests*3
        assert len(terminals)==29
        for index,row in enumerate(actual["cases_data"]):
            assert row["status"]=="PASS"
            disk=json.loads((root/"cases"/(str(index).zfill(4)+".json")).read_bytes())
            assert disk==row
            event,payload=terminals[row["label"]]
            outcome=row["outcome"]
            assert event[5]==outcome["domain"]
            if event[5]==0:assert payload.decode("ascii")==outcome["receipt"]
            elif event[5]==1:assert payload.decode("utf-8")==outcome["message"]
            else:assert event[5]==2 and event[7]==outcome["errno"] and payload.hex()==outcome["path"]
        assert len(set(actual["private_labels"]))==11
        for label in actual["private_labels"]:
            selected_entries=[e for e in entries if e["label"] in
                ("private-"+label+"/bad-reply","private-"+label+"/good-followup")]
            assert len(selected_entries)==2 and all(e["return_value"]==0xfffffffd for e in selected_entries)
        outer=json.loads(found["summary.json"].read_bytes())
        assert outer["status"]=="PASS" and outer["details"]["actual"]==actual
        assert outer["frozen_source_and_reference_before_after_equal"] is True
        assert outer["submitted_script_pins_before_after_equal"] is True
        assert (a.zip.stat().st_size,file_hash(a.zip))==original
        emit(summary_path.relative_to(all_raw).as_posix(),actual_raw)
        emit("outer-summary.json",found["summary.json"].read_bytes())
        manifest=root/"compile/manifest.json"
        emit(manifest.relative_to(all_raw).as_posix(),manifest.read_bytes())
        report.update(status="PASS",original_cases=29,original_private_controls=11,
            original_publication_entries=counts["publication"],original_hash_entries=counts["sha"],
            original_hash_requests=hash_requests,original_filesystem_syscalls=fs,
            actual_entry_records=len(entries),native_ledger_matches_original_summary=True,
            all_29_final_native_views_match_saved_outcomes=True,
            all_11_malformed_replies_and_followups_permanent_BAD=True,
            zip_members=len(zip_rows),tar_members=len(tar_rows),
            cas_objects=len(cas_rows),cas_logical_bytes=sum(r["logical_bytes"] for r in cas_rows),
            all_zip_tar_bytes_sha256_modes_and_cas_verified=True,
            original_zip_unchanged=True,original_summary_sha256=digest(actual_raw),
            actual=actual)
    except BaseException as error:
        report.update(error_class=type(error).__name__,error=str(error))
        traceback.print_exc()
    finally:
        save(a.out/"zip-members.json",zip_rows);save(a.out/"tar-members.json",tar_rows)
        save(a.out/"cas-readback.json",cas_rows);save(a.out/"summary.json",report)
        print(json.dumps({k:v for k,v in report.items() if k!="actual"},sort_keys=True),flush=True)
    if report["status"]!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
