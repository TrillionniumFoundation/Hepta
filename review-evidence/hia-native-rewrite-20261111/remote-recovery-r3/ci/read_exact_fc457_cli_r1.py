"""Verify exact fc457 CLI originals; 176 equivalent cases and 17 explicit OPEN.

This reader executes no HIA, oracle or project code. ZIP and nested tar identities
are fixed independently below. Every original tar member is checked against the
producer's complete index, including byte hash, size and mode. Compressed CAS
objects additionally verify their uncompressed content-address digest.
"""
from __future__ import annotations
import argparse,base64,json,os,re,stat,tarfile,traceback,zipfile,zlib
from hashlib import sha256
from pathlib import Path,PurePosixPath
PINS={"cli":dict(artifact_id=13899330292,zip_bytes=45990964,
    zip_sha256="ce3dc2c2019a7c85f7d3e97429a60c971b50b547ab53be562b593ef0d5fa4b4d",
    prefix="hia-cli-recovery",zip_files=49,
    tar_bytes=6712968,tar_sha256="abcd4411cf5fea4c26deb392471fed1dffc4581ce53fa38f062d4ba40ef4258f",
    index_bytes=624748,index_sha256="096cdf766094d0768f04da1abe641f7002daf486dd6c366713614c75f33bcaa7",
    members=1453,original_bytes=56079779)}
CASE_ROOT="cli/project/development/entry-independent-ci-native-r1"
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
        print(json.dumps(dict(event="EXACT_CLI_ORIGINAL_BASE64",name=name,offset=offset,
            total_bytes=len(raw),sha256=sha256(raw).hexdigest(),
            data=base64.b64encode(raw[offset:offset+18000]).decode()),sort_keys=True),flush=True)
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--kind",choices=tuple(PINS),required=True)
    ap.add_argument("--zip",type=Path,required=True)
    ap.add_argument("--output",type=Path,required=True)
    a=ap.parse_args();pin=PINS[a.kind];a.output.mkdir(parents=True,exist_ok=False)
    summary=dict(status="FAIL",scope="READ_ONLY_EXACT_FC457_CLI_ORIGINALS",
        commit="fc4579420727cfcca72b59e226a6f3af885679f4",run_id=43115476503,
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
                capture=(item.name.endswith(("/summary.json","/bundle.json"))
                         or item.name.startswith(CASE_ROOT+"/"))
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
                    if item.name.endswith(("/summary.json","/bundle.json","/result.json")):
                        report=json.loads(raw)
                        reports.append(dict(name=item.name,bytes=size,sha256=row["sha256"],report=report))
                        if item.name.endswith(("/summary.json","/result.json")):emit(item.name,raw)
        assert checked==set(by_name)
        assert (a.zip.stat().st_size,digest_file(a.zip))==before
        original=json.loads(found["summary.json"].read_bytes())
        assert original["status"]=="PASS"
        assert original["whole_stack_closed"] is False and original["production_activated"] is False
        assert original["frozen_source_and_reference_before_after_equal"] is True
        assert original["submitted_script_pins_before_after_equal"] is True
        base=a.output/"original-reports"/CASE_ROOT
        result=json.loads((base/"result.json").read_bytes())
        cases=json.loads((base/"cases-completed.json").read_bytes())
        ledger=[json.loads(line) for line in (base/"cases.jsonl").read_bytes().splitlines()]
        assert cases==ledger and len(cases)==193 and len({r["label"] for r in cases})==193
        assert result["status"]=="PASS" and result["source_pins_unchanged"] is True
        assert result["cases"]==193 and result["native_processes"]==193
        assert result["exact_equivalence_cases"]==176 and result["reference_processes"]==176
        assert result["explicit_open_handoff_cases"]==17
        assert result["ordinary_business_owner_closed"] is False
        assert result["installed_entry_activated"] is False and result["publication_closed"] is False
        assert original["details"]["new_actual_entry"]==result
        checked_cases=[];equivalent=0;open_cases=0
        def process_data(row,kind):
            p=base/"cases"/row["label"]/kind
            record=json.loads((p/"process.json").read_bytes())
            assert record==row[kind]
            assert record["timed_out"] is False
            assert os.waitstatus_to_exitcode(record["wait_status"])==record["returncode"]
            parts=[]
            for stream in ("stdout","stderr"):
                value=(p/(stream+".bin")).read_bytes()
                reference=record[stream]
                safe(reference["path"])
                assert reference["compression"]=="zlib"
                compressed=base/reference["path"]
                restored=zlib.decompress(compressed.read_bytes())
                assert value==restored
                assert (len(value),sha256(value).hexdigest())==(reference["bytes"],reference["sha256"])
                parts.append(value)
            return record["returncode"],parts[0],parts[1]
        for row in cases:
            label=row["label"];assert "/" not in label and label not in (".","..")
            actual=process_data(row,"native")
            if row["scope"]=="ACTUAL_ELF_FULL_STDOUT_STDERR_EXIT_EQUIVALENCE":
                expected_result=process_data(row,"reference")
                assert actual==expected_result and row["equal"] is True,label
                equivalent+=1
            elif row["scope"]=="EXPLICIT_OPEN_BUSINESS_HANDOFF_NOT_EQUIVALENCE":
                assert "reference" not in row and row["expected_exit"]==126
                assert row["not_a_successful_business_result"] is True
                assert actual==(126,b"",b""),label
                assert not (base/"cases"/label/"reference").exists()
                open_cases+=1
            else:raise AssertionError(("unknown scope",row["scope"]))
            checked_cases.append(dict(label=label,scope=row["scope"],returncode=actual[0],
                stdout_bytes=len(actual[1]),stdout_sha256=sha256(actual[1]).hexdigest(),
                stderr_bytes=len(actual[2]),stderr_sha256=sha256(actual[2]).hexdigest()))
        assert (equivalent,open_cases)==(176,17)
        save(a.output/"independent-case-byte-readback.json",checked_cases)
        summary.update(actual_cases_readback=193,full_equivalence_cases=176,
            explicit_open_cases=17,open_126_is_not_proven_business_handoff=True,
            original_native_processes=193,original_reference_processes=176,
            new_native_processes=0,new_reference_processes=0)
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
