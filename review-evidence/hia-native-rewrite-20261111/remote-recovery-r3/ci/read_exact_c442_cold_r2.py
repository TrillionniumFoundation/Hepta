"""Read the exact c442 cold artifact; never import or execute project code.

Input ZIP must be the original artifact bytes, not an extracted directory or a
new qualification. All file members are streamed and hashed. Original report,
owner, stdout, stderr, request and JSON/log evidence are retained byte-for-byte.
r2 preserves the original disk receipt and the augmented run_owned return.
The reader reports the producer's facts without classifying a 164 s failure as
the earlier b433 timeout.
"""
from __future__ import annotations
import argparse,base64,json,os,stat,traceback,zipfile
from hashlib import sha256
from pathlib import Path,PurePosixPath

PIN=dict(repository="TrillionniumFoundation/Hepta",
    commit="c4424483c586a7f91f3311cae6107966cdcf4d4a",
    run_id=43113333402,job_id=130834816288,artifact_id=13898190121,
    artifact_name="hia-core-native-c4424483c586a7f91f3311cae6107966cdcf4d4a-1",
    zip_bytes=54152870,
    zip_sha256="cea6392d44930dc0ad0e304dbdb292cb977167af144c06df893e722dcd33bed1",
    producer_upload_file_count=6395)
REQUIRED=("hia-cold.json","hia-cold.cold/process-owner.json",
          "hia-cold.cold/request.json","hia-cold.cold/stdout.log",
          "hia-cold.cold/stderr.log")
def digest_file(path):
    h=sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1<<20),b""):h.update(chunk)
    return h.hexdigest()
def save(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(obj,indent=2,sort_keys=True)+"\n")
def safe_name(name):
    p=PurePosixPath(name)
    if not name or p.is_absolute() or ".." in p.parts or "\\" in name or "\0" in name:
        raise ValueError("invalid original ZIP member spelling")
    return p
def export_text(name,raw):
    # Transport only: exact raw bytes remain under originals/. Avoid a single
    # oversized log line and preserve arbitrary original UTF-8/error bytes.
    if len(raw)>2*1024*1024:
        print(json.dumps(dict(event="ORIGINAL_NOT_PRINTED_SIZE",member=name,bytes=len(raw),
                              sha256=sha256(raw).hexdigest())),flush=True)
        return
    for offset in range(0,len(raw),18000):
        part=raw[offset:offset+18000]
        print(json.dumps(dict(event="EXACT_C442_ORIGINAL_BASE64",member=name,offset=offset,
            total_bytes=len(raw),sha256=sha256(raw).hexdigest(),
            data=base64.b64encode(part).decode("ascii")),sort_keys=True),flush=True)
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--zip",type=Path,required=True)
    ap.add_argument("--output",type=Path,required=True)
    args=ap.parse_args()
    args.output.mkdir(parents=True,exist_ok=False)
    summary=dict(scope="READ_ONLY_EXACT_C442_COLD_ORIGINALS",
        pin=PIN,project_imports=0,native_entries=0,new_qualification=False,
        classification="UNREAD",status="FAIL")
    rows=[];retained=[];required={};source_expected={};source_actual={}
    try:
        before=dict(bytes=args.zip.stat().st_size,sha256=digest_file(args.zip))
        assert before==dict(bytes=PIN["zip_bytes"],sha256=PIN["zip_sha256"]),before
        names=set()
        with zipfile.ZipFile(args.zip) as z:
            for item in z.infolist():
                name=item.filename;safe_name(name)
                assert name not in names,("duplicate member",name)
                names.add(name)
                mode=item.external_attr>>16
                assert not stat.S_ISLNK(mode),("unexpected symlink",name)
                if item.is_dir():continue
                keep=(name in REQUIRED or name.endswith((".json",".jsonl",".log",".txt"))
                      and "/source/" not in name)
                target=args.output/"originals"/name if keep else None
                if target:target.parent.mkdir(parents=True,exist_ok=True)
                h=sha256();size=0
                out=target.open("xb") if target else None
                try:
                    with z.open(item) as f:
                        for chunk in iter(lambda:f.read(1<<20),b""):
                            h.update(chunk);size+=len(chunk)
                            if out:out.write(chunk)
                finally:
                    if out:out.close()
                assert size==item.file_size,(name,size,item.file_size)
                row=dict(path=name,bytes=size,sha256=h.hexdigest(),mode=mode,
                         compressed_bytes=item.compress_size,crc32=item.CRC)
                rows.append(row)
                if target:
                    assert target.stat().st_size==size and digest_file(target)==row["sha256"]
                    retained.append(row)
                if name in REQUIRED:required[name]=target.read_bytes()
                if name.startswith("hia-cold.cold/source/"):
                    source_actual[name[len("hia-cold.cold/source/"):]]=row["sha256"]
            assert len(rows)==PIN["producer_upload_file_count"],len(rows)
            assert set(required)==set(REQUIRED),sorted(set(REQUIRED)-set(required))
        for name in REQUIRED:
            export_text(name,required[name])
        cold=json.loads(required["hia-cold.json"])
        owner=json.loads(required["hia-cold.cold/process-owner.json"])
        request=json.loads(required["hia-cold.cold/request.json"])
        assert cold["schema"]=="hepta.hia.selfhost-cold-replay.v1"
        # run_owned parses the immutable disk receipt, then augments its returned
        # Python object. These are intentionally two different original records.
        returned=cold["process_owner"]
        assert type(returned) is dict and type(returned.get("supervisor_returncode")) is int
        expected_returned=dict(owner)
        expected_returned["supervisor_returncode"]=returned["supervisor_returncode"]
        expected_returned["receipt_sha256"]=sha256(required["hia-cold.cold/process-owner.json"]).hexdigest()
        if returned["supervisor_returncode"]!=0 and owner["status"]=="OWNED_PROCESS_COMPLETED":
            expected_returned["status"]="OWNER_EXIT_MISMATCH_HOLD"
        owner_differences=[]
        for key in sorted(set(owner)|set(returned)):
            if key not in owner or key not in returned or owner[key]!=returned[key]:
                owner_differences.append(dict(field=key,disk_present=key in owner,
                    returned_present=key in returned,disk_value=owner.get(key),
                    returned_value=returned.get(key)))
        save(args.output/"owner-record-differences.json",owner_differences)
        print(json.dumps(dict(event="EXACT_OWNER_RECORD_DIFFERENCES",
                              differences=owner_differences),sort_keys=True),flush=True)
        assert returned==expected_returned,("run_owned augmentation differs",owner_differences)
        assert cold["qualification_wall_limit_seconds"]==180
        assert cold["cleanup_wall_limit_seconds"]==3
        assert request["source_manifest"]==cold["source_manifest"]
        source_expected=cold["source_manifest"]
        assert all(source_actual.get(k)==v for k,v in source_expected.items())
        facts={k:cold.get(k) for k in (
            "schema","status","profile","checks","returncode","process_owner",
            "qualification_wall_limit_seconds","cleanup_wall_limit_seconds",
            "wall_elapsed_ns","nested_report","nested_report_sha256",
            "seed_sha256","generation_sha256","modified_generation_sha256")}
        save(args.output/"cold-facts.json",facts)
        # A qualification report can be absent on an exception. Retain both that
        # absence and the actual process-owner result; do not invent a report.
        nested=[r for r in rows if r["path"]=="hia-cold.cold/qualification.json"]
        phase_files=[r for r in rows if "phase" in r["path"].lower()
                     and r["path"].endswith((".json",".jsonl"))]
        receipts=[r for r in rows if r["path"].endswith(".receipt.json")]
        nested_archives=[r for r in rows if r["path"].endswith((".zip",".tar.xz",".tar.gz"))]
        save(args.output/"phase-receipt-index.json",dict(
            phase_files=phase_files,receipts=receipts,nested_archives=nested_archives))
        after=dict(bytes=args.zip.stat().st_size,sha256=digest_file(args.zip))
        assert after==before
        summary.update(status="PASS",classification="PRODUCER_FACTS_ONLY",
            original_cold_status=cold["status"],original_returncode=cold["returncode"],
            checks_passed=sum(cold["checks"].values()),checks_total=len(cold["checks"]),
            original_process_owner=returned,raw_owner_receipt=owner,
            owner_record_differences=owner_differences,
            original_wall_elapsed_ns=cold["wall_elapsed_ns"],
            nested_report_present=bool(nested),generation_sha256=cold["generation_sha256"],
            modified_generation_sha256=cold["modified_generation_sha256"],
            all_zip_members_streamed=True,zip_unchanged=True,members=len(rows),
            original_bytes=sum(r["bytes"] for r in rows),retained_members=len(retained),
            source_manifest_members=len(source_expected),source_members_verified=True,
            phase_index_candidates=len(phase_files),receipt_members=len(receipts),
            nested_archive_members=len(nested_archives))
        print(json.dumps(dict(event="EXACT_C442_COLD_FACTS",facts=facts),sort_keys=True),flush=True)
        for row in phase_files:
            export_text(row["path"],(args.output/"originals"/row["path"]).read_bytes())
    except BaseException as exc:
        summary.update(error_class=type(exc).__name__,error=str(exc))
        traceback.print_exc()
    finally:
        save(args.output/"zip-members.json",rows)
        save(args.output/"retained-members.json",retained)
        save(args.output/"summary.json",summary)
        print(json.dumps(summary,sort_keys=True),flush=True)
    if summary["status"]!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
