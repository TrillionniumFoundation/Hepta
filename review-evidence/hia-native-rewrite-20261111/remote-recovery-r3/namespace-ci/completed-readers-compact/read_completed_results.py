"""Read compact exact results from already completed namespace readers.

No target code, HIA generator, compiler, VM, native image or qualification runs.
The input directories come from exact pinned download-artifact IDs. Their ZIP
digests are GitHub declarations; this reader does not claim outer ZIP CRC/SHA
verification. It independently verifies every nested original sealed member,
the existing member index, original summaries and complete gzip prefixes.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import base64,collections,gzip,hashlib,json,os,re,resource,signal,stat,tarfile,time,traceback,zlib
from pathlib import Path,PurePosixPath
ARTIFACTS=[
 {"env":"HIA_NAMESPACE_READER40_DIR","run":43187803104,"job":131079272150,"artifact":13931725533,
  "bytes":201343680,"ZIP_SHA256":"d88c087669846279ec87d55c5e6a22df3d135ceec035b70294abeab6d3746f3a",
  "scopes":["reuse37","adopt38"]},
 {"env":"HIA_NAMESPACE_READER41_DIR","run":43189935529,"job":131086386894,"artifact":13931725318,
  "bytes":99698143,"ZIP_SHA256":"709bc759822567760b79875a22527906f3e7e24c2a2127fbf4facf996b5a9457",
  "scopes":["fs8follow39"]}]
ORIGINALS={
 "reuse37":{"archive_bytes":6290944,"archive_sha256":"a66531f907f19f5f04cb68d9fa9114f9aaf04979a5c3346ab715ee1d4b148ead","members":114,"raw_bytes":43390347},
 "adopt38":{"archive_bytes":6326732,"archive_sha256":"b6b2bd8d265b4d57fad750ead1b4e722c93593a3bab02063b11eafee0c82cf2b","members":119,"raw_bytes":43651859},
 "fs8follow39":{"archive_bytes":5521628,"archive_sha256":"276f9ef374fa178fb076b27c3a47340e982cd59281878aab74654c9909400cc1","members":93,"raw_bytes":42128691}}
def sha(raw):return hashlib.sha256(raw).hexdigest()
def git(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def pin(path):
    path=Path(path);info=path.lstat();assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
    h=hashlib.sha256();g=hashlib.sha1(b"blob "+str(info.st_size).encode()+b"\0");n=0
    with path.open("rb") as stream:
        for block in iter(lambda:stream.read(1<<20),b""):n+=len(block);h.update(block);g.update(block)
    assert n==info.st_size
    return dict(bytes=n,mode=stat.S_IMODE(info.st_mode),sha256=h.hexdigest(),git_blob_sha1=g.hexdigest())
def files(root):
    result=[]
    for directory,dirs,names in os.walk(root,followlinks=False):
        for name in dirs:assert not (Path(directory)/name).is_symlink()
        for name in names:
            path=Path(directory)/name
            result.append({"name":path.relative_to(root).as_posix(),**pin(path)})
    return sorted(result,key=lambda x:x["name"])
def copy_exact(source,target,expected=None):
    target.parent.mkdir(parents=True,exist_ok=True)
    before=pin(source)
    if expected is not None:assert before==expected
    with source.open("rb") as src,target.open("xb") as dst:
        for block in iter(lambda:src.read(1<<20),b""):dst.write(block)
    target.chmod(before["mode"]);assert pin(target)==before and pin(source)==before
    return before
def record_cas(raw,out,label):
    parsed=json.loads(raw);found=[]
    def walk(value,path):
        if isinstance(value,dict):
            for key,item in value.items():
                here=path+"/"+str(key)
                if str(key).endswith("_hex") and isinstance(item,str):
                    assert len(item)%2==0 and re.fullmatch("[0-9a-fA-F]*",item)
                    data=bytes.fromhex(item);digest=sha(data);target=out/"CAS"/digest
                    target.parent.mkdir(parents=True,exist_ok=True)
                    if target.exists():assert target.read_bytes()==data
                    else:target.write_bytes(data)
                    found.append(dict(record=label,JSON_pointer=here,bytes=len(data),sha256=digest,
                        git_blob_sha1=git(data),path=target.relative_to(out).as_posix()))
                else:walk(item,here)
        elif isinstance(value,list):
            for i,item in enumerate(value):walk(item,path+"/"+str(i))
    walk(parsed,"")
    return found
def ledger(path,dest,name):
    dest.mkdir(parents=True,exist_ok=False);before=pin(path)
    decoder=zlib.decompressobj(16+zlib.MAX_WBITS);digest=hashlib.sha256()
    pending=b"";prefix_bytes=0;lines=0;valid=0;first=[];last=[];parse_errors=[]
    phases=collections.Counter();kinds=collections.Counter();tests={};vm=0;native=0;error=None
    def feed(chunk):
        nonlocal pending,prefix_bytes,lines,valid,vm,native
        digest.update(chunk);prefix_bytes+=len(chunk);pending+=chunk
        while b"\n" in pending:
            line,pending=pending.split(b"\n",1);lines+=1
            try:value=json.loads(line);assert isinstance(value,dict)
            except (json.JSONDecodeError,UnicodeDecodeError,AssertionError) as e:
                parse_errors.append(dict(line=lines,bytes=len(line),sha256=sha(line),
                    error_class=type(e).__name__,error=str(e)));continue
            valid+=1;phase=str(value.get("phase","ABSENT"));kind=str(value.get("kind","invocation"))
            phases[phase]+=1;kinds[kind]+=1;test=str(value.get("test_id","ABSENT"))
            row=tests.setdefault(test,dict(records=0,phases={},returned_VM_records=0,native_records=0))
            row["records"]+=1;row["phases"][phase]=row["phases"].get(phase,0)+1
            if phase in ("vm","paired_vm") and "returned" in value:vm+=1;row["returned_VM_records"]+=1
            if phase=="paired_native" and "actual_return" in value:native+=1;row["native_records"]+=1
            small={key:value[key] for key in ("phase","kind","test_id","role","entry","returned",
                "actual_return","expected_return","exception_class","exception","output_capacity",
                "vm_step_budget","command","handle","value","flags","expected_code","expected_result") if key in value}
            item=dict(line=lines,bytes=len(line)+1,sha256=sha(line+b"\n"),fields=small,raw=line+b"\n")
            if len(first)<5:first.append(item)
            last.append(item)
            if len(last)>5:del last[0]
    with path.open("rb") as stream:
        for block in iter(lambda:stream.read(65536),b""):
            try:feed(decoder.decompress(block))
            except zlib.error as e:error=dict(error_class=type(e).__name__,error=str(e));break
    if error is None:
        try:feed(decoder.flush())
        except zlib.error as e:error=dict(error_class=type(e).__name__,error=str(e))
    after=pin(path);assert after==before
    cas=[];first_rows=[];last_rows=[]
    for label,items,rows in (("first",first,first_rows),("last",last,last_rows)):
        for i,item in enumerate(items):
            raw=item["raw"];target=dest/(label+"-complete-record-"+str(i)+".jsonl");target.write_bytes(raw)
            assert target.read_bytes()==raw
            rows.append({k:v for k,v in item.items() if k!="raw"}|{"path":target.name})
            cas+=record_cas(raw,dest,target.name)
    if pending:
        target=dest/"incomplete-trailing-record.bin";target.write_bytes(pending);assert target.read_bytes()==pending
    result=dict(original_compressed_before={k:before[k] for k in ("bytes","mode","sha256")},
        original_compressed_after={k:after[k] for k in ("bytes","mode","sha256")},
        exact_decompressed_prefix_bytes=prefix_bytes,exact_decompressed_prefix_sha256=digest.hexdigest(),
        gzip_footer_completed=decoder.eof,gzip_decoder_error=error,trailing_compressed_bytes=len(decoder.unused_data),
        incomplete_last_line_bytes=len(pending),incomplete_last_line_sha256=sha(pending),
        complete_newline_records=lines,parsed_JSON_object_records=valid,JSON_parse_errors=parse_errors,
        phases=dict(phases),kinds=dict(kinds),test_record_counts=tests,recorded_returned_VM_entries=vm,
        recorded_native_return_entries=native,last_complete_records=last_rows,
        counts_scope="ONLY complete records present in original bytes; an in-flight unrecorded invocation remains unknown.",
        target_suite_terminal_inferred=False,qualification_status="ORIGINAL_FAIL_UNCHANGED")
    save(dest/"recomputed-ledger-prefix.json",result);save(dest/"first-records.json",first_rows);save(dest/"CAS-index.json",cas)
    return result,first_rows,cas
def locate(root,scope):
    found=[]
    for directory,dirs,names in os.walk(root,followlinks=False):
        for name in dirs:assert not (Path(directory)/name).is_symlink()
        if all(name in names for name in ("original-evidence.tar.xz","verified-members.json","summary.json")):
            path=Path(directory);info=pin(path/"original-evidence.tar.xz")
            if info["sha256"]==ORIGINALS[scope]["archive_sha256"]:found.append(path)
    assert len(found)==1,(scope,"unique completed reader result",len(found))
    return found[0]
def read_scope(scope,root,out):
    out.mkdir(parents=True,exist_ok=False);where=locate(root,scope);config=ORIGINALS[scope]
    original=where/"original-evidence.tar.xz";index=where/"verified-members.json";summary=where/"summary.json"
    controls={name:pin(path) for name,path in (("archive",original),("index",index),("summary",summary))}
    assert controls["archive"]["bytes"]==config["archive_bytes"]
    row_index=json.loads(index.read_bytes());prior=json.loads(summary.read_bytes())
    assert prior["status"]=="PASS_READBACK_ONLY" and prior["original_qualification_status"]=="FAIL_UNCHANGED"
    assert prior["source_before"]==prior["source_after"] and prior["full_member_bytes_modes_SHA256_Git_verified"]
    assert prior["members"]==config["members"] and prior["raw_bytes"]==config["raw_bytes"]
    assert all(prior[k]==0 for k in ("new_generation","new_VM_entries","new_B3_compiles","new_native_entries"))
    assert prior["configuration"]["archive_sha256"]==config["archive_sha256"]
    assert len(row_index)==config["members"]
    expected={}
    for row in row_index:
        name=row["name"];p=PurePosixPath(name)
        assert not p.is_absolute() and ".." not in p.parts and p.as_posix()==name and name not in expected
        if "copy_path" in row:
            copied=PurePosixPath(row["copy_path"])
            assert not copied.is_absolute() and ".." not in copied.parts and copied.as_posix()==row["copy_path"]
        expected[name]=row
    copy_exact(summary,out/"original-reader-summary.json",controls["summary"])
    copy_exact(index,out/"original-reader-verified-members.json",controls["index"])
    copy_exact(original,out/"original-failed-target-evidence.tar.xz",controls["archive"])
    seen=set();total=0;ledgers=[];exports=[];canonical=[];raw_reports=[]
    with tarfile.open(original,"r:xz") as tf:
        for member in tf:
            assert member.isfile() and member.name in expected and member.name not in seen
            assert member.uid==member.gid==member.mtime==0
            row=expected[member.name];assert (member.size,member.mode)==(row["bytes"],row["mode"])
            basename=PurePosixPath(member.name).name
            keep=basename.endswith((".py",".S",".c",".hiaasm",".image.bin",".receipt.json",".request.json")) or basename.endswith(".json") or basename=="invocations.jsonl.gz" or "stdout" in basename or "stderr" in basename
            target=out/"original-members"/str(len(seen))/basename
            if keep:target.parent.mkdir(parents=True,exist_ok=True)
            stream=tf.extractfile(member);assert stream is not None
            h=hashlib.sha256();g=hashlib.sha1(b"blob "+str(member.size).encode()+b"\0");n=0
            writer=target.open("xb") if keep else None
            try:
                for block in iter(lambda:stream.read(1<<20),b""):
                    n+=len(block);h.update(block);g.update(block)
                    if writer is not None:writer.write(block)
            finally:
                if writer is not None:writer.close()
            assert n==row["bytes"] and h.hexdigest()==row["sha256"] and g.hexdigest()==row["git_blob_sha1"]
            observed=dict(name=member.name,bytes=n,mode=member.mode,sha256=h.hexdigest(),git_blob_sha1=g.hexdigest())
            total+=n;seen.add(member.name)
            if keep:
                target.chmod(member.mode);assert pin(target)=={k:observed[k] for k in ("bytes","mode","sha256","git_blob_sha1")}
                observed["copy_path"]=target.relative_to(out).as_posix();exports.append(observed)
                if basename=="invocations.jsonl.gz":
                    old_copy=where/row["copy_path"];old_info=pin(old_copy)
                    assert (old_info["bytes"],old_info["sha256"],old_info["git_blob_sha1"])==(n,h.hexdigest(),g.hexdigest())
                    ledgers.append((member.name,old_copy))
                elif basename.endswith((".hiaasm",".image.bin",".receipt.json",".request.json")):canonical.append(observed)
                if basename in ("summary.json","validation.json","process.json") or basename.endswith((".process.json",".summary.json")) or "stderr" in basename or "stdout" in basename:
                    raw_reports.append(observed)
    assert seen==set(expected) and total==config["raw_bytes"]
    ledger_results=[]
    for number,(name,path) in enumerate(ledgers):
        value,first,cas=ledger(path,out/("ledger-"+str(number)),name)
        matches=[r for r in prior["original_ledgers"] if r["name"]==name];assert len(matches)==1
        old=matches[0]["readback"]
        assert value==old,(scope,name,"entire original gzip-prefix interpretation differs")
        old_dir=where/("ledger-"+str(number));new_dir=out/("ledger-"+str(number))
        old_prefix=old_dir/"ledger-prefix.json";assert json.loads(old_prefix.read_bytes())==old
        copy_exact(old_prefix,new_dir/"original-reader-ledger-prefix.json")
        for row in value["last_complete_records"]:
            before_raw=(old_dir/row["path"]).read_bytes()
            after_raw=(new_dir/row["path"]).read_bytes()
            assert before_raw==after_raw and len(before_raw)==row["bytes"] and sha(before_raw)==row["sha256"]
        if value["incomplete_last_line_bytes"]:
            before_raw=(old_dir/"incomplete-trailing-record.bin").read_bytes()
            assert before_raw==(new_dir/"incomplete-trailing-record.bin").read_bytes()
        ledger_results.append(dict(name=name,prefix=value,first_complete_records=first,
            complete_first_last_record_CAS=cas,original_reader_interpretation_equal=True))
    assert len(ledger_results)==len(prior["original_ledgers"])
    after={name:pin(path) for name,path in (("archive",original),("index",index),("summary",summary))}
    assert after==controls
    result=dict(status="PASS_READBACK_ONLY",scope=scope,original_target_status="FAIL_UNCHANGED",
        original_archive=controls["archive"],verified_member_index=controls["index"],reader_summary=controls["summary"],
        members=len(seen),raw_bytes=total,source_before=controls,source_after=after,
        complete_original_archive_copied=True,all_original_member_bytes_modes_SHA256_Git_checked=True,
        original_raw_reports=raw_reports,canonical_sources_images_and_budgets=canonical,
        original_ledgers=ledger_results,new_HIA_generation=0,new_B3=0,new_VM=0,new_native=0,
        actual_unrecorded_inflight_call="UNKNOWN",performance_root_cause="NOT_INFERRED",
        outer_ZIP_SHA_or_CRC_independently_read=False)
    save(out/"exported-original-members.json",exports);save(out/"result.json",result)
    return result
def exact_console(value):
    # Only the readable projection changes integer presentation. All original
    # JSON files and ledger records are sealed in their original exact bytes.
    if isinstance(value,bool) or value is None:return value
    if isinstance(value,int):return str(value)
    if isinstance(value,list):return [exact_console(v) for v in value]
    if isinstance(value,dict):return {k:exact_console(v) for k,v in value.items()}
    return value
def seal(out):
    content=out/"payload";rows=files(content)
    index=out/"evidence-members.json";save(index,rows)
    archive=out/"evidence.tar.gz"
    with archive.open("xb") as raw,gzip.GzipFile(filename="",mode="wb",fileobj=raw,mtime=0,compresslevel=1) as gz,tarfile.open(fileobj=gz,mode="w|") as tf:
        for row in rows:
            path=content/row["name"];assert pin(path)=={k:row[k] for k in ("bytes","mode","sha256","git_blob_sha1")}
            info=tarfile.TarInfo(row["name"]);info.size=row["bytes"];info.mode=row["mode"]
            info.uid=info.gid=info.mtime=0;info.uname=info.gname=""
            with path.open("rb") as stream:tf.addfile(info,stream)
    expected={r["name"]:r for r in rows};seen=set()
    with tarfile.open(archive,"r:gz") as tf:
        for member in tf:
            assert member.isfile() and member.name in expected and member.name not in seen
            row=expected[member.name];assert member.mode==row["mode"] and member.size==row["bytes"]
            assert member.uid==member.gid==member.mtime==0
            stream=tf.extractfile(member);h=hashlib.sha256();g=hashlib.sha1(b"blob "+str(member.size).encode()+b"\0");n=0
            for block in iter(lambda:stream.read(1<<20),b""):n+=len(block);h.update(block);g.update(block)
            assert n==row["bytes"] and h.hexdigest()==row["sha256"] and g.hexdigest()==row["git_blob_sha1"]
            seen.add(member.name)
    assert seen==set(expected) and files(content)==rows
    result=dict(schema="hia.namespace.reader-results.seal.v1",archive=pin(archive),index=pin(index),
        members=len(rows),raw_bytes=sum(r["bytes"] for r in rows),all_members_full_bytes_modes_SHA256_Git_readback=True)
    save(out/"custody.json",result);return result
def main():
    resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError("reader result-only wall180")))
    signal.alarm(180);assert sys.version_info[:3]==(3,12,14)
    out=Path(os.environ["HIA_CI_OUTPUT"]).absolute();out.mkdir(parents=True,exist_ok=False)
    payload=out/"payload";payload.mkdir()
    self_before=pin(Path(__file__).resolve())
    copy_exact(Path(__file__).resolve(),payload/"reader-source.py",self_before)
    status="FAIL";results=[];roots=[];error=None;after_errors=[];custody=None
    try:
        for spec in ARTIFACTS:
            root=Path(os.environ[spec["env"]]).resolve(strict=True)
            assert not out.is_relative_to(root)
            before=files(root);roots.append((root,before))
            save(payload/("artifact-"+str(spec["artifact"])+"-before.json"),dict(GitHub_declaration=spec,files=before,
                input_scope="Materialized official download-artifact directory; no pre-existing whole reader-directory seal is claimed."))
            for scope in spec["scopes"]:results.append(read_scope(scope,root,payload/scope))
        assert len(results)==3 and all(r["status"]=="PASS_READBACK_ONLY" for r in results)
        status="PASS_READBACK_ONLY"
    except BaseException as e:
        error=dict(error_class=type(e).__name__,error=str(e),traceback=traceback.format_exc())
        save(payload/"failure.json",error)
    finally:
        self_after=None
        try:
            self_after=pin(Path(__file__).resolve());assert self_after==self_before
        except BaseException as e:after_errors.append(dict(root="reader-source",error=repr(e)))
        for root,before in roots:
            try:
                observed=files(root)
                save(payload/(root.name+"-after.json"),observed)
                assert observed==before
            except BaseException as e:after_errors.append(dict(root=str(root),error=repr(e)))
        if after_errors:status="FAIL"
        report=dict(status=status,results=results,error=error,after_check_errors=after_errors,
            new_target_executions=0,original_qualification_status="ALL_ORIGINAL_FAILURES_UNCHANGED",
            input_directory_integrity_scope="Every regular downloaded file hashed before/after; nested original target seals fully verified.",
            original_reader_whole_directory_preexisting_seal=False,reader_source_before=self_before,reader_source_after=self_after)
        save(payload/"complete-readback.json",report)
        try:custody=seal(out)
        except BaseException as e:
            status="FAIL";save(out/"sealing-failure.json",dict(error_class=type(e).__name__,error=str(e),traceback=traceback.format_exc()))
        projection=dict(status=status,original_failures_unchanged=True,new_target_executions=0,custody=custody,
            error=error,after_check_errors=after_errors,results=[])
        for r in results:
            projection["results"].append(dict(scope=r["scope"],members=r["members"],raw_bytes=r["raw_bytes"],
                original_archive=r["original_archive"],reader_summary=r["reader_summary"],
                original_raw_reports=r["original_raw_reports"],canonical_index_count=len(r["canonical_sources_images_and_budgets"]),
                original_ledgers=[dict(name=x["name"],prefix=x["prefix"],first_complete_records=x["first_complete_records"],
                    complete_first_last_record_CAS_count=len(x["complete_first_last_record_CAS"])) for x in r["original_ledgers"]]))
        projection=exact_console(projection)
        projection["integer_presentation"]="Decimal strings in this readable projection only; original JSON/u64 bytes remain unchanged in sealed files."
        raw=(json.dumps(projection,sort_keys=True,separators=(",",":"))+"\n").encode()
        (out/"console-summary.json").write_bytes(raw)
        # Never truncate or partially serialize a claimed complete JSON.
        if len(raw)>=900000:
            status="FAIL"
            print(json.dumps(dict(status="FAIL_CONSOLE_BOUND",complete_summary_bytes=len(raw),
                complete_summary_sha256=sha(raw),complete_summary_saved=True,new_target_executions=0)),flush=True)
        else:print("HIA_NAMESPACE_COMPLETED_READER_RESULTS "+raw.decode(),end="",flush=True)
        signal.alarm(0)
    return 0 if status=="PASS_READBACK_ONLY" else 1
if __name__=="__main__":raise SystemExit(main())
