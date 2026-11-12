"""Read exact failed reuse37/adopt38 seals, including unfinished gzip prefixes.
No generation, VM, native execution, compiler invocation or qualification retry.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import base64,collections,hashlib,json,os,resource,shutil,signal,stat,tarfile,traceback,zlib
from pathlib import Path,PurePosixPath
CONFIGS=json.loads("[{\"name\":\"reuse37\",\"head\":\"e3ea7f33f1d7bf3350e4b54a9a8d3522746223c7\",\"run\":43180758618,\"job\":131055867137,\"artifact\":13927872296,\"archive_bytes\":6290944,\"archive_sha256\":\"a66531f907f19f5f04cb68d9fa9114f9aaf04979a5c3346ab715ee1d4b148ead\",\"index_bytes\":37611,\"index_sha256\":\"4ffb2e8c019a452013c9d0f1601b477da9d8bd838415236b5592adac39ec66f4\",\"members\":114,\"raw_bytes\":43390347,\"expected_custody_status\":\"FAIL\"},{\"name\":\"adopt38\",\"head\":\"86c3e60966085f9aefde1170fbbb737c20a52422\",\"run\":43181547044,\"job\":131058484751,\"artifact\":13927383885,\"archive_bytes\":6326732,\"archive_sha256\":\"b6b2bd8d265b4d57fad750ead1b4e722c93593a3bab02063b11eafee0c82cf2b\",\"index_bytes\":39380,\"index_sha256\":\"52c237c0f38589da2f5ac457fa76e49f6471d2cd356ff9f4aff85cd9fe03f880\",\"members\":119,\"raw_bytes\":43651859,\"expected_custody_status\":\"FAIL\"}]")
def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def pin(path):
    st=path.lstat();assert stat.S_ISREG(st.st_mode) and not path.is_symlink()
    h=hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda:stream.read(1<<20),b""):h.update(block)
    return dict(bytes=st.st_size,mode=stat.S_IMODE(st.st_mode),sha256=h.hexdigest())
def emit(name,raw):
    print("HIA_NAMESPACE_TIMEOUT_RAW_META "+json.dumps(dict(name=name,bytes=len(raw),sha256=sha(raw),encoding="base64",chunk_bytes=6144),sort_keys=True),flush=True)
    for at in range(0,len(raw),6144):
        block=raw[at:at+6144]
        print("HIA_NAMESPACE_TIMEOUT_RAW_CHUNK "+json.dumps(dict(name=name,offset=at,bytes=len(block),sha256=sha(block),base64=base64.b64encode(block).decode("ascii")),sort_keys=True),flush=True)
    print("HIA_NAMESPACE_TIMEOUT_RAW_END "+json.dumps(dict(name=name,bytes=len(raw),sha256=sha(raw)),sort_keys=True),flush=True)
def inspect_ledger(path,destination,name):
    raw_before=pin(path);decoder=zlib.decompressobj(16+zlib.MAX_WBITS)
    prefix_digest=hashlib.sha256();prefix_bytes=0;pending=b"";complete_lines=0;valid_rows=0
    phases=collections.Counter();kinds=collections.Counter();tests={};last=[];parse_errors=[]
    returned_VM=0;recorded_native=0;error=None
    def feed(chunk):
        nonlocal pending,complete_lines,valid_rows,prefix_bytes,returned_VM,recorded_native
        prefix_bytes+=len(chunk);prefix_digest.update(chunk);pending+=chunk
        while b"\n" in pending:
            line,pending=pending.split(b"\n",1);complete_lines+=1
            try:
                value=json.loads(line)
                assert isinstance(value,dict)
            except (json.JSONDecodeError,UnicodeDecodeError,AssertionError) as failure:
                parse_errors.append(dict(line=complete_lines,bytes=len(line),sha256=sha(line),
                    error_class=type(failure).__name__,error=str(failure)))
                continue
            valid_rows+=1;phase=str(value.get("phase","ABSENT"));kind=str(value.get("kind","invocation"))
            phases[phase]+=1;kinds[kind]+=1
            test=str(value.get("test_id","ABSENT"))
            current=tests.setdefault(test,dict(records=0,phases={},returned_VM_records=0,native_records=0))
            current["records"]+=1;current["phases"][phase]=current["phases"].get(phase,0)+1
            if phase in ("vm","paired_vm") and "returned" in value:
                returned_VM+=1;current["returned_VM_records"]+=1
            if phase=="paired_native" and "actual_return" in value:
                recorded_native+=1;current["native_records"]+=1
            small={key:value[key] for key in ("phase","kind","test_id","role","entry","returned",
                "actual_return","expected_return","exception_class","exception","output_capacity",
                "vm_step_budget","command","handle","value","flags","expected_code","expected_result")
                if key in value}
            last.append(dict(line=complete_lines,bytes=len(line)+1,sha256=sha(line+b"\n"),fields=small,raw=line+b"\n"))
            if len(last)>5:del last[0]
    with path.open("rb") as stream:
        for block in iter(lambda:stream.read(65536),b""):
            try:
                feed(decoder.decompress(block))
            except zlib.error as failure:
                error=dict(error_class=type(failure).__name__,error=str(failure))
                break
    if error is None:
        try:feed(decoder.flush())
        except zlib.error as failure:error=dict(error_class=type(failure).__name__,error=str(failure))
    exported=[]
    for i,item in enumerate(last):
        raw=item.pop("raw");target=destination/("last-complete-record-"+str(i)+".jsonl")
        target.write_bytes(raw);assert target.read_bytes()==raw
        exported.append({**item,"path":target.name})
        emit(name+"/"+target.name,raw)
    if pending:
        target=destination/"incomplete-trailing-record.bin"
        target.write_bytes(pending);assert target.read_bytes()==pending
        emit(name+"/"+target.name,pending)
    after=pin(path);assert after==raw_before
    result=dict(original_compressed_before=raw_before,original_compressed_after=after,
        exact_decompressed_prefix_bytes=prefix_bytes,exact_decompressed_prefix_sha256=prefix_digest.hexdigest(),
        gzip_footer_completed=decoder.eof,gzip_decoder_error=error,
        trailing_compressed_bytes=len(decoder.unused_data),incomplete_last_line_bytes=len(pending),
        incomplete_last_line_sha256=sha(pending),complete_newline_records=complete_lines,
        parsed_JSON_object_records=valid_rows,JSON_parse_errors=parse_errors,
        phases=dict(phases),kinds=dict(kinds),test_record_counts=tests,
        recorded_returned_VM_entries=returned_VM,recorded_native_return_entries=recorded_native,
        last_complete_records=exported,
        counts_scope="ONLY complete records present in original bytes; an in-flight unrecorded invocation remains unknown.",
        target_suite_terminal_inferred=False,qualification_status="ORIGINAL_FAIL_UNCHANGED")
    save(destination/"ledger-prefix.json",result)
    print("HIA_NAMESPACE_TIMEOUT_LEDGER_PREFIX "+json.dumps(result,sort_keys=True),flush=True)
    return result
def read_one(config,download,out):
    out.mkdir(parents=True,exist_ok=False)
    matches=[]
    for directory,dirs,files in os.walk(download,followlinks=False):
        for name in dirs:assert not (Path(directory)/name).is_symlink()
        if all(name in files for name in ("evidence.tar.xz","evidence-members.json","custody.json")):
            p=Path(directory)
            if pin(p/"evidence.tar.xz")["sha256"]==config["archive_sha256"]:matches.append(p)
    assert len(matches)==1,(config["name"],"unique original seal",len(matches))
    directory=matches[0];archive=directory/"evidence.tar.xz";index=directory/"evidence-members.json";custody_path=directory/"custody.json"
    before={str(p):pin(p) for p in (archive,index,custody_path)}
    assert before[str(archive)]["bytes"]==config["archive_bytes"]
    assert before[str(index)]["bytes"]==config["index_bytes"] and before[str(index)]["sha256"]==config["index_sha256"]
    index_raw=index.read_bytes();custody_raw=custody_path.read_bytes()
    rows=json.loads(index_raw);custody=json.loads(custody_raw)
    assert len(rows)==config["members"] and sum(r["bytes"] for r in rows)==config["raw_bytes"]
    assert custody["status"]==config["expected_custody_status"]=="FAIL"
    assert custody["members"]==config["members"] and custody["original_bytes"]==config["raw_bytes"]
    assert custody["sha256"]==config["archive_sha256"] and custody["bytes"]==config["archive_bytes"]
    assert custody["member_index_sha256"]==config["index_sha256"]
    assert custody["member_index_bytes"]==config["index_bytes"]
    assert custody["all_original_and_tar_member_bytes_sha256_modes_readback"] is True
    expected={}
    for row in rows:
        name=row["name"];p=PurePosixPath(name)
        assert not p.is_absolute() and ".." not in p.parts and p.as_posix()==name and name not in expected
        expected[name]=row
    seen=set();total=0;verified=[];selected={};ledgers=[];canonical=[]
    originals=out/"originals";originals.mkdir()
    with tarfile.open(archive,"r:xz") as tf:
        for member in tf:
            assert member.isfile() and member.name in expected and member.name not in seen
            row=expected[member.name]
            assert member.size==row["bytes"] and member.mode==row["mode"]
            assert member.uid==member.gid==member.mtime==0
            base=PurePosixPath(member.name).name
            # Preserve all original JSON and all stdout/stderr text; source .py
            # and HIA/image bytes stay in the unchanged complete archive.
            wanted=base.endswith(".json") or "stdout" in base or "stderr" in base or base.endswith(".log")
            ledger=base=="invocations.jsonl.gz"
            stream=tf.extractfile(member);assert stream is not None
            h=hashlib.sha256();g=hashlib.sha1(b"blob "+str(member.size).encode()+b"\0");n=0
            target=originals/str(len(verified));writer=target.open("xb") if wanted or ledger else None
            try:
                for block in iter(lambda:stream.read(1<<20),b""):
                    n+=len(block);h.update(block);g.update(block)
                    if writer is not None:writer.write(block)
            finally:
                if writer is not None:writer.close()
            assert n==row["bytes"] and h.hexdigest()==row["sha256"],member.name
            item=dict(name=member.name,bytes=n,mode=member.mode,sha256=h.hexdigest(),git_blob_sha1=g.hexdigest())
            verified.append(item);seen.add(member.name);total+=n
            if wanted or ledger:
                assert pin(target)["bytes"]==n and pin(target)["sha256"]==h.hexdigest()
                item["copy_path"]=str(target.relative_to(out))
            if wanted:selected[member.name]=target
            if ledger:ledgers.append((member.name,target))
            if base.endswith((".hiaasm",".image.bin",".receipt.json",".request.json")):canonical.append(item)
    assert seen==set(expected) and total==config["raw_bytes"]
    # This byte export intentionally precedes optional nested schema/ledger
    # interpretation, so an unfamiliar original cannot hide its actual trace.
    save(out/"verified-members.json",verified)
    shutil.copyfile(archive,out/"original-evidence.tar.xz")
    assert pin(out/"original-evidence.tar.xz")["sha256"]==config["archive_sha256"]
    emit(config["name"]+"/control/evidence-members.json",index_raw)
    emit(config["name"]+"/control/custody.json",custody_raw)
    exports=[]
    for name,path in sorted(selected.items()):
        raw=path.read_bytes();emit(config["name"]+"/"+name,raw)
        exports.append(dict(name=name,path=str(path.relative_to(out)),bytes=len(raw),sha256=sha(raw)))
    save(out/"exported-originals.json",exports)
    ledger_results=[]
    for number,(name,path) in enumerate(ledgers):
        destination=out/("ledger-"+str(number));destination.mkdir()
        ledger_results.append(dict(name=name,readback=inspect_ledger(path,destination,config["name"]+"/"+name)))
    after={str(p):pin(p) for p in (archive,index,custody_path)}
    assert before==after
    result=dict(status="PASS_READBACK_ONLY",original_qualification_status="FAIL_UNCHANGED",
        configuration=config,source_before=before,source_after=after,
        full_member_bytes_modes_SHA256_Git_verified=True,members=len(seen),raw_bytes=total,
        complete_original_JSON_and_logs_exported=exports,canonical_source_and_image_index=canonical,
        original_ledgers=ledger_results,outer_ZIP_bytes_or_CRC_read=False,
        new_generation=0,new_VM_entries=0,new_B3_compiles=0,new_native_entries=0,
        ordinary_Store_closed=False,full_unixOpen_closed=False)
    save(out/"summary.json",result)
    print("HIA_NAMESPACE_TIMEOUT_ORIGINAL_READBACK "+json.dumps(result,sort_keys=True),flush=True)
    return result
def main():
    resource.setrlimit(resource.RLIMIT_CPU,(90,90))
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError("original reader wall180")))
    signal.alarm(180)
    out=Path(os.environ["HIA_CI_OUTPUT"]).absolute();out.mkdir(parents=True,exist_ok=False)
    results=[];status="FAIL"
    try:
        for config in CONFIGS:
            root=Path(os.environ["HIA_NAMESPACE_"+config["name"].upper()+"_DIR"]).resolve(strict=True)
            assert not out.is_relative_to(root)
            results.append(read_one(config,root,out/config["name"]))
        assert len(results)==2 and all(r["status"]=="PASS_READBACK_ONLY" for r in results)
        status="PASS_READBACK_ONLY"
    except BaseException as error:
        save(out/"reader-failure.json",dict(error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc()))
        traceback.print_exc()
    finally:
        signal.alarm(0)
        save(out/"summary.json",dict(status=status,results=results,
            original_qualification_status="BOTH_FAIL_UNCHANGED",new_target_executions=0))
    return 0 if status=="PASS_READBACK_ONLY" else 1
if __name__=="__main__":raise SystemExit(main())
