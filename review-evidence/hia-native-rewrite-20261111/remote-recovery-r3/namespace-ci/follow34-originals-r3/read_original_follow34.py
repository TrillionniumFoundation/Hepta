"""Strict original follow34 readback. No native, VM, compilation or assembly."""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import base64,hashlib,json,os,resource,shutil,signal,stat,struct,tarfile,traceback,zlib
from pathlib import Path,PurePosixPath
MODELS=[
 dict(name="physical",env="HIA_NAMESPACE_PHYSICAL34_DIR",artifact=13918533320,run=43162559333,job=130996905266,
 archive_bytes=6939000,archive_sha="fd9556b23ee9144d39fab66c038db5f1d3828fa0f948e4abc3eae0326b034a10",
 index_bytes=76424,index_sha="c561b3140924caca6233b2534a3e5964c65ba84979b2d7198c2fc95238649b34",members=211,raw_bytes=57844918,build="db-join-build-r1"),
 dict(name="robust",env="HIA_NAMESPACE_ROBUST34_DIR",artifact=13918832204,run=43162559333,job=130996905291,
 archive_bytes=5848768,archive_sha="2f847906196b50a0f0d87e0c8b1afab191042fc6a36c289fb5470008c433ecce",
 index_bytes=26525,index_sha="3f31a18e65b745f42d62c1787343e731746ea9290370aa1416875b4890e32b1e",members=82,raw_bytes=44209189,build="build-r1")]
def sha(b):return hashlib.sha256(b).hexdigest()
def save(p,value):
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def pin(p):
    st=p.lstat();assert stat.S_ISREG(st.st_mode) and not p.is_symlink()
    h=hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda:f.read(1<<20),b""):h.update(b)
    return dict(bytes=st.st_size,sha256=h.hexdigest(),mode=stat.S_IMODE(st.st_mode))
def emit(name,raw):
    print("HIA_NAMESPACE_FOLLOW34_RAW_META "+json.dumps(dict(name=name,bytes=len(raw),sha256=sha(raw),encoding="base64",chunk_bytes=6144),sort_keys=True),flush=True)
    for at in range(0,len(raw),6144):
        b=raw[at:at+6144]
        print("HIA_NAMESPACE_FOLLOW34_RAW_CHUNK "+json.dumps(dict(name=name,offset=at,bytes=len(b),sha256=sha(b),base64=base64.b64encode(b).decode("ascii")),sort_keys=True),flush=True)
    print("HIA_NAMESPACE_FOLLOW34_RAW_END "+json.dumps(dict(name=name,bytes=len(raw),sha256=sha(raw)),sort_keys=True),flush=True)
def elf_relocations(raw):
    assert raw[:6]==b"\x7fELF\x02\x01" and len(raw)>=64
    assert struct.unpack_from("<HH",raw,16)==(1,62)
    off=struct.unpack_from("<Q",raw,40)[0]
    size,count,names=struct.unpack_from("<HHH",raw,58)
    assert size==64 and count>0 and names<count and off<=len(raw) and count*size<=len(raw)-off
    sections=[struct.unpack_from("<IIQQQQIIQQ",raw,off+i*size) for i in range(count)]
    def body(index):
        assert 0<=index<count
        row=sections[index];start,n=row[4:6]
        assert start<=len(raw) and n<=len(raw)-start
        return raw[start:start+n]
    def text(table,index):
        assert index<len(table)
        end=table.index(0,index)
        return table[index:end].decode("utf-8","strict")
    namesraw=body(names);section_names=[text(namesraw,row[0]) for row in sections]
    relocations=[]
    for index,row in enumerate(sections):
        if row[1] not in (4,9):continue
        entry_size=24 if row[1]==4 else 16
        assert row[9]==entry_size and row[5]%entry_size==0
        symindex=row[6];target=row[7];assert symindex<count and target<count
        symrow=sections[symindex];assert symrow[1]==2 and symrow[9]==24 and symrow[5]%24==0
        symdata=body(symindex);strings=body(symrow[6]);data=body(index)
        for at in range(0,len(data),entry_size):
            address,info=struct.unpack_from("<QQ",data,at)
            si=info>>32;assert si<len(symdata)//24
            symbol=struct.unpack_from("<IBBHQQ",symdata,si*24)
            rel=dict(section=section_names[index],target_section=section_names[target],
                offset=address,type=info&0xffffffff,symbol_index=si,
                symbol_name=text(strings,symbol[0]),symbol_binding=symbol[1]>>4,
                symbol_type=symbol[1]&15,symbol_section_index=symbol[3],
                symbol_value=symbol[4],symbol_size=symbol[5])
            if row[1]==4:rel["addend"]=struct.unpack_from("<q",data,at+16)[0]
            relocations.append(rel)
    return dict(status="PARSED_ORIGINAL_ET_REL_ONLY",bytes=len(raw),sha256=sha(raw),
        count=len(relocations),relocations=relocations,object_executed=False)

def gzip_prefix(name,raw,out):
    """Read every complete original JSONL prefix; never repair a truncated gzip."""
    decoder=zlib.decompressobj(31);pending=b"";count=0;byrole={};last=[];digest=hashlib.sha256();total=0
    status="INCOMPLETE_PREFIX";error=None
    p=out/"derived"/(Path(name).name+".decoded-prefix");p.parent.mkdir(exist_ok=True)
    with p.open("xb") as stream:
        def take(chunk):
            nonlocal pending,count,total,last
            stream.write(chunk);digest.update(chunk);total+=len(chunk);pending+=chunk
            while b"\n" in pending:
                line,pending=pending.split(b"\n",1)
                if not line:raise ValueError("empty original JSONL line")
                obj=json.loads(line);count+=1
                row=dict(index=count,name=obj.get("name"),label=obj.get("label"),
                    role=obj.get("role"),equal=obj.get("equal"),keys=sorted(obj))
                if "role" in obj:
                    role=str(obj["role"]);record=byrole.setdefault(role,dict(records=0,vm=0,native=0,complete_equal=0))
                    record["records"]+=1
                    for key in ("vm","native"):
                        if key in obj:record[key]+=1
                    if obj.get("equal") is True:record["complete_equal"]+=1
                    row["vm_steps"]=obj.get("vm",{}).get("steps")
                    row["vm_result"]=obj.get("vm",{}).get("result")
                    row["native_result"]=obj.get("native",{}).get("result")
                last.append((row,line));last=last[-3:]
        try:
            for at in range(0,len(raw),65536):
                chunk=raw[at:at+65536]
                while chunk:
                    take(decoder.decompress(chunk,1<<20))
                    chunk=decoder.unconsumed_tail
            if decoder.eof and not decoder.unused_data and not pending:
                status="COMPLETE_SEALED_GZIP_JSONL"
            elif decoder.unused_data:
                status="TRAILING_GZIP_BYTES_UNINTERPRETED"
        except (zlib.error, ValueError, UnicodeError) as exc:
            # Corrupt original encoded bytes are reportable. Timeout, allocation
            # and output IO failures must escape to the aggregate FAIL handler.
            error=dict(error_class=type(exc).__name__,error=str(exc));status="DECODE_STOPPED_ORIGINAL_RETAINED"
    for i,(_,line) in enumerate(last):emit(name+"/last-complete-record-"+str(i),line)
    return dict(original_name=name,compressed_bytes=len(raw),compressed_sha256=sha(raw),
        status=status,gzip_eof=decoder.eof,trailing_gzip_bytes=len(decoder.unused_data),
        complete_jsonl_records=count,entries_by_role=byrole,last_complete_records=[r for r,_ in last],
        decoded_prefix_bytes=total,decoded_prefix_sha256=digest.hexdigest(),
        unfinished_line_bytes=len(pending),unfinished_line_sha256=sha(pending),error=error,
        producer_active_call_unknown=True,qualification_still_FAIL=True,
        decoded_prefix_is_not_a_replacement_original=True)

def read_one(model,destination):
    root=Path(os.environ[model["env"]]).resolve(strict=True);out=destination/model["name"]
    assert not out.is_relative_to(root);out.mkdir(mode=0o700)
    matches=[]
    for directory,dirs,files in os.walk(root,followlinks=False):
        for name in dirs:assert not (Path(directory)/name).is_symlink()
        if all(n in files for n in ("evidence.tar.xz","evidence-members.json","custody.json")):
            d=Path(directory)
            if pin(d/"evidence.tar.xz")["sha256"]==model["archive_sha"]:matches.append(d)
    assert len(matches)==1
    d=matches[0];ap=d/"evidence.tar.xz";ip=d/"evidence-members.json";cp=d/"custody.json"
    before={str(p):pin(p) for p in (ap,ip,cp)}
    assert before[str(ap)]["bytes"]==model["archive_bytes"]
    assert before[str(ip)]["bytes"]==model["index_bytes"] and before[str(ip)]["sha256"]==model["index_sha"]
    ir=ip.read_bytes();cr=cp.read_bytes();rows=json.loads(ir);custody=json.loads(cr)
    assert isinstance(rows,list) and len(rows)==model["members"]
    expected={}
    for row in rows:
        name=row["name"];p=PurePosixPath(name)
        assert not p.is_absolute() and ".." not in p.parts and p.as_posix()==name and name not in expected
        expected[name]=row
    assert sum(r["bytes"] for r in rows)==model["raw_bytes"]
    assert custody["status"]=="FAIL" and custody["members"]==model["members"] and custody["original_bytes"]==model["raw_bytes"]
    assert custody["bytes"]==model["archive_bytes"] and custody["sha256"]==model["archive_sha"]
    assert custody["member_index_bytes"]==model["index_bytes"] and custody["member_index_sha256"]==model["index_sha"]
    assert custody["all_original_and_tar_member_bytes_sha256_modes_readback"] is True
    selected={};canonical={};ledger={};seen=set();total=0
    with tarfile.open(ap,"r:xz") as tf:
        for m in tf:
            assert m.isfile() and m.name in expected and m.name not in seen
            row=expected[m.name];assert m.size==row["bytes"] and m.mode==row["mode"] and m.uid==m.gid==m.mtime==0
            b=PurePosixPath(m.name).name
            pick=(b.endswith((".json",".stdout",".stderr")) and not b.endswith(".document.json")) or b in ("stdout.log","stderr.log","executor.o")
            native=(("/"+model["build"]+"/") in m.name and (b.endswith(".hiaasm") or b.endswith(".image.bin")))
            capture=b in ("invocations.jsonl.gz","complete-cases.jsonl.gz")
            h=hashlib.sha256();n=0;chunks=[];f=tf.extractfile(m);assert f is not None
            for block in iter(lambda:f.read(1<<20),b""):
                n+=len(block);h.update(block)
                if pick or native or capture:chunks.append(block)
            assert n==row["bytes"] and h.hexdigest()==row["sha256"],m.name
            seen.add(m.name);total+=n
            if pick:selected[m.name]=b"".join(chunks)
            if native:canonical[m.name]=b"".join(chunks)
            if capture:ledger[m.name]=b"".join(chunks)
    assert seen==set(expected) and total==model["raw_bytes"]
    shutil.copyfile(ap,out/"original-evidence.tar.xz")
    assert pin(out/"original-evidence.tar.xz")["sha256"]==model["archive_sha"]
    # Before any nested schema interpretation, preserve/emit all exact controls,
    # original reports and process diagnostics, including full build summary.
    originals={"control/evidence-members.json":ir,"control/custody.json":cr,**selected}
    exported=[]
    for i,(name,raw) in enumerate(sorted(originals.items())):
        p=out/"selected-originals"/str(i);p.parent.mkdir(exist_ok=True);p.write_bytes(raw)
        assert p.read_bytes()==raw
        exported.append(dict(name=name,bytes=len(raw),sha256=sha(raw),path=str(p.relative_to(out))))
        emit(model["name"]+"/"+name,raw)
    save(out/"selected-originals.json",exported)
    def one(suffix,collection=selected):
        got=[(n,b) for n,b in collection.items() if n.endswith(suffix)]
        assert len(got)==1,(suffix,len(got));return got[0]
    _,build_raw=one("/"+model["build"]+"/summary.json");build=json.loads(build_raw)
    report=dict(status="INCOMPLETE",model=model,selected_originals=exported,
        original_build_summary=build,original_build_bytes=len(build_raw),original_build_sha256=sha(build_raw),
        new_VM_entries=0,new_native_entries=0,new_B3_compiles=0,outer_ZIP_read=False,
        producer_original_status="FAIL",whole_store_closed=False)
    if model["name"]=="physical":
        assert build["status"]=="FAIL" and build["fresh_role_compiles"]==6 and build["packer_entries"]==0 and build["actual_carrier_processes"]==0
        assert build["profile_frontiers"]["packer"]["profile"]["max_block_params"]==23
        name,raw=one("/relocations.stdout")
        assert b"There are no relocations in this file." in raw
        report["actual_original_readelf"]=dict(name=name,bytes=len(raw),sha256=sha(raw),text=raw.decode())
        for suffix in ("/assemble.json","/relocations.json"):
            name,raw=one(suffix);value=json.loads(raw);assert value["returncode"]==0
            report[PurePosixPath(name).stem]=value
        _,raw=one("/executor.o");relocs=elf_relocations(raw);assert relocs["count"]==0
        report["original_object_relocations"]=relocs
    else:
        assert build["status"]=="PASS_BUILD_ONLY" and build["fresh_HIA_B3_compiles"]==2 and build["C_reference_compiles"]==1
        report["ledger_prefixes"]=[]
        for i,(name,raw) in enumerate(sorted(ledger.items())):
            p=out/"original-ledgers"/str(i);p.parent.mkdir(exist_ok=True);p.write_bytes(raw);assert p.read_bytes()==raw
            report["ledger_prefixes"].append(gzip_prefix(model["name"]+"/"+name,raw,out))
        assert len(ledger)==2,"need both genuine partial/completed original captures"
    # Export actual canonical HIA source and image bytes with original mode and
    # exact receipt binding. Uncompiled packer source is separately labelled.
    bound=[];roles=build["compiled_roles"]
    for role,row in sorted(roles.items()):
        for kind in ("source","image"):
            original=row[kind];original_path=original["path"];marker="/"+model["build"]+"/"
            assert marker in original_path
            suffix=marker+original_path.split(marker,1)[1]
            name,raw=one(suffix,canonical)
            assert len(raw)==original["bytes"] and sha(raw)==original["sha256"]
            target=out/"canonical-native"/("role-"+str(role)+(".hiaasm" if kind=="source" else ".image.bin"))
            target.parent.mkdir(exist_ok=True);target.write_bytes(raw);target.chmod(expected[name]["mode"])
            assert pin(target)==dict(bytes=len(raw),sha256=sha(raw),mode=expected[name]["mode"])
            bound.append(dict(role=role,kind=kind,member=name,path=str(target.relative_to(out)),
                bytes=len(raw),sha256=sha(raw),mode=expected[name]["mode"],producer_compiled=True))
        receipt=row["compile_receipt"]
        assert receipt["produced_sha256"]==row["image"]["sha256"] and receipt["source_sha256"]==row["source"]["sha256"]
        assert receipt["artifact_sha256"]==receipt["image_sha256"]=="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
        assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
    assert len(bound)==(12 if model["name"]=="physical" else 4)
    report["canonical_compiled_inputs"]=bound;save(out/"canonical-native-index.json",bound)
    assert build["source_pins_unchanged"] is True
    after={str(p):pin(p) for p in (ap,ip,cp)};assert after==before
    report.update(status="PASS_READBACK_ONLY",members=len(seen),raw_bytes=total,
        all_member_bytes_modes_sha256_verified=True,source_before=before,source_after=after,artifact_controls_unchanged=True)
    save(out/"summary.json",report)
    print("HIA_NAMESPACE_FOLLOW34_READBACK "+json.dumps(report,sort_keys=True),flush=True)
    return report

def main():
    resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError("readback wall180")));signal.alarm(180)
    out=Path(os.environ["HIA_CI_OUTPUT"]).absolute();out.mkdir(parents=True,exist_ok=False,mode=0o700)
    report=dict(status="INCOMPLETE",new_native_entries=0,new_VM_entries=0,new_B3_compiles=0,results=[])
    try:
        for model in reversed(MODELS):
            report["results"].append(read_one(model,out));save(out/"summary.json",report)
        report["status"]="PASS_READBACK_ONLY"
    except BaseException as exc:
        report.update(status="READBACK_FAIL",error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc());traceback.print_exc()
    finally:
        signal.alarm(0);save(out/"summary.json",report)
        print("HIA_NAMESPACE_FOLLOW34_AGGREGATE "+json.dumps({k:v for k,v in report.items() if k!="results"},sort_keys=True),flush=True)
    return 0 if report["status"]=="PASS_READBACK_ONLY" else 1
if __name__=="__main__":raise SystemExit(main())
