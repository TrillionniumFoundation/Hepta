"""Read exact follow32 six-role failure; no compiler, assembler, VM or native rerun."""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import base64,hashlib,json,os,resource,shutil,signal,stat,struct,tarfile,traceback
from pathlib import Path,PurePosixPath
ARCHIVE_BYTES=6866468
ARCHIVE_SHA="4fd90ee0d17eb9bd9ea3143826911175bcba24e540b0cee7bb3333a19ce36022"
INDEX_BYTES=72926
INDEX_SHA="e8733a35bdf769aba559214a2753a6a4d9c902dfa600e12610e2e97c33fc0f25"
MEMBERS=201
RAW_BYTES=57053157
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
    print("HIA_NAMESPACE_FOLLOW32_RAW_META "+json.dumps(dict(name=name,bytes=len(raw),sha256=sha(raw),encoding="base64",chunk_bytes=6144),sort_keys=True),flush=True)
    for at in range(0,len(raw),6144):
        b=raw[at:at+6144]
        print("HIA_NAMESPACE_FOLLOW32_RAW_CHUNK "+json.dumps(dict(name=name,offset=at,bytes=len(b),sha256=sha(b),base64=base64.b64encode(b).decode("ascii")),sort_keys=True),flush=True)
    print("HIA_NAMESPACE_FOLLOW32_RAW_END "+json.dumps(dict(name=name,bytes=len(raw),sha256=sha(raw)),sort_keys=True),flush=True)
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
def main():
    resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError("readback wall180")))
    signal.alarm(180)
    root=Path(os.environ["HIA_NAMESPACE_FOLLOW32_DIR"]).resolve(strict=True)
    out=Path(os.environ["HIA_CI_OUTPUT"]).absolute()
    assert not out.is_relative_to(root)
    out.mkdir(parents=True,exist_ok=False,mode=0o700)
    report=dict(status="INCOMPLETE",artifact_id=13916982376,run_id=43158320484,job_id=130983370334,
        original_failure_preserved=True,new_B3_compilations=0,new_VM_entries=0,new_native_entries=0,
        outer_ZIP_read=False,whole_store_closed=False,relocation_gate_not_relaxed=True)
    try:
        matches=[]
        for directory,dirs,files in os.walk(root,followlinks=False):
            for name in dirs:assert not (Path(directory)/name).is_symlink()
            if all(n in files for n in ("evidence.tar.xz","evidence-members.json","custody.json")):
                d=Path(directory)
                if pin(d/"evidence.tar.xz")["sha256"]==ARCHIVE_SHA:matches.append(d)
        assert len(matches)==1
        d=matches[0];ap=d/"evidence.tar.xz";ip=d/"evidence-members.json";cp=d/"custody.json"
        before={str(p):pin(p) for p in (ap,ip,cp)}
        assert before[str(ap)]["bytes"]==ARCHIVE_BYTES
        assert before[str(ip)]["bytes"]==INDEX_BYTES and before[str(ip)]["sha256"]==INDEX_SHA
        ir=ip.read_bytes();cr=cp.read_bytes();rows=json.loads(ir);custody=json.loads(cr)
        assert isinstance(rows,list) and len(rows)==MEMBERS
        expected={}
        for row in rows:
            name=row["name"];p=PurePosixPath(name)
            assert not p.is_absolute() and ".." not in p.parts and p.as_posix()==name and name not in expected
            expected[name]=row
        assert sum(row["bytes"] for row in rows)==RAW_BYTES
        assert custody["status"]=="FAIL" and custody["members"]==MEMBERS and custody["original_bytes"]==RAW_BYTES
        assert custody["bytes"]==ARCHIVE_BYTES and custody["sha256"]==ARCHIVE_SHA
        assert custody["member_index_bytes"]==INDEX_BYTES and custody["member_index_sha256"]==INDEX_SHA
        assert custody["all_original_and_tar_member_bytes_sha256_modes_readback"] is True
        selected={};seen=set();total=0
        with tarfile.open(ap,"r:xz") as tf:
            for m in tf:
                assert m.isfile() and m.name in expected and m.name not in seen
                row=expected[m.name]
                assert m.size==row["bytes"] and m.mode==row["mode"] and m.uid==m.gid==m.mtime==0
                base=PurePosixPath(m.name).name
                pick=("/db-join-build-r1/" in m.name and not base.endswith(".document.json") and
                    (base.endswith((".json",".stdout",".stderr")) or base=="executor.o"))
                pick=pick or base in ("stdout.log","stderr.log") or m.name.endswith("/run/summary.json")
                h=hashlib.sha256();n=0;chunks=[];f=tf.extractfile(m);assert f is not None
                for block in iter(lambda:f.read(1<<20),b""):
                    n+=len(block);h.update(block)
                    if pick:chunks.append(block)
                assert n==row["bytes"] and h.hexdigest()==row["sha256"],m.name
                seen.add(m.name);total+=n
                if pick:selected[m.name]=b"".join(chunks)
        assert seen==set(expected) and total==RAW_BYTES
        # Preserve archive/control and emit all selected originals before
        # interpreting any nested schema, including ELF/readelf diagnostics.
        shutil.copyfile(ap,out/"original-evidence.tar.xz")
        assert pin(out/"original-evidence.tar.xz")["sha256"]==ARCHIVE_SHA
        originals={"control/evidence-members.json":ir,"control/custody.json":cr,**selected}
        exported=[]
        for i,(name,raw) in enumerate(sorted(originals.items())):
            p=out/"selected-originals"/str(i);p.parent.mkdir(exist_ok=True)
            p.write_bytes(raw);assert p.read_bytes()==raw
            exported.append(dict(name=name,bytes=len(raw),sha256=sha(raw),path=str(p.relative_to(out))))
            emit(name,raw)
        save(out/"selected-originals.json",exported)
        def one(suffix):
            got=[(n,b) for n,b in selected.items() if n.endswith(suffix)]
            assert len(got)==1,(suffix,len(got))
            return got[0]
        name,raw=one("/relocations.stdout")
        report["original_readelf_stdout"]={"name":name,"bytes":len(raw),"sha256":sha(raw),"text":raw.decode("utf-8")}
        for suffix in ("/assemble.json","/relocations.json"):
            name,raw=one(suffix);value=json.loads(raw)
            assert value["returncode"]==0
            report["original_"+PurePosixPath(name).stem+"_process"]=value
        name,raw=one("/executor.o");report["original_object_relocations"]=elf_relocations(raw)
        name,raw=one("/db-join-build-r1/summary.json");summary=json.loads(raw)
        assert summary["status"]=="FAIL" and summary["source_pins_unchanged"] is True
        assert summary["fresh_role_compiles"]==6 and summary["packer_entries"]==0 and summary["actual_carrier_processes"]==0
        report["original_build_summary"]=summary
        after={str(p):pin(p) for p in (ap,ip,cp)};assert after==before
        report.update(status="PASS_READBACK_ONLY",members=len(seen),raw_bytes=total,
            all_member_bytes_modes_sha256_verified=True,source_before=before,source_after=after,
            artifact_controls_unchanged=True,selected_originals=exported)
    except BaseException as error:
        report.update(status="READBACK_FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        signal.alarm(0);save(out/"summary.json",report)
        print("HIA_NAMESPACE_FOLLOW32_READBACK "+json.dumps(report,sort_keys=True),flush=True)
    return 0 if report["status"]=="PASS_READBACK_ONLY" else 1
if __name__=="__main__":raise SystemExit(main())
