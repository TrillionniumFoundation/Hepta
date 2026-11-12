"""Read every recorded byte of one new physical-after group; zero target entries."""
from pathlib import Path
from hashlib import sha256
from itertools import zip_longest
import argparse,json,lzma,os,stat,struct,sys,traceback,types,zlib
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
SUBJECT_SHA="386c110c77ef3b89a5f3e72c54737dff60c8b8625f3e544b0cc2acb242e7a3b3"
HELPERS={
 "reference/implementation_files_test_reference.py":"ff09bf45efe5b32324de767c69401337008a458fe341051662fe35e5d6fe3837",
 "tests/physical_after_native_adapter.py":"90c8312a18464f1c2dd55fcb3254c7baec36978f3d5c7920892ca1f92b625339",
 "tests/implementation_files_native_adapter.py":"c9ebdb266cc3a4e1b9796bc79ae412cfd73fd966e41217b28f7d5ff6ef4ae441"}
def digest(raw):return sha256(raw).hexdigest()
def q(raw,at=0):return struct.unpack_from("<Q",raw,at)[0]
def magic(value):return int.from_bytes(value.encode("ascii"),"little")
def save(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+"\n")
def load(name,path,expected):
    path=Path(path);raw=path.read_bytes();assert digest(raw)==expected
    module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
    exec(compile(raw,str(path),"exec"),module.__dict__);return module
def identity(path):
    path=Path(path);info=path.lstat()
    assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
    h=sha256();n=0
    with path.open("rb") as stream:
        opened=os.fstat(stream.fileno())
        assert (opened.st_dev,opened.st_ino,opened.st_size)==(info.st_dev,info.st_ino,info.st_size)
        while True:
            raw=stream.read(1<<18)
            if not raw:break
            h.update(raw);n+=len(raw)
        closed=os.fstat(stream.fileno())
    after=path.lstat()
    fields=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    assert fields(info)==fields(opened)==fields(closed)==fields(after) and n==info.st_size
    return dict(bytes=n,sha256=h.hexdigest(),mode=stat.S_IMODE(info.st_mode))
def tree(root):
    rows=[]
    for path in sorted(Path(root).rglob("*")):
        info=path.lstat()
        assert not stat.S_ISLNK(info.st_mode),"unretired alias: "+str(path)
        if stat.S_ISDIR(info.st_mode):continue
        rows.append(dict(path=str(path.relative_to(root)),**identity(path)))
    return rows
def fixed_summary(path):
    raw=Path(path).read_bytes()
    return json.loads(raw),raw
def source_custody(root):
    before=json.loads((root/"source-before.json").read_bytes())
    after=json.loads((root/"source-after.json").read_bytes())
    assert len(before)==len(after)>0
    for first,last in zip(before,after):
        source=Path(first["path"]);copy=root/first["snapshot"]
        expected={k:first[k] for k in ("bytes","sha256","mode")}
        assert identity(source)==identity(copy)==expected
        assert source.read_bytes()==copy.read_bytes()
        assert last["same"] and {k:last[k] for k in ("path","bytes","sha256","mode")}=={
            k:first[k] for k in ("path","bytes","sha256","mode")}
    return dict(files=len(before),all_source_before_after_and_snapshots_exact=True)
def source_images(document):
    rows=[]
    for role,row in document["roles"].items():
        m=row["manifest"]
        for kind in ("source","image"):
            path=Path(m[kind+"_path"]);observed=identity(path)
            assert (observed["bytes"],observed["sha256"])==(m[kind+"_bytes"],m[kind+"_sha256"])
            rows.append(dict(role=role,kind=kind,path=str(path),**observed))
    return rows
def process(directory):
    value=json.loads((directory/"process.json").read_bytes())
    assert value["exit_code"]==0 and not value["timeout"] and value["child_reaped"]
    assert value["limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0],wall=180)
    assert value["user_seconds"]+value["system_seconds"]<90 and value["wall_seconds"]<180
    assert (directory/"stdout.bin").read_bytes()==(directory/"stderr.bin").read_bytes()==b""
    return value
def encoded(directory,helper):
    raw=json.loads((directory/"exact-raw-encoding.json").read_bytes())
    assert raw["schema"]=="hia-complete-raw-lossless-encoding-v1"
    assert raw["full_effective_extents_retained"] and raw["no_target_entry_during_encoding"]
    assert len(raw["rows"])==2
    rows={}
    for name in ("trace.bin","final-slots.bin"):
        path,value=helper.encoded_row(directory,name)
        rows[name]=(path,value)
    closed=json.loads((directory/"closed-evidence.json").read_bytes())
    assert closed["source_image_before_after_exact"] and closed["complete_event_ACK_trace"]
    assert not closed["all_intermediate_workspaces"]
    assert closed["trace"]==rows["trace.bin"][1] and closed["all_final_slots"]==rows["final-slots.bin"][1]
    return rows
def whole_final(path,recorded,trace,adapter,refs):
    used=set();last=-1;total=0;hashes={};whole=sha256()
    with lzma.open(path,"rb") as stream:
        def read(n):
            nonlocal total
            raw=adapter.read_exact(stream,n);whole.update(raw);total+=n;return raw
        head=struct.unpack("<8Q",read(64));event=read(128)
        assert head[:2]==(magic("HIAEMXS1"),1)
        assert head[2:5]==(trace["native_entries"],trace["commands"],trace["returned"])
        assert head[6:]==(128,0) and event.hex()==trace["terminal_hex"]
        for _ in range(head[5]):
            slot,n,ro,owned,*reserved=struct.unpack("<8Q",read(64))
            assert last<slot<64 and ro in (0,1) and owned==1 and reserved==[0]*4
            selected=refs.get(slot,[])
            for start,value in selected:
                assert 0<=start<=n and len(value)<=n-start and ro==1
            h=sha256();at=0
            while at<n:
                raw=read(min(1<<18,n-at));h.update(raw)
                for start,value in selected:
                    low=max(at,start);high=min(at+len(raw),start+len(value))
                    if low<high:assert raw[low-at:high-at]==value[low-start:high-start]
                at+=len(raw)
            hashes[str(slot)]=dict(bytes=n,readonly=bool(ro),sha256=h.hexdigest())
            used.add(slot);last=slot
        assert stream.read(1)==b"" and set(refs)<=used
    assert dict(bytes=total,sha256=whole.hexdigest())==recorded
    return dict(slots=hashes,full_slot_bytes=total,event_hex=event.hex(),all_selected_bytes_equal=True)
def actual_refs(case,trace,before=False):
    event=bytes.fromhex(trace["terminal_hex"]);words=struct.unpack("<16Q",event)
    assert words[0:3]==(magic("HIACDE01"),7,19)
    if before:
        value=json.loads((case/"actual-before.json").read_bytes())
        payload=bytes.fromhex(value["descriptor_hex"]);sha=(case/"actual-before-sha256.bin").read_bytes()
        assert len(sha)==32 and sha.hex()==value["sha256"]
        h=struct.unpack("<16Q",payload)
        assert h[:6]==(magic("HIAIFR01"),1,19,1,0,20) and h[8:]==(0,0,0,7,32,0,0,0)
        assert words[6:9]==(9,0,128)
        return {9:[(0,payload)],7:[(0,sha)]}
    payload=(case/"native-result.bin").read_bytes()
    assert (case/"native-terminal.bin").read_bytes()==event and words[8]==len(payload)
    refs={words[6]:[(words[7],payload)]}
    if words[4]==0:
        h=struct.unpack("<64Q",payload)
        for offset,name in ((8,"native-object.bin"),(11,"native-text.bin"),(14,"native-metadata.json")):
            raw=(case/name).read_bytes();assert len(raw)==h[offset+2]
            refs.setdefault(h[offset],[]).append((h[offset+1],raw))
        if h[23]:
            raw=(case/"native-plan.json").read_bytes();assert len(raw)==h[22]
            refs.setdefault(h[20],[]).append((h[21],raw))
    return refs
def final_CAS(case,directory):
    value=json.loads((case/"python-final-CAS.json").read_bytes())
    refs={item["complete_bytes"]["id"]:item for item in value["slots"].values()}
    found=set();count=0
    with (directory/"snapshots.jsonl").open() as stream:
        for line in stream:
            row=json.loads(line);assert row["id"]==count;count+=1
            if row["id"] not in refs:continue
            item=refs[row["id"]];complete=item["complete_bytes"]
            assert complete=={k:row[k] for k in ("id","key","bytes","sha256")}
            assert item["size"]==row["bytes"];found.add(row["id"])
    assert found==set(refs)==set(range(count-len(refs),count))
    return value,{slot:dict(bytes=item["size"],readonly=item["readonly"],sha256=item["complete_bytes"]["sha256"])
        for slot,item in value["slots"].items()}
def C_records(adapter,path,size):
    pending=None;raw_call=None
    for kind,raw in adapter.trace_records(path,size):
        if kind==4:
            serial,role,returned,n=struct.unpack_from("<4Q",raw)
            assert len(raw)==32+n;yield ("RETURNED",serial-1,role,returned,raw[32:])
        elif kind==5:pending=raw
        elif kind==6:
            assert pending is not None;yield ("ACK",pending,raw);pending=None
        elif kind==9:
            number,sequence,primitive,before,result,error,answer,after=struct.unpack("<8Q",raw)
            signed=adapter.signed
            raw_call=(number,primitive,0 if primitive==1 and signed(result)>=0 else signed(result),
                error,answer,signed(before)>=0,signed(after)>=0)
        elif kind==11:
            assert raw_call is not None;yield ("SYSCALL",raw_call,raw);raw_call=None
    assert pending is None and raw_call is None
def CAS_records(directory):
    def value(d):
        raw=b"".join(zlib.decompress((directory/"cas"/(h+".zlib")).read_bytes()) for h in d["pages"])
        assert len(raw)==d["bytes"] and digest(raw)==d["sha256"];return raw
    with (directory/"entries.jsonl").open() as stream:
        for line in stream:
            row=json.loads(line);kind=row["status"]
            if kind=="RETURNED":yield ("RETURNED",row["number"],row["role"],row["returned"],bytes.fromhex(row["event_hex"]))
            elif kind=="MECHANICAL_ACK":yield ("ACK",bytes.fromhex(row["event_hex"]),value(row["ack"]))
            elif kind=="RAW_SYSCALL":
                yield ("SYSCALL",(row["number"],row["primitive"],
                    0 if row["primitive"]==1 and row["raw_result"]>=0 else row["raw_result"],
                    row["errno"],row["returned"],row["fd_before"]>=0,row["fd_after"]>=0),value(row["full_payload"]))
def encoded_case(case,directory,assets,adapter,helper,expected_entries,expected_roles,before=False):
    process_value=process(directory);rows=encoded(directory,helper)
    initial=(directory/"initial.bin").read_bytes()
    if not before:assert initial==(case/"initial.bin").read_bytes()
    trace_path,trace_id=rows["trace.bin"]
    trace=adapter.validate_trace(trace_path,assets,initial,logical_bytes=trace_id["bytes"])
    assert json.loads(json.dumps(trace))==json.loads((directory/"trace-summary.json").read_bytes())
    assert trace["native_entries"]==expected_entries
    assert trace["by_role"]=={int(k):v for k,v in expected_roles.items()}
    refs=actual_refs(case,trace,before)
    final=whole_final(*rows["final-slots.bin"],trace,adapter,refs)
    if before:
        expected=json.loads((case/"actual-before.json").read_bytes())
        assert trace["raw_syscalls"]==expected["raw_syscalls"]
    else:
        label=json.loads((case/"result.json").read_bytes())
        divisor=2 if label["complete_fixed_carrier_comparison"] is not None else 1
        assert trace["raw_syscalls"]*divisor==label["actual_after_raw_syscalls"]
    return dict(trace=trace,final=final,process=process_value,encoded_original_files=2)
def oracle_bytes(case,row):
    if row["private"]:return
    oracle=json.loads((case/"oracle.json").read_bytes());assert oracle==row["oracle"]
    before=json.loads((case/"actual-before.json").read_bytes())
    assert oracle["implementation_before"]==before["sha256"]
    initial=(case/"initial.bin").read_bytes()
    assert initial[192:224]==bytes.fromhex(before["sha256"]) and initial[224:256]==bytes(32)
    assert len(initial)==q(initial,96)+q(initial,104) and q(initial,96)==320+q(initial,72)
    assert oracle["full_original_emit_program_machine_used"] and oracle["after_hash_not_supplied_to_target"]
    error=oracle["error"]
    if error is None:
        for name in ("object.bin","text.bin","metadata.json"):
            assert (case/("native-"+name)).read_bytes()==(case/("reference."+name)).read_bytes()
            if row["full_CAS"]:assert (case/("python-"+name)).read_bytes()==(case/("reference."+name)).read_bytes()
        if (case/"reference.plan.json").exists():
            assert (case/"native-plan.json").read_bytes()==(case/"reference.plan.json").read_bytes()
            if row["full_CAS"]:assert (case/"python-plan.json").read_bytes()==(case/"reference.plan.json").read_bytes()
    elif error["domain"]==5:
        value=(case/"native-result.bin").read_bytes();head=struct.unpack_from("<16Q",value)
        assert head[0]==magic("HIABFE01") and head[7]==error["errno"]
        assert value[128:].hex()==error["filename_hex"] and row["original_OS_error_fields_equal"]
    else:
        raw=(case/"reference.error.bin").read_bytes()
        assert raw==error["text"].encode("utf-8","surrogatepass")== (case/"native-result.bin").read_bytes()
        if row["full_CAS"]:assert raw==(case/"python-result.bin").read_bytes()
        assert row["original_error_full_text_equal"]
    assert json.loads((case/"fixture-before-target.json").read_bytes())==json.loads((case/"fixture-after-target.json").read_bytes())

def main():
    parser=argparse.ArgumentParser()
    for key in ("group-root","assets","before-assets","out"):parser.add_argument("--"+key,type=Path,required=True)
    args=parser.parse_args();group=args.group_root.resolve()
    module=load("physical_reader_subject",ROOT/"tools/bounded_physical_subject.py",SUBJECT_SHA)
    subject=module.Subject(args.out,"physical-after-recorded-originals")
    subject.report.update(native_entries_executed=0,VM_entries_executed=0,product_imports=0)
    inputs={};before_tree=None;pairs=None;assets=before_assets=None
    try:
        assert sys.version_info[:3]==(3,12,14)
        subject.capture(__file__);subject.capture(ROOT/"tools/bounded_physical_subject.py",SUBJECT_SHA)
        for path,expected in HELPERS.items():subject.capture(ROOT/path,expected)
        helper=load("physical_reader_file_reference",ROOT/"reference/implementation_files_test_reference.py",
            HELPERS["reference/implementation_files_test_reference.py"])
        adapter=load("physical_reader_new_adapter",ROOT/"tests/physical_after_native_adapter.py",
            HELPERS["tests/physical_after_native_adapter.py"])
        before_adapter=load("physical_reader_old_adapter",ROOT/"tests/implementation_files_native_adapter.py",
            HELPERS["tests/implementation_files_native_adapter.py"])
        for key,path in (("assets",args.assets),("before_assets",args.before_assets),("summary",group/"summary.json")):
            observed=identity(path);raw=Path(path).read_bytes()
            assert len(raw)==observed["bytes"] and digest(raw)==observed["sha256"]
            inputs[key]=(Path(path).absolute(),observed)
            copy=subject.out/"originals"/(key+".json");copy.parent.mkdir(exist_ok=True)
            copy.write_bytes(raw);copy.chmod(observed["mode"]);assert identity(copy)==observed
        before_tree=tree(group);save(subject.out/"all-input-members-before.json",before_tree)
        assets=json.loads(args.assets.read_bytes());before_assets=json.loads(args.before_assets.read_bytes())
        assert assets["schema"]=="hia-backend-physical-after-assets-v1" and set(assets["roles"])=={str(i) for i in range(1,24)}
        assert before_assets["schema"]=="hia-implementation-files-runtime-assets-v1" and set(before_assets["roles"])=={"1","2"}
        for alias,role in (("1","22"),("2","19")):
            assert before_assets["roles"][alias]["manifest"]==assets["roles"][role]["manifest"]
        pairs=source_images(assets)
        summary=json.loads((group/"summary.json").read_bytes())
        assert summary["status"]=="PASS" and not summary["failures"] and summary["source_pins_unchanged"]
        for key in ("pre_output_budget","post_output_budget","post_persist_budget"):
            assert summary[key]["cpu_seconds"]<90 and summary[key]["wall_seconds"]<180
        assert summary["actual_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
        source=source_custody(group)
        rows=[];roles={str(i):0 for i in range(1,24)};before_roles={"1":0,"2":0}
        raw_syscalls=before_raw=private=full=cross=encoded_files=0;before_processes=target_processes=0
        starts=sorted((group/"cases").glob("*/case-start.json"))
        results=sorted((group/"cases").glob("*/result.json"))
        assert len(starts)==len(results)==summary["cases"]==summary["expected_cases"]
        assert [p.parent for p in starts]==[p.parent for p in results]
        for path in results:
            case=path.parent;row=json.loads(path.read_bytes());assert row["status"]=="PASS"
            oracle_bytes(case,row)
            record=dict(label=row["label"],private=row["private"])
            assert set(row["by_role"])==set(roles) and row["actual_native_entries"]==sum(row["by_role"].values())
            for role,n in row["by_role"].items():roles[role]+=n
            raw_syscalls+=row["actual_after_raw_syscalls"]
            native=case/"actual-after-native";cas=case/"python-full-CAS"
            if cas.exists():
                proof=helper.readback_cas(cas);final,slot_hashes=final_CAS(case,cas)
                assert proof["native_entries"]==row["primary_entries"]
                assert final["by_role"]==row["primary_by_role"] and sum(final["by_role"].values())==proof["native_entries"]
                assert final["entries"]==proof["native_entries"] and final["commands"]==proof["commands"]
                assert final["raw_syscalls"]==proof["raw_syscalls"]
                record["CAS"]=proof;record["CAS_final"]=final;full+=1
            else:assert not row["full_CAS"]
            if native.exists():
                assert not row["private"];target_processes+=1
                paired=row["complete_fixed_carrier_comparison"] is not None
                counts=row["crosscheck_by_role"] if paired else row["primary_by_role"]
                n=row["crosscheck_entries"] if paired else row["primary_entries"]
                record["native"]=encoded_case(case,native,assets,adapter,helper,n,counts)
                encoded_files+=2
                if paired:
                    assert cas.exists() and counts==row["primary_by_role"] and n==row["primary_entries"]
                    assert record["native"]["final"]["slots"]==slot_hashes
                    cpath,cidentity=helper.encoded_row(native,"trace.bin")
                    marker=object();count=0
                    for left,right in zip_longest(C_records(adapter,cpath,cidentity["bytes"]),CAS_records(cas),fillvalue=marker):
                        assert left is not marker and right is not marker and left==right
                        count+=1
                    record["independent_full_CAS_C_crosscheck_records"]=count;cross+=1
            else:assert row["private"] and cas.exists()
            if row["private"]:
                private+=1
                assert row["original_valid_ACK_retry_permanent_BAD"] and row["no_replayed_syscall_or_command"]
                assert row["interceptions"] in (0,1)
                assert row["crosscheck_entries"]==0 and row["crosscheck_by_role"]=={}
                close_rows=[json.loads(line) for line in (cas/"entries.jsonl").read_text().splitlines()
                    if '"PRIVATE_ABORT_FD_CLEANUP"' in line]
                assert len(close_rows)==int(row["actual_owned_FD_before_abort_cleanup"]>=0)
                if close_rows:
                    assert close_rows[0]["fd"]==row["actual_owned_FD_before_abort_cleanup"]
                    assert close_rows[0]["raw_result"]==close_rows[0]["errno"]==0
            rows.append(record)
        before_cases=[p.parent for p in sorted(group.glob("cases/*/actual-before-native"))]
        prototype=group/"private-prototype"
        if prototype.exists():before_cases.append(prototype)
        for case in before_cases:
            expected=json.loads((case/"actual-before.json").read_bytes())
            one=encoded_case(case,case/"actual-before-native",before_assets,before_adapter,helper,
                expected["native_entries"],expected["by_role"],before=True)
            for role,n in one["trace"]["by_role"].items():before_roles[str(role)]+=n
            before_raw+=one["trace"]["raw_syscalls"];before_processes+=1;encoded_files+=2
        assert len({r["label"] for r in rows})==len(rows)
        assert roles==summary["by_role"] and sum(roles.values())==summary["native_entries"]==summary["completed_case_entries"]
        assert before_roles==summary["before_by_role"] and sum(before_roles.values())==summary["before_native_entries"]
        assert raw_syscalls==summary["actual_after_raw_syscalls"] and before_raw==summary["before_raw_syscalls"]
        assert (private,full,cross)==(summary["private_controls"],summary["complete_full_CAS_cases"],summary["complete_fixed_carrier_crosschecks"])
        assert private==summary["expected_private_controls"]
        assert before_processes==summary["actual_before_processes_started"]
        assert target_processes==summary["actual_backend_processes_started"]
        save(subject.out/"case-originals.json",rows)
        subject.report.update(status="PASS",group=summary["group"],variant=summary["variant"],
            cases=len(rows),private_controls=private,native_entries=sum(roles.values()),by_role=roles,
            before_native_entries=sum(before_roles.values()),before_by_role=before_roles,
            actual_after_raw_syscalls=raw_syscalls,before_raw_syscalls=before_raw,
            full_CAS_cases=full,fixed_C_crosschecks=cross,encoded_original_files=encoded_files,
            source_custody=source,all_full_recorded_bytes_read=True,
            complete_raw_target_trace_and_ACK_comparison=True,installed=False,whole_public_build=False)
    except BaseException as error:
        subject.failure(error);subject.attempt("traceback",traceback.print_exc)
    finally:
        for key,(path,expected) in inputs.items():
            def verify_one(path=path,expected=expected):
                assert identity(path)==expected
            subject.attempt("input-after:"+key,verify_one)
        if before_tree is not None:
            def verify_tree():
                observed=tree(group);save(subject.out/"all-input-members-after.json",observed)
                assert observed==before_tree
            subject.attempt("all-input-members-after",verify_tree)
        if pairs is not None:
            def verify_pairs():assert source_images(assets)==pairs
            subject.attempt("source-image-after",verify_pairs)
        subject.finish("PASS")
if __name__=="__main__":main()
