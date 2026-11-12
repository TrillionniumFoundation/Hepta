"""Read the exact failed follow27 preparation artifact; execute no saved source."""
from pathlib import Path,PurePosixPath
from hashlib import sha1,sha256
import argparse,base64,io,json,os,resource,stat,struct,tarfile,traceback,zipfile,zlib
ZIP_BYTES=51028112
ZIP_SHA="11161709068e89e0b390898b85fba68ce661af8c59c354d0f7c0baf9021af74a"
INNER_BYTES=8283312
INNER_SHA="abb065435fd2450f136ce5d2d83d120be29ed0ac0304313a23edd96b628725db"
INDEX_BYTES=630767
INDEX_SHA="a2b1834b2981a38b298d301dd5d0fc614438be95b407577ad80ba3a88e6c8021"
MEMBERS=1362
RAW_BYTES=54952596
GROUPS={"semantic":113,"errors":58,"private":32,"functions-1024":1,"large-bytes":1,"large-nodes":1}
ROOT="ordinary-patch-prepare/"
MAGIC=int.from_bytes(b"HIAPPE01","little")
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
def digest(raw):return sha256(raw).hexdigest()
def ident(raw):return dict(bytes=len(raw),sha256=digest(raw),gitsha=sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest())
def metadata(info):return info.st_dev,info.st_ino,info.st_mode,info.st_size,info.st_mtime_ns,info.st_ctime_ns
def read(path):
    before=path.lstat()
    if not stat.S_ISREG(before.st_mode):raise ValueError("ordinary input file required")
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        assert metadata(os.fstat(descriptor))==metadata(before)
        with os.fdopen(descriptor,"rb",closefd=False) as stream:raw=stream.read()
        assert len(raw)==before.st_size and metadata(os.fstat(descriptor))==metadata(before)==metadata(path.lstat())
    finally:os.close(descriptor)
    return raw
def safe(name):
    p=PurePosixPath(name)
    assert name and not p.is_absolute() and ".." not in p.parts and str(p)==name
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--zip",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args();out=args.out.absolute();out.mkdir(parents=True,exist_ok=False)
    original_zip=args.zip.absolute();selfpath=Path(__file__).resolve();selfraw=read(selfpath)
    before=metadata(original_zip.lstat());held={};exported=[];emitted=0
    result=dict(schema="hia-ordinary-patch-follow27-original-readback-v1",status="FAIL",
        run=43151734029,job=130962283503,head="78fff04d3476a70a3513af0606a8c91a945ed6a5",
        artifact=13914152509,original_status="FAIL",old_failure_relabelled=False,
        new_HIA_generation=0,new_B3=0,new_VM=0,new_native=0,whole_stack_closed=False)
    def emit(name,raw,log=True):
        nonlocal emitted
        safe(name);path=out/"originals"/name;path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(raw);assert path.read_bytes()==raw
        row=dict(path=name,**ident(raw));exported.append(row)
        if not log:return
        emitted+=len(raw)
        if emitted>2<<20:raise ValueError("primary log extent")
        for at in range(0,max(1,len(raw)),12000):
            part=raw[at:at+12000]
            print("HIA_PATCH_PREPARE_ORIGINAL "+json.dumps(dict(**row,offset=at,
                part_bytes=len(part),base64=base64.b64encode(part).decode()),sort_keys=True),flush=True)
    try:
        raw=read(original_zip);assert (len(raw),digest(raw))==(ZIP_BYTES,ZIP_SHA)
        zipped={}
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            names=[i.filename for i in z.infolist() if not i.is_dir()]
            assert len(names)==216 and len(names)==len(set(names))
            for name in names:
                safe(name);info=z.getinfo(name);assert 0<=info.file_size<=128<<20
                value=z.read(info);assert len(value)==info.file_size
                zipped[name]=ident(value)
                if name.endswith("/evidence.tar.xz") or name.endswith("/evidence-members.json") or name.endswith("/custody.json"):
                    held[name]=value
        indexes=[v for k,v in held.items() if k.endswith("/evidence-members.json")]
        archives=[v for k,v in held.items() if k.endswith("/evidence.tar.xz")]
        custodies=[v for k,v in held.items() if k.endswith("/custody.json")]
        assert len(indexes)==len(archives)==len(custodies)==1
        index_raw=indexes[0];archive_raw=archives[0];custody_raw=custodies[0]
        assert (len(index_raw),digest(index_raw))==(INDEX_BYTES,INDEX_SHA)
        assert (len(archive_raw),digest(archive_raw))==(INNER_BYTES,INNER_SHA)
        rows=json.loads(index_raw);assert len(rows)==MEMBERS
        expected={r["name"]:r for r in rows};assert len(expected)==MEMBERS
        assert sum(r["bytes"] for r in rows)==RAW_BYTES
        custody=json.loads(custody_raw)
        assert custody["status"]=="FAIL" and custody["scope"]=="ordinary-patch-prepare"
        assert custody["members"]==MEMBERS and custody["original_bytes"]==RAW_BYTES
        assert custody["sha256"]==INNER_SHA and custody["member_index_sha256"]==INDEX_SHA
        inner={}
        with tarfile.open(fileobj=io.BytesIO(archive_raw),mode="r:xz") as tar:
            for item in tar:
                safe(item.name);assert item.isfile() and item.name not in inner
                row=expected[item.name];value=tar.extractfile(item).read()
                assert (len(value),digest(value),item.mode)==(row["bytes"],row["sha256"],row["mode"])
                assert item.uid==item.gid==item.mtime==0
                inner[item.name]=value
        assert set(inner)==set(expected)
        emit("provider/custody.json",custody_raw)
        emit("provider/evidence-members.json",index_raw,False)
        save(out/"complete-provider-zip-member-manifest.json",zipped)
        emit(ROOT+"development/build-r1/manifest.json",inner[ROOT+"development/build-r1/manifest.json"])
        manifest=json.loads(inner[ROOT+"development/build-r1/manifest.json"])
        for field in ("source","image"):
            matches=[r for r in rows if r["path"]==manifest[field+"_path"]]
            assert len(matches)==1
            value=inner[matches[0]["name"]]
            assert len(value)==manifest[field+"_bytes"] and digest(value)==manifest[field+"_sha256"]
        author_tests=[]  # The failed finally still retained the exact test in CAS.
        original_summary=json.loads(inner["run/summary.json"])
        assert original_summary["status"]=="FAIL" and original_summary["scope"]=="ordinary-patch-prepare"
        emit("run/summary.json",inner["run/summary.json"])
        groups={};case_comparisons=0;all_entries=0;all_cas=0;logical_cas=0
        for group,planned in GROUPS.items():
            base=ROOT+"development/native-"+group+"/"
            inv=json.loads(inner[base+"planned-inventory.json"])
            assert inv["expected"]==planned and len(inv["labels"])==planned
            emit(base+"planned-inventory.json",inner[base+"planned-inventory.json"])
            records=[json.loads(line) for line in inner[base+"entries.jsonl"].splitlines()]
            emit(base+"entries.jsonl",inner[base+"entries.jsonl"],False)
            casmap={}
            for name,value in inner.items():
                if not name.startswith(base+"cas/"):continue
                assert name.endswith(".zlib")
                data=zlib.decompress(value)
                assert digest(data)==PurePosixPath(name).name[:-5]
                assert len(data)<=128<<20
                casmap[name]=ident(data);all_cas+=1;logical_cas+=len(data)
                if digest(data)=="ef003cff6dfc4868505eb1e11e9dab6c4f4e050e67a6ded09df2efe65b74d8b0":
                    assert len(data)==31318;author_tests.append(name)
            def cas(ref):
                assert type(ref)is dict and set(ref)=={"path","bytes","sha256"}
                safe(ref["path"]);assert ref["path"].startswith("cas/")
                name=base+ref["path"];pin=casmap[name]
                assert (pin["bytes"],pin["sha256"])==(ref["bytes"],ref["sha256"])
                value=zlib.decompress(inner[name])
                assert (len(value),digest(value))==(ref["bytes"],ref["sha256"])
                return value
            def refs(value):
                if type(value)is dict:
                    if set(value)=={"path","bytes","sha256"}:
                        name=base+value["path"];pin=casmap[name]
                        assert (pin["bytes"],pin["sha256"])==(value["bytes"],value["sha256"])
                    else:
                        for v in value.values():refs(v)
                elif type(value)is list:
                    for v in value:refs(v)
            assert len(records)%2==0
            terminal={}
            for at in range(0,len(records),2):
                enter,leave=records[at:at+2];refs(enter);refs(leave)
                assert enter["status"]=="ENTER" and leave["status"]=="RETURN"
                assert enter["index"]==leave["index"]==at//2+1 and enter["label"]==leave["label"]
                assert leave["source_readonly_and_canaries_unchanged"]
                assert enter["source"]==leave["source"]==leave["source_after"]
                assert enter["output_before"]==leave["output_before"] and enter["work_before"]==leave["work_before"]
                for guard in leave["observed_guards"].values():
                    assert guard=={"prefix":"a5"*32,"suffix":"5a"*32}
                terminal[leave["label"]]=leave
            all_entries+=len(records)//2
            expected_files=sorted(k for k in inner if k.startswith(base+"expected-") and k.endswith(".json"))
            compared=[]
            for name in expected_files:
                frozen=json.loads(inner[name]);refs(frozen)
                if "expected" not in frozen:continue
                label=frozen["label"]
                choices=[terminal[label+"-"+str(n)] for n in range(3) if label+"-"+str(n) in terminal]
                assert choices
                leave=choices[-1];outbuf=cas(leave["output"]);event=struct.unpack_from("<16Q",outbuf)
                assert leave["result"]==128 and event[:2]==(MAGIC,1) and event[6]==128 and not any(event[12:])
                assert cas(leave["source"])==cas(frozen["envelope"])
                expected_result=frozen["expected"]
                payload=outbuf[128:128+event[7]];assert len(payload)==event[7]
                if expected_result["kind"]=="candidate":
                    assert event[2]==0 and event[3]==0 and payload==cas(expected_result["bytes"])
                    assert (event[8],event[9],event[10],event[11])==(expected_result["schema"],expected_result["policy"],expected_result["edits"],expected_result["edits"])
                else:
                    assert expected_result["kind"]=="error" and event[2]==2 and 1<=event[3]<=22
                    assert payload==expected_result["message"].encode("utf-8")
                compared.append(dict(label=label,kind=expected_result["kind"],payload=ident(payload),complete_bytes_equal=True))
            case_comparisons+=len(compared)
            failures=[k for k in inner if k.startswith(base) and k.endswith("failure.txt")]
            for name in failures:emit(name,inner[name])
            groups[group]=dict(planned_cases=planned,complete_native_entries=len(records)//2,
                frozen_semantic_expectations=len(compared),semantic_comparisons=compared,
                original_terminal_summary_present=base+"summary.json" in inner,
                original_failure_files=failures,complete_entry_buffers_verified=True)
        assert case_comparisons==176 and len(author_tests)==6
        assert metadata(original_zip.lstat())==before and read(original_zip)==raw and read(selfpath)==selfraw
        result.update(status="PASS_READBACK_ONLY",zip_members=216,inner_members=MEMBERS,
            all_original_bytes_and_modes_verified=True,all_original_inputs_unchanged=True,
            original_fresh_B3=1,complete_native_entries=all_entries,
            frozen_semantic_candidate_or_error_comparisons=case_comparisons,
            full_CAS_objects_verified=all_cas,logical_CAS_bytes=logical_cas,groups=groups,
            original_source_pin_summary_failure="dict(path=str(path), **cas(raw)) repeats path",
            original_function_count_assertion_failure="Original reference emits E_HIA_FORMAT, while the old assertion expected E_HIA_LIMIT",
            original_cases_not_relabelled_as_qualified=True,original_missing_summaries_not_reconstructed=True)
    except BaseException as exc:
        result.update(error_class=type(exc).__name__,error=str(exc))
        (out/"failure.txt").write_text(traceback.format_exc());traceback.print_exc()
    finally:
        result["raw_original_exports"]=exported
        save(out/"summary.json",result)
        save(out/"original-export-index.json",exported)
        print("HIA_PATCH_PREPARE_ORIGINAL_OBSERVED "+json.dumps({k:v for k,v in result.items() if k not in ("raw_original_exports","groups")},
            sort_keys=True),flush=True)
    if result["status"]!="PASS_READBACK_ONLY":raise SystemExit(1)
if __name__=="__main__":main()
