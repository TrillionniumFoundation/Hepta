"""Read exact retained namespace source and its complete 31-operation ABI.

No old source is imported, executed, rewritten, or counted as qualification.
The complete original archive is checked before exposing individual members.
"""
from pathlib import Path,PurePosixPath
from hashlib import sha1,sha256
import argparse,base64,io,json,stat,tarfile,traceback
PREFIX="review-evidence/hia-native-rewrite-20261111/reconstructed-components-r4/namespace-rows-r1/"
PIN=dict(gitsha="1b2919a3ac82c74c648968c923bdf53115b66890",bytes=78580,
 sha256="3f50ea0ede4b9abf29921a319f0fffd189d34765db6a64631dd39899b7da1d8b",
 members=20,raw_bytes=489452,source_manifest_sha256="b3c3f8ae19faeb005256982c046a9af0518575bd240798b0887c844588820bc0")
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--repo",type=Path,required=True)
    ap.add_argument("--out",type=Path,required=True);a=ap.parse_args()
    out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    inputs={};members=[];status="FAIL";detail={}
    def read(path):
        path=path.resolve();raw=path.read_bytes();mode=stat.S_IMODE(path.stat().st_mode)
        if path in inputs:assert inputs[path]==(raw,mode)
        inputs[path]=(raw,mode);return raw
    try:
        read(Path(__file__))
        archive=read(a.repo/PREFIX/"source.tar.xz")
        assert (gitsha(archive),len(archive),digest(archive))==(PIN["gitsha"],PIN["bytes"],PIN["sha256"])
        custody_raw=read(a.repo/PREFIX/"custody.json")
        assert gitsha(custody_raw)=="0faaee961151a3288481d6381e05b79807d169b7"
        custody=json.loads(custody_raw)
        for field in ("bytes","sha256","members","raw_bytes","source_manifest_sha256"):
            assert custody[field]==PIN[field],field
        assert custody["git_blob_sha1"]==PIN["gitsha"] and custody["all_members_bytes_modes_verified"] is True
        readback_raw=read(a.repo/PREFIX/"root-readback.json")
        assert gitsha(readback_raw)=="8c6fb84da59b924e90a4897a17e7044e8a9644d5"
        readback=json.loads(readback_raw)
        assert readback["sha256"]==PIN["sha256"] and readback["members"]==PIN["members"]
        assert readback["all_original_bytes_modes_checked"] is True
        (out/"original-custody.json").write_bytes(custody_raw)
        (out/"original-root-readback.json").write_bytes(readback_raw)
        seen=set();abi=[]
        with tarfile.open(fileobj=io.BytesIO(archive),mode="r:xz") as tf:
            for item in tf:
                p=PurePosixPath(item.name)
                assert item.name and not p.is_absolute() and ".." not in p.parts and "\\" not in item.name and "\0" not in item.name
                assert str(p)==item.name and item.name not in seen
                assert item.isfile() and not item.issym() and not item.islnk() and not item.mode&0o7000
                raw=tf.extractfile(item).read();assert len(raw)==item.size
                target=out/"members"/p;target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(raw);target.chmod(item.mode)
                assert target.read_bytes()==raw and stat.S_IMODE(target.stat().st_mode)==item.mode
                row=dict(path=item.name,bytes=len(raw),sha256=digest(raw),gitsha=gitsha(raw),mode=item.mode)
                members.append(row);seen.add(item.name)
                if p.name=="HIA_AGENT_NAMESPACE_STORE_ABI.json":abi.append((row,raw))
        assert len(members)==PIN["members"] and sum(r["bytes"] for r in members)==PIN["raw_bytes"]
        assert abi and all(raw==abi[0][1] for row,raw in abi)
        row,raw=abi[0];catalog=json.loads(raw)
        assert catalog["schema"]=="hepta.hia.agent-namespace-store-abi.v1"
        assert len(catalog["tables"])==10
        assert [r["id"] for r in catalog["relational_operations"]]==list(range(1,32))
        assert sum(len(r["call_sites"]) for r in catalog["relational_operations"])==45
        original=out/"HIA_AGENT_NAMESPACE_STORE_ABI.original.json";original.write_bytes(raw)
        print("HIA_NAMESPACE_ORIGINAL_ABI "+json.dumps(dict(**row,
            base64=base64.b64encode(raw).decode("ascii")),sort_keys=True),flush=True)
        status="PASS_READBACK_ONLY"
        detail.update(ABI=row,matching_ABI_copies=len(abi),
            complete_relational_operations=31,complete_tables=10,original_call_sites=45,
            historical_source_manifest_pin=PIN["source_manifest_sha256"],
            actual_member_hash_matches_for_source_manifest=[r["path"] for r in members if r["sha256"]==PIN["source_manifest_sha256"]])
    except BaseException as error:
        detail.update(error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc();raise
    finally:
        unchanged=all(path.read_bytes()==raw and stat.S_IMODE(path.stat().st_mode)==mode
            for path,(raw,mode) in inputs.items())
        save(out/"members.json",members)
        save(out/"source-pins.json",[dict(path=str(p),bytes=len(raw),sha256=digest(raw),mode=mode)
            for p,(raw,mode) in inputs.items()])
        result=dict(status=status,pin=PIN,detail=detail,all_original_inputs_unchanged=unchanged,
            verified_members=len(members),new_native_entries=0,new_VM_entries=0,
            old_case_counts_inherited=False,whole_store_closed=False)
        save(out/"summary.json",result)
        print("HIA_NAMESPACE_ORIGINAL_SOURCE_READBACK "+json.dumps(result,sort_keys=True),flush=True)
        assert unchanged
if __name__=="__main__":main()
