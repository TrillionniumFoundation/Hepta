"""Read-only complete d1 CLI fault artifact verification; executes no HIA."""
from pathlib import Path,PurePosixPath
from hashlib import sha256
import argparse,json,stat,tarfile,traceback
EXPECTED=dict(run_id=43109366132,job_id=130821003897,artifact_id=13896150884,
    artifact_name="hia-cli-recovery-43109366132-1",
    zip_bytes=45570355,zip_sha256="361782911b36f36ce8e3bc75b8aad7d1c17b4f8d0e0f63294360c4cce2d26a27",
    archive_bytes=6744744,archive_sha256="44456161a2def03f5c3cfcded5d56777f37ca04eef8b2d3a9971dcc44cd9af4d",
    index_bytes=144273,index_sha256="96f5500c1a31a41d95d0c3d98adcbe4a77d101e3e32ed4678a96a641e0dfef92",
    members=388,raw_bytes=56010708)
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--download-dir",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    args=p.parse_args()
    source=args.download_dir.resolve();out=args.out.resolve()
    out.mkdir(parents=True,exist_ok=False)
    result=dict(scope="INDEPENDENT_FULL_RAW_ARTIFACT_READBACK_NO_NATIVE_EXECUTION",
                status="FAIL",expected=EXPECTED,native_entries=0,executables_run=0)
    try:
        candidates=list(source.rglob("evidence.tar.xz"))
        assert len(candidates)==1,candidates
        archive=candidates[0]
        index=archive.with_name("evidence-members.json")
        custody=archive.with_name("custody.json")
        for path in (archive,index,custody):
            assert path.is_file() and not path.is_symlink()
        before={str(path):path.read_bytes() for path in (archive,index,custody)}
        ar=before[str(archive)];ir=before[str(index)];cr=before[str(custody)]
        assert (len(ar),digest(ar))==(EXPECTED["archive_bytes"],EXPECTED["archive_sha256"])
        assert (len(ir),digest(ir))==(EXPECTED["index_bytes"],EXPECTED["index_sha256"])
        rows=json.loads(ir);manifest=json.loads(cr)
        assert manifest["status"]=="FAIL" and manifest["scope"]=="cli-independent-entry-failure-diagnostic-r4"
        assert manifest["all_original_and_tar_member_bytes_sha256_modes_readback"] is True
        assert (manifest["bytes"],manifest["sha256"],manifest["members"],manifest["original_bytes"],
                manifest["member_index_bytes"],manifest["member_index_sha256"])==(
                    EXPECTED["archive_bytes"],EXPECTED["archive_sha256"],EXPECTED["members"],EXPECTED["raw_bytes"],
                    EXPECTED["index_bytes"],EXPECTED["index_sha256"])
        wanted={row["name"]:row for row in rows}
        assert len(wanted)==len(rows)==EXPECTED["members"]
        assert sum(row["bytes"] for row in rows)==EXPECTED["raw_bytes"]
        found=set();total=0;fault_raw=None;fault_name=None;outer=None;verified=[]
        with tarfile.open(archive,"r:xz") as tf:
            for item in tf:
                path=PurePosixPath(item.name)
                assert item.isfile() and not item.issym() and not item.islnk()
                assert not path.is_absolute() and ".." not in path.parts
                assert item.name not in found and item.name in wanted
                row=wanted[item.name];raw=tf.extractfile(item).read()
                assert (len(raw),digest(raw),stat.S_IMODE(item.mode))==(
                    row["bytes"],row["sha256"],row["mode"]),(item.name,row)
                found.add(item.name);total+=len(raw)
                verified.append(dict(name=item.name,bytes=len(raw),mode=stat.S_IMODE(item.mode),sha256=digest(raw)))
                if item.name.endswith("/entry-actual-fault-r1/summary.json"):
                    assert fault_raw is None
                    fault_raw=raw;fault_name=item.name
                if item.name=="run/summary.json":
                    outer=json.loads(raw)
        assert found==set(wanted) and total==EXPECTED["raw_bytes"]
        assert fault_raw is not None and outer is not None
        fault=json.loads(fault_raw)
        assert fault==outer["details"]["actual_fault_capture"]
        assert outer["status"]=="FAIL" and outer["whole_stack_closed"] is False
        assert fault["scope"]=="INSTRUMENTED_DEVELOPMENT_FAULT_ONLY_NOT_EQUIVALENCE"
        assert fault["source_pins_unchanged"] is True and fault["exit"]==126
        assert fault["fault"] is not None
        assert fault["original_assembly_sha256"]=="d44539b7bba266622d870c6065484e05030b7cce477ffb287d2ab0fd8c5d82c9"
        (out/"actual-fault-summary.json").write_bytes(fault_raw)
        (out/"original-custody.json").write_bytes(cr)
        (out/"original-members.json").write_bytes(ir)
        save(out/"verified-members.json",verified)
        assert all(Path(path).read_bytes()==raw for path,raw in before.items())
        result.update(status="PASS_READBACK_ONLY",members=len(found),raw_bytes=total,
            source_pins_unchanged=True,fault_summary=dict(member=fault_name,bytes=len(fault_raw),sha256=digest(fault_raw)),
            original_entry_status="FAIL",fault_probe_scope="same class of missing-file input, different argv/environment",
            zip_verification="outer ZIP size/digest are GitHub producer metadata; inner archive and all members independently verified")
        print("HIA_CLI_FAULT_JSON_BEGIN",flush=True)
        print(fault_raw.decode("utf-8"),end="",flush=True)
        print("HIA_CLI_FAULT_JSON_END",flush=True)
        print("HIA_CLI_FAULT_BINDING "+json.dumps(result["fault_summary"],sort_keys=True),flush=True)
    except BaseException:
        result["failure"]=traceback.format_exc()
        print(result["failure"],flush=True)
        raise
    finally:
        save(out/"readback-summary.json",result)
        print("HIA_CLI_FAULT_READBACK "+json.dumps(result,sort_keys=True),flush=True)
if __name__=="__main__":main()
