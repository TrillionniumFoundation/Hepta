"""Read original timed-out cold phase and native receipt evidence; execute none."""
from pathlib import Path
from hashlib import sha256
import argparse,json
p=argparse.ArgumentParser()
p.add_argument("--download",type=Path,required=True)
p.add_argument("--manifest",type=Path,required=True)
p.add_argument("--out",type=Path,required=True)
a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
raw=a.manifest.read_bytes()
assert sha256(raw).hexdigest()=="a14b53db4d3710f82d6c79f1f58b8e6334a999cd7412a1fc68009306fa0bf1e9"
manifest=json.loads(raw)
roots=list(a.download.rglob("hia-cold.cold"))
assert len(roots)==1 and roots[0].is_dir()
root=roots[0];before={};receipts=[];phase=None
for row in manifest["files"]:
    path=root/row["name"]
    assert path.is_file() and not path.is_symlink()
    data=path.read_bytes()
    assert (len(data),sha256(data).hexdigest())==(row["bytes"],row["sha256"]),row["name"]
    before[path]=data
    target=a.out/"original"/row["name"];target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
    value=json.loads(data)
    if row["name"].endswith("/phase-index.json"):
        phase=value
        print("HIA_ORIGINAL_COLD_PHASE_INDEX_BEGIN",flush=True)
        print(data.decode("utf-8"),end="",flush=True)
        print("HIA_ORIGINAL_COLD_PHASE_INDEX_END",flush=True)
    else:
        # Every unfiltered original receipt is retained; this display is a
        # compact inventory only and does not convert failure into a pass.
        receipts.append(dict(name=row["name"],bytes=row["bytes"],sha256=row["sha256"],
          status=value.get("status"),abi_status=value.get("abi_status"),
          core_u32=value.get("core_u32"),returncode=value.get("returncode"),
          child_returncode=value.get("child_returncode"),timed_out=value.get("timed_out"),
          wall_elapsed_ns=value.get("wall_elapsed_ns"),elapsed_ns=value.get("elapsed_ns"),
          source_unchanged=value.get("source_unchanged"),keys=sorted(value)))
assert phase is not None
assert all(path.read_bytes()==data for path,data in before.items())
(a.out/"receipts-index.json").write_text(json.dumps(receipts,indent=2,sort_keys=True)+"\n")
print("HIA_ORIGINAL_COLD_RECEIPTS "+json.dumps(receipts,sort_keys=True),flush=True)
result=dict(status="PASS_READBACK_ONLY",original_cold_status="QUALIFICATION_TIMEOUT",
 files=len(before),native_receipts=len(receipts),all_pinned_hashes_preserved=True,
 actual_B3_compilations=0,actual_native_entries=0,actual_reference_tests=0,
 source_artifact=13894063931,original_wall_seconds=180,whole_stack_closed=False)
(a.out/"summary.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
print("HIA_COLD_PHASE_READBACK "+json.dumps(result,sort_keys=True),flush=True)
