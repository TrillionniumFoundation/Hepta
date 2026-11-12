"""Read every original R13 byte and expose exact Worker/Graph authors.
No repository module is imported; no generation, VM or native entry executes.
"""
from pathlib import Path,PurePosixPath
from hashlib import sha1,sha256
import argparse,base64,io,json,stat,sys,tarfile,traceback
PIN={
  "archive": {
    "path": "review-evidence/hia-native-rewrite-20261111/reconstructed-components-r13/worker-report/development.tar.xz",
    "bytes": 313476,
    "sha256": "99aab27976baff0072f78612196545fb423bd6b439d5e63c1f64d658efbde90e",
    "gitsha": "801828af63ebade941c2b24c6c6e633d992438f6"
  },
  "index": {
    "path": "review-evidence/hia-native-rewrite-20261111/reconstructed-components-r13/worker-report/members.json",
    "bytes": 382574,
    "gitsha": "fec2fe3632fd0086314f89d7f79d8401352401a7",
    "sha256": "a2beb8f4237055723735dba444ef088080d741d7b49e15c9538439f917daa20d"
  },
  "custody": {
    "path": "review-evidence/hia-native-rewrite-20261111/reconstructed-components-r13/worker-report/custody.json",
    "bytes": 785,
    "gitsha": "92f3f8d2793a471e718582b85790404de9906cf9",
    "sha256": "ef3af9840bf0b34d290b87e8fbba078edfbd1bebcef1e6e6485178855da392a2"
  },
  "members": 1660,
  "raw_bytes": 8965311,
  "selected": [
    {
      "bytes": 14222,
      "mode": 420,
      "path": "development/report-compile-r1/source/13/generate_hia_worker_request.py",
      "sha256": "6616f3a11a0c77823444980764dc0a2d84b1166f93a21584d529a7d0a1806c4a"
    },
    {
      "bytes": 19632,
      "mode": 420,
      "path": "development/report-compile-r1/source/15/generate_hia_agent_edit_apply_graph.py",
      "sha256": "488719745efdc53c073641d311408ae47ce654d99d8d255e0b61892259d6bee7"
    },
    {
      "bytes": 11265,
      "mode": 420,
      "path": "development/report-compile-r1/source/16/generate_hia_graph_merge.py",
      "sha256": "b4cda58e84da76a17a2daa919f37483eb2973dcfdbb00cd30c074ebc9aca8ed9"
    },
    {
      "bytes": 23950,
      "mode": 420,
      "path": "development/report-compile-r1/source/17/hia_agent_edit_source_views.py",
      "sha256": "555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c"
    },
    {
      "bytes": 18081,
      "mode": 420,
      "path": "development/report-compile-r1/source/2/generate_hia_worker_report.py",
      "sha256": "dc69eb36aacc256287f2ca4ccbd634c4626da8255d1dfddbe0b5b5a1cf829cb1"
    }
  ]
}
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def safe(value):
    p=PurePosixPath(value)
    assert not p.is_absolute() and p.parts and p.as_posix()==value
    assert all(part not in ("",".","..") for part in p.parts)
    return p
def save(path,value):
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def main():
    p=argparse.ArgumentParser();p.add_argument("--repo",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True);a=p.parse_args()
    root=a.repo.resolve();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    seen=set();total=0;exports=[];pins={};status="FAIL";failure=None
    try:
        for label in ("archive","index","custody"):
            row=PIN[label];path=root/row["path"];assert not path.is_symlink()
            raw=path.read_bytes()
            assert (len(raw),digest(raw),gitsha(raw))==(row["bytes"],row["sha256"],row["gitsha"]),label
            pins[path]=raw
        index=json.loads(pins[root/PIN["index"]["path"]])
        expected={row["path"]:row for row in index}
        assert len(index)==len(expected)==PIN["members"]
        assert sum(row["bytes"] for row in index)==PIN["raw_bytes"]
        custody=json.loads(pins[root/PIN["custody"]["path"]])
        assert custody["all_members_bytes_mode_sha_original_readback"] is True
        assert (custody["bytes"],custody["sha256"],custody["member_count"],custody["member_bytes"],
            custody["member_manifest_sha256"])==(PIN["archive"]["bytes"],PIN["archive"]["sha256"],
            PIN["members"],PIN["raw_bytes"],PIN["index"]["sha256"])
        selected={row["path"]:row for row in PIN["selected"]}
        assert all(expected[path]==row for path,row in selected.items())
        sources=out/"originals";sources.mkdir()
        with tarfile.open(fileobj=io.BytesIO(pins[root/PIN["archive"]["path"]]),mode="r:xz") as archive:
            for member in archive:
                path=safe(member.name)
                assert member.isfile() and member.name not in seen and member.name in expected
                row=expected[member.name]
                assert (member.size,stat.S_IMODE(member.mode))==(row["bytes"],row["mode"]),member.name
                stream=archive.extractfile(member);h=sha256();size=0;chunks=[]
                while True:
                    part=stream.read(1<<20)
                    if not part:break
                    size+=len(part);h.update(part)
                    if member.name in selected:chunks.append(part)
                assert (size,h.hexdigest())==(row["bytes"],row["sha256"]),member.name
                seen.add(member.name);total+=size
                if member.name in selected:
                    raw=b"".join(chunks);raw.decode("utf-8")
                    target=sources/path.name;assert not target.exists()
                    target.write_bytes(raw);target.chmod(row["mode"])
                    assert target.read_bytes()==raw and stat.S_IMODE(target.stat().st_mode)==row["mode"]
                    record=dict(member=member.name,file=path.name,bytes=len(raw),sha256=digest(raw),
                        gitsha=gitsha(raw),mode=row["mode"])
                    exports.append(record)
                    for at in range(0,len(raw),12000):
                        print("HIA_WORKER_ORIGINAL_SOURCE "+json.dumps(dict(record,offset=at,
                            base64=base64.b64encode(raw[at:at+12000]).decode("ascii")),sort_keys=True),flush=True)
        assert seen==set(expected) and len(seen)==PIN["members"] and total==PIN["raw_bytes"]
        assert len(exports)==len(selected)==5 and {r["member"] for r in exports}==set(selected)
        for label,suffix in (("archive","development.tar.xz"),("index","members.json"),("custody","custody.json")):
            (out/suffix).write_bytes(pins[root/PIN[label]["path"]])
        assert all(path.read_bytes()==raw for path,raw in pins.items())
        save(out/"complete-member-index.json",index)
        save(out/"source-index.json",exports)
        status="PASS_READBACK_ONLY"
    except BaseException as error:
        failure=dict(error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        unchanged=all(path.read_bytes()==raw for path,raw in pins.items())
        if not unchanged:status="FAIL"
        report=dict(status=status,scope="EXACT_COMPLETE_R13_WORKER_SOURCE_READBACK",
            original_archive_gitsha=PIN["archive"]["gitsha"],members_verified=len(seen),
            original_bytes_verified=total,selected_sources=exports,
            source_archive_and_manifest_unchanged=unchanged,failure=failure,
            repository_imports=0,generated_HIA=0,VM_entries=0,native_entries=0,
            source_only=True,whole_Worker_closed=False,ordinary_namespace_closed=False)
        save(out/"summary.json",report)
        print("HIA_WORKER_ORIGINAL_SOURCE_READBACK "+json.dumps(report,sort_keys=True),flush=True)
    if status!="PASS_READBACK_ONLY":raise SystemExit(1)
if __name__=="__main__":main()
