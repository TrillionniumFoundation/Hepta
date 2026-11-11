"""Read exact completed b433 cold and private-projector evidence only.
No compiler, native image, or reference business entry is executed.
"""
from hashlib import sha256
import io,json,os,stat,tarfile
from pathlib import Path
COLD=Path(os.environ["HIA_COLD_READBACK_DIR"]).resolve()
PROGRAM=Path(os.environ["HIA_PROGRAM_READBACK_DIR"]).resolve()
CANDIDATE=Path(os.environ["HIA_CANDIDATE_READBACK_DIR"]).resolve()
OUT=Path(os.environ["HIA_CI_OUTPUT"]).resolve()
OUT.mkdir(parents=True,exist_ok=False)
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def info(path,root):
    assert path.is_file() and not path.is_symlink()
    raw=path.read_bytes()
    return dict(name=path.relative_to(root).as_posix(),bytes=len(raw),
                sha256=digest(raw),mode=stat.S_IMODE(path.stat().st_mode))
def one(root,suffix):
    rows=[p for p in root.rglob("*") if p.is_file() and p.as_posix().endswith(suffix)]
    assert len(rows)==1,(suffix,[str(p) for p in rows])
    return rows[0]
before={name:[info(p,root) for p in sorted(root.rglob("*")) if p.is_file()]
        for name,root in (("cold",COLD),("program",PROGRAM),("candidate",CANDIDATE))}
archive=one(PROGRAM,"/hia-program-recovery/evidence.tar.xz")
members_file=one(PROGRAM,"/hia-program-recovery/evidence-members.json")
assert (archive.stat().st_size,digest(archive.read_bytes()))==(13011724,"2d2f87e1bc129d082406f77778776f72e68e5abc9b910783f4cb8a13ca354a58")
assert (members_file.stat().st_size,digest(members_file.read_bytes()))==(676306,"1957ab7000d2fe6d4a340feb39bc7ba2f4c6ea324357a26f2412923667766b65")
members=json.loads(members_file.read_bytes());assert len(members)==1394
expected={row["name"]:row for row in members};assert len(expected)==1394
selected={};seen=set()
with tarfile.open(archive,"r:xz") as tf:
    for member in tf:
        assert member.isfile() and member.name not in seen and member.name in expected
        raw=tf.extractfile(member).read();row=expected[member.name]
        assert (len(raw),digest(raw),member.mode)==(row["bytes"],row["sha256"],row["mode"])
        seen.add(member.name)
        if member.name in ("program/development/native-projection-r1/summary.json",
                           "program/development/native-projection-r1/progress.json",
                           "program/development/compile-r1/summary.json","run/summary.json"):
            selected[member.name]=raw
assert seen==set(expected) and sum(row["bytes"] for row in members)==53090930
assert len(selected)==4,sorted(selected)
for name,raw in selected.items():
    destination=OUT/"projector"/name
    destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(raw)
    parsed=json.loads(raw)
    if name=="run/summary.json":shown={k:v for k,v in parsed.items() if k not in ("details",)}
    else:shown={k:v for k,v in parsed.items() if k not in ("case_results","protocol_results")}
    print("HIA_B433_PROJECTOR_ORIGINAL "+json.dumps(dict(member=name,bytes=len(raw),
          sha256=digest(raw),report=shown),sort_keys=True),flush=True)
candidate_archive=one(CANDIDATE,"/hia-candidate-recovery/evidence.tar.xz")
candidate_index=one(CANDIDATE,"/hia-candidate-recovery/evidence-members.json")
assert (candidate_archive.stat().st_size,digest(candidate_archive.read_bytes()))==(20412188,"d9790ead23d139bbcbd0f4aef078905ed361775236ecd2376004452684d8ac7e")
assert (candidate_index.stat().st_size,digest(candidate_index.read_bytes()))==(336814,"b04de1534eeb7d4f360d3e82a84dfd98ef6aa42e12f6667b571e62562748087d")
candidate_members=json.loads(candidate_index.read_bytes())
candidate_expected={row["name"]:row for row in candidate_members};assert len(candidate_expected)==len(candidate_members)==784
candidate_seen=set();candidate_selected={}
with tarfile.open(candidate_archive,"r:xz") as tf:
    for member in tf:
        assert member.isfile() and member.name not in candidate_seen
        row=candidate_expected[member.name];raw=tf.extractfile(member).read()
        assert (len(raw),digest(raw),member.mode)==(row["bytes"],row["sha256"],row["mode"])
        candidate_seen.add(member.name)
        if member.name in ("candidate/development/snapshot-limit-protocol-r1/summary.json",
                           "candidate/development/snapshot-whole-boundary-r1/summary.json","run/summary.json"):
            candidate_selected[member.name]=raw
assert candidate_seen==set(candidate_expected) and sum(x["bytes"] for x in candidate_members)==158441057
assert len(candidate_selected)==3,sorted(candidate_selected)
for name,raw in candidate_selected.items():
    destination=OUT/"candidate"/name;destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(raw)
    parsed=json.loads(raw)
    shown={k:v for k,v in parsed.items() if k not in ("case_results",)}
    print("HIA_B433_CANDIDATE_ORIGINAL "+json.dumps(dict(member=name,bytes=len(raw),sha256=digest(raw),report=shown),sort_keys=True),flush=True)
cold_path=one(COLD,"/hia-cold.json")
cold_raw=cold_path.read_bytes();cold=json.loads(cold_raw)
assert cold["schema"]=="hepta.hia.selfhost-cold-replay.v1"
assert cold["qualification_wall_limit_seconds"]==180 and cold["cleanup_wall_limit_seconds"]==3
(OUT/"cold-original.json").write_bytes(cold_raw)
print("HIA_B433_COLD_ORIGINAL "+json.dumps(dict(bytes=len(cold_raw),sha256=digest(cold_raw),
      report={k:v for k,v in cold.items() if k!="source_manifest"}),sort_keys=True),flush=True)
cold_tree=one(COLD,"/hia-cold.cold/request.json").parent
interesting=[]
for path in sorted(cold_tree.rglob("*")):
    if not path.is_file() or path.is_relative_to(cold_tree/"source"):continue
    interesting.append(info(path,cold_tree))
    rel=path.relative_to(cold_tree).as_posix()
    if rel in ("stdout.log","stderr.log","process-owner.json","qualification.json"):
        raw=path.read_bytes()
        target=OUT/"cold-selected"/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
        if path.suffix==".json":
            parsed=json.loads(raw)
            if rel=="qualification.json":parsed={k:v for k,v in parsed.items() if k not in ("source_manifest",)}
            print("HIA_B433_COLD_NESTED "+json.dumps(dict(name=rel,bytes=len(raw),sha256=digest(raw),report=parsed),sort_keys=True),flush=True)
        else:
            print("HIA_B433_COLD_NESTED_LOG "+json.dumps(dict(name=rel,bytes=len(raw),sha256=digest(raw),
                  tail_utf8=raw[-50000:].decode("utf-8","replace")),sort_keys=True),flush=True)
save(OUT/"cold-generated-file-index.json",interesting)
print("HIA_B433_COLD_GENERATED_FILES "+json.dumps(interesting,sort_keys=True),flush=True)
after={name:[info(p,root) for p in sorted(root.rglob("*")) if p.is_file()]
       for name,root in (("cold",COLD),("program",PROGRAM),("candidate",CANDIDATE))}
assert before==after
save(OUT/"original-downloads-index.json",before)
# Retain every downloaded byte beyond the predecessor's short artifact lifetime.
out_archive=OUT/"original-downloads.tar.xz"
with tarfile.open(out_archive,"w:xz",preset=1) as tf:
    for label,root in (("cold",COLD),("program",PROGRAM),("candidate",CANDIDATE)):
        for row in before[label]:
            raw=(root/row["name"]).read_bytes()
            assert len(raw)==row["bytes"] and digest(raw)==row["sha256"]
            member=tarfile.TarInfo(label+"/"+row["name"]);member.size=len(raw);member.mode=row["mode"]
            member.uid=member.gid=member.mtime=0
            tf.addfile(member,io.BytesIO(raw))
checks={}
with tarfile.open(out_archive,"r:xz") as tf:
    for member in tf:
        raw=tf.extractfile(member).read();checks[member.name]=(len(raw),digest(raw),member.mode)
assert checks=={label+"/"+row["name"]:(row["bytes"],row["sha256"],row["mode"])
               for label,rows in before.items() for row in rows}
summary=dict(status="PASS",scope="READ_ONLY_COMPLETED_B433_EVIDENCE",actual_native_entries=0,
    actual_B3_compilations=0,actual_reference_tests=0,
    program_artifact_id=13893949293,cold_artifact_id=13894063931,
    program_members_verified=1394,program_original_bytes=53090930,
    candidate_artifact_id=13893874697,candidate_members_verified=784,candidate_original_bytes=158441057,
    original_downloads_before_after_equal=True,
    retained_original_files=len(checks),retained_archive_bytes=out_archive.stat().st_size,
    retained_archive_sha256=digest(out_archive.read_bytes()),
    original_cold_status=cold["status"],whole_stack_closed=False)
save(OUT/"summary.json",summary)
print("HIA_B433_READBACK "+json.dumps(summary,sort_keys=True),flush=True)
