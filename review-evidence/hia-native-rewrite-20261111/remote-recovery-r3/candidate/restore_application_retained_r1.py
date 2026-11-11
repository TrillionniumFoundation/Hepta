"""Restore only verified prior application fixtures for new actual-ELF gates."""
from hashlib import sha1, sha256
import io, json, os
from pathlib import Path, PurePosixPath
import stat, sys, tarfile, time, traceback
sys.dont_write_bytecode = True
BASE = Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111")
SOURCE = BASE / "source"
PUBLISHED = SOURCE / "review-evidence/hia-native-rewrite-20261111/reconstructed-components-r12"
OUT = BASE / "root-recovery/application-reference-r1"
OUT.mkdir(exist_ok=False)
started = time.monotonic_ns()
report = dict(status="INCOMPLETE", new_semantic_tests=0, scope="VERIFIED_PRIOR_APPLICATION_FIXTURE_RESTORE_ONLY")
pins = {}
def read(path):
    raw = path.read_bytes()
    pins[path] = raw
    return raw
def git_sha(raw):
    return sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
try:
    transport_raw = read(PUBLISHED / "transport-application.json")
    assert git_sha(transport_raw) == "c87553c2242846788ea431d67ccfb3e543fcbeb1"
    transport = json.loads(transport_raw)
    custody_raw = read(PUBLISHED / "application/custody.json")
    assert git_sha(custody_raw) == "796b056369dfce0058dfd514e270d8e03ab6ecbe"
    custody = json.loads(custody_raw)
    assembled = {}
    for obj in transport["objects"]:
        if obj["name"] not in ("application/development.tar.xz", "application/members.json"):
            continue
        chunks = []
        for part in obj["ordered_parts"]:
            rel = PurePosixPath(part["path"])
            assert not rel.is_absolute() and ".." not in rel.parts
            raw = read(SOURCE / str(rel))
            assert (len(raw), sha256(raw).hexdigest(), git_sha(raw)) == (part["bytes"], part["sha256"], part["git_sha"])
            chunks.append(raw)
        raw = b"".join(chunks)
        assert (len(raw), sha256(raw).hexdigest()) == (obj["bytes"], obj["sha256"])
        assembled[obj["name"]] = raw
        (OUT / Path(obj["name"]).name).write_bytes(raw)
    archive = assembled["application/development.tar.xz"]
    manifest = json.loads(assembled["application/members.json"])
    assert isinstance(manifest, list) and len(manifest) == custody["members"] == 8105
    by_name = {row["name"]: row for row in manifest}
    assert len(by_name) == len(manifest)
    prefixes = (
      "/native-edit-apply-next/development/complete-native-r1/",
      "/native-edit-apply-next/development/complete-native-panel-r2/",
      "/native-edit-apply-next/development/whole-Core-boundary-r2/case-000/",
    )
    selected = {name: row for name, row in by_name.items() if any(p in row["original"] for p in prefixes)}
    assert selected, "No exact retained fixture names found"
    old_prefix = "/workspace/scratch/9acdfa9f5639/"
    restored = []
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:xz") as tf:
        members = {m.name:m for m in tf.getmembers() if m.isfile()}
        assert len(members) == len(manifest)
        for name,row in sorted(selected.items()):
            member = members[name]
            assert member.isfile() and member.size == row["bytes"] and stat.S_IMODE(member.mode) == row["mode"]
            assert row["original"].startswith(old_prefix)
            rel = PurePosixPath(row["original"][len(old_prefix):])
            assert not rel.is_absolute() and ".." not in rel.parts
            raw = tf.extractfile(member).read()
            assert (len(raw),sha256(raw).hexdigest()) == (row["bytes"],row["sha256"])
            dest = OUT / "fixtures" / str(rel)
            dest.parent.mkdir(parents=True,exist_ok=True)
            with dest.open("xb") as handle: handle.write(raw)
            dest.chmod(row["mode"])
            assert dest.read_bytes() == raw and stat.S_IMODE(dest.stat().st_mode) == row["mode"]
            restored.append(dict(member=name,path=str(dest),bytes=len(raw),sha256=row["sha256"],mode=row["mode"]))
    panels = []
    fixture_root = OUT / "fixtures/native-edit-apply-next/development"
    for name,expected in (("complete-native-r1",11),("complete-native-panel-r2",40)):
        panel = fixture_root / name
        summary = json.loads((panel / "summary.json").read_bytes())
        assert summary["status"] == "PASS"
        cases = sorted(p for p in panel.glob("case-*") if p.is_dir())
        assert len(cases) == expected, (name,len(cases))
        for case in cases:
            for filename in ("input.bin","stdout.bin","stderr.bin","process.json"):
                assert (case/filename).is_file()
        panels.append(dict(path=str(panel),cases=len(cases),prior_status=summary["status"]))
    boundary = fixture_root / "whole-Core-boundary-r2/case-000"
    assert sha256((boundary/"input.bin").read_bytes()).hexdigest() == "0c5d7909dcc12775bf9b9d3423741c0d836ab5e0d589ed8e47d94a338ed537af"
    for name in ("candidate","receipt","query"):
        assert (boundary/("expected-"+name+".bin")).is_file()
    (OUT/"restored-members.json").write_text(json.dumps(restored,indent=2,sort_keys=True)+"\n")
    report.update(status="PASS",archive_bytes=len(archive),archive_sha256=sha256(archive).hexdigest(),
                  archive_members=len(manifest),restored_files=len(restored),
                  restored_bytes=sum(r["bytes"] for r in restored),panels=panels,boundary=str(boundary),
                  all_selected_member_bytes_sha256_modes_readback=True)
except BaseException as exc:
    report.update(status="FAIL",error_class=type(exc).__name__,error=str(exc))
    traceback.print_exc()
    raise
finally:
    report.update(elapsed_ns=time.monotonic_ns()-started,published_source_before_after_equal=all(p.read_bytes()==raw for p,raw in pins.items()))
    (OUT/"restore.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps(report,sort_keys=True),flush=True)
    assert report["published_source_before_after_equal"]
