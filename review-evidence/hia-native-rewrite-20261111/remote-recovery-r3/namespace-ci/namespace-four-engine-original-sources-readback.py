"""Strict readonly export of four already sealed namespace engine source sets.

No original compiler, image, test or qualification is rerun. Archive Git identity,
every original payload member, and complete before/after identities are checked.
Only the selected final text bytes are exported for subsequent source authoring.
"""
from __future__ import annotations
import base64,hashlib,io,json,os,resource,stat,tarfile,time,traceback
from pathlib import Path,PurePosixPath
CONFIG=json.loads("[{\"label\":\"transactions\",\"archive\":{\"path\":\"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r7/namespace-transactions-r3.tar.xz\",\"git_blob\":\"610d42ed4bea8900b7ef795d762660b765a051a6\",\"bytes\":3839412},\"custody\":{\"path\":\"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r7/namespace-transactions-r3-custody.json\",\"git_blob\":\"afdba10b037564625918f8fe5ff5d1a3404b0336\"},\"original_files\":95,\"original_bytes\":8743225,\"selected\":[{\"name\":\"transactions/local-native-r2/compile/source/tools/generate_hia_agent_namespace_transactions.py\",\"bytes\":20643,\"sha256\":\"07daa89c57d049cab5b874128ec95dacdf9a42d762e333b9e8aac31c08f50db3\",\"mode\":420},{\"name\":\"transactions/local-native-r2/compile/source/docs/HIA_AGENT_NAMESPACE_TRANSACTIONS.md\",\"bytes\":10496,\"sha256\":\"293f18a61ff0a34d7a09258f641e8b127e95fc6264369416263de02ae036c887\",\"mode\":420}]},{\"label\":\"log\",\"archive\":{\"path\":\"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r12/namespace-log/development.tar.xz\",\"git_blob\":\"6f72cee652911ecb02cbddd227d2b0a26517241c\",\"bytes\":2175548},\"custody\":{\"path\":\"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r12/namespace-log/custody.json\",\"git_blob\":\"2149ab7e75d2db15e8af51b570dda78f4fe2ed0a\"},\"original_files\":102,\"original_bytes\":9174709,\"selected\":[{\"name\":\"log/authoring-r2/source/tools/generate_hia_agent_namespace_log.py\",\"bytes\":17269,\"sha256\":\"5634b5f126cd32e30956f54825c756ad68f634f33e60b975a9de072b28ae29e8\",\"mode\":420},{\"name\":\"log/authoring-r2/source/docs/HIA_AGENT_NAMESPACE_PHYSICAL.md\",\"bytes\":7917,\"sha256\":\"428e1cd13484d27d95b43ec618e5e1906ddfa57aa4846ca8f52fe4852e462779\",\"mode\":420},{\"name\":\"log/authoring-r2/source/tests/test_hia_agent_namespace_log.py\",\"bytes\":14600,\"sha256\":\"80fd94ca0fb6c828694ff8bafdc4e19ad1d69d75f91bcf9f7c1a454e2a8f91f6\",\"mode\":420}]},{\"label\":\"views\",\"archive\":{\"path\":\"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r13/namespace-views/development.tar.xz\",\"git_blob\":\"bce24d49664ae72bdb020159a1008651594157a2\",\"bytes\":2572864},\"custody\":{\"path\":\"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r13/namespace-views/custody.json\",\"git_blob\":\"d4c86ea603aa8f60fbd36a8f39ed62d6529adb95\"},\"original_files\":96,\"original_bytes\":11025017,\"selected\":[{\"name\":\"views/authoring-r2/source/tools/generate_hia_agent_namespace_views.py\",\"bytes\":22801,\"sha256\":\"50b387993a0dcc5316503deb4c286c642e2a278e5dba6441b1774e2828226588\",\"mode\":420},{\"name\":\"views/authoring-r2/source/docs/HIA_AGENT_NAMESPACE_VIEWS.md\",\"bytes\":11090,\"sha256\":\"8924dc8a6624b37a165ad25c3424fac099888a2b189d2d479e4ca89b8eaf7f2a\",\"mode\":420},{\"name\":\"views/authoring-r2/source/tests/test_hia_agent_namespace_views.py\",\"bytes\":21375,\"sha256\":\"7cd1db8908d0d896e77e8268ccf4a17351da265ad10cbd3eae8b2335fe466f60\",\"mode\":420}]},{\"label\":\"commit\",\"archive\":{\"path\":\"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r14/namespace-commit/development.tar.xz\",\"git_blob\":\"800349b90e10ff70e454c4df84131bb2327a0d41\",\"bytes\":2162412},\"custody\":{\"path\":\"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r14/namespace-commit/custody.json\",\"git_blob\":\"cfd31d62a081e41206c18ec1c21a7fa4ef14a5c4\"},\"original_files\":102,\"original_bytes\":14552924,\"selected\":[{\"name\":\"commit/authoring-r2/source/tools/generate_hia_agent_namespace_commit.py\",\"bytes\":28098,\"sha256\":\"36ca9a5a52e72769fb02f2090fbec8e53e9f29431705b8de35b773ea7d825fe9\",\"mode\":420},{\"name\":\"commit/authoring-r2/source/docs/HIA_AGENT_NAMESPACE_COMMIT.md\",\"bytes\":8923,\"sha256\":\"c9bdc9d790e332aa189a1338505e28a740cc5bdfe5c2821b092b9d1f15601397\",\"mode\":420}]}]")
def sha(raw):return hashlib.sha256(raw).hexdigest()
def git(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def capture(path,expected=None):
    info=path.lstat();assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
    data=path.read_bytes();assert len(data)==info.st_size
    result=dict(path=str(path),bytes=len(data),mode=stat.S_IMODE(info.st_mode),sha256=sha(data),git_blob=git(data))
    if expected:
        assert result["git_blob"]==expected["git_blob"]
        if "bytes" in expected:assert result["bytes"]==expected["bytes"]
    return data,result
def member_name(name):
    p=PurePosixPath(name)
    assert name and not p.is_absolute() and ".." not in p.parts and str(p)==name
    return name
def emit_text(label,row,raw):
    assert len(raw)==row["bytes"] and sha(raw)==row["sha256"]
    raw.decode("utf-8")
    identity=dict(label=label,name=row["name"],bytes=len(raw),sha256=sha(raw),git_blob=git(raw),mode=row["mode"])
    print("NAMESPACE_RECOVERED_TEXT_IDENTITY "+json.dumps(identity,sort_keys=True),flush=True)
    for offset in range(0,len(raw),9000):
        part=raw[offset:offset+9000]
        print("NAMESPACE_RECOVERED_TEXT_CHUNK "+json.dumps(dict(label=label,name=row["name"],offset=offset,
            bytes=len(part),sha256=sha(part),base64=base64.b64encode(part).decode("ascii")),sort_keys=True),flush=True)
def main():
    assert os.environ.get("GITHUB_ACTIONS")=="true"
    resource.setrlimit(resource.RLIMIT_CPU,(90,90))
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    affinity=os.sched_getaffinity(0);assert affinity
    os.sched_setaffinity(0,{min(affinity)})
    repo=Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    out=Path(os.environ["HIA_CI_OUTPUT"]).resolve();out.mkdir(parents=True,exist_ok=False)
    summary=dict(schema="hia.namespace-four-original-engines-readonly-export.v1",status="INCOMPLETE",
        run_id=os.environ.get("GITHUB_RUN_ID"),commit=os.environ.get("GITHUB_SHA"),
        source_pins={},archives={},selected=[],actual_native_entries=0,actual_VM_entries=0,
        original_counts_inherited=False,ordinary_Store_closed=False,all_prior_failures_preserved=True,
        original_qualification="0ef FAIL/HOLD unchanged; NDU deletion actor UNKNOWN",
        scope="Archive identity and full member byte/mode verification, then exact source export only",
        limits=dict(cpu_seconds=90,wall_seconds=180,address_bytes=1<<30,core_bytes=0))
    originals=[]
    try:
        for config in CONFIG:
            label=config["label"];ap=repo/config["archive"]["path"];cp=repo/config["custody"]["path"]
            raw,archive_pin=capture(ap,config["archive"]);custody_raw,custody_pin=capture(cp,config["custody"])
            originals.extend([(ap,archive_pin),(cp,custody_pin)])
            custody=json.loads(custody_raw);expected={member_name(r["name"]):r for r in custody["members"]}
            assert len(expected)==len(custody["members"])==config["original_files"]==custody["original_files"]
            assert sum(r["bytes"] for r in expected.values())==config["original_bytes"]==custody["original_bytes"]
            chosen={r["name"]:r for r in config["selected"]};extracted={};indexed=[];found=set();unlisted=[]
            with tarfile.open(fileobj=io.BytesIO(raw),mode="r:xz") as archive:
                for member in archive:
                    name=member_name(member.name)
                    assert name not in found and member.isfile() and not member.issym() and not member.islnk()
                    found.add(name);stream=archive.extractfile(member);assert stream is not None
                    data=stream.read();assert len(data)==member.size
                    row=dict(name=name,bytes=len(data),mode=member.mode,sha256=sha(data),git_blob=git(data))
                    indexed.append(row)
                    if name in expected:
                        actual=expected[name]
                        assert (row["bytes"],row["mode"],row["sha256"])==(actual["bytes"],actual["mode"],actual["sha256"]),name
                    else:
                        # An original archive self-manifest is not assigned a fabricated
                        # sidecar digest. Its exact bytes remain bound by the whole
                        # original Git blob, and are reported separately.
                        unlisted.append(row)
                    if name in chosen:
                        selected=chosen[name]
                        assert (row["bytes"],row["mode"],row["sha256"])==(selected["bytes"],selected["mode"],selected["sha256"])
                        extracted[name]=data
            assert set(expected)<=found and set(extracted)==set(chosen)
            # Verified original source text is emitted before interpreting the
            # optional archive self-manifest shape or aggregate counters.
            source_dir=out/label/"source";source_dir.mkdir(parents=True)
            selected_pins=[]
            for ordinal,item in enumerate(config["selected"]):
                name=item["name"];data=extracted[name]
                target=source_dir/str(ordinal)/Path(name).name;target.parent.mkdir()
                with target.open("xb") as f:f.write(data)
                target.chmod(item["mode"])
                copied,copy_pin=capture(target)
                assert copied==data and copy_pin["mode"]==item["mode"]
                selected_pins.append(dict(**item,git_blob=git(data),export_path=str(target)))
                emit_text(label,item,data)
            save(out/label/"all-member-readback.json",indexed)
            assert len(found)==len(expected)+len(unlisted)
            assert len(unlisted)<=1 and all(r["name"].endswith(".json") for r in unlisted)
            summary["archives"][label]=dict(archive=archive_pin,custody=custody_pin,
                original_payload_members=len(expected),original_payload_bytes=config["original_bytes"],
                all_archive_members=len(indexed),all_archive_bytes=sum(r["bytes"] for r in indexed),
                every_original_member_byte_mode_sha_equal=True,whole_archive_git_identity_equal=True,
                extra_original_manifest_bound_by_archive_git=unlisted,selected=selected_pins,
                historical_custody_scope=custody.get("scope"))
            summary["selected"].extend(dict(label=label,**p) for p in selected_pins)
        assert len(summary["selected"])==10
        summary["status"]="PASS"
    except BaseException as error:
        summary.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        checks=[]
        for path,before in originals:
            try:raw,after=capture(path);same=after==before
            except BaseException:after=None;same=False
            checks.append(dict(before=before,after=after,unchanged=same))
        summary["source_checks"]=checks
        if len(checks)!=8 or not all(r["unchanged"] for r in checks):summary["status"]="FAIL"
        save(out/"summary.json",summary)
        print("NAMESPACE_ORIGINAL_ENGINES_SUMMARY "+json.dumps(summary,sort_keys=True),flush=True)
    return 0 if summary["status"]=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
