"""Restore exact published HIA archives into separate snapshots and a traceable development overlay."""
from pathlib import Path,PurePosixPath
import hashlib,json,os,shutil,stat,tarfile,time
BASE=Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111")
SOURCE=BASE/"source"
OUT=BASE/"root-recovery"
PLAN=json.loads("[{\"label\":\"r5-root\",\"path\":\"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r5/root-completed.tar.xz\",\"git_sha\":\"2af0221542fe9510b7a721b26db5eb49365187b9\",\"bytes\":1873424,\"workspace_prefix\":\"\"},{\"label\":\"r6-root\",\"path\":\"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r6/root-completed.tar.xz\",\"git_sha\":\"b18b2a4964830cf0c7a0d1924681c4e2fd97428b\",\"bytes\":1633776,\"workspace_prefix\":\"\"},{\"label\":\"r7-root\",\"path\":\"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r7/root-completed.tar.xz\",\"git_sha\":\"ed57e5ce81ca828de77a2e7f4a19adf2e82284cf\",\"bytes\":4455820,\"workspace_prefix\":\"\"},{\"label\":\"r8-root\",\"path\":\"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r8/root-completed.tar.xz\",\"git_sha\":\"b31651bc660875d3b1acaa0d961412dcb6b804ac\",\"bytes\":3185600,\"workspace_prefix\":\"\"},{\"label\":\"r9-root\",\"path\":\"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r9/root-completed-edit-inputs.tar.xz\",\"git_sha\":\"329ee7baa3fde5407b6f308ab52912e8b662ff27\",\"bytes\":5311896,\"workspace_prefix\":\"\"},{\"label\":\"r10-root\",\"path\":\"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r10/root-completed-edit-composition.tar.xz\",\"git_sha\":\"31b5a36e1aa39335dcb39bba8b627c0c2509e069\",\"bytes\":4550964,\"workspace_prefix\":\"\"},{\"label\":\"r11-root\",\"path\":\"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r11/root-native-controllers-r1-development.tar.xz\",\"git_sha\":\"dd3a340f651fca0dc99ccf31a1282c34d73b164d\",\"bytes\":3000596,\"workspace_prefix\":\"\"},{\"label\":\"r12-controller\",\"rev\":12,\"name\":\"root/controller-integration.tar.xz\",\"workspace_prefix\":\"\"},{\"label\":\"r12-json\",\"rev\":12,\"name\":\"root/json-entry-r2.tar.xz\",\"workspace_prefix\":\"native-edit-json-next\"},{\"label\":\"r13-root\",\"rev\":13,\"name\":\"root/development.tar.xz\",\"workspace_prefix\":\"\"},{\"label\":\"r14-root\",\"rev\":14,\"name\":\"root/development.tar.xz\",\"workspace_prefix\":\"\"}]")
assert not OUT.exists(), "Inspect existing recovery before choosing a new output revision"
OUT.mkdir(mode=0o700)
(OUT/"snapshots").mkdir()
(OUT/"archives").mkdir()
WORK=OUT/"workspace";WORK.mkdir()
checkpoint=json.loads((BASE/"RECOVERY_CHECKOUT.json").read_text())
assert checkpoint["head"]=="a3c61136b79fdb7a4b6d6428fb4bdf31cd5ed270"
assert checkpoint["verified_git_blob_bytes_modes_sizes"] is True
start=time.monotonic()
summary=[]; overlays=[]; installed={}; manifest_checks=[]
def digest_file(p):
    h=hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):h.update(chunk)
    return h.hexdigest()
def verify_git(p,want,sz=None):
    st=p.lstat()
    assert stat.S_ISREG(st.st_mode) and st.st_nlink==1
    if sz is not None:assert st.st_size==sz
    h=hashlib.sha1(b"blob "+str(st.st_size).encode()+b"\0")
    with p.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):h.update(chunk)
    assert h.hexdigest()==want,str(p)
def archive_for(spec):
    if "path" in spec:
        p=SOURCE/spec["path"];verify_git(p,spec["git_sha"],spec["bytes"])
        return p,digest_file(p)
    rev=spec["rev"]
    folder=SOURCE/"review-evidence/hia-native-rewrite-20261111"/("reconstructed-components-r"+str(rev))
    transport=json.loads((folder/"transport-objects.json").read_text())
    matches=[o for o in transport["objects"] if o["name"]==spec["name"]]
    assert len(matches)==1
    obj=matches[0]
    if "ordered_parts" in obj:
        p=OUT/"archives"/(spec["label"]+".tar.xz")
        with p.open("xb") as sink:
            for part in obj["ordered_parts"]:
                q=SOURCE/part["path"];verify_git(q,part["git_sha"],part["bytes"])
                raw=q.read_bytes()
                assert hashlib.sha256(raw).hexdigest()==part["sha256"]
                sink.write(raw)
        assert p.stat().st_size==obj["bytes"]
    else:
        p=folder/obj.get("transport_object_name",obj["name"])
        verify_git(p,obj["git_sha"],obj["bytes"])
    digest=digest_file(p)
    assert digest==obj["sha256"]
    return p,digest
for spec in PLAN:
    arc,archive_hash=archive_for(spec)
    snapshot=OUT/"snapshots"/spec["label"];snapshot.mkdir()
    members=[];seen=set()
    with tarfile.open(arc,"r|xz") as tf:
        for item in tf:
            rel=PurePosixPath(item.name)
            assert item.name and not rel.is_absolute() and all(x not in ("..","") for x in rel.parts)
            assert item.name not in seen;seen.add(item.name)
            assert item.isfile(),("non-regular archive member",item.name)
            assert not item.mode&0o7000,("special file mode",item.name)
            target=snapshot.joinpath(*rel.parts)
            target.parent.mkdir(parents=True,exist_ok=True)
            h=hashlib.sha256();n=0
            with tf.extractfile(item) as src,target.open("xb") as sink:
                for chunk in iter(lambda:src.read(1024*1024),b""):
                    n+=len(chunk);h.update(chunk);sink.write(chunk)
            assert n==item.size
            target.chmod(item.mode)
            assert target.stat().st_size==n and stat.S_IMODE(target.stat().st_mode)==item.mode
            assert digest_file(target)==h.hexdigest()
            row={"path":item.name,"bytes":n,"mode":item.mode,"sha256":h.hexdigest()}
            members.append(row)
    assert digest_file(arc)==archive_hash
    indexed={r["path"]:r for r in members}
    mp=snapshot/"MANIFEST.json"
    checked=0
    if mp.exists():
        doc=json.loads(mp.read_text())
        rows=doc if isinstance(doc,list) else doc.get("files")
        if isinstance(rows,list) and all(isinstance(r,dict) and {"path","bytes","mode","sha256"}<=set(r) for r in rows):
            for row in rows:
                actual=indexed[row["path"]]
                assert all(actual[k]==row[k] for k in ("bytes","mode","sha256")),(spec["label"],row["path"])
                checked+=1
            assert set(indexed)==set(r["path"] for r in rows)|{"MANIFEST.json"}
    manifest_checks.append({"archive":spec["label"],"indexed_original_members_checked":checked})
    for row in members:
        rel=PurePosixPath(row["path"])
        if len(rel.parts)==1 and rel.name in ("MANIFEST.json","CUSTODY.json","ORIGINALS.json","ARCHIVE_MANIFEST.json"):continue
        key=(PurePosixPath(spec["workspace_prefix"])/rel).as_posix() if spec["workspace_prefix"] else rel.as_posix()
        dest=WORK/key;dest.parent.mkdir(parents=True,exist_ok=True)
        origin=snapshot/row["path"]
        previous=installed.get(key)
        if previous is not None and previous["sha256"]!=row["sha256"]:
            overlays.append({"path":key,"old":previous,"new":{"archive":spec["label"],**row}})
        if dest.exists():assert dest.is_file() and not dest.is_symlink()
        shutil.copyfile(origin,dest)
        dest.chmod(row["mode"])
        assert digest_file(dest)==row["sha256"]
        installed[key]={"archive":spec["label"],**row}
    (OUT/(spec["label"]+"-members.json")).write_text(json.dumps(members,indent=2,sort_keys=True)+"\n")
    r={"label":spec["label"],"archive":str(arc),"archive_bytes":arc.stat().st_size,"archive_sha256":archive_hash,"members":len(members),"original_member_bytes":sum(x["bytes"] for x in members),"manifest_members_verified":checked,"snapshot":str(snapshot),"workspace_prefix":spec["workspace_prefix"]}
    summary.append(r)
    (OUT/"progress.json").write_text(json.dumps(summary,indent=2,sort_keys=True)+"\n")
    print(json.dumps(r),flush=True)
r13=json.loads((OUT/"snapshots/r13-root/MANIFEST.json").read_text())
inherited=r13["inherited_unchanged_json_r2_files"]
for row in inherited:
    p=WORK/row["path"]
    assert p.stat().st_size==row["bytes"] and stat.S_IMODE(p.stat().st_mode)==row["mode"]
    assert digest_file(p)==row["sha256"],row["path"]
for key,row in installed.items():
    p=WORK/key
    assert p.stat().st_size==row["bytes"] and stat.S_IMODE(p.stat().st_mode)==row["mode"]
    assert digest_file(p)==row["sha256"],key
(OUT/"workspace-index.json").write_text(json.dumps(installed,indent=2,sort_keys=True)+"\n")
(OUT/"overlays.json").write_text(json.dumps(overlays,indent=2,sort_keys=True)+"\n")
receipt={"schema":"hia-published-root-archive-restore-v1","status":"PASS","host":"rog","source_head":checkpoint["head"],"archives":summary,"total_archived_members":sum(r["members"] for r in summary),"total_archived_member_bytes":sum(r["original_member_bytes"] for r in summary),"workspace_files":len(installed),"workspace_bytes":sum(r["bytes"] for r in installed.values()),"changed_overlay_paths":len(overlays),"inherited_r12_json_members_checked":len(inherited),"all_archive_bytes_members_modes_and_restored_readbacks_verified":True,"compressed_payloads_retained_without_claim_of_new_decompression_tests":True,"native_tests_run":0,"elapsed_seconds":time.monotonic()-start}
(OUT/"RESTORE_RECEIPT.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
print(json.dumps({k:v for k,v in receipt.items() if k!="archives"}),flush=True)
