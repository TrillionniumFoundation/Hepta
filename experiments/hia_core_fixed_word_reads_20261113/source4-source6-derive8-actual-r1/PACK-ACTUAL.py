"""Lossless pack of already closed fixed-word-read source actuals. No project imports or qualification execution."""
from __future__ import annotations
import base64,gzip,hashlib,io,json,os,stat,tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent
checks=0
def need(x,why):
 global checks
 checks+=1
 if not x:raise RuntimeError(why)
def identity(s):
 return dict(dev=s.st_dev,ino=s.st_ino,mode=stat.S_IMODE(s.st_mode),uid=s.st_uid,gid=s.st_gid,nlink=s.st_nlink,size=s.st_size,mtime_ns=s.st_mtime_ns,ctime_ns=s.st_ctime_ns)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),git_blob_sha1=hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest())
def read(p):
 p=Path(p).absolute();need(p.resolve(strict=True)==p,"symlink alias")
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1,"regular/single link")
  with os.fdopen(fd,"rb",closefd=False) as f:b=f.read()
  need(identity(a)==identity(os.fstat(fd))==identity(p.lstat()),"read identity")
 finally:os.close(fd)
 return b,dict(path=str(p),identity=identity(a),**pin(b))
def load(p):b,q=read(p);return json.loads(b),b,q
def save(p,b):
 p=Path(p);p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,"wb") as f:
  f.write(b);f.flush();os.fsync(f.fileno())
 v,q=read(p);need(v==b,"output full readback");return q
def js(p,v):return save(p,(json.dumps(v,sort_keys=True,indent=2)+"\n").encode())
config,configraw,configpin=load(ROOT/"PACK-CONFIG.json")
need(config["root"]==str(ROOT),"exact package root")
sdk,sdkraw,sdkpin=load(config["sdk_manifest"]);pieces=[];at=0
for i,row in enumerate(sdk["parts"]):
 b,q=read(row["path"]);need(row["ordinal"]==i and row["offset"]==at and q["bytes"]==row["bytes"] and q["sha256"]==row["sha256"],"complete tool-result carrier")
 pieces.append(b);at+=len(b)
sdkbody=b"".join(pieces);need(pin(sdkbody)["sha256"]==sdk["sha256"] and len(sdkbody)==sdk["bytes"],"full SDK byte reconstruction")
sdkdoc=json.loads(sdkbody);need(len(sdkdoc["blob_calls"])==45 and sdkdoc["pure"]==config["pure_commit"] and sdkdoc["ci"]==config["ci_commit"] and sdkdoc["tree"]==config["tree"],"SDK publication scope")
for row in sdkdoc["blob_calls"]:
 content=row["get_full"]["structuredContent"]["content"].encode();observed=pin(content)
 need(row["post_ack"]["structuredContent"]["sha"]==row["post_intent"]["sha"]==observed["git_blob_sha1"] and observed["bytes"]==row["post_intent"]["bytes"] and observed["sha256"]==row["post_intent"]["sha256"],"full Git GET body held")
del pieces,sdkbody,sdkdoc
rows=[];names=set()
def add(p,name):
 p=Path(p).absolute();s=p.lstat();need(name not in names,"duplicate archive path");names.add(name)
 r=dict(name=name,path=str(p),identity=identity(s))
 if stat.S_ISDIR(s.st_mode):
  need(p.resolve(strict=True)==p,"directory alias");r["kind"]="directory"
 elif stat.S_ISREG(s.st_mode):
  b,q=read(p);r.update(kind="regular",bytes=q["bytes"],sha256=q["sha256"],git_blob_sha1=q["git_blob_sha1"])
 elif stat.S_ISLNK(s.st_mode):
  r.update(kind="symlink",link_target=os.readlink(p));need(identity(s)==identity(p.lstat()),"link identity")
 else:raise RuntimeError("unsupported original type: "+str(p))
 rows.append(r);return r
def scan(root,prefix,excluded):
 root=Path(root).absolute();add(root,prefix)
 def rec(d):
  for p in sorted(d.iterdir(),key=lambda p:p.name):
   rel=p.relative_to(root).as_posix()
   if any(rel==x or rel.startswith(x+"/") for x in excluded):continue
   r=add(p,prefix+"/"+rel)
   if r["kind"]=="directory":rec(p)
 rec(root)
for spec in config["roots"]:scan(spec["path"],spec["name"],spec["excluded_subtrees"])
for spec in config["extra_files"]:
 row=add(spec["path"],spec["name"])
 need(row["kind"]=="regular" and row["bytes"]==spec["bytes"] and row["sha256"].startswith(spec["sha256_prefix"]),"Root/peer stopped original "+spec["name"])
add(__file__,"publication/PACK-ACTUAL.py")
add(ROOT/"PACK-CONFIG.json","publication/PACK-CONFIG.json")
need(len(rows)<=config["maximum_typed_members"] and sum(r.get("bytes",0) for r in rows)<=config["maximum_original_bytes"],"archive-only accidental checkout guard")
actuals=[]
for spec in config["actual_directories"]:
 audit,raw,ap=load(spec["audit"]);need(ap["sha256"]==spec["audit_sha256"] and audit["status"]=="FULL_ACTUAL_READBACK_PASS_ONLY","existing independent actual proof")
 found=[r for r in rows if r["kind"]=="regular" and (r["path"].startswith(spec["root"]+"/"))]
 need(len(found)==spec["count"] and sum(r["bytes"] for r in found)==spec["bytes"],"complete actual population")
 amap={x["path"]:x for x in audit["actual_files"]}
 need(set(amap)=={x["path"] for x in found},"actual exact names")
 for row in found:
  a=amap[row["path"]];need(row["identity"]==a["identity"] and row["bytes"]==a["bytes"] and row["sha256"]==a["sha256"],"actual exact original bytes/metadata")
 actuals.append(dict(root=spec["root"],files=len(found),bytes=spec["bytes"],audit=ap,all_originals_equal=True))
rows.sort(key=lambda x:x["name"])
manifest=dict(schema="hia.fixed-word-reads.combined-originals.typed-manifest.v1",typed_members=len(rows),regular_files=sum(r["kind"]=="regular" for r in rows),regular_bytes=sum(r.get("bytes",0) for r in rows),members=rows,actuals=actuals,explicitly_excluded_checkout_copies=[dict(root=x["path"],subtrees=x["excluded_subtrees"]) for x in config["roots"] if x["excluded_subtrees"]],source_reconstruction="Full exact source bytes via immutable base/pure Git tree plus recorded physical metadata and actual generated copies. Original inode/ctime are retained as evidence, not claimed recreated.",product_pure=config["pure_commit"],product_tree=config["tree"])
mraw=(json.dumps(manifest,sort_keys=True,indent=2)+"\n").encode()
def mtime(ns):return str(ns//1000000000)+"."+str(ns%1000000000).zfill(9)
archive=ROOT/"all-originals.tar.gz"
fd=os.open(archive,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,"wb") as outer:
 with gzip.GzipFile(fileobj=outer,mode="wb",filename="",mtime=0,compresslevel=6) as gz:
  with tarfile.open(fileobj=gz,mode="w|",format=tarfile.PAX_FORMAT) as tf:
   mi=tarfile.TarInfo(".TYPED-MANIFEST.json");mi.mode=0o600;mi.size=len(mraw);mi.mtime=0;tf.addfile(mi,io.BytesIO(mraw))
   for row in rows:
    s=row["identity"];ti=tarfile.TarInfo(row["name"]);ti.mode=s["mode"];ti.uid=s["uid"];ti.gid=s["gid"];ti.mtime=s["mtime_ns"]//1000000000;ti.pax_headers={"mtime":mtime(s["mtime_ns"])}
    if row["kind"]=="directory":
     ti.type=tarfile.DIRTYPE;tf.addfile(ti)
    elif row["kind"]=="symlink":
     need(os.readlink(row["path"])==row["link_target"] and identity(Path(row["path"]).lstat())==s,"unchanged symlink")
     ti.type=tarfile.SYMTYPE;ti.linkname=row["link_target"];tf.addfile(ti)
    else:
     b,q=read(row["path"]);need(q["identity"]==s and q["sha256"]==row["sha256"] and q["bytes"]==row["bytes"],"held original before tar")
     ti.size=len(b);tf.addfile(ti,io.BytesIO(b))
 outer.flush();os.fsync(outer.fileno())
expected={x["name"]:x for x in rows};seen=set();decoded_bytes=0
with archive.open("rb") as f:
 with gzip.GzipFile(fileobj=f,mode="rb") as gz:
  with tarfile.open(fileobj=gz,mode="r|") as tf:
   for ti in tf:
    need(ti.name not in seen,"duplicate tar member");seen.add(ti.name)
    if ti.name==".TYPED-MANIFEST.json":
     need(ti.isfile() and tf.extractfile(ti).read()==mraw,"full embedded manifest");continue
    row=expected[ti.name];s=row["identity"]
    need(ti.mode==s["mode"] and ti.uid==s["uid"] and ti.gid==s["gid"] and ti.pax_headers.get("mtime")==mtime(s["mtime_ns"]),"exact tar metadata")
    if row["kind"]=="directory":need(ti.isdir(),"typed directory")
    elif row["kind"]=="symlink":need(ti.issym() and ti.linkname==row["link_target"],"typed symlink")
    else:
     need(ti.isfile() and ti.size==row["bytes"],"typed regular")
     b=tf.extractfile(ti).read();q=pin(b);need(q["sha256"]==row["sha256"] and q["git_blob_sha1"]==row["git_blob_sha1"] and q["bytes"]==row["bytes"],"every original full body")
     decoded_bytes+=len(b)
  while gz.read(1048576):pass
need(seen==set(expected)|{".TYPED-MANIFEST.json"} and decoded_bytes==manifest["regular_bytes"],"entire typed archive and gzip CRC")
for row in rows:
 p=Path(row["path"]);need(identity(p.lstat())==row["identity"],"original final metadata")
 if row["kind"]=="regular":
  b,q=read(p);need(q["bytes"]==row["bytes"] and q["sha256"]==row["sha256"],"original final full bytes")
 elif row["kind"]=="symlink":need(os.readlink(p)==row["link_target"],"original final link")
compressed,compressedpin=read(archive);g=ROOT/"git-files"
mp=save(g/"TYPED-MANIFEST.json",mraw)
parts=[]
for i,start in enumerate(range(0,len(compressed),config["archive_raw_chunk_bytes"])):
 block=compressed[start:start+config["archive_raw_chunk_bytes"]];name="archive/part-%04d.b64"%i;b64=base64.encodebytes(block)
 op=save(g/name,b64);parts.append(dict(path=name,offset=start,raw_bytes=len(block),raw_sha256=hashlib.sha256(block).hexdigest(),**{k:op[k] for k in ("bytes","sha256","git_blob_sha1")}))
rebuilt=b"".join(base64.b64decode(read(g/x["path"])[0],validate=False) for x in parts)
need(rebuilt==compressed,"all base64 carriers reconstruct exact compressed bytes")
save(g/"PACK-ACTUAL.py",read(__file__)[0]);save(g/"PACK-CONFIG.json",configraw)
reconstruction=dict(schema="hia.fixed-word-reads.source-reconstruction.v1",base_commit=config["base_commit"],pure_commit=config["pure_commit"],pure_tree=config["tree"],ci_commit=config["ci_commit"],full_source_file_count=4128,full_source_bytes=411835729,product_delta45_full_raw_git_get_verified=True,source4_before="base855 plus the two author overlays in generation2-source4 inputs; exact SOURCE-MATERIALIZATION-r2 and before snapshot retain identity/mode",source4_after="same base and overlays plus all41 full actual generated-original copies; exact source-after snapshot",fixture_before="closed source4 after plus the3 raw overlay files and exact SOURCE-MATERIALIZATION",fixture_after="pure78462259 exact4128 Git leaves; actual support doc retained and coverage byte-identical",inode_and_ctime_are_recorded_evidence_not_recreated=True)
js(g/"SOURCE-RECONSTRUCTION.json",reconstruction)
keys=[
("source4-FINAL.json",Path(config["actual_directories"][0]["root"])/"FINAL.json"),
("source4-report.json",Path(config["actual_directories"][0]["root"])/"source4-report.json"),
("source4-independent-readback.json",Path(config["actual_directories"][0]["audit"])),
("fixture-FINAL.json",Path(config["actual_directories"][1]["root"])/"FINAL.json"),
("source6-report.json",Path(config["actual_directories"][1]["root"])/"source6-report.json"),
("derive8-report.json",Path(config["actual_directories"][1]["root"])/"derive8-report.json"),
("fixture-independent-readback.json",Path(config["actual_directories"][1]["audit"])),
("PURE-CI-HANDOFF.json",Path(config["actual_directories"][1]["root"]).parent/"proof/PURE-CI-HANDOFF.json"),
("PURE-PRODUCT-PLAN.json",Path(config["actual_directories"][1]["root"]).parent/"proof/PURE-PRODUCT-PLAN.json")]
for name,path in keys:save(g/"key-originals"/name,read(path)[0])
archive_doc=dict(schema="hia.fixed-word-reads.lossless-archive.v1",archive=compressedpin,parts=parts,manifest=mp,typed_members=len(rows),regular_files=manifest["regular_files"],regular_bytes=manifest["regular_bytes"],archive_member_count=len(rows)+1,full_gzip_CRC_and_every_typed_member_body_readback=True,all_original_source_paths_unchanged=True,actuals=actuals)
ap=js(g/"ARCHIVE.json",archive_doc)
rp=js(g/"PACK-READBACK.json",dict(schema="hia.fixed-word-reads.pack-readback.v1",status="ALL_ORIGINALS_FULL_BYTE_AND_TYPED_METADATA_PASS",checks=checks,archive=ap,all_members_and_originals_full_read=True,carrier_reverse_bytes_equal=True,product_or_test_or_generator_executions=0,originals_unchanged=True))
hp=js(g/"HANDOFF.json",dict(schema="hia.fixed-word-reads.two-actuals-handoff.v1",status="SOURCE4_AND_SOURCE6_DERIVE8_CLOSED_PASS_ONLY",pure=config["pure_commit"],ci=config["ci_commit"],tree=config["tree"],standard_CI_run=43405081180,standard_CI_result="PENDING_IN_THIS_CHECKPOINT",original_116_18_32_native_cold_installed_pass_claimed=False,source4=dict(methods=4,author_calls=2,physical_generated_outputs=41,changed_asm=39,UNPACK_original_nine_caps=True),source6=dict(methods=6,original_commands=8,whole_source_idempotent=True,changed_documents=["docs/HIA_SELFHOST_CORE_SUPPORT.json"]),originals=actuals,archive=ap,pack_readback=rp,root_review_PR_R8_R9_CI_trigger_originals_retained=True,old_a2_timeout_remains_failure=True,static_preparation_mode_error_is_not_product_failure=True))
files=[]
for p in sorted(g.rglob("*")):
 if p.is_file():
  b,q=read(p);files.append(dict(path=p.relative_to(g).as_posix(),**q))
plan=js(ROOT/"FILES.json",dict(schema="hia.fixed-word-reads.evidence-publication-files.v1",base_commit=config["pure_commit"],prefix="experiments/hia_core_fixed_word_reads_20261113/source4-source6-derive8-actual-r1",files=files))
print(json.dumps(dict(status="ALL_ORIGINALS_FULL_BYTE_AND_TYPED_METADATA_PASS",checks=checks,typed=len(rows),regular=manifest["regular_files"],regular_bytes=manifest["regular_bytes"],archive=compressedpin,parts=len(parts),git_files=len(files),files_plan=plan,handoff=hp),sort_keys=True))
