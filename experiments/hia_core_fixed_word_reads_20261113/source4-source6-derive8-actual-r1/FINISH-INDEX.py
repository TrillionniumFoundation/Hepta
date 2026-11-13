"""Finish publication metadata only after the preserved archive/index TypeError. Never repack or rerun products."""
from pathlib import Path
import base64,hashlib,json,os,stat
ROOT=Path(__file__).resolve().parent
G=ROOT/"git-files"
def need(x,m):
 if not x:raise RuntimeError(m)
def ident(s):return dict(dev=s.st_dev,ino=s.st_ino,mode=stat.S_IMODE(s.st_mode),uid=s.st_uid,gid=s.st_gid,nlink=s.st_nlink,size=s.st_size,mtime_ns=s.st_mtime_ns,ctime_ns=s.st_ctime_ns)
def read(p):
 p=Path(p);need(p.resolve(strict=True)==p.absolute(),"alias");fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_nlink==1,"regular")
  with os.fdopen(fd,"rb",closefd=False) as f:b=f.read()
  need(ident(s)==ident(os.fstat(fd))==ident(p.lstat()),"stable")
 finally:os.close(fd)
 return b,dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),git_blob_sha1=hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest(),identity=ident(s))
def save(p,b):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,"wb") as f:f.write(b);f.flush();os.fsync(f.fileno())
 v,q=read(p);need(v==b,"save readback");return q
def js(p,v):return save(p,(json.dumps(v,sort_keys=True,indent=2)+"\n").encode())
doc=json.loads(read(G/"ARCHIVE.json")[0]);proof=json.loads(read(G/"PACK-READBACK.json")[0])
need(proof["status"]=="ALL_ORIGINALS_FULL_BYTE_AND_TYPED_METADATA_PASS" and proof["all_members_and_originals_full_read"] is True and proof["carrier_reverse_bytes_equal"] is True,"prior full archive readback")
raw,ap=read(doc["archive"]["path"]);need(ap==doc["archive"],"held archive unchanged")
blocks=[]
for row in doc["parts"]:
 b,q=read(G/row["path"]);need(all(q[k]==row[k] for k in ("bytes","sha256","git_blob_sha1")),"full carrier")
 block=base64.b64decode(b,validate=False);need(len(block)==row["raw_bytes"] and hashlib.sha256(block).hexdigest()==row["raw_sha256"],"carrier decode")
 need(row["offset"]==sum(len(x) for x in blocks),"ordinal offsets");blocks.append(block)
need(b"".join(blocks)==raw,"complete exact existing archive reverse")
save(G/"FINISH-INDEX.py",read(__file__)[0])
fix=js(G/"INDEX-CORRECTION.json",dict(schema="hia.fixed-word-reads.index-correction.v1",status="METADATA_ONLY_INDEX_COMPLETED",old_pack_job="1a1d45d6a76-392-38d",old_pack_rc=1,cause="dict(path=relative, **q) duplicates q.path after archive and all member readback had passed",old_failure_record="PACK-INDEX-FAILURE.original.json",fix="Use separate relative and absolute path fields in FILES entries",archive_repacked=False,source_or_qualifications_reexecuted=False,held_archive=ap,complete_40_carriers_reversed=True,prior_full_typed_body_readback="PACK-READBACK.json"))
files=[]
for p in sorted(G.rglob("*")):
 if p.is_file():
  b,q=read(p);files.append(dict(relative=p.relative_to(G).as_posix(),**q))
plan=js(ROOT/"FILES.json",dict(schema="hia.fixed-word-reads.evidence-publication-files.v2",base_commit="784622590d079083a374ca534273ba17db28ff8b",prefix="experiments/hia_core_fixed_word_reads_20261113/source4-source6-derive8-actual-r1",files=files,index_correction=fix))
print(json.dumps(dict(status="METADATA_ONLY_INDEX_COMPLETED",archive_bytes=len(raw),archive_sha256=ap["sha256"],git_files=len(files),files_plan=plan),sort_keys=True))
