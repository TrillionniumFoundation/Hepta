"""Seal all closed nine-role build/failure and DB alpha raw records; zero target entries."""
from __future__ import annotations
import hashlib,json,lzma,stat,tarfile,time
from pathlib import Path
OUT=Path(__file__).resolve().parent
ROOTS={
 "nine-role-local-r4":Path("/workspace/scratch/9acdfa9f5639/runtime-development/nine-role-local-r4"),
 "DB-alpha-all-attempts":Path("/dev/shm/hia-namespace-db-alpha-development-r1"),
 "token-and-trace-proof":Path("/workspace/scratch/9acdfa9f5639/runtime-development/nine-repair-proofs-r3"),
 "derived-observation":OUT}
EXCLUDE={"all-closed-local-raw.tar.xz","members.json","custody.json","seal.stdout","seal.stderr","seal.process.json"}
def dig(path):
 h=hashlib.sha256();s=hashlib.sha1();n=path.stat().st_size;s.update(b"blob "+str(n).encode()+b"\0")
 with path.open("rb") as f:
  while b:=f.read(1<<20):h.update(b);s.update(b)
 return dict(bytes=n,sha256=h.hexdigest(),gitsha=s.hexdigest())
def main():
 started=time.monotonic_ns();rows=[];sources={}
 for label,root in ROOTS.items():
  for p in sorted(root.rglob("*")):
   rel=p.relative_to(root)
   if root==OUT and str(rel) in EXCLUDE:continue
   st=p.lstat()
   if stat.S_ISDIR(st.st_mode):continue
   assert stat.S_ISREG(st.st_mode) and not p.is_symlink(),str(p)
   name=label+"/"+str(rel)
   row=dict(path=name,mode=stat.S_IMODE(st.st_mode),**dig(p))
   rows.append(row);sources[name]=p
 rows.sort(key=lambda x:x["path"])
 archive=OUT/"all-closed-local-raw.tar.xz";assert not archive.exists()
 with lzma.open(archive,"wb",filters=[{"id":lzma.FILTER_LZMA2,"preset":3,"dict_size":32<<20}]) as f,tarfile.open(fileobj=f,mode="w|") as tf:
  for r in rows:
   t=tarfile.TarInfo(r["path"]);t.size=r["bytes"];t.mode=r["mode"];t.mtime=0
   with sources[r["path"]].open("rb") as p:tf.addfile(t,p)
 archive.chmod(0o644)
 seen=[]
 with tarfile.open(archive,"r:xz") as tf:
  for m,e in zip(tf,rows,strict=True):
   assert m.isfile() and (m.name,m.size,m.mode)==(e["path"],e["bytes"],e["mode"])
   f=tf.extractfile(m);h=hashlib.sha256();s=hashlib.sha1();s.update(b"blob "+str(m.size).encode()+b"\0");n=0
   while b:=f.read(1<<20):h.update(b);s.update(b);n+=len(b)
   assert (n,h.hexdigest(),s.hexdigest())==(e["bytes"],e["sha256"],e["gitsha"])
   p=sources[m.name];assert stat.S_IMODE(p.stat().st_mode)==e["mode"] and dig(p)=={k:e[k] for k in ["bytes","sha256","gitsha"]}
   seen.append(m.name)
 assert len(seen)==len(rows)==len(set(seen))
 raw=(json.dumps(rows,sort_keys=True,indent=2)+"\n").encode();(OUT/"members.json").write_bytes(raw);assert (OUT/"members.json").read_bytes()==raw
 receipt=dict(status="PASS_COMPLETE_LOCAL_MEMBER_READBACK",scope="ARCHIVE_ONLY_ORIGINAL_TARGET_FAILURES_UNCHANGED",
  archive=dict(path=str(archive),mode=0o644,**dig(archive)),members=len(rows),raw_bytes=sum(x["bytes"] for x in rows),
  exact_labels=list(ROOTS),all_original_files_after_equal=True,whole_group_pass_claimed=False,
  nine_build_PASS=True,nine_raw_prefix_CPU_FAIL=True,db_alpha_r1_fixture_FAIL_preserved=True,db_alpha_r2_PASS=True,
  target_entries=0,elapsed_ns=time.monotonic_ns()-started)
 raw=(json.dumps(receipt,sort_keys=True,indent=2)+"\n").encode();(OUT/"custody.json").write_bytes(raw);assert (OUT/"custody.json").read_bytes()==raw
 print(json.dumps(receipt,sort_keys=True),flush=True)
if __name__=="__main__":main()
