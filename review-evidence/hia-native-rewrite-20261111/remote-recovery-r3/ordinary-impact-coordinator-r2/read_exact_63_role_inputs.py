"""Read every exact historical candidate member and restore inactive E table.
No historical Python module, native image or old test is executed by this file.
Only complete source/image bytes matching the fixed 63-role manifest are issued.
"""
from pathlib import Path,PurePosixPath
from hashlib import sha1,sha256
import argparse,json,re,stat,tarfile,zlib
PIN=dict(run=43107344619,artifact=13893874697,bytes=20412188,
 sha256="d9790ead23d139bbcbd0f4aef078905ed361775236ecd2376004452684d8ac7e",
 member_index_bytes=336814,member_index_sha256="b04de1534eeb7d4f360d3e82a84dfd98ef6aa42e12f6667b571e62562748087d",
 members=784,original_bytes=158441057,
 outer_bytes=59330856,outer_sha256="17d8c274bc9d66b19e634c6558f18bc429ab119e5da5671f4eff021fdfea60c6")
def digest(raw):return sha256(raw).hexdigest()
def git_blob(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def hash_file(path):
    h=sha256()
    with path.open("rb") as f:
        for block in iter(lambda:f.read(1<<20),b""):h.update(block)
    return h.hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def safe(name):
    path=PurePosixPath(name)
    assert name and not path.is_absolute() and ".." not in path.parts and "\\" not in name and "\0" not in name
def main():
    ap=argparse.ArgumentParser()
    for name in ("download-dir","manifest","workspace","out"):ap.add_argument("--"+name,type=Path,required=True)
    a=ap.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    manifest_raw=a.manifest.read_bytes()
    assert git_blob(manifest_raw)=="35202c1c5961923b60f6100e07fa696e2c8f84a0"
    manifest=json.loads(manifest_raw)
    assert manifest["schema"]=="hia-candidate-snapshot-components-v1"
    assert set(manifest["components"])=={str(i) for i in range(1,64)}
    wanted={}
    for role in (59,60):
        row=manifest["components"][str(role)]
        for kind in ("source","image"):
            identity=(row[kind+"_bytes"],row[kind+"_sha256"])
            assert identity not in wanted
            wanted[identity]=(role,kind)
    archives=list(a.download_dir.rglob("evidence.tar.xz"));assert len(archives)==1
    archive=archives[0];index=archive.with_name("evidence-members.json");custody=archive.with_name("custody.json")
    before={p.resolve():(p.stat().st_size,hash_file(p)) for p in(archive,index,custody,a.manifest)}
    assert before[archive.resolve()]==(PIN["bytes"],PIN["sha256"])
    assert before[index.resolve()]==(PIN["member_index_bytes"],PIN["member_index_sha256"])
    original=json.loads(custody.read_bytes())
    for key in("bytes","sha256","member_index_bytes","member_index_sha256","members","original_bytes"):
        assert original[key]==PIN[key],key
    assert original["status"]=="PASS" and original["all_original_and_tar_member_bytes_sha256_modes_readback"]
    rows=json.loads(index.read_bytes());ledger={r["name"]:r for r in rows}
    assert len(rows)==len(ledger)==PIN["members"] and sum(r["bytes"] for r in rows)==PIN["original_bytes"]
    total=0;seen=set();selected={};decoded=[];restored=[]
    with tarfile.open(archive,"r|xz") as tf:
        for item in tf:
            safe(item.name);assert item.isfile() and not item.issym() and not item.islnk()
            assert item.name not in seen and item.name in ledger
            row=ledger[item.name]
            assert (item.size,stat.S_IMODE(item.mode))==(row["bytes"],row["mode"])
            key=(row["bytes"],row["sha256"]);keep=key in wanted
            match=re.fullmatch(r"([0-9a-f]{64})\.(zlib|gz)",PurePosixPath(item.name).name)
            decoder=zlib.decompressobj(31 if match and match[2]=="gz" else 15) if match else None
            h=sha256();lh=sha256();n=logical=0;chunks=[]
            with tf.extractfile(item) as f:
                for part in iter(lambda:f.read(1<<20),b""):
                    h.update(part);n+=len(part)
                    if keep:chunks.append(part)
                    if decoder:
                        remaining=part
                        while remaining:
                            raw=decoder.decompress(remaining,1<<20)
                            lh.update(raw);logical+=len(raw);remaining=decoder.unconsumed_tail
                        while True:
                            raw=decoder.decompress(b"",1<<20)
                            if not raw:break
                            lh.update(raw);logical+=len(raw)
                if decoder:
                    raw=decoder.flush();lh.update(raw);logical+=len(raw)
                    assert decoder.eof and not decoder.unused_data and lh.hexdigest()==match[1]
                    decoded.append(dict(name=item.name,bytes=logical,sha256=lh.hexdigest()))
            assert (n,h.hexdigest())==key,item.name
            seen.add(item.name);total+=n
            if keep:
                raw=b"".join(chunks);role,kind=wanted[key]
                if (role,kind) in selected:assert selected[(role,kind)]==raw
                else:selected[(role,kind)]=raw
                restored.append(dict(role=role,kind=kind,member=item.name,bytes=n,sha256=h.hexdigest(),mode=row["mode"]))
    assert seen==set(ledger) and total==PIN["original_bytes"]
    assert set(selected)=={(r,k) for r in(59,60) for k in("source","image")}
    current={}
    for role in range(1,64):
        row=manifest["components"][str(role)]
        for kind,filename in (("source","source.hiaasm"),("image","image.bin")):
            expected=(row[kind+"_bytes"],row[kind+"_sha256"])
            if role in(59,60):
                raw=selected[(role,kind)];origin="EXACT_ALL_MEMBER_VERIFIED_CANDIDATE_ARCHIVE"
            else:
                candidates=row.get(kind+"_frozen_copies",[])+[row[kind+"_path"]]
                mapped=[]
                for name in candidates:
                    marker="/root-recovery/workspace/"
                    assert marker in name,name
                    path=a.workspace/str(name).split(marker,1)[1]
                    if path not in mapped:mapped.append(path)
                existing=[p for p in mapped if p.is_file() and not p.is_symlink()]
                assert existing,("missing exact common restored component",role,kind,list(map(str,mapped)))
                raw=existing[0].read_bytes();assert (len(raw),digest(raw))==expected,(role,kind,existing[0])
                for path in existing:
                    assert path.read_bytes()==raw
                    before[path.resolve()]=(len(raw),digest(raw))
                origin=str(existing[0])
            assert (len(raw),digest(raw))==expected,(role,kind)
            target=out/"roles"/str(role)/filename;target.parent.mkdir(parents=True,exist_ok=True)
            with target.open("xb") as f:f.write(raw)
            assert target.read_bytes()==raw;target.chmod(0o444)
            current[str(role)+":"+kind]=dict(path=str(target),bytes=len(raw),sha256=digest(raw),origin=origin)
    for path,pin in before.items():assert (path.stat().st_size,hash_file(path))==pin,path
    (out/"original-members.json").write_bytes(index.read_bytes())
    (out/"original-custody.json").write_bytes(custody.read_bytes())
    (out/"original-role-map.json").write_bytes(manifest_raw)
    save(out/"all-member-readback.json",dict(pin=PIN,complete_members=len(seen),original_bytes=total,
        cas=decoded,selected_aliases=restored,original_scope=original.get("scope")))
    result=dict(status="PASS_READBACK_ONLY",scope="INACTIVE_EXACT_63_ROLE_TABLE_DEPENDENCY",
        complete_archive_members=len(seen),complete_archive_bytes=total,roles=63,resources=current,
        all_sources_and_images_bound=True,old_counts_inherited=False,new_native_entries=0,
        E_runtime_qualified=False,assembly_qualified=False,originals_unchanged=True)
    save(out/"summary.json",result)
    print("HIA_ASSEMBLY_INACTIVE_TABLE_READY "+json.dumps({k:v for k,v in result.items() if k!="resources"},sort_keys=True),flush=True)
if __name__=="__main__":main()
