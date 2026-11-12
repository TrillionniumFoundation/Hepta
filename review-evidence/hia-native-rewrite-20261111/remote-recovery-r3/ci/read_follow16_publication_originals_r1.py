"""Read exact follow16 publication/Path originals; zero native execution."""
from pathlib import Path,PurePosixPath
from hashlib import sha256
import argparse,base64,json,re,stat,tarfile,traceback,zlib
PINS={
 "fixedpub":dict(artifact=13903118353,run=43126608841,scope="cli-fixed-publication-native-r2",
  bytes=8400300,sha256="9ae45efdea3a86d0a8a2743619d34969a880e3445588b4e884c4ed412a5d8df2",
  member_index_bytes=296223,member_index_sha256="ee3ada1d50fe7be70baa0ed9bcbd3395e6c320e73a17d4676c35d776bb6ffdd2",
  members=716,original_bytes=108624176,summary="fixed-publication-raw/summary.json"),
 "path":dict(artifact=13903841421,run=43126608841,scope="cli-publication-path-prefix-r1",
  bytes=5495984,sha256="2f5e19b992d2f170ae79a2317be2f772b1f91064418a40d16434396d7b460a7f",
  member_index_bytes=541445,member_index_sha256="98ac34387292279a0776a35685c9f926c6572ff8537013cac0fd759659463aad",
  members=1193,original_bytes=41374049,summary="path-raw/summary.json")}
def hash_file(p):
    h=sha256()
    with p.open("rb") as f:
        for raw in iter(lambda:f.read(1<<20),b""):h.update(raw)
    return h.hexdigest()
def save(p,value):p.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--downloads",type=Path,required=True);ap.add_argument("--out",type=Path,required=True)
    a=ap.parse_args();a.out.mkdir(parents=True,exist_ok=False);result=dict(status="FAIL",native_entries=0,archives={})
    try:
        for label,pin in PINS.items():
            matches=list((a.downloads/label).rglob("evidence.tar.xz"));assert len(matches)==1,matches
            archive=matches[0];index=archive.with_name("evidence-members.json");custody=archive.with_name("custody.json")
            before={p:(p.stat().st_size,hash_file(p)) for p in (archive,index,custody)}
            assert before[archive]==(pin["bytes"],pin["sha256"])
            assert before[index]==(pin["member_index_bytes"],pin["member_index_sha256"])
            cr=json.loads(custody.read_bytes());assert cr["status"]=="PASS" and cr["scope"]==pin["scope"]
            for key in ("bytes","sha256","member_index_bytes","member_index_sha256","members","original_bytes"):assert cr[key]==pin[key]
            assert cr["all_original_and_tar_member_bytes_sha256_modes_readback"] is True
            ledger=json.loads(index.read_bytes());wanted={x["name"]:x for x in ledger};assert len(wanted)==len(ledger)==pin["members"]
            assert sum(x["bytes"] for x in ledger)==pin["original_bytes"]
            seen=set();total=0;cas=[];reports={}
            dest=a.out/label;dest.mkdir();(dest/"originals").mkdir()
            with tarfile.open(archive,"r|xz") as tf:
                for item in tf:
                    name=item.name;p=PurePosixPath(name)
                    assert name and not p.is_absolute() and ".." not in p.parts and "\\" not in name and "\0" not in name
                    assert item.isfile() and not item.issym() and not item.islnk() and name not in seen
                    row=wanted[name];assert (item.size,stat.S_IMODE(item.mode))==(row["bytes"],row["mode"])
                    match=re.fullmatch(r"([0-9a-f]{64})\.(zlib|gz)",p.name)
                    dec=zlib.decompressobj(31 if match and match[2]=="gz" else 15) if match else None
                    decoded=sha256();logical=0;h=sha256();size=0
                    capture=(name==pin["summary"] or name.endswith(("/source-pins.json","/profile.json",
                        "/manifest.json","/source-before.json","/source-after.json","/cas-index.json")))
                    keep=bytearray() if capture else None
                    with tf.extractfile(item) as f:
                        for chunk in iter(lambda:f.read(1<<20),b""):
                            h.update(chunk);size+=len(chunk)
                            if keep is not None:keep.extend(chunk)
                            if dec:
                                pending=chunk
                                while pending:
                                    raw=dec.decompress(pending,1<<20);decoded.update(raw);logical+=len(raw);pending=dec.unconsumed_tail
                                while True:
                                    raw=dec.decompress(b"",1<<20)
                                    if not raw:break
                                    decoded.update(raw);logical+=len(raw)
                        if dec:
                            raw=dec.flush();decoded.update(raw);logical+=len(raw)
                            assert dec.eof and not dec.unused_data and decoded.hexdigest()==match[1]
                            cas.append(dict(name=name,bytes=logical,sha256=decoded.hexdigest()))
                    assert (size,h.hexdigest())==(row["bytes"],row["sha256"]),name
                    seen.add(name);total+=size
                    if keep is not None:
                        target=dest/"originals"/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(keep)
                        assert (target.stat().st_size,hash_file(target))==(size,row["sha256"])
                        reports[name]=json.loads(keep)
                        if name==pin["summary"] or name.endswith(("/source-pins.json","/profile.json","/manifest.json")):
                            raw=bytes(keep)
                            for offset in range(0,len(raw),18000):
                                print("HIA_EXACT_PUBLICATION_ORIGINAL "+json.dumps(dict(label=label,name=name,
                                    bytes=len(raw),sha256=h.hexdigest(),offset=offset,
                                    base64=base64.b64encode(raw[offset:offset+18000]).decode()),sort_keys=True),flush=True)
            assert seen==set(wanted) and total==pin["original_bytes"]
            actual=reports[pin["summary"]];assert actual["status"]=="PASS" and actual["source_pins_unchanged"]
            assert actual["cas_readback"]["status"]=="PASS"
            if label=="fixedpub":
                assert tuple(actual[k] for k in ("publication_cases","utility_cases","private_controls",
                    "native_processes","native_packer_entries"))==(24,2,17,43,20)
                assert actual["all_22_fs_kinds_executed"] and actual["fd_zero_open_and_close_exact"]
                assert actual["sparse_live_fd_table_growth_executed"] and actual["original_finite_service_child_body_exact"]
                public=actual["cases"];assert len(public)==24
                for key,offset in (("publication_actual_hia_calls",2),("publication_actual_fs_calls",3),
                                   ("publication_actual_hash_calls",4)):
                    assert actual[key]==sum(x["actual"]["telemetry"][offset] for x in public)
                counts={k:actual[k] for k in ("publication_cases","utility_cases","private_controls",
                    "native_processes","native_packer_entries","publication_actual_hia_calls",
                    "publication_actual_fs_calls","publication_actual_hash_calls")}
            else:
                assert (actual["cases"],actual["private_controls"])==(26,10)
                assert actual["native_entries"]>0 and actual["actual_fs_syscalls"]>0
                counts={k:actual[k] for k in ("cases","private_controls","native_entries","actual_fs_syscalls",
                    "source_sha256","image_sha256","profile")}
            assert all((p.stat().st_size,hash_file(p))==v for p,v in before.items())
            save(dest/"verified-members.json",ledger);save(dest/"CAS-readback.json",cas)
            save(dest/"original-custody.json",cr)
            result["archives"][label]=dict(pin,verified_members=len(seen),verified_original_bytes=total,
                decompressed_CAS_objects=len(cas),decompressed_CAS_bytes=sum(x["bytes"] for x in cas),
                source_pins_original_true=True,counts=counts,zero_new_execution=True)
        result["status"]="PASS_READBACK_ONLY"
        print("HIA_PUBLICATION_FOLLOW16_READBACK "+json.dumps(result,sort_keys=True),flush=True)
    except BaseException:
        result["failure"]=traceback.format_exc();raise
    finally:save(a.out/"summary.json",result)
if __name__=="__main__":main()
