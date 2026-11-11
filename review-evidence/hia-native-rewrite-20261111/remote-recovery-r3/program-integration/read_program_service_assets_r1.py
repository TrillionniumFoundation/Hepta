"""Verify complete original archives before reusing native component bytes.
No previous case count is added to the new A integration. All byte inventories,
original status and original raw archives remain available with the new evidence.
"""
from pathlib import Path,PurePosixPath
from hashlib import sha256
import argparse,json,stat,tarfile,shutil

ARCHIVES={
 "wire":dict(run=43101326649,artifact=13892287301,status="FAIL",
  scope="cli-independent-reconstruction-r1",bytes=7522140,
  sha256="6d03b8ae26f437d3474ba169e0daa8a1561421474ed3ff447d72f52f2ed891e1",
  member_index_bytes=2985474,member_index_sha256="7b0c0055e6db85a921d7f70a48af11e880a5d238bdfd7ced81e42e5b4dc26b1a",
  members=6053,original_bytes=60723728),
 "projector":dict(run=43109366132,artifact=13895662425,status="PASS",
  scope="private-program-projection",bytes=13408788,
  sha256="a8a3ead4f59891a21d29a812523495c69acb43dc6ff062e079fd15f6db036b67",
  member_index_bytes=727912,member_index_sha256="7dd4a5b4319455af8879eef309cb0358ab8c1888b2b262169c021f6df597d0bd",
  members=1498,original_bytes=54789264)}
COMPONENTS={
 "wire-scan":dict(archive="wire",role=29,
  manifest="cli/project/development/cli-wire-reconstructed-compile-r1/scan.manifest.json",
  source_sha256="7ac81329c5bcaea0bfd4a2a31f9efdfb1d24590307ec90fa72250371b16f3d2e",
  image_sha256="bbd4d6c19b3159c3a64c5be4e2f77a943eb057696fe00ded55e8b4bd70a5e4c4"),
 "wire-emit":dict(archive="wire",role=30,
  manifest="cli/project/development/cli-wire-reconstructed-compile-r1/emit.manifest.json",
  source_sha256="1eb4e4236a7caf222254f3d10d510bf650074ce666ddf68f7423a374245e05ea",
  image_sha256="9498c83fab2af063bfa15ebee750b60bae9aa1ad21e03443f788891b69d054fd"),
 "projector":dict(archive="projector",role=60,
  manifest="program/development/compile-r1/program-inspection.manifest.json",
  source_bytes=180552,source_sha256="75f3ebda87bf907d89ab35936ff08d54e07fc738b24a288e31ed86c91423d358",
  image_bytes=253808,image_sha256="2378e3cf8ef742eae5dbd03a633e96311cf2828e0c175bdec7227d03b794d714")}
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--download-dir",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args()
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    retained={};before={};reports={}
    for label,expected in ARCHIVES.items():
        candidates=list((args.download_dir/label).rglob("evidence.tar.xz"))
        assert len(candidates)==1,(label,candidates)
        archive=candidates[0];index=archive.with_name("evidence-members.json");custody=archive.with_name("custody.json")
        ar=archive.read_bytes();ir=index.read_bytes();cr=custody.read_bytes()
        before.update({archive:ar,index:ir,custody:cr})
        assert (len(ar),digest(ar))==(expected["bytes"],expected["sha256"])
        assert (len(ir),digest(ir))==(expected["member_index_bytes"],expected["member_index_sha256"])
        outer=json.loads(cr);ledger=json.loads(ir)
        for key in ("status","scope","bytes","sha256","member_index_bytes","member_index_sha256","members","original_bytes"):
            assert outer[key]==expected[key],(label,key,outer[key],expected[key])
        assert outer["all_original_and_tar_member_bytes_sha256_modes_readback"] is True
        wanted={r["name"]:r for r in ledger};assert len(wanted)==len(ledger)==expected["members"]
        actual=set();total=0;selected={};verified=[]
        with tarfile.open(archive,"r:xz") as tf:
            for member in tf:
                path=PurePosixPath(member.name)
                assert member.isfile() and not member.issym() and not member.islnk()
                assert not path.is_absolute() and ".." not in path.parts
                assert member.name not in actual and member.name in wanted
                raw=tf.extractfile(member).read();row=wanted[member.name]
                assert (len(raw),digest(raw),stat.S_IMODE(member.mode))==(row["bytes"],row["sha256"],row["mode"]),(label,member.name)
                actual.add(member.name);total+=len(raw);verified.append(row)
                if ("/cli-wire-reconstructed-compile-r1/" in member.name
                    or "/cli_graph_json_wire_" in member.name
                    or member.name.startswith("program/development/compile-r1/")
                    or member.name=="program/examples/hia_bootstrap/program_inspection.hiaasm"):
                    selected[member.name]=raw
        assert actual==set(wanted) and total==expected["original_bytes"]
        retained[label]=selected
        preserved=out/"preserved-original"/label;preserved.mkdir(parents=True)
        for path,raw in ((archive,ar),(index,ir),(custody,cr)):
            (preserved/path.name).write_bytes(raw)
        save(preserved/"verified-members.json",verified)
        reports[label]=dict(expected,complete_members_verified=len(actual),complete_member_bytes_verified=total,
            native_entries=0,original_overall_status_preserved=expected["status"])
    components={}
    for label,pin in COMPONENTS.items():
        raw=retained[pin["archive"]][pin["manifest"]];manifest=json.loads(raw)
        dest=out/"components"/label;dest.mkdir(parents=True)
        (dest/"original-manifest.json").write_bytes(raw)
        if pin["archive"]=="wire":
            prefix="cli/project/";cut="/native-hia-cli-next/"
        else:
            prefix="program/";cut="/native-program-service-reconstructed-r1/"
        for kind,suffix in (("source",".hiaasm"),("image",".bin")):
            old=manifest[kind+"_path"];assert old.count(cut)==1,old
            name=prefix+old.split(cut,1)[1]
            data=retained[pin["archive"]][name]
            assert digest(data)==pin[kind+"_sha256"]==manifest[kind+"_sha256"]
            assert len(data)==manifest[kind+"_bytes"]
            if kind+"_bytes" in pin:assert len(data)==pin[kind+"_bytes"]
            path=dest/(kind+suffix);path.write_bytes(data);path.chmod(0o444)
            components.setdefault(label,dict(role=pin["role"],original_manifest=pin["manifest"],original_archive=pin["archive"]))
            components[label].update({kind+"_path":str(path),kind+"_bytes":len(data),kind+"_sha256":digest(data),kind+"_member":name})
        assert manifest["compiler_sha256"]=="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
        receipt=manifest.get("receipt")
        if receipt is None:
            rp=prefix+manifest["receipt_path"].split(cut,1)[1]
            receipt_raw=retained[pin["archive"]][rp];(dest/"original-receipt.json").write_bytes(receipt_raw)
            receipt=json.loads(receipt_raw)
        else:save(dest/"original-receipt.json",receipt)
        assert receipt["artifact_sha256"]==manifest["compiler_sha256"]
        assert receipt["input_sha256"]==components[label]["source_sha256"]
        assert receipt["produced_sha256"]==components[label]["image_sha256"]
        assert receipt["status"]=="returned" and receipt["abi_status"]==0
        assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
    assert all(p.read_bytes()==raw for p,raw in before.items())
    result=dict(status="PASS_READBACK_ONLY",scope="EXACT_ORIGINAL_COMPONENT_BYTE_REUSE",
        archives=reports,components=components,original_source_unchanged=True,
        new_B3_compilations=0,new_native_entries=0,inherited_case_counts=False)
    save(out/"assets.json",result)
    print("HIA_A_ASSET_READBACK "+json.dumps(result,sort_keys=True),flush=True)
if __name__=="__main__":main()
