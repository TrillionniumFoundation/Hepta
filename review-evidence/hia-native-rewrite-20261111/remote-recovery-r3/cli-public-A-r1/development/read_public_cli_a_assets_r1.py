"""Reuse exact completed CLI/A native assets after complete archive readback.

No old test or project module is executed by this reader. Every nested tar
member is streamed against its immutable ledger. Only selected source, image,
manifest and input files are retained. Case counts are never inherited.
"""
from pathlib import Path,PurePosixPath
from hashlib import sha256
import argparse,json,re,shutil,stat,tarfile,traceback,zlib

PINS={
 "cli":dict(run=43115476503,artifact=13899330292,scope="cli-independent-entry-errno-ack-r5",
    bytes=6712968,sha256="abcd4411cf5fea4c26deb392471fed1dffc4581ce53fa38f062d4ba40ef4258f",
    member_index_bytes=624748,member_index_sha256="096cdf766094d0768f04da1abe641f7002daf486dd6c366713614c75f33bcaa7",
    members=1453,original_bytes=56079779),
 "a75":dict(run=43122922476,artifact=13902950213,scope="real-A-service-fixed-carrier-integration",
    bytes=495911716,sha256="e754ac28c5a5117cb02bc0fdd5f82b541f5c6d9bae91247b3ca173cc6d54f43d",
    member_index_bytes=936594,member_index_sha256="b8e44fd84f56e28bcab73bb96a589ceb739669f9df8d0aca55be83a1e7d6eefc",
    members=1823,original_bytes=1441424405)}
BUILD="cli/project/development/entry-independent-ci-build-r1"
ACTUAL="program-integration/workspace/native-cli-program-service-integration-r1/development/actual-r1"
COMPILER="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
def digest(raw):return sha256(raw).hexdigest()
def hash_file(path):
    h=sha256()
    with path.open("rb") as stream:
        for raw in iter(lambda:stream.read(1<<20),b""):h.update(raw)
    return h.hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def safe(name):
    p=PurePosixPath(name)
    assert name and not p.is_absolute() and ".." not in p.parts and "\\" not in name and "\0" not in name,name
def selected(label,name):
    if label=="cli":
        return name.startswith(BUILD+"/frozen/") or name in (
            BUILD+"/bundle.json",BUILD+"/summary.json",BUILD+"/cli-entry.manifest.json")
    return (name.startswith(ACTUAL+"/frozen/")
        or name.startswith(ACTUAL+"/compiles/finite-packer/")
        or name.startswith(ACTUAL+"/oracle/")
        or name in [ACTUAL+"/"+n for n in ("summary.json","actual-service-bundle.json",
                    "source-pins.json","prefix.bin","layout.json","composition.json","compiles.json")]
        or name.startswith("program-integration/assets/components/")
        or name.startswith("program-service/"))
def original_name(path):
    path=str(path)
    if "/native-hia-cli-next/" in path:
        return "cli/project/"+path.split("/native-hia-cli-next/",1)[1]
    if "/program-integration-recovery/" in path:
        return "program-integration/"+path.split("/program-integration-recovery/",1)[1]
    if "/native-program-service-root-r1/" in path:
        return "program-service/"+path.split("/native-program-service-root-r1/",1)[1]
    raise AssertionError(("unmapped original path",path))
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--download-dir",required=True,type=Path)
    ap.add_argument("--out",required=True,type=Path)
    a=ap.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    report=dict(status="FAIL",new_native_entries=0,old_case_counts_inherited=False,archives={})
    before={};inventory={}
    try:
        for label,pin in PINS.items():
            options=list((a.download_dir/label).rglob("evidence.tar.xz"))
            assert len(options)==1,(label,options)
            archive=options[0];index=archive.with_name("evidence-members.json")
            custody=archive.with_name("custody.json")
            before[archive]=(archive.stat().st_size,hash_file(archive))
            before[index]=(index.stat().st_size,hash_file(index))
            before[custody]=(custody.stat().st_size,hash_file(custody))
            assert before[archive]==(pin["bytes"],pin["sha256"])
            assert before[index]==(pin["member_index_bytes"],pin["member_index_sha256"])
            original=json.loads(custody.read_bytes())
            # CLI's exact historical scope is retained verbatim; its bytes and
            # ledger are independently fixed above rather than inferred from it.
            for key in ("bytes","sha256","member_index_bytes","member_index_sha256","members","original_bytes"):
                assert original[key]==pin[key],(label,key)
            assert original["status"]=="PASS"
            assert original["scope"]==pin["scope"]
            assert original["all_original_and_tar_member_bytes_sha256_modes_readback"] is True
            rows=json.loads(index.read_bytes());wanted={r["name"]:r for r in rows}
            assert len(rows)==len(wanted)==pin["members"]
            assert sum(row["bytes"] for row in rows)==pin["original_bytes"]
            seen=set();verified=[];cas_rows=[];kept=[];total=0
            with tarfile.open(archive,"r|xz") as tf:
                for item in tf:
                    safe(item.name)
                    assert item.isfile() and not item.issym() and not item.islnk()
                    assert item.name not in seen and item.name in wanted
                    row=wanted[item.name]
                    assert (item.size,stat.S_IMODE(item.mode))==(row["bytes"],row["mode"])
                    target=out/"restored"/item.name if selected(label,item.name) else None
                    if target:target.parent.mkdir(parents=True,exist_ok=True)
                    writer=target.open("xb") if target else None
                    match=re.fullmatch(r"([0-9a-f]{64})\.(zlib|gz)",PurePosixPath(item.name).name)
                    decoder=zlib.decompressobj(31 if match and match[2]=="gz" else 15) if match else None
                    h=sha256();logical=sha256();count=logical_bytes=0
                    try:
                        with tf.extractfile(item) as stream:
                            for chunk in iter(lambda:stream.read(1<<20),b""):
                                h.update(chunk);count+=len(chunk)
                                if writer:writer.write(chunk)
                                if decoder:
                                    remaining=chunk
                                    while remaining:
                                        raw=decoder.decompress(remaining,1<<20)
                                        logical.update(raw);logical_bytes+=len(raw)
                                        remaining=decoder.unconsumed_tail
                                    while True:
                                        raw=decoder.decompress(b"",1<<20)
                                        if not raw:break
                                        logical.update(raw);logical_bytes+=len(raw)
                            if decoder:
                                raw=decoder.flush();logical.update(raw);logical_bytes+=len(raw)
                                assert decoder.eof and not decoder.unused_data
                                assert logical.hexdigest()==match[1],item.name
                                cas_rows.append(dict(name=item.name,bytes=logical_bytes,sha256=logical.hexdigest()))
                    finally:
                        if writer:writer.close()
                    assert (count,h.hexdigest())==(row["bytes"],row["sha256"]),item.name
                    seen.add(item.name);total+=count;verified.append(row)
                    if target:
                        assert (target.stat().st_size,hash_file(target))==(count,row["sha256"])
                        target.chmod(0o444)
                        inventory[item.name]=dict(path=str(target),bytes=count,sha256=row["sha256"],
                                                  original_mode=row["mode"],local_mode=0o444)
                        kept.append(item.name)
            assert seen==set(wanted) and total==pin["original_bytes"]
            dest=out/"original-ledgers"/label;dest.mkdir(parents=True)
            for path in (index,custody):
                raw=path.read_bytes();(dest/path.name).write_bytes(raw)
                assert (len(raw),digest(raw))==before[path]
            save(dest/"verified-members.json",verified);save(dest/"cas-readback.json",cas_rows)
            report["archives"][label]=dict(pin,actual_original_scope=original["scope"],
                verified_members=len(seen),verified_original_bytes=total,selected_members=len(kept),
                decoded_CAS_objects=len(cas_rows),decoded_CAS_bytes=sum(x["bytes"] for x in cas_rows),
                complete_original_archive=True,old_native_tests_rerun=0)
            print("HIA_CLI_A_ASSET_ARCHIVE "+json.dumps(report["archives"][label],sort_keys=True),flush=True)
        def read(name):
            assert name in inventory,("not selected",name)
            row=inventory[name];raw=Path(row["path"]).read_bytes()
            assert (len(raw),digest(raw))==(row["bytes"],row["sha256"])
            return raw
        def record(name):read(name);return inventory[name]
        def json_at(name):return json.loads(read(name))
        def bound(source,image,expected_source,expected_image,source_bytes=None,image_bytes=None):
            s=record(source);i=record(image)
            assert s["sha256"]==expected_source and i["sha256"]==expected_image
            if source_bytes is not None:assert s["bytes"]==source_bytes
            if image_bytes is not None:assert i["bytes"]==image_bytes
            return dict(source=s,image=i)
        cli=json_at(BUILD+"/bundle.json");cli_roles={}
        assert cli["scope"]=="DEVELOPMENT_COMPONENT_SLICE_NOT_INSTALLED_NOT_COLD"
        for role in range(1,7):
            component=cli["components"][str(role)]
            mname=original_name(component["manifest"]["copy"]);manifest=json_at(mname)
            sname=original_name(component["source"]["copy"]);iname=original_name(component["image"]["copy"])
            for kind,name in (("manifest",mname),("source",sname),("image",iname)):
                row=component[kind];assert (len(read(name)),digest(read(name)))==(row["bytes"],row["sha256"])
            cli_roles[str(role)]=bound(sname,iname,manifest["source_sha256"],manifest["image_sha256"])
            cli_roles[str(role)]["manifest"]=record(mname)
        summary=json_at(ACTUAL+"/summary.json")
        assert summary["status"]=="PASS" and summary["source_pins_unchanged"]
        assert (summary["cases"],summary["native_processes"])==(75,75)
        roles=json_at(ACTUAL+"/frozen/reference/program-roles.json")["components"]
        service_roles={}
        for role in list(range(1,56))+[58]:
            pin=roles[str(role)]
            service_roles[str(role)]=bound(ACTUAL+"/frozen/issued-roles/"+str(role)+"/source.hiaasm",
                ACTUAL+"/frozen/issued-roles/"+str(role)+"/image.bin",
                pin["source_sha256"],pin["image_sha256"],pin["source_bytes"],pin["image_bytes"])
        issued=json_at(ACTUAL+"/actual-service-bundle.json")
        for label,pin in issued["assets"].items():
            role=str(pin["role"])
            service_roles[role]=bound(original_name(pin["source_path"]),original_name(pin["image_path"]),
                pin["source_sha256"],pin["image_sha256"],pin["source_bytes"],pin["image_bytes"])
        root=issued["root"];assert root["actual_native_B3"] is True and root["compiler_sha256"]==COMPILER
        service_roles["56"]=bound(original_name(root["source_path"]),original_name(root["image_path"]),
            root["source_sha256"],root["image_sha256"],root["source_bytes"],root["image_bytes"])
        assert set(issued["assets"])=={"wire-scan","wire-emit","projector"}
        assert set(service_roles)=={str(i) for i in list(range(1,57))+[58,60]}
        pm=json_at(ACTUAL+"/compiles/finite-packer/manifest.json")
        packer=bound(ACTUAL+"/compiles/finite-packer/source.hiaasm",original_name(pm["path"]),
                     pm["source_sha256"],pm["image_sha256"],image_bytes=pm["image_bytes"])
        receipt=pm["receipt"]
        assert receipt["artifact_sha256"]==COMPILER
        assert receipt["input_sha256"]==packer["source"]["sha256"]
        assert receipt["produced_sha256"]==packer["image"]["sha256"]
        assert receipt["status"]=="returned" and receipt["abi_status"]==0
        assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
        packer.update(manifest=record(ACTUAL+"/compiles/finite-packer/manifest.json"),
                      prefix=record(ACTUAL+"/prefix.bin"),layout=record(ACTUAL+"/layout.json"),
                      assembly=record(ACTUAL+"/frozen/authoring/cli_business_executor.S"))
        assert packer["assembly"]["sha256"]=="f06b915cdfb415894e05c8c4a3e7bbdba9fe9c0bc5b8791878516f91cdfa66de"
        layout=json_at(ACTUAL+"/layout.json")
        assert (layout["prefix_bytes"],layout["prefix_sha256"])==(packer["prefix"]["bytes"],packer["prefix"]["sha256"])
        oracle=json_at(ACTUAL+"/oracle/summary.json")
        assert (oracle["inputs"],oracle["accepted"],oracle["rejected"])==(25,17,8)
        inputs=[]
        for row in oracle["rows"]:
            pin=record(ACTUAL+"/oracle/"+row["label"]+"/input.bin")
            assert (pin["bytes"],pin["sha256"])==(row["input_bytes"],row["input_sha256"])
            inputs.append(dict(label=row["label"],accepted=row["accepted"],input=pin))
        assert len(inputs)==25 and len({r["label"] for r in inputs})==25
        compiler=record(ACTUAL+"/frozen/compiler/B3.image.bin")
        assert (compiler["bytes"],compiler["sha256"])==(669556,COMPILER)
        assert all((p.stat().st_size,hash_file(p))==v for p,v in before.items())
        report.update(status="PASS_READBACK_ONLY",source_image_bindings=True,cli_roles=cli_roles,
            service_roles=service_roles,packer=packer,inputs=inputs,compiler=compiler,
            preserved_original_inputs_unchanged=True,unexecuted_public_parent=True)
        save(out/"selected-member-pins.json",inventory);save(out/"assets.json",report)
        print("HIA_CLI_A_ASSETS_READY "+json.dumps({k:v for k,v in report.items()
            if k not in ("cli_roles","service_roles","packer","inputs")},sort_keys=True),flush=True)
    except BaseException as error:
        report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        save(out/"failed-readback.json",report);raise
if __name__=="__main__":main()
