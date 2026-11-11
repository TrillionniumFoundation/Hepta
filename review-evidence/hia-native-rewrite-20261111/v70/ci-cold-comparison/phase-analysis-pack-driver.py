import hashlib,json,pathlib,sys,zipfile,zlib
base=pathlib.Path("/home/qq/hia-native-self-rewrite-20261111-dda7")
root=base/"ci-cold-phase-analysis-v70-r1"
output=root/"transfer-r1";output.mkdir(mode=0o700)
manifest=json.loads((root/"results.json").read_text())
packet={"schema":"hia.ci.original-cold-phase-analysis-transfer.v1","reports":[],"original_phase_files":[],"qualification":False}
overview=[]
for item in manifest:
    path=pathlib.Path(item["report_path"]);raw=path.read_bytes()
    if len(raw)!=item["bytes"] or hashlib.sha256(raw).hexdigest()!=item["sha256"]:raise ValueError("analysis identity changed")
    data=json.loads(raw)
    packet["reports"].append({"label":item["label"],"path":str(path),"bytes":len(raw),"sha256":item["sha256"],"content":raw.decode("utf-8")})
    original_archive={"673-push":base/"ci-673-cold-artifact-v70-r1/original-artifact-13894877342.zip","8aade-push":base/"ci-cold-comparison-v70-r1/original-8aade-push/original-artifact-13891487322.zip","673-pr-merge":base/"ci-cold-comparison-v70-r1/original-673-associated-pr-merge/original-artifact-13894188701.zip"}[item["label"]]
    with zipfile.ZipFile(original_archive) as z:
        names=z.namelist()
        for name in names:
            if "/qualification.evidence/phase-" not in name:continue
            if not (name.endswith(".process.json") or name.endswith("/phase-index.json")):continue
            info=z.getinfo(name)
            if info.file_size>2*1024*1024:raise ValueError("original phase receipt too large")
            original=z.read(name)
            packet["original_phase_files"].append({"label":item["label"],"member":name,"bytes":len(original),"sha256":hashlib.sha256(original).hexdigest(),"content":original.decode("utf-8")})
    started=data["cold_process_owner"]["events"][0]["monotonic_ns"]
    rows=[{"family":row["family"],"compiler":row["compiler_label"],"seconds":row["wall_elapsed_ns"]/1e9,"start_after_cold_s":(row["started_monotonic_ns"]-started)/1e9,"end_after_cold_s":(row["completed_monotonic_ns"]-started)/1e9,"archive_end_after_cold_s":(row["archive_completed_monotonic_ns"]-started)/1e9 if row["archive_completed_monotonic_ns"] else None,"returncode":row["returncode"]} for row in data["phase_receipts"]]
    overview.append({"label":item["label"],"cold_status":data["cold_status"],"cold_seconds":data["cold_wall_elapsed_ns"]/1e9,"rows":rows,"index":[{"completed":v["value"].get("completed"),"exceptions":v["value"].get("exceptions"),"pending":[p for p in v["value"].get("phases",[]) if p["state"]!="completed"]} for v in data["indexes"]],"nested_elapsed_ns":data["nested"]["elapsed_ns"] if data["nested"] else None})
raw=(json.dumps(packet,ensure_ascii=True,separators=(",",":"))+"\n").encode()
compressed=zlib.compress(raw,6)
(output/"original-phase-packet.json.zlib").write_bytes(compressed)
(output/"original-phase-packet.json").write_bytes(raw)
(output/"overview.json").write_text(json.dumps(overview,indent=2)+"\n",encoding="utf-8")
receipt={"schema":packet["schema"],"reports":len(packet["reports"]),"original_phase_files":len(packet["original_phase_files"]),"raw_bytes":len(raw),"raw_sha256":hashlib.sha256(raw).hexdigest(),"compressed_bytes":len(compressed),"compressed_sha256":hashlib.sha256(compressed).hexdigest(),"path":str(output/"original-phase-packet.json.zlib")}
(output/"receipt.json").write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf-8")
print(json.dumps(receipt),flush=True)
