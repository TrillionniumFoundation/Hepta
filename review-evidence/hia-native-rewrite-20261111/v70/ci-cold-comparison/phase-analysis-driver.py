import hashlib,json,pathlib,sys,zipfile
base=pathlib.Path("/home/qq/hia-native-self-rewrite-20261111-dda7")
root=base/"ci-cold-phase-analysis-v70-r1"
root.mkdir(mode=0o700)
sources=[
{"label":"673-push","archive":str(base/"ci-673-cold-artifact-v70-r1/original-artifact-13894877342.zip"),"sha256":"4e34fc9ad90027a4c42fbf85eaa2bf8a9608ffa1629efe5b4558a15162c397c8"},
{"label":"8aade-push","archive":str(base/"ci-cold-comparison-v70-r1/original-8aade-push/original-artifact-13891487322.zip"),"sha256":"00eacd3fd8120ddc52e15f140a8dc99dea55b481aadb3b10d07873f03761ab62"},
{"label":"673-pr-merge","archive":str(base/"ci-cold-comparison-v70-r1/original-673-associated-pr-merge/original-artifact-13894188701.zip"),"sha256":"78fc0291bdeb88be115e61322b95d6408dc7aac874187cbbf9b39ba596423989"}]
def digest(path):
    with open(path,"rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
results=[]
for source in sources:
    path=pathlib.Path(source["archive"])
    if digest(path)!=source["sha256"]:raise ValueError("original archive changed")
    rows=[];indexes=[];top=[];jsonmeta=[];nested=None
    with zipfile.ZipFile(path) as z:
        members=z.infolist()
        for member in members:
            name=member.filename
            if "hia-cold" not in name or not name.endswith(".json"):continue
            if "/qualification.evidence/" not in name and pathlib.PurePosixPath(name).name!="qualification.json":continue
            rel=name.split("/qualification.evidence/",1)[-1]
            if "/" not in rel:top.append({"name":name,"bytes":member.file_size})
            needed=name.endswith(".process.json") and "/phase-" in name or name.endswith("/phase-index.json") or name.endswith("/reference-index.json") or pathlib.PurePosixPath(name).name=="qualification.json"
            if not needed:continue
            if member.file_size>80*1024*1024:raise ValueError("JSON observation exceeds explicit bound")
            raw=z.read(member)
            data=json.loads(raw)
            identity={"member":name,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
            jsonmeta.append(identity)
            if name.endswith(".process.json") and "/phase-" in name:
                rows.append({**identity,"schema":data.get("schema"),"family":data.get("family"),"compiler_label":data.get("compiler_label"),"returncode":data.get("returncode"),"worker_pid":data.get("worker_pid"),"started_monotonic_ns":data.get("started_monotonic_ns"),"completed_monotonic_ns":data.get("completed_monotonic_ns"),"wall_elapsed_ns":data.get("wall_elapsed_ns"),"archive_completed_monotonic_ns":data.get("archive_completed_monotonic_ns"),"report_sha256":data.get("report_sha256"),"raw_artifacts":data.get("raw_artifacts")})
            elif name.endswith("index.json"):indexes.append({"identity":identity,"value":data})
            else:
                nested={"identity":identity,"keys":list(data),"status":data.get("status"),"elapsed_ns":data.get("elapsed_ns"),"checks_total":len(data.get("checks",{})),"checks_passed":sum(v is True for v in data.get("checks",{}).values()),"generations":data.get("generations"),"modified_generations":data.get("modified_generations"),"seed":data.get("seed"),"qualification_scheduling":data.get("qualification_scheduling")}
        raw=z.read("hia-cold.json");cold=json.loads(raw)
    if digest(path)!=source["sha256"]:raise ValueError("original archive changed during read")
    out={"label":source["label"],"archive_sha256":source["sha256"],"archive_unchanged":True,"cold_status":cold["status"],"cold_wall_elapsed_ns":cold["wall_elapsed_ns"],"cold_process_owner":cold["process_owner"],"phase_receipts":rows,"indexes":indexes,"top_level_evidence_json":top,"nested":nested,"source_members":jsonmeta}
    raw=(json.dumps(out,indent=2,sort_keys=True)+"\n").encode()
    destination=root/(source["label"]+".json");destination.write_bytes(raw)
    result={"label":source["label"],"status":"ORIGINAL_ARCHIVE_ANALYZED","report_path":str(destination),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"phase_receipts":len(rows),"indexes":len(indexes),"has_nested":nested is not None,"archive_unchanged":True}
    results.append(result);print(json.dumps(result),flush=True)
(root/"results.json").write_text(json.dumps(results,indent=2)+"\n",encoding="utf-8")
