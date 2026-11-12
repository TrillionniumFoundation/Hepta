from pathlib import Path
import hashlib,json,zipfile,time
base=Path("/workspace/scratch/9acdfa9f5639");p=base/"artifacts/follow56-core-native-original.zip";out=base/"follow57-root-originals/core56";out.mkdir(parents=True,exist_ok=True)
def identity(b):return {"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest(),"gitsha":hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()}
raw=p.read_bytes();pin=identity(raw);assert pin["sha256"]=="80255daff108960626d98d4ea7ba4a7399c37ceac15fba04300c746b3c48441d" and pin["bytes"]==57997495;del raw
rows=[];exports=[];names=set()
with zipfile.ZipFile(p) as z:
 for m in z.infolist():
  assert m.filename not in names and not m.is_dir();names.add(m.filename);data=z.read(m);ip=identity(data);assert ip["bytes"]==m.file_size
  rows.append({"path":m.filename,"mode":m.external_attr>>16,"zip_crc":m.CRC,**ip})
  if m.filename=="hia-cold.json" or m.filename=="hia-cold.cold/process-owner.json" or (m.filename.startswith("hia-cold.cold/qualification.evidence/phase-") and m.filename.endswith(".json")):
   dest=out/"originals"/m.filename;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data);assert dest.read_bytes()==data;exports.append(m.filename)
 report={"schema":"hia-root-follow56-core-full-original-readback-r1","status":"PASS_READBACK_OF_FAILED_TARGET","target_status":"FAIL","artifact_id":13971156800,"job_id":131386174351,"archive":pin,"members":len(rows),"raw_file_bytes":sum(x["bytes"] for x in rows),"full_zip_member_bytes_crc_sha_git_read":True,"target_executions":0,"original_export_paths":exports,"source_after_equal":identity(p.read_bytes())==pin}
 (out/"members.json").write_text(json.dumps(rows,indent=2)+"\n");(out/"full-readback.json").write_text(json.dumps(report,indent=2)+"\n")
 phase=[n for n in names if "phase" in n and ("index" in n or "manifest" in n)]
 print(json.dumps({k:v for k,v in report.items() if k!="original_export_paths"},sort_keys=True));print("phase indexes",phase)
 for n in phase:
  b=z.read(n);target=out/"originals"/n;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(b);print(n,b[:500].decode(errors="replace"))
