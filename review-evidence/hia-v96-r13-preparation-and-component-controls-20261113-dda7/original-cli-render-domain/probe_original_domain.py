from __future__ import annotations
import hashlib,json,os,pathlib,subprocess,sys,time
ROOT=pathlib.Path("/workspace/scratch/dda74a4fae35/v94-union-r12/source")
OUT=pathlib.Path("/workspace/scratch/dda74a4fae35/v96-render-domain-audit-r1")
OUT.mkdir(exist_ok=True)
def h(b): return hashlib.sha256(b).hexdigest()
paths=["hepta/cli.py","hepta/hia_program.py","hepta/hia_agent_assembly.py","hepta/hia_schema.py"]
before={p:{"bytes":len((b:=(ROOT/p).read_bytes())),"sha256":h(b)} for p in paths}
env=dict(os.environ)
active={k:v for k,v in env.items() if k.startswith("HEPTA_HIA_")}
if active: raise RuntimeError("diagnostic requires unset HEPTA_HIA_* selections")
env["PYTHONPATH"]=str(ROOT);env["PYTHONDONTWRITEBYTECODE"]="1"
rows=[]
for version in (6,7,8):
 for count in (128,129,256,257):
  name=f"v{version}-functions-{count}"
  directory=OUT/name;directory.mkdir(exist_ok=False)
  functions=[]
  for i in range(count):
   functions.append({"name":f"f{i}","params":[{"name":"x","type":"u32"}],"returns":["u32"],"effects":[],"entry":"entry","blocks":[{"id":"entry","params":[{"name":"x","type":"u32"}],"ops":[],"term":{"op":"ret","values":["x"]}}]})
  document={"schema":f"hepta.hia.program.v{version}","module":"function_boundary","exports":[],"functions":functions}
  source=json.dumps(document,sort_keys=True,separators=(",",":")).encode()+b"\n"
  sourcepath=directory/"input.json";sourcepath.write_bytes(source)
  command=[sys.executable,"-B","-c","from hepta.cli import hia_main;raise SystemExit(hia_main())","render-assembly",str(sourcepath)]
  start=time.monotonic();r=subprocess.run(command,cwd=ROOT,env=env,capture_output=True,timeout=20);elapsed=time.monotonic()-start
  (directory/"stdout.bin").write_bytes(r.stdout);(directory/"stderr.bin").write_bytes(r.stderr)
  row={"name":name,"schema":version,"functions":count,"command":command,"returncode":r.returncode,"elapsed":elapsed,"input_bytes":len(source),"input_sha256":h(source),"stdout_bytes":len(r.stdout),"stdout_sha256":h(r.stdout),"stderr_bytes":len(r.stderr),"stderr_sha256":h(r.stderr),"expected_acceptance":count<=256}
  if count>256: row["diagnostic"]=json.loads(r.stdout)
  row["matched"]=r.returncode==(0 if count<=256 else 2) and not r.stderr
  (directory/"RESULT.json").write_text(json.dumps(row,indent=2,sort_keys=True)+"\n");rows.append(row)
after={p:{"bytes":len((b:=(ROOT/p).read_bytes())),"sha256":h(b)} for p in paths}
report={"schema":"hia.original-render-domain-boundary.v1","status":"PASS" if all(x["matched"] for x in rows) and before==after else "FAIL","scope":"Original hosted CLI observable domain; independent diagnostic, zero Native candidate executions","source_baseline":"06524acb76047fc271ab6b6597362fd5f3499d00","source_identity_note":"Four exact audited implementation files recorded; no claim of fresh whole-tree reconstruction by this reader","python":sys.version,"python_executable":sys.executable,"selected_hia_environment":active,"original_source_before":before,"original_source_after":after,"original_source_unchanged":before==after,"cases":rows,"native_candidate_execution":0,"whole_native":False}
(OUT/"REPORT.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
print(json.dumps({"status":report["status"],"cases":len(rows),"accepted":[r["name"] for r in rows if r["returncode"]==0],"refused":[r["name"] for r in rows if r["returncode"]!=0],"source_unchanged":before==after}))
raise SystemExit(0 if report["status"]=="PASS" else 1)
