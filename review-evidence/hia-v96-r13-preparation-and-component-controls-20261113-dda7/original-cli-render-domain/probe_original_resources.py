from __future__ import annotations
import hashlib,json,os,pathlib,subprocess,sys,time
ROOT=pathlib.Path("/workspace/scratch/dda74a4fae35/v94-union-r12/source")
OUT=pathlib.Path("/workspace/scratch/dda74a4fae35/v96-render-domain-audit-r1")
def h(b): return hashlib.sha256(b).hexdigest()
env=dict(os.environ)
if any(k.startswith("HEPTA_HIA_") for k in env): raise RuntimeError("unexpected HIA selection")
env["PYTHONPATH"]=str(ROOT);env["PYTHONDONTWRITEBYTECODE"]="1"
cases=[("v7-chain","examples/hia_recursive_chain/core_v7.hepta"),("v8-returned-loans","examples/hia_returned_loans/core_v8.hepta"),("v8-cross-target-loans","examples/hia_program/returned_loans_cross_target_v8.hepta"),("v8-parameter-loan-return","examples/hia_program/parameter_loan_return_v8.hepta")]
rows=[]
for name,relative in cases:
 directory=OUT/name;directory.mkdir(exist_ok=False)
 source=(ROOT/relative).read_bytes();inputpath=directory/"input.json";inputpath.write_bytes(source)
 command=[sys.executable,"-B","-c","from hepta.cli import hia_main;raise SystemExit(hia_main())","render-assembly",str(inputpath)]
 start=time.monotonic();r=subprocess.run(command,cwd=ROOT,env=env,capture_output=True,timeout=20);elapsed=time.monotonic()-start
 (directory/"stdout.bin").write_bytes(r.stdout);(directory/"stderr.bin").write_bytes(r.stderr)
 row={"name":name,"original_input_path":relative,"input_bytes":len(source),"input_sha256":h(source),"original_input_unchanged":source==(ROOT/relative).read_bytes(),"command":command,"elapsed":elapsed,"returncode":r.returncode,"stdout_bytes":len(r.stdout),"stdout_sha256":h(r.stdout),"stderr_bytes":len(r.stderr),"stderr_sha256":h(r.stderr),"matched":r.returncode==0 and not r.stderr}
 (directory/"RESULT.json").write_text(json.dumps(row,indent=2,sort_keys=True)+"\n");rows.append(row)
report={"schema":"hia.original-render-resource-domain.v1","scope":"Original hosted CLI; independent diagnostic, zero Native candidate executions","status":"PASS" if all(x["matched"] and x["original_input_unchanged"] for x in rows) else "FAIL","cases":rows,"python":sys.version,"native_candidate_executions":0,"whole_native":False}
(OUT/"RESOURCE-DOMAIN-REPORT.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
print(json.dumps({"status":report["status"],"cases":[{"name":r["name"],"returncode":r["returncode"],"stdout_bytes":r["stdout_bytes"]} for r in rows]}))
raise SystemExit(0 if report["status"]=="PASS" else 1)
