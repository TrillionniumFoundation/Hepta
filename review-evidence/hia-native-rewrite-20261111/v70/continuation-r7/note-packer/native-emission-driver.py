from __future__ import annotations
import hashlib,json,os,pathlib,subprocess,sys,time,traceback
P=pathlib.Path
SOURCE=P(sys.argv[1]);BASE=P(sys.argv[2]);OUT=BASE/"native-r1"
inputs_raw=sys.stdin.buffer.read();inputs=json.loads(inputs_raw)
report={"schema":"hepta.hia.cpython-note-packer.native-development.v1",
 "status":"RUNNING","scope":"PREDECESSOR_COMPILER_DEVELOPMENT_HIA_PACKER_EMISSION",
 "started_ns":time.time_ns(),"observations":[],"failures":[],
 "current_source_cold_qualification":False,"whole_native":False,
 "default_native":False,"live_migration":False,"legacy_deletion":False,
 "native_adapter_executed":False,"production_c_compiler_used":False,
 "limits":{"outer_seconds":180,"native_compile_seconds":20,"native_observation_seconds":20}}
def digest(raw):return hashlib.sha256(raw).hexdigest()
def identity(path):
 raw=path.read_bytes()
 return {"path":str(path),"bytes":len(raw),"sha256":digest(raw)}
def verify(path,expected_sha,expected_bytes=None):
 raw=path.read_bytes()
 if digest(raw)!=expected_sha or expected_bytes is not None and len(raw)!=expected_bytes:
  raise AssertionError("identity changed: "+str(path))
 return raw
try:
 OUT.mkdir(mode=0o700)
 (OUT/"request-inputs.json").write_bytes(inputs_raw)
 report["inputs"]={"bytes":len(inputs_raw),"sha256":digest(inputs_raw)}
 report["interpreter_before"]=identity(P(sys.executable))
 reference_path=BASE/"reference-RESULT.json"
 reference_raw=verify(reference_path,inputs["reference_sha256"],inputs["reference_bytes"])
 reference=json.loads(reference_raw)
 if (reference["status"]!="PASS_REFERENCE_BEFORE_NATIVE_PACKER"
    or len(reference["observations"])!=14 or not all(r["passed"] for r in reference["observations"])
    or not reference["assembled"]["every_byte_equal"]
    or reference["native_packer_compiled"] or reference["native_adapter_executed"]):
  raise AssertionError("independent reference not complete before native compile")
 report["independent_reference"]=identity(reference_path)
 packer_path=BASE/"source/examples/hia_bootstrap/cpython_note_packer.hiaasm"
 packer=verify(packer_path,inputs["packer_sha256"],inputs["packer_bytes"])
 expected_path=BASE/"expected.image.bin"
 expected=verify(expected_path,inputs["image_sha256"],inputs["image_bytes"])
 report["packer_source_before"]=identity(packer_path)
 report["expected_before"]=identity(expected_path)
 cold_raw=inputs["original_cold_report"].encode()
 if digest(cold_raw)!=inputs["cold_sha256"]:raise AssertionError("cold report transport mismatch")
 cold=json.loads(cold_raw)
 if cold["status"]!="COLD_SELFHOST_REPLAY_PASS" or len(cold["checks"])!=11 or not all(cold["checks"].values()):
  raise AssertionError("retained compiler cold provenance did not pass")
 nested_path=P(cold["nested_report"])
 nested_raw=verify(nested_path,cold["nested_report_sha256"])
 nested=json.loads(nested_raw)
 compiler=P(nested["generations"][-1]["produced_image"])
 compiler_raw=verify(compiler,inputs["compiler_sha256"])
 if cold["generation_sha256"]!=[digest(compiler_raw)]*3:raise AssertionError("B1/B2/B3 mismatch")
 report["compiler_before"]=identity(compiler)
 report["retained_compiler_provenance"]={"cold_sha256":digest(cold_raw),"nested":identity(nested_path),
   "generation_sha256":cold["generation_sha256"],"qualification_seconds":cold["qualification_wall_limit_seconds"],
   "cleanup_seconds":cold["cleanup_wall_limit_seconds"]}
 process=subprocess.run(["/usr/bin/git","status","--porcelain=v1"],cwd=SOURCE,capture_output=True,timeout=30)
 if process.returncode or process.stdout:raise AssertionError("frozen base source not clean")
 report["source_clean_before"]=True
 removed=[]
 for key in list(os.environ):
  if key.startswith("HEPTA_"):
   removed.append(key);del os.environ[key]
 report["inherited_hepta_selectors_removed"]=sorted(removed)
 sys.path.insert(0,str(SOURCE))
 from tools.qualify_hia_selfhost import compile_stage,invoke
 native,compilation=compile_stage(OUT,"cpython-note-packer",compiler,packer)
 report["native_compilation"]=compilation
 report["native_packer_before"]=identity(native)
 cases=[("exact",b"",len(expected),len(expected),expected),
        ("short",b"",len(expected)-1,4294967294,bytes([165])*(len(expected)-1)),
        ("nonempty",b"Z",len(expected),4294967295,bytes([165])*len(expected)),
        ("precedence",b"Z",0,4294967295,b""),
        ("zero-output",b"",0,4294967294,b""),
        ("tail",b"",len(expected)+3,len(expected),expected+bytes([165])*3)]
 emitted=None
 for name,source,capacity,wanted_status,wanted_output in cases:
  actual,output=invoke(OUT,"emit-"+name,native,source,capacity=capacity,workspace_size=0)
  passed=(actual.get("status")=="returned" and actual.get("abi_status")==0
    and actual.get("core_u32")==wanted_status and actual.get("source_unchanged")
    and output==wanted_output)
  report["observations"].append({"case":name,"passed":bool(passed),"actual":actual,
      "expected_status":wanted_status,"expected_bytes":len(wanted_output),
      "expected_sha256":digest(wanted_output),"actual_bytes":len(output),"actual_sha256":digest(output),
      "every_byte_equal":output==wanted_output})
  if not passed:raise AssertionError("native packer control failed: "+name)
  if name=="exact":emitted=output
 if emitted is None or emitted!=expected:raise AssertionError("no actual native production")
 path=OUT/"cpython-note.image.bin"
 with path.open("xb") as stream:stream.write(emitted)
 report["produced_image"]=identity(path)
 report["native_packer_after"]=identity(native)
 report["compiler_after"]=identity(compiler)
 report["packer_source_after"]=identity(packer_path)
 report["expected_after"]=identity(expected_path)
 report["interpreter_after"]=identity(P(sys.executable))
 verify(reference_path,inputs["reference_sha256"],inputs["reference_bytes"])
 verify(nested_path,cold["nested_report_sha256"])
 for prefix in ("native_packer","compiler","packer_source","expected","interpreter"):
  if report[prefix+"_before"]!=report[prefix+"_after"]:raise AssertionError(prefix+" changed")
 process=subprocess.run(["/usr/bin/git","status","--porcelain=v1"],cwd=SOURCE,capture_output=True,timeout=30)
 if process.returncode or process.stdout:raise AssertionError("frozen base source changed")
 report["source_clean_after"]=True
 report["status"]="PASS_HIA_PACKER_EMISSION_ONLY"
except BaseException as error:
 report["status"]="FAIL"
 report["failures"].append({"type":type(error).__name__,"message":str(error),"traceback":traceback.format_exc()})
finally:
 report["finished_ns"]=time.time_ns()
 if OUT.is_dir():
  raw=(json.dumps(report,sort_keys=True,indent=2)+"\n").encode()
  (OUT/"native-RESULT.json").write_bytes(raw)
  print(json.dumps({"status":report["status"],"observations":len(report["observations"]),
    "failures":report["failures"],"report_bytes":len(raw),"report_sha256":digest(raw),
    "report":str(OUT/"native-RESULT.json"),"image":report.get("produced_image")}),flush=True)
if report["status"]!="PASS_HIA_PACKER_EMISSION_ONLY":raise SystemExit(1)
