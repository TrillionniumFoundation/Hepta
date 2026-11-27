import hashlib,json,pathlib,subprocess,sys,types
root,out,phase,original_blob=sys.argv[1:]
sys.path.insert(0,root)
if phase=="before":
 raw_module=subprocess.check_output(["git","show","32692030505f2e81e9d33e22dbf6857c65af83ed:tools/hia_cold_compiler.py"],cwd=root)
 if hashlib.sha1(b"blob "+str(len(raw_module)).encode()+b"\0"+raw_module).hexdigest()!=original_blob:raise ValueError("original selector bytes differ")
 module=types.ModuleType("hia_original_cold_compiler_observation")
 module.__file__=str(pathlib.Path(root)/"tools/hia_cold_compiler.py")
 sys.modules[module.__name__]=module
 exec(compile(raw_module,module.__file__,"exec"),module.__dict__)
 read_cold_build_inputs=module.read_cold_build_inputs
else:
 from tools.hia_cold_compiler import read_cold_build_inputs
 raw_module=(pathlib.Path(root)/"tools/hia_cold_compiler.py").read_bytes()
base=pathlib.Path("/tmp/hia-core-wiring-readback-326920-2807")
cold=base/"fresh/cold.json";original_index=base/"fresh/cold.generations.json"
raw=cold.read_bytes();index_raw=original_index.read_bytes();index=json.loads(index_raw)
if hashlib.sha256(raw).hexdigest()!="c40e0736b58b00644a5176467d08063421a3fb581caa35fb8b49099cb98628d6":raise ValueError("original report changed")
if hashlib.sha256(index_raw).hexdigest()!="d171637b4f95805b62629be876df104b294f39ee53d626c5fde13adfc26ad5f9":raise ValueError("original index changed")
if index["source_head"]!="32692030505f2e81e9d33e22dbf6857c65af83ed":raise ValueError("wrong original source")
index["native_report"]["path"]=str(cold);images=[]
for row in index["generations"]:
 path=base/"fresh/cold.native-cold/chain/cold/qualification/base"/(row["name"]+".flat");image=path.read_bytes()
 if len(image)!=row["produced_bytes"] or hashlib.sha256(image).hexdigest()!=row["produced_sha256"]:raise ValueError("original compiler changed")
 row["produced_image"]=str(path);images.append({"name":row["name"],"bytes":len(image),"sha256":hashlib.sha256(image).hexdigest(),"prefix_hex":image[:32].hex()})
relocated=pathlib.Path(out)/(phase+".relocated.generations.json")
relocated.write_text(json.dumps(index,indent=2,sort_keys=True)+chr(10))
record={"phase":phase,"selector_sha256":hashlib.sha256(raw_module).hexdigest(),"original_source_head":index["source_head"],"original_cold_sha256":hashlib.sha256(raw).hexdigest(),"original_index_sha256":hashlib.sha256(index_raw).hexdigest(),"relocated_index":str(relocated),"relocation_scope":"Location-index paths only; original cold and images unchanged; no qualification fields synthesized","images":images,"qualification_mocks_used":False,"admitted":False}
try:
 inputs=read_cold_build_inputs(cold,generation_index=relocated);inputs.unchanged()
 record.update(admitted=True,source_count=len(inputs.sources),source_head=inputs.source_head,report_schema=inputs.report["schema"],five_original_inputs=len(inputs.files),complete_admission_passed=True)
except Exception as exc:record.update(error=type(exc).__name__+": "+str(exc),complete_admission_passed=False)
if cold.read_bytes()!=raw or original_index.read_bytes()!=index_raw:raise ValueError("original artifact bytes changed")
(pathlib.Path(out)/(phase+".actual-compiler.json")).write_text(json.dumps(record,indent=2,sort_keys=True)+chr(10))
print(json.dumps(record,sort_keys=True))
