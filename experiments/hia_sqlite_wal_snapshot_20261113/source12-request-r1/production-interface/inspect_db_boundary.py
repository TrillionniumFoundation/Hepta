"""Read only exact-source AST index; imports no Hepta and executes no tests."""
from pathlib import Path
import ast, hashlib, json
ROOT=Path("/home/qq/hia-rewrite-20261113-e26e-r1/pc-fixture-successor-r1/source")
OUT=Path("/home/qq/hia-rewrite-20261113-e26e-r1/agent-store-production-static-r1")
PINS=[{"path":"tests/test_hia_agent_native_tools.py","bytes":42664,"sha256":"fe9f54d7132432bc7514ee58451111897ac06907f44e724c502f51028da5d901","git_blob_sha1":"0f30ac1762ced2c88fabbea86451ee205921e43e"},{"path":"tests/test_hia_agent_native_proof_contract.py","bytes":23396,"sha256":"0a9a3feb8444d33ec97afb4259a847cd6b738fc3a77cf07980b4772096c112a6","git_blob_sha1":"cff64347e6d7fa02569da55032caddf264859e1a"},{"path":"tests/test_hia_agent_native_lease_snapshot.py","bytes":2785,"sha256":"476e49225ad1b2215f08323079f3521b5b9dbcdb33edc8b619013f426643e823","git_blob_sha1":"15be054a47985d38486f16c586b5d73bd265728d"},{"path":"tests/test_hia_agent_native_machine_choices.py","bytes":3840,"sha256":"c35b13d6e94da9129456913ade57e362c901619e8b7d87a4a0fdfbb1d06681cc","git_blob_sha1":"06fd18591ce5a12f822b9f31f8f5798f4a2d132c"},{"path":"tests/test_hia_agent_native_campaign.py","bytes":9345,"sha256":"472e3a0020c1532c217db21a9d087f128dcc0aec1902425698bd5c1d869b765b","git_blob_sha1":"15a12392cae76a4fddd3ed22c52436037f180a0d"},{"path":"tests/test_hia_agent_candidate_native.py","bytes":25099,"sha256":"5393de26621d240e90383462694581c39f38be98ce3ac62b8ffb217e9f09904d","git_blob_sha1":"414e696c3c2d94d2b802cd71b045204875dd8e7e"},{"path":"tests/test_hia_worker_request_native.py","bytes":12947,"sha256":"136e4bde0971edfd7eeb0a1dbbcb1e09dff33104919d5c2f241845b803a535a9","git_blob_sha1":"655257cbe6a97284bbaef96b4055709323101e46"},{"path":"tests/test_hia_worker_request_review.py","bytes":16487,"sha256":"3952145fdaf95c2368aab55a7a54ab1d403ff34b40f92612b63ffa82c88f7ff0","git_blob_sha1":"13c6689c7cf581e15cdf7e02ffd68adf3a177306"},{"path":"tests/test_hia_agent_journal_native.py","bytes":48029,"sha256":"f9bb236820af1ab6e7af416d43b437b38d446ebbd137e60e21aa310bdebaf35b","git_blob_sha1":"ae44db40949e3ea94535ef3f0665b58ac1330646"},{"path":"tests/test_hia_agent_store_authority_native.py","bytes":31014,"sha256":"afcfaa1b5c548866ac7ef7c44a0a71c6f2ce5675a593e49b0440eb6bc7ea326c","git_blob_sha1":"5394dee6fe859c08d47ae0f02ee806f80c5681bb"},{"path":"tests/test_hia_artifact_read_native.py","bytes":26294,"sha256":"e9d9e950502c99fb5c4dac2e92183a2a370b7388a1e16be79ef371695e8f4580","git_blob_sha1":"f382981ef2f62b6cf04e331fdd1b766036e976e8"},{"path":"tests/test_hia_agent_artifact_store_native.py","bytes":20396,"sha256":"a27d8608868f8b7f074b07b85fe502c7cc656a7405ea112e4b86215084a63306","git_blob_sha1":"f4ac219884a0bc6c3f2a6d6f6c9741a2e1aab868"},{"path":"tests/test_hia_worker_report_native.py","bytes":47676,"sha256":"555d39928bd0d934bedcc24c11c5fa1911d7295daf713130c043f199373a28d4","git_blob_sha1":"a6ab0ff0f876968b9c1ddb4d3b4568c6b239e394"},{"path":"hepta/hia_agent_store.py","bytes":21838,"sha256":"822a493b7c6096934af384099eaadd5c4467c6d89193dc3f695887aca256e579","git_blob_sha1":"935fd9b5c327f91407f9e910afa23edd0f01f04f"},{"path":"hepta/hia_agent_service.py","bytes":101065,"sha256":"1d8180c6a3d009350edeec5b055b9f35dbfcc84ae38d8dcd0a8cf110ad4c59c4","git_blob_sha1":"e8eb3f28e77d9e4c7d3b3f3ea018d8cec76b9271"},{"path":"hepta/hia_agent_journal_native.py","bytes":22923,"sha256":"1cbd3c43ad5439f6fcfa1455d0c10725d38f7ae2807e403d9d3f47cdba874d21","git_blob_sha1":"8ce760d5d6155aa69164b265b79253a76b5a937c"},{"path":"hepta/hia_agent_store_authority_native.py","bytes":13331,"sha256":"d8a565fb52df4c3f14bec06679eebeacf99b3868e6c16e5d05f8ce9c6c1d923a","git_blob_sha1":"3424f046d10f18f176d9624bb1c0ed4253135bc7"},{"path":"hepta/hia_artifact_page_native.py","bytes":14759,"sha256":"fae7a042f41488d7e02530d8d81fd695efe21b8a9671d2e448a4820f8da6c814","git_blob_sha1":"e396e79632e50e4f214c87a58ac2c9ade90e45cc"},{"path":"tools/generate_hia_agent_store_authority.py","bytes":22082,"sha256":"907b7bb7024012e7486d68d3960cb80cff579c06cfce2ed3645428b3bd8e99a8","git_blob_sha1":"2dad7c56fb99ed08a7fa213b451e06251a4d78fc"},{"path":"tools/generate_hia_artifact_page.py","bytes":22229,"sha256":"c2c33093f21c7783ab47d2e7071e3fbb4f6286d16c1f5ff55720c96bad39aaf9","git_blob_sha1":"7dfd27c4881aee90c8e987acfef46a6d8922cba7"},{"path":"tools/qualify_hia_agent_journal_callers.py","bytes":9133,"sha256":"f56b8d94836f9cfeea2a8860158e20ba945fe4cc3f710c790409e30e0dfaea10","git_blob_sha1":"d015a4348b44f51eb6824d8dcfabc4e74ed8d4b1"},{"path":"tools/qualify_hia_agent_store_authority_callers.py","bytes":14139,"sha256":"47c07f35a4f40c461255488bce452f958816a178111453a01e0b9f1c28305eb9","git_blob_sha1":"9750e6051f77b7f08b56ee2da3843df5b69d1fb9"},{"path":"tools/qualify_hia_artifact_read_callers.py","bytes":11194,"sha256":"9339cb2c165029947fdc4681a41f1dd9a3af7e9b9066e3c3dd55badd0e22d747","git_blob_sha1":"fa8833e0f45b068fdbf449767da475cbf11a8adf"}]
TESTS=["tests/test_hia_agent_native_tools.py","tests/test_hia_agent_native_proof_contract.py","tests/test_hia_agent_native_lease_snapshot.py","tests/test_hia_agent_native_machine_choices.py","tests/test_hia_agent_native_campaign.py","tests/test_hia_agent_candidate_native.py","tests/test_hia_worker_request_native.py","tests/test_hia_worker_request_review.py","tests/test_hia_agent_journal_native.py","tests/test_hia_agent_store_authority_native.py","tests/test_hia_artifact_read_native.py","tests/test_hia_agent_artifact_store_native.py","tests/test_hia_worker_report_native.py"]
QUALIFIERS=["tools/qualify_hia_agent_journal_callers.py","tools/qualify_hia_agent_store_authority_callers.py","tools/qualify_hia_artifact_read_callers.py"]
data={}
def pin(path,body):
 return {"path":path,"bytes":len(body),"sha256":hashlib.sha256(body).hexdigest(),"git_blob_sha1":hashlib.sha1(b"blob "+str(len(body)).encode()+b"\0"+body).hexdigest()}
for wanted in PINS:
 body=(ROOT/wanted["path"]).read_bytes()
 if pin(wanted["path"],body)!=wanted: raise ValueError("source identity drift: "+wanted["path"])
 data[wanted["path"]]=(body.decode(),ast.parse(body,filename=wanted["path"]))
classes={};direct=[]
for path in TESTS:
 mod=path[:-3].replace("/",".")
 raw,tree=data[path]
 for node in tree.body:
  if not isinstance(node,ast.ClassDef): continue
  methods={n.name:{"method":n.name,"defining_id":mod+"."+node.name+"."+n.name,
    "path":path,"line":n.lineno,"end_line":n.end_lineno} for n in node.body
    if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name.startswith("test")}
  key=mod+"."+node.name
  classes[key]={"class_id":key,"bases":[ast.unparse(x) for x in node.bases],"methods":methods}
  direct.extend(methods.values())
def resolve(key,seen=()):
 if key in seen:raise ValueError("class cycle")
 item=classes[key];methods={}
 for base in item["bases"]:
  if base=="unittest.TestCase":continue
  target=(key.rsplit(".",1)[0]+"."+base)
  if base=="AgentToolCase":target="tests.test_hia_agent_native_tools.AgentToolCase"
  if base=="existing.MachinePlanTests":target="tests.test_hia_agent_native_tools.MachinePlanTests"
  if target not in classes:raise ValueError("unresolved test base: "+key+" -> "+base)
  methods.update(resolve(target,seen+(key,)))
 methods.update(item["methods"])
 return methods
module_ids={}
for path in TESTS:
 mod=path[:-3].replace("/",".");ids=[]
 for key in sorted(classes):
  if key.rsplit(".",1)[0]!=mod:continue
  for name,item in sorted(resolve(key).items()):
   ids.append(dict(item,id=key+"."+name,inherited=item["defining_id"]!=key+"."+name))
 module_ids[mod]=ids
qualifiers=[]
for path in QUALIFIERS:
 raw,tree=data[path];assignment=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="DEFAULT_MODULES" for t in n.targets))
 modules=ast.literal_eval(assignment.value)
 ordered=[x for mod in modules for x in module_ids[mod]]
 qualifiers.append({"path":path,"line":assignment.lineno,"modules":list(modules),"static_original_id_count":len(ordered),"ids":[x["id"] for x in ordered],"runtime_not_imported_or_executed":True})
queries=[]
for path,(raw,tree) in data.items():
 parents={}
 for n in ast.walk(tree):
  for c in ast.iter_child_nodes(n):parents[c]=n
 def scope(n):
  result=[]
  while n in parents:
   n=parents[n]
   if isinstance(n,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)):result.append(n.name)
  return ".".join(reversed(result))
 for n in ast.walk(tree):
  if isinstance(n,ast.Constant) and type(n.value) is str and n.value.lstrip().upper().startswith(("SELECT ","INSERT ","UPDATE ","CREATE TABLE","PRAGMA ","BEGIN ","COMMIT","ROLLBACK")):
   queries.append({"path":path,"line":n.lineno,"scope":scope(n),"value":n.value})
result={"schema":"hia.agent-store.exact-db-boundary-static.v1","source_commit":"8556199d761540f84c15856a6a9cf1a6f863ffc5","source_tree":"d60dbcda95d3c06797fae7a4d97c4640fe37f627","status":"STATIC_ONLY_NOT_EXECUTED_TESTS","inputs":PINS,"module_methods":module_ids,"qualifiers":qualifiers,"SQL_string_constants":queries,"no_product_imports":True,"no_tests_or_native":True,"note":"Resolved existing test inheritance from AST only; this is not a replacement runtime qualification denominator."}
body=(json.dumps(result,sort_keys=True,indent=2)+"\n").encode()
path=OUT/"DB-BOUNDARY-AND-CALLERS.json"
with path.open("xb") as f:f.write(body)
print(json.dumps(dict(pin(str(path),body),qualifiers=[{"path":x["path"],"static_original_id_count":x["static_original_id_count"]} for x in qualifiers],modules=len(module_ids),SQL_constants=len(queries))))
