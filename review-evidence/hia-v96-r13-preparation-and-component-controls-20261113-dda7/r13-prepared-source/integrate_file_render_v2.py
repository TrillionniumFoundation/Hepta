"""Compose fixed R12-R2 with the frozen v2 file-render component.

No product import, generator, unittest loader, Native entry, ref write or
qualification occurs here. Every old source and every component preimage is
checked before an exclusive source directory is written.
"""
from __future__ import annotations
import ast,base64,copy,difflib,hashlib,importlib.util,json,pathlib,re,shutil,sys,traceback,zlib
import yaml
sys.dont_write_bytecode=True
HERE=pathlib.Path(__file__).resolve().parent;WORK=HERE.parent
BASE=WORK/"v94-union-r12-r2/source";COMP=WORK/"v95-native-file-render-r2/handoff-r3"
BASE_TREE="49284c6dfdccd54ca67bdfc1bb5ac9c5ec728f19"
PACKET="120718a7f8b48bd267b82d3dd1a91bc32b2407dd"
SPEC="6fc52a87b813ed9fb97096dee42a4d6494a50160"
WORKFLOW=".github/workflows/hia-core.yml"
s=importlib.util.spec_from_file_location("frozen_r12_integration_helpers",WORK/"v94-union-r12/integrate_linux_file.py")
h=importlib.util.module_from_spec(s);s.loader.exec_module(h)
encode,identity,snapshot,tree_hash=h.encoded,h.identity,h.snapshot,h.tree_hash
decl,append_tuple,replace_once=h.declarations,h.append_tuple,h.replace_once
methods,method_bytes,relative_imports=h.methods,h.method_bytes,h.relative_imports

def put(path,raw):
 path.parent.mkdir(parents=True,exist_ok=True)
 with path.open("xb") as f:f.write(raw)

def main():
 assert not (HERE/"source").exists() and not (HERE/"source-attempt-r1").exists()
 packet_raw=(COMP/"SOURCE-PACKET.zlib.json").read_bytes();spec_raw=(COMP/"REGISTRATION-SPEC.json").read_bytes()
 assert identity(packet_raw)["git_blob"]==PACKET and identity(spec_raw)["git_blob"]==SPEC
 wrap=json.loads(packet_raw);raw=zlib.decompress(base64.b64decode(wrap["payload"],validate=True))
 assert identity(raw)==wrap["decoded"]
 component=json.loads(raw);spec=json.loads(spec_raw);rows=component["files"]
 assert component["base_tree"]=="06524acb76047fc271ab6b6597362fd5f3499d00"
 assert component["current_tree"]=="cee29d828985f1c43b39eb11d68d931b0f7001f7" and len(rows)==16
 assets=tuple(spec["ENTRY_BUILD_FILES_additions"])
 generators=[row["argv"][-1].removeprefix("tools.generate_hia_") for row in spec["generators"]]
 assert len(assets)==len(generators)==5
 new_paths=sorted(name for name,row in rows.items() if row["before"] is None)
 assert len(new_paths)==13 and new_paths==sorted(spec["SOURCE_FILES_additions"])
 base,caches=snapshot(BASE)
 assert not caches and len(base)==3108 and tree_hash(base)==BASE_TREE
 assert base==json.loads((BASE.parent/"SOURCE-MANIFEST.json").read_bytes())
 contents={};projections={};history={}
 def read(name):return contents[name] if name in contents else (BASE/name).read_bytes()
 def edit(name,value,reason):
  assert name not in contents
  before=(BASE/name).read_bytes() if name in base else None
  assert value!=before
  contents[name]=value;history[name]={"before":base.get(name),"after":identity(value),"reason":reason}
 for name,row in rows.items():
  value=row["text"].encode();assert identity(value)=={k:row[k] for k in ("bytes","git_blob","sha256","mode")}
  if row["before"] is None:assert name not in base
  else:
   previous=row["before"];before=previous["text"].encode()
   assert identity(before)=={k:previous[k] for k in ("bytes","git_blob","sha256","mode")}
   assert (BASE/name).read_bytes()==before and base[name]==identity(before)
  edit(name,value,"Exact frozen v2 component with complete R12 preimage; its development result is not inherited.")
 shared=sorted(name for name,row in rows.items() if row["before"] is not None)
 assert shared==["hepta/hia_agent_assembly.py","hepta/hia_program.py","hepta/hia_program_runtime.py"]

 name="hepta/hia_agent_contract.py";before=read(name).decode()
 edit(name,append_tuple(before,"ENTRY_BUILD_FILES",assets).encode(),"Append five explicit ENTRY resources; preserve all twelve roles and NATIVE92.")
 name="tools/hia_selfhost_contract.py";before=read(name).decode()
 edit(name,append_tuple(before,"SOURCE_FILES",new_paths).encode(),"Append thirteen full source paths after the original1332.")
 name="MANIFEST.in";before=read(name).decode()
 added="".join("include "+a+"\n" for a in assets)
 assert before.endswith("\n") and all("include "+a not in before.splitlines() for a in assets)
 edit(name,(before+added).encode(),"Append exactly the same five resources to the sdist.")
 name="tools/hia_candidate_preflight.py";before=read(name).decode()
 anchor="        'examples/hia_bootstrap/native_file_read.hepta',\n    })\n    combined = files + entry"
 replacement="        'examples/hia_bootstrap/native_file_read.hepta',\n"+"".join("        "+repr(a)+",\n" for a in assets)+"    })\n    combined = files + entry"
 edit(name,replace_once(before,anchor,replacement).encode(),"Extend exact ENTRY allowlist; retain original256 bound, sequential reads and uniqueness.")
 name="hepta/hia_checker_identity.py";before=read(name).decode()
 after=append_tuple(before,"MECHANISM_SOURCE_FILES",("hia_linux_file_render.py",))
 anchor="CHECKER_MECHANISM_EXTERNAL_PROVIDERS = {\n"
 after=replace_once(after,anchor,anchor+" 'hia_linux_file_render.py': ('hia_program_runtime.py',),\n")
 generated="# END GENERATED CHECKER CUSTODY\n"
 assert before.split(generated,1)[0]==after.split(generated,1)[0]
 edit(name,after.encode(),"Add one exact mechanism/provider; retain generated closure seed for actual final regeneration.")
 name="tools/check_hia_core_only.py";before=read(name).decode()
 anchor="    'examples/hia_bootstrap/native_file_read.hepta': 'hepta.hia.linux-file.v1',\n"
 new_role="    'examples/hia_bootstrap/native_file_render.hepta': 'hepta.hia.linux-file-render.v2',\n"
 edit(name,replace_once(before,anchor,anchor+new_role).encode(),"Add one exact source/profile; preserve default and unknown-path refusals.")

 name="tests/test_hia_source_suffix.py";before=read(name).decode()
 anchor="        expected_profiles['examples/hia_bootstrap/native_file_read.hepta'] = 'hepta.hia.linux-file.v1'\n"
 added_expected="        expected_profiles['examples/hia_bootstrap/native_file_render.hepta'] = 'hepta.hia.linux-file-render.v2'\n"
 after=replace_once(before,anchor,anchor+added_expected)
 old_methods=methods(before,name[:-3].replace("/","."))
 template=next(n for n in old_methods.values() if n.name=="test_native_file_source_role_is_explicit_and_fully_verified")
 template_text=method_bytes(before,template);new_method=template_text
 for old,new,count in (
 ("test_native_file_source_role_is_explicit_and_fully_verified","test_native_file_render_source_role_is_explicit_and_fully_verified",1),
 ("from hepta.hia_linux_file import PROFILE","from hepta.hia_linux_file_render import PROFILE",1),
 ("examples/hia_bootstrap/native_file_read.hepta","examples/hia_bootstrap/native_file_render.hepta",1),
 ("unregistered_file","unregistered_file_render",2)):
  assert new_method.count(old)==count,(old,new_method.count(old));new_method=new_method.replace(old,new)
 after=replace_once(after,template_text,template_text+"\n"+new_method)
 edit(name,after.encode(),"Preserve old test bodies; add exact v2 source role with real default/unknown/SSA/symlink refusals.")
 projections[name]={"new_method":new_method,"expected_mapping_added":added_expected}

 name="tests/test_hia_installed_fixture_resources.py";before=read(name).decode()
 anchor="               'examples/hia_bootstrap/native_file_read.hepta')"
 replacement="               'examples/hia_bootstrap/native_file_read.hepta',\n"+",\n".join("               "+repr(a) for a in assets)+")"
 after=replace_once(before,anchor,replacement)
 after=replace_once(after,"self.assertEqual(len(assets),205)","self.assertEqual(len(assets),210)")
 edit(name,after.encode(),"Extend exact ENTRY tuple and resource count; keep fresh installed bytes and all negative controls.")
 name="tests/test_hia_linux_stdio_cold.py";before=read(name).decode()
 anchor="        self.assertEqual(ENTRY_BUILD_FILES, original + PROFILE_SOURCE_FILES + process + cli_process + file_process)"
 replacement="        file_render = ("+",\n                       ".join(repr(a) for a in assets)+")\n"
 replacement+="        self.assertEqual(ENTRY_BUILD_FILES, original + PROFILE_SOURCE_FILES + process + cli_process + file_process + file_render)"
 after=replace_once(before,anchor,replacement)
 after=replace_once(after,"for name in PROFILE_SOURCE_FILES + process + cli_process + file_process:","for name in PROFILE_SOURCE_FILES + process + cli_process + file_process + file_render:")
 old_test_sha=hashlib.sha256(before.encode()).hexdigest();new_test_sha=hashlib.sha256(after.encode()).hexdigest()
 edit(name,after.encode(),"Extend only Source resource inventory; preserve all Native methods and cold authority.")
 name="tools/qualify_hia_linux_stdio.py";before=read(name).decode()
 anchor=" 'tests/test_hia_linux_stdio_cold.py': '"+old_test_sha+"',"
 after=replace_once(before,anchor," 'tests/test_hia_linux_stdio_cold.py': '"+new_test_sha+"',")
 assert decl(after)["TEST_SOURCE_PINS"]==dict(decl(before)["TEST_SOURCE_PINS"],**{"tests/test_hia_linux_stdio_cold.py":new_test_sha})
 edit(name,after.encode(),"Update only the complete source pin of the extended inventory test.")
 name="tests/test_hia_proof_contract_native.py";before=read(name).decode()
 after=replace_once(before,"self.assertEqual((len(core), len(mechanisms), len(core | mechanisms)), (54, 53, 107))","self.assertEqual((len(core), len(mechanisms), len(core | mechanisms)), (54, 54, 108))")
 edit(name,after.encode(),"Update one exact role-count tuple; preserve exhaustive actual provider-edge assertions.")

 before_workflow=read(WORKFLOW).decode()
 after_workflow=replace_once(before_workflow," native_file_read; do"," native_file_read "+" ".join(generators)+"; do")
 selector=spec["Source_selector"]
 anchor="              'tests.test_hia_linux_file.LinuxFileSourceTests',\n"
 after_workflow=replace_once(after_workflow,anchor,anchor+"              "+repr(selector)+",\n")
 assert before_workflow.split("\n  native:\n",1)[1]==after_workflow.split("\n  native:\n",1)[1]
 old_yaml,new_yaml=yaml.safe_load(before_workflow),yaml.safe_load(after_workflow)
 assert {k:v for k,v in old_yaml.items() if k!="jobs"}=={k:v for k,v in new_yaml.items() if k!="jobs"}
 assert {k:v for k,v in old_yaml["jobs"].items() if k!="source"}=={k:v for k,v in new_yaml["jobs"].items() if k!="source"}
 assert len(new_yaml["jobs"]["native"]["steps"])==121
 def selectors(value):
  step=next(s for s in value["jobs"]["source"]["steps"] if s.get("name")=="Core source and independent reference controls")
  script=step["run"].split("python -B - <<'PY'\n",1)[1].rsplit("\nPY",1)[0]
  return decl(script)["names"]
 old_selectors,new_selectors=selectors(old_yaml),selectors(new_yaml)
 old_gens=re.search(r"for component in (.*?); do",before_workflow).group(1).split()
 new_gens=re.search(r"for component in (.*?); do",after_workflow).group(1).split()
 assert len(old_gens)==126 and new_gens==old_gens+generators and len(new_gens)==131
 assert len(old_selectors)==230 and new_selectors==old_selectors+(selector,) and len(new_selectors)==231
 edit(WORKFLOW,after_workflow.encode(),"Append five generators and one Source selector; Native121 fragment remains exact.")

 original_contract=decl((BASE/"hepta/hia_agent_contract.py").read_text());contract=decl(read("hepta/hia_agent_contract.py"))
 groups={n:contract[n] for n in h.ROLE_NAMES}
 assert len(groups)==12 and len(groups["NATIVE_SOURCE_FILES"])==92 and len(groups["ENTRY_BUILD_FILES"])==19
 assert groups["ENTRY_BUILD_FILES"]==original_contract["ENTRY_BUILD_FILES"]+assets
 assert all(groups[n]==original_contract[n] for n in h.ROLE_NAMES if n!="ENTRY_BUILD_FILES")
 assert sum(map(len,groups.values()))==210
 all_assets=tuple("docs/"+n for n in groups["DISCOVERY_FILES"])+tuple(p for n in h.ROLE_NAMES[1:] for p in groups[n])
 assert len(all_assets)==len(set(all_assets))==210
 old_sources=decl((BASE/"tools/hia_selfhost_contract.py").read_text())["SOURCE_FILES"]
 new_sources=decl(read("tools/hia_selfhost_contract.py"))["SOURCE_FILES"]
 assert len(old_sources)==1332 and new_sources==old_sources+tuple(new_paths) and len(set(new_sources))==1345
 assert all(n in base or n in contents for n in new_sources)
 old_checker=decl((BASE/"hepta/hia_checker_identity.py").read_text());checker=decl(read("hepta/hia_checker_identity.py"))
 assert checker["SEMANTIC_CORE_SOURCE_FILES"]==old_checker["SEMANTIC_CORE_SOURCE_FILES"]
 assert checker["MECHANISM_SOURCE_FILES"]==old_checker["MECHANISM_SOURCE_FILES"]+("hia_linux_file_render.py",)
 core=set(checker["SEMANTIC_CORE_SOURCE_FILES"]);mech=set(checker["MECHANISM_SOURCE_FILES"])
 assert len(core)==len(mech)==54 and core.isdisjoint(mech)
 providers=checker["CHECKER_MECHANISM_EXTERNAL_PROVIDERS"]
 assert providers==dict(old_checker["CHECKER_MECHANISM_EXTERNAL_PROVIDERS"],**{"hia_linux_file_render.py":("hia_program_runtime.py",)})
 edges={}
 for n in sorted(mech):
  dep=set(relative_imports(read("hepta/"+n)));external=dep-core-mech
  assert external==set(providers.get(n,())),(n,external,providers.get(n))
  edges[n]={"relative_imports":sorted(dep),"external":sorted(external)}
 for n in ("NATIVE_OWNERS","HELD_NATIVE_OWNERS","CAPTURED_NATIVE_OWNERS"):assert checker[n]==old_checker[n]
 old_profiles=decl((BASE/"tools/check_hia_core_only.py").read_text())["EXPLICIT_SOURCE_PROFILES"]
 assert decl(read("tools/check_hia_core_only.py"))["EXPLICIT_SOURCE_PROFILES"]==dict(old_profiles,**spec["core_only_exact_source_profile"])
 allowed={
 "tests/test_hia_source_suffix.py":{"test_linux_stdio_source_roles_are_explicit_and_fully_verified"},
 "tests/test_hia_installed_fixture_resources.py":{"test_standalone_entry_role_is_exact_disjoint_and_preflight_bounded","test_entry_assets_are_fresh_identity_inputs_and_missing_fails_before_backend"},
 "tests/test_hia_linux_stdio_cold.py":{"test_entry_resources_keep_all_four_predecessors_and_are_not_runtime_bridges"},
 "tests/test_hia_proof_contract_native.py":{"test_core_and_mechanism_roles_have_exact_provider_edges"}}
 preservation={};suffix_ids=[]
 for n,permitted in allowed.items():
  before=(BASE/n).read_text();after=read(n).decode();old=methods(before,n[:-3].replace("/","."));new=methods(after,n[:-3].replace("/","."))
  assert [k for k in new if k in old]==list(old)
  changed=[]
  for k,node in old.items():
   a,b=method_bytes(before,node),method_bytes(after,new[k])
   if a!=b:
    changed.append(node.name)
    assertions=lambda t:sum(isinstance(x,ast.Call) and isinstance(x.func,ast.Attribute) and x.func.attr.startswith("assert") for x in ast.walk(t))
    assert assertions(node)==assertions(new[k]),k
  assert set(changed)==permitted,(n,changed,permitted)
  added=sorted(set(new)-set(old));assert len(added)==(1 if n.endswith("test_hia_source_suffix.py") else 0)
  suffix_ids+=added
  preservation[n]={"old_definition_order_ids":list(old),"changed_Source_methods":changed,"added_ids":added,"all_other_original_method_bytes_unchanged":True,"assertion_counts_preserved":True}
 new_test_ids=sorted(methods(read("tests/test_hia_linux_file_render.py"),"tests.test_hia_linux_file_render"))
 assert new_test_ids==spec["Source_ordered_ids_actually_executed"] and len(new_test_ids)==9
 added_ids=suffix_ids+new_test_ids;assert len(added_ids)==10
 for n in base:
  if n.startswith("tests/") and n not in allowed:assert n not in contents
 for n in ("setup.py","tools/hia_retained_agent_callers.py","hepta/hia_native_helpers.py"):
  assert read(n)==(BASE/n).read_bytes()
 for n,b in contents.items():
  if n.endswith(".py"):ast.parse(b,filename=n)
 final=dict(base);final.update({n:identity(b) for n,b in contents.items()})
 assert len(final)==3121 and len(contents)==28 and len(new_paths)==13
 workflow_projection={"before":identity(before_workflow.encode()),"after":identity(after_workflow.encode()),"Native_steps":121,"entire_native_fragment_unchanged":True,"native_fragment_sha256":hashlib.sha256(before_workflow.split("\n  native:\n",1)[1].encode()).hexdigest(),"generators_before":old_gens,"generators_after":new_gens,"selectors_before":old_selectors,"selectors_after":new_selectors,"expected_Source_before":1342,"expected_Source_after":1352,"not_an_executed_loader":True}
 report={"schema":"hia.r13.file-render-v2-source-integration.v1","status":"AUTHORED_NOT_GENERATED_NOT_TESTED","base_tree":BASE_TREE,"source_tree":tree_hash(final),"source_files":3121,"changes":history,"new_paths":new_paths,"source_contract_paths":1345,"ENTRY":19,"NATIVE":92,"resource_groups":groups,"resources":210,"Core":54,"MECH":54,"all54_mechanism_edges":edges,"generators":131,"selectors":231,"Source_expected":1352,"Source_added_ids":added_ids,"Source_method_preservation":preservation,"workflow_projection":workflow_projection,"frozen_component_packet":PACKET,"frozen_component_registration":SPEC,"component_development_results_inherited":False,"full_13_cli_file_actions_replaced":False,"current_source_cold_qualified":False,"whole_native":False,"generation_executed":False,"product_tests_executed":0}
 stage=HERE/"source-attempt-r1";stage.mkdir()
 for n in base:
  p=stage/n;p.parent.mkdir(parents=True,exist_ok=True)
  if n in contents:p.write_bytes(contents[n])
  else:shutil.copyfile(BASE/n,p)
  p.chmod(0o644)
 for n in new_paths:
  p=stage/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(contents[n]);p.chmod(0o644)
 actual,extra=snapshot(stage);assert actual==final and not extra
 after_base,after_caches=snapshot(BASE);assert after_base==base and after_caches==caches
 stage.rename(HERE/"source")
 put(HERE/"BASELINE-MANIFEST.json",encode(base));put(HERE/"SOURCE-MANIFEST.json",encode(final));put(HERE/"INTEGRATION.json",encode(report))
 packet={"schema":"hia.r13.file-render-v2-full-source-overlay.v1","base_tree":BASE_TREE,"current_tree":tree_hash(final),"base_manifest":base,"current_manifest":final,"registration":report,"files":[{"path":n,"before":None if n not in base else dict(base[n],text=(BASE/n).read_text()),"after":dict(final[n],text=contents[n].decode())} for n in sorted(contents)],"whole_native":False}
 decoded=encode(packet);capsule=encode({"schema":"hia.lossless.zlib-json.v1","decoded":identity(decoded),"payload":base64.b64encode(zlib.compress(decoded,9)).decode()})
 put(HERE/"SOURCE-PACKET.zlib.json",capsule)
 for key in ("SOURCE-PACKET.zlib.json","INTEGRATION.json"):
  assert (HERE/key).is_file()
 print(json.dumps({k:report[k] for k in ("status","base_tree","source_tree","source_files","source_contract_paths","ENTRY","resources","Core","MECH","generators","selectors","Source_expected","product_tests_executed")}))
 return report

if __name__=="__main__":
 try:main()
 except BaseException:
  failure={"schema":"hia.r13.integration-authoring-failure.v1","traceback":traceback.format_exc(),"author_script":identity(pathlib.Path(__file__).read_bytes()),"author_script_text":pathlib.Path(__file__).read_text(),"product_tests_executed":0,"whole_native":False}
  put(HERE/"INTEGRATION-FAILURE-R1.json",encode(failure))
  raise
