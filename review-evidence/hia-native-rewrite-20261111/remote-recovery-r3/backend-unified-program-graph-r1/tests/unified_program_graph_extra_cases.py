"""Exact original P16 oracle/mode plans and unchanged late-Core fixtures.

Development test helper only. It neither runs a target nor builds any Core or
Graph authority. The same actual unified ELF is selected by the caller.
Non-target modes retain the exact original parse_result validator.
"""
from __future__ import annotations
import ast,importlib.util,json,struct
from hashlib import sha256
from pathlib import Path

P16_SHA="d10d9b4f2289a4e770a6680a2a10a81975d941bcec387cfd4fb59f3f23c37937"
PUBLIC_SHA="587eaf984b191928bb53b993f51cdc46e4b3b4d6c0b8e120eba839139150d9c3"
PRIVATE_SHA="010abb4d3eece479ad88bd34f75e58fda2491ce5537a16cc125a2b870cd4c01a"
COUNTS={"compat-semantic":23,"compat-assembly":22,"compat-object":6,
 "late-node-below":1,"late-node-equal":1,"late-node-over":1,
 "late-byte-below":1,"late-byte-equal":1,"late-byte-over":1,
 "late-depth-and-order":6,"late-private-protocol":38}

def prepare(ns):
 path=ns["PROJECT"]/"reference_fixtures/test_worker_program_service_r4.py"
 raw=ns["pin"](path)
 assert (len(raw),sha256(raw).hexdigest())==(27251,P16_SHA)
 names={"canonical","receipt_expected","reference","parse_result","primitive",
  "composite","assembly_text","semantic_plan","assembly_boundary_plan","object_boundary_plan"}
 selected=[node for node in ast.parse(raw,filename=str(path)).body
  if isinstance(node,ast.FunctionDef) and node.name in names]
 assert len(selected)==len(names) and {n.name for n in selected}==names
 oracle={key:ns[key] for key in ("verify_program","HIAProgramRejected","HIAAssemblyRejected",
  "render_assembly","assemble_program","diagnose_assembly","transport")}
 oracle.update(json=json,struct=struct,PLAN=ns["PLAN"])
 exec(compile(ast.Module(body=selected,type_ignores=[]),
  str(path)+":unchanged-original-oracle-functions","exec"),oracle)
 return oracle

def add_public(ns,label,mode,value,tree=0,accept=None,raw=False):
 source=bytes(value) if raw else ns["transport"](value)
 reference=ns["P16"]["reference"](mode,source,tree)
 if accept is not None:
  assert (reference["kind"]!=4)==accept,(label,reference)
 if mode==1 and tree==0:
  if reference["kind"]==1:
   old=reference["program"]
   expected=dict(kind=1,core=old["core"],input_sha256=old["input_sha256"],
    core_sha256=old["core_sha256"],input_bytes=old["input_bytes"],
    structured=old["kind"],version=old["version"],core_version=old["core_version"])
  else:
   assert reference["kind"]==4 and reference["domain"]==1
   expected=dict(kind=4,text=reference["payload"],code=reference["code"],
    error_class="HIAProgramRejected")
 else:
  expected=dict(reference)
 # Exact unchanged late fixture code checks these complete original fields.
 for key in ("payload","program","domain","phase","line"):
  expected[key]=reference[key]
 if "code" in reference:expected["code"]=reference["code"]
 ns["PLAN"].append(dict(label=label,mode=mode,tree=tree,source=source,raw=source,
  digits=4300,expected=expected,p16_expected=reference))

def plan(ns,group):
 assert group in COUNTS and not ns["PLAN"]
 if group.startswith("compat-"):
  def add_compatible(label,mode,value,tree=0,accept=None,raw=False):
   # This explicit new scope is all original non-Graph input combinations.
   # Target mode1/tree0 is covered by the complete original Graph corpus.
   if mode==1 and tree==0:return
   add_public(ns,label,mode,value,tree,accept,raw)
  oracle=ns["P16"];oracle["add"]=add_compatible
  name={"compat-semantic":"semantic_plan","compat-assembly":"assembly_boundary_plan",
   "compat-object":"object_boundary_plan"}[group]
  oracle[name]()
 else:
  assert group!="late-private-protocol"
  path=ns["PROJECT"]/"reference_fixtures/late_core_public_plans_r3.py"
  raw=ns["pin"](path);assert sha256(raw).hexdigest()==PUBLIC_SHA
  spec=importlib.util.spec_from_file_location("unified_exact_late_public",path)
  module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  values=dict(ns)
  values["add"]=lambda label,mode,value,tree=0,accept=None,raw=False:add_public(
   ns,label,mode,value,tree,accept,raw)
  module.plan(values,group)
 assert len(ns["PLAN"])==COUNTS[group]
 if group.startswith("compat-"):
  assert all(row["mode"]!=1 or row["tree"]!=0 for row in ns["PLAN"])
 return dict(group=group,planned_cases=COUNTS[group],original_functions_unmodified=True,
  all_expected_values_from_original_public_oracle_before_native=True,
  no_reference_native_entries=0)

def private(ns):
 path=ns["PROJECT"]/"reference_fixtures/late_core_private_controls_r2.py"
 raw=ns["pin"](path);assert sha256(raw).hexdigest()==PRIVATE_SHA
 spec=importlib.util.spec_from_file_location("unified_exact_late_private",path)
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 values=dict(ns,bundle=ns["BUNDLE"],KERNEL_ENTRIES=0,
  parse_result=ns["P16"]["parse_result"])
 result=None
 try:result=module.run(values)
 finally:
  ns["PRIVATE_ENTRIES"]+=values["KERNEL_ENTRIES"]
  ns["PRIVATE_CASES"]=len(ns["ROWS"])
 if result is not None:
  assert result["planned_cases"]==38
  assert result["actual_entries_by_role"]=={"56":values["KERNEL_ENTRIES"]}
  assert result["complete_sources_outputs_workspaces_and_canaries_recorded"]
 return result
