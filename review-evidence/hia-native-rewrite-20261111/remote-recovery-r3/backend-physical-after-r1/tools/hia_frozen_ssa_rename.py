"""Development-only bijective SSA renaming of frozen canonical HIA.

No operation, argument position, label, type, literal, attribute, function order,
block order or edge order changes. The full inverse mapping must reconstruct the
entire original admitted document exactly before the revised source is compiled.
This authoring transform is not a runtime interpreter or a new language quota.
"""
from copy import deepcopy
def definitions(function):
 for block in function["blocks"]:
  yield from block["params"]
  for op in block["ops"]:yield from op["out"]
def visit(function,mapping):
 for param in function["params"]:param["name"]=mapping[param["name"]]
 for block in function["blocks"]:
  for param in block["params"]:param["name"]=mapping[param["name"]]
  for op in block["ops"]:
   op["args"]=[mapping[x] for x in op["args"]]
   for value in op["out"]:value["name"]=mapping[value["name"]]
  term=block["term"];kind=term["op"]
  if kind=="ret":term["values"]=[mapping[x] for x in term["values"]]
  elif kind=="jump":term["args"]=[mapping[x] for x in term["args"]]
  elif kind=="branch":
   term["cond"]=mapping[term["cond"]]
   for side in("then","else"):
    term[side]["args"]=[mapping[x] for x in term[side]["args"]]
  else:assert kind=="trap",kind
def rename(document):
 before=deepcopy(document);changed=deepcopy(document);mappings=[];rows=[]
 assert len({f["name"] for f in before["functions"]})==len(before["functions"])
 for old,new in zip(before["functions"],changed["functions"]):
  names=[x["name"] for x in definitions(old)]
  assert names and len(names)==len(set(names))
  assert all(type(n) is str and n.startswith("v") and n[1:].isdigit() for n in names)
  mapping={name:"v"+str(i) for i,name in enumerate(names)}
  assert len(mapping)==len(set(mapping.values()))
  assert all(p["name"] in mapping for p in old["params"])
  rows.append(dict(function=old["name"],distinct_definitions=len(names),
    original_max_numeric_suffix=max(int(n[1:]) for n in names),
    revised_max_numeric_suffix=len(names)-1,
    old_to_new=[[name,mapping[name]] for name in names]))
  visit(new,mapping);mappings.append(mapping)
 restored=deepcopy(changed)
 for function,mapping in zip(restored["functions"],mappings):
  visit(function,{v:k for k,v in mapping.items()})
 assert restored==before and document==before
 assert len(changed["functions"])==len(document["functions"])
 return changed,dict(schema="hia-frozen-HIA-bijective-SSA-rename-v1",
   original_entire_document_restored_by_inverse=True,
   input_document_unmodified=True,only_SSA_definition_and_use_spellings_changed=True,
   operations_types_literals_attributes_labels_and_order_unchanged=True,
   original_limits_unchanged=True,functions=rows,
   actual_B3_compilation_required=True,actual_semantic_validation_required=True)
