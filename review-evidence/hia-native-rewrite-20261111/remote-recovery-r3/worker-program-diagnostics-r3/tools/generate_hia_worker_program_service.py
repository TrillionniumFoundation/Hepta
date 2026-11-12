"""Generate Worker program and complete assembly service controllers.

Only method-level adaptation of exact retained native owners is permitted.
This file performs development authoring, never production dispatch or parsing.
Every generated source, actual compiler receipt and image requires a fresh gate.
"""
from pathlib import Path
from hashlib import sha256
import ast,copy,importlib.util,json,re,sys
ROOT=Path(__file__).resolve().parents[1]
INPUTS={}
PINS={
 "program_service_root_reference.py":"f378c5cd7ef6a053ec63090cc3b3322929f54ef566a29fbaa3f687318c6779d9",
 "assembly_service_control_reference.py":"cca8e05fab7d9e73369729bc2c3f9070b97bf322f26a7d6bdd92de9cbede1bdc",
 "worker_program_service.py":"c7575f39085d09c05df5999087657f2825d9219e6d1512beba21d77c3551a3e4",
}
def load(name,filename):
    path=ROOT/"tools"/filename;raw=path.read_bytes()
    assert sha256(raw).hexdigest()==PINS[filename],(path,sha256(raw).hexdigest())
    INPUTS[path.resolve()]=raw
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec);sys.modules[name]=mod
    spec.loader.exec_module(mod)
    return mod
base=load("worker_program_exact_base_r1","program_service_root_reference.py")
assembly=load("worker_program_exact_assembly_r1","assembly_service_control_reference.py")
owner=load("worker_program_owner_r1","worker_program_service.py")
assembly_source,assembly_constants=assembly.literal_source()
CONSTANTS=dict(base.CONSTANTS)
for values in (assembly_constants,owner.CONSTANTS):
    for name,value in values.items():
        assert name not in CONSTANTS or CONSTANTS[name]==value,name
        CONSTANTS[name]=value
assert CONSTANTS["MIN_WORK"]==1048576
assert CONSTANTS["WP_MAGIC"]==73728 and CONSTANTS["WP_HEADER"]+256<=CONSTANTS["MIN_WORK"]
assert CONSTANTS["WP_RECEIPT"]+256<=CONSTANTS["WP_HEADER"]
assert CONSTANTS["AS_ERROR_LITERAL"]<CONSTANTS["WP_MAGIC"]
assert CONSTANTS["AS_CODE_PREFIX"]-CONSTANTS["AS_MAGIC"]+8==320
assert CONSTANTS["B_PROGRAM"]==1 and CONSTANTS["B_EMPTY"]==0 and CONSTANTS["B_CONTROLLER"]==2
assert CONSTANTS["B_RESULT"]==30 and CONSTANTS["MAIN"]==56
for name in ("B_PROGRAM","B_PROGRAM_FRAME","B_CORE","B_CONTROLLER","B_RESULT"):
    assert CONSTANTS[name] not in range(51,59),name
for name in CONSTANTS:
    if name.startswith("B_SHA"):
        assert CONSTANTS[name] not in range(51,59) and CONSTANTS[name]!=30,name

def functions(source):
    tree=ast.parse(source)
    assert all(isinstance(n,ast.FunctionDef) for n in tree.body)
    result={n.name:n for n in tree.body}
    assert len(result)==len(tree.body)
    return result

base_extra=base.literal_functions()
CONSTANTS.update({k:v for k,v in base.CONSTANTS.items() if k not in CONSTANTS})
original_base=functions("\n".join((base.SOURCE,base.ADMISSION,base.HASH,base.HEX,
                                  base.HELPERS,base.COMMON,base_extra)))
original_assembly=functions(assembly_source)
working={k:copy.deepcopy(v) for k,v in original_base.items()}
assert not(set(working)&set(original_assembly))
working.update({k:copy.deepcopy(v) for k,v in original_assembly.items()})
new=functions(owner.BODY)
decide=new.pop("worker_assembly_decide_step");decide.name="assembly_decide_step"
new["assembly_decide_step"]=decide
assert set(new)&set(working)=={"start_result","assembly_decide_step"}
working.update(new)

# The initial verifier's source is an actual immutable raw or completed
# object-prefix byte lease. The original child and its full receipt checks
# otherwise retain their exact AST.
child=copy.deepcopy(original_base["program_child"]);child.name="worker_program_child"
class ChildSource(ast.NodeTransformer):
    def __init__(self):self.count=0
    def visit_Name(self,node):
        if isinstance(node.ctx,ast.Load) and node.id=="B_PROGRAM":
            self.count+=1
            return ast.copy_location(ast.parse("get(w, WP_SELECTED_SLOT)",mode="eval").body,node)
        return node
change=ChildSource();child=change.visit(child)
assert change.count==2
working[child.name]=ast.fix_missing_locations(child)

# The same complete object snapshot/structure/canonical owner can precede
# initial verify. Its input comes from the issuer's complete object transport,
# not a syntax result; all original validation and capacity branches remain.
obj=copy.deepcopy(original_assembly["assembly_object_step"]);obj.name="worker_object_step"
class ObjectInput(ast.NodeTransformer):
    def __init__(self):self.source=0;self.phases={}
    def visit_Name(self,node):
        if isinstance(node.ctx,ast.Load) and node.id=="AS_SYNTAX_WORK":
            self.source+=1
            return ast.copy_location(ast.Name(id="B_PROGRAM",ctx=ast.Load()),node)
        return node
    def visit_Constant(self,node):
        if type(node.value) is int:
            old=node.value
            if 60100<=old<=60107:new_value=old+10900
            elif old==60200:new_value=1
            elif old==62000:new_value=71500
            else:return node
            self.phases[old]=self.phases.get(old,0)+1
            return ast.copy_location(ast.Constant(new_value),node)
        return node
change=ObjectInput();obj=change.visit(obj)
assert change.source==1 and set(change.phases)==set(range(60100,60108))|{60200,62000}
working[obj.name]=ast.fix_missing_locations(obj)

# Preserve the actual validated 256B child receipt before a later render
# roundtrip releases/reuses that child slot. Never synthesize its hashes.
primitive=copy.deepcopy(original_assembly["assembly_primitive_step"])
target=ast.dump(ast.parse("put(w, AS_FINAL_BYTES, get(w, E_CORE_BYTES))").body[0],include_attributes=False)
class ReceiptCapture(ast.NodeTransformer):
    def __init__(self):self.count=0
    def visit_Expr(self,node):
        if ast.dump(node,include_attributes=False)==target:
            self.count+=1
            extra=ast.parse(
                "if get(w, AS_MODE) == 0:\n"
                "    if worker_save_receipt(w, AS_FINAL_CORE) == 0:\n"
                "        return refuse(w, 12070)\n").body
            return extra+[node]
        return node
change=ReceiptCapture();primitive=change.visit(primitive)
assert change.count==1
working[primitive.name]=ast.fix_missing_locations(primitive)

UNCHANGED_ASSEMBLY=sorted(set(original_assembly)-{"assembly_decide_step","assembly_primitive_step"})
for name in UNCHANGED_ASSEMBLY:
    assert ast.dump(working[name],include_attributes=False)==ast.dump(original_assembly[name],include_attributes=False)
for name in ("program_child_frame","program_receipt_header","prefix_failure"):
    assert ast.dump(working[name],include_attributes=False)==ast.dump(original_base[name],include_attributes=False)

def expanded(entry):
    live={entry};pending=[entry]
    while pending:
        for node in ast.walk(working[pending.pop()]):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name):
                name=node.func.id
                if name in working and name not in live:
                    live.add(name);pending.append(name)
    assert not(live&{"parser_row","projection_step","wire_step","result_step","publication_step",
                     "opaque_step","object_step","stream_step","outer_step","helper_step"})
    nodes=[copy.deepcopy(working[entry])]
    nodes.extend(copy.deepcopy(node) for name,node in working.items() if name in live and name!=entry)
    tree=ast.Module(body=nodes,type_ignores=[])
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            if isinstance(node.ctx,ast.Load) and node.id in CONSTANTS:
                return ast.copy_location(ast.Constant(CONSTANTS[node.id]),node)
            return node
    tree=ast.fix_missing_locations(Expand().visit(tree))
    for node in tree.body:
        if node.name!=entry:
            assert isinstance(node.returns,ast.Name) and node.returns.id in ("u32","u64")
            node.returns.id="u64"
    return ast.unparse(tree)+"\n",sorted(live)

def measured(doc):
    fs=doc["functions"];ssa=[]
    for fn in fs:
        names=[x["name"] for x in fn["params"]]
        for block in fn["blocks"]:
            names.extend(x["name"] for x in block["params"])
            for op in block["ops"]:names.extend(x["name"] for x in op.get("out",[]))
        ssa.extend(int(m.group(1)) for n in names if (m:=re.search(r"(\d+)$",n)))
    result=dict(functions=len(fs),blocks=sum(len(f["blocks"]) for f in fs),
        operations=sum(len(b["ops"]) for f in fs for b in f["blocks"]),
        max_function_blocks=max(len(f["blocks"]) for f in fs),
        max_block_parameters=max(len(b["params"]) for f in fs for b in f["blocks"]),
        max_ssa_numeric_suffix=max(ssa,default=0))
    assert result["functions"]<=128 and result["blocks"]<=1536 and result["operations"]<=8192
    assert result["max_function_blocks"]<=256 and result["max_block_parameters"]<=16
    assert result["max_ssa_numeric_suffix"]<2048
    return result

def generate(destination):
    destination=Path(destination);destination.mkdir(parents=True,exist_ok=False)
    records={}
    for entry,label in (("worker_program_service","worker_program_root"),("assembly_service","worker_assembly_control")):
        text,live=expanded(entry)
        (destination/(label+".authoring.py")).write_text(text)
        doc=base.document(text);doc["module"]=label
        profile=measured(doc)
        (destination/(label+".document.json")).write_text(json.dumps(doc,sort_keys=True)+"\n")
        raw=base.render_assembly(doc).encode("utf-8");base.assemble_program(raw)
        assert 0<len(raw)<=1048576
        target=destination/(label+".hiaasm");target.write_bytes(raw)
        records[label]=dict(entry=entry,source=str(target),profile=profile,reachable=live,
                            bytes=len(raw),sha256=sha256(raw).hexdigest())
    pins={**base.RAW,**INPUTS}
    assert all(p.read_bytes()==raw for p,raw in pins.items())
    proof=dict(schema="hia-worker-program-assembly-generation-r1",status="GENERATED_ONLY",
        records=records,unchanged_assembly_methods=UNCHANGED_ASSEMBLY,
        exact_receipt_frame_and_prefix_error_AST_preserved=True,
        program_child_source_selection_only_changed=True,
        actual_native_compilations=0,actual_native_entries=0,
        arbitrary_foreign_object_capture_closed=False,namespace_issued=False,
        inherited_composite_error_groups_without_text=[1,2,3,4,5,6,9],
        source_pins=[dict(path=str(p),bytes=len(raw),sha256=sha256(raw).hexdigest()) for p,raw in pins.items()])
    (destination/"generation.json").write_text(json.dumps(proof,sort_keys=True,indent=2)+"\n")
    print(json.dumps(proof,sort_keys=True),flush=True)
    return proof

if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser();p.add_argument("--out",required=True)
    generate(p.parse_args().out)
