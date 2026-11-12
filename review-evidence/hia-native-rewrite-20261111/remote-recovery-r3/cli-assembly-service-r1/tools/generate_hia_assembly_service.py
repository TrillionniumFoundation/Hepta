"""Generate the complete assembly continuation and extended A root.

This is development authoring only. The generated images require independent
actual fixed-carrier and full public reference comparisons. Original A functions
are read from one exact immutable generator snapshot; new assembly control is
a separate file, and the service-two E image table is not part of this module.
"""
from pathlib import Path
from hashlib import sha256
import ast,copy,importlib.util,json,sys
ROOT=Path(__file__).resolve().parents[1]
BASE_SOURCE=ROOT/"tools/program_service_root_reference.py"
CONTROL_SOURCE=ROOT/"tools/assembly_service_control.py"
BASE_SHA="f378c5cd7ef6a053ec63090cc3b3322929f54ef566a29fbaa3f687318c6779d9"
CONTROL_SHA="cca8e05fab7d9e73369729bc2c3f9070b97bf322f26a7d6bdd92de9cbede1bdc"
INPUTS={}
def load_exact(name,path,expected):
    raw=path.read_bytes();assert sha256(raw).hexdigest()==expected,(path,sha256(raw).hexdigest())
    INPUTS[path.resolve()]=raw
    module=type(sys)(name);module.__file__=str(path)
    exec(compile(raw,str(path),"exec"),module.__dict__)
    return module
base=load_exact("assembly_A_root_reference",BASE_SOURCE,BASE_SHA)
control=load_exact("assembly_service_control_reference",CONTROL_SOURCE,CONTROL_SHA)
def one(source,old,new):
    assert source.count(old)==1,(old,source.count(old))
    return source.replace(old,new,1)
def method(text,name):
    node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name==name)
    return ast.unparse(node)+"\n"
original_nodes={n.name:n for n in ast.parse(base.SOURCE).body}
changed={}
def tree_for(name):
    return ast.parse(changed.get(name,method(base.SOURCE,name)))
def save_tree(name,tree):
    changed[name]=ast.unparse(ast.fix_missing_locations(tree))+"\n"
def matching_if(tree,condition):
    expected=ast.dump(ast.parse(condition,mode="eval").body,include_attributes=False)
    hits=[n for n in ast.walk(tree) if isinstance(n,ast.If) and
          ast.dump(n.test,include_attributes=False)==expected]
    assert len(hits)==1,(condition,len(hits))
    return hits[0]
def replace_test(name,old,new):
    tree=tree_for(name);matching_if(tree,old).test=ast.parse(new,mode="eval").body
    save_tree(name,tree)
tree=tree_for("program_service")
node=matching_if(tree,"phase >= 300 and phase < 320");old=copy.deepcopy(node)
prefix=ast.parse(
 "if phase == 87000:\n    result = assembly_finish(w)\n"
 "elif phase >= 60000 and phase < 64000:\n"
 "    result = switch(o, w, ASSEMBLY_DRIVER, phase)\n"
 "else:\n    pass").body[0]
prefix.orelse[0].orelse=[old]
node.test=prefix.test;node.body=prefix.body;node.orelse=prefix.orelse
save_tree("program_service",tree)
replace_test("service_begin","action < 6 or action > 8 or digits > 4294967295",
 "action < 3 or action > 8 or digits > 4294967295")
tree=tree_for("service_begin")
expected=ast.dump(ast.parse("put(w, C_PHASE, 1)").body[0],include_attributes=False)
class StartPhase(ast.NodeTransformer):
    def __init__(self):self.hits=0
    def visit_Expr(self,node):
        if ast.dump(node,include_attributes=False)==expected:
            self.hits+=1
            return ast.parse(
                "if action == 3 or action == 5:\n    put(w, C_PHASE, 60000)\n"
                "else:\n    put(w, C_PHASE, 1)").body[0]
        return node
transform=StartPhase();tree=transform.visit(tree);assert transform.hits==1
save_tree("service_begin",tree)
tree=tree_for("admission_step");node=matching_if(tree,"index == 16")
node.body=ast.parse(
 "if get(w, A_ACTION) == 4:\n    return switch(o, w, ASSEMBLY_DRIVER, 61000)").body+node.body
save_tree("admission_step",tree)
replace_test("parser_row","get(w, A_ACTION) != 8",
 "get(w, A_ACTION) != 3 and get(w, A_ACTION) != 4 and get(w, A_ACTION) != 8")
replace_test("start_result",
 "get(w, A_ACTION) != 8 or get(w, A_OUTPUT) != 1 or domain != 0 or exitcode != 0 or field != 2 or policy != 1 or target != B_PUBLIC_RECEIPT or cap(w, target) != 0 or get(w, A_REQUEST) == 0",
 "assembly_publication_action(w) == 0 or get(w, A_OUTPUT) != 1 or domain != 0 or exitcode != 0 or field != 2 or policy != assembly_publication_policy(w) or target != B_PUBLIC_RECEIPT or cap(w, target) != 0 or get(w, A_REQUEST) == 0")
replace_test("start_result",
 "domain != 0 or exitcode > 1 or field != 0 or policy != 1 or target != 0",
 "domain != 0 or exitcode > 1 or field != 0 or target != 0 or (policy != 1 and (get(w, A_ACTION) != 4 or policy != 2))")
replace_test("result_step",
 "get(w, OBS + 56) <= get(w, A_PARENT_SEQUENCE) or get(w, OBS + 64) != 2 or get(w, OBS + 72) != B_PUBLIC_RECEIPT or get(w, OBS + 88) != 1",
 "get(w, OBS + 56) <= get(w, A_PARENT_SEQUENCE) or get(w, OBS + 64) != 2 or get(w, OBS + 72) != B_PUBLIC_RECEIPT or get(w, OBS + 88) != get(w, A_RESULT_POLICY)")
replace_test("publication_step",
 "get(w, OBS + 32) != get(w, A_YIELD_SEQUENCE) or get(w, OBS + 40) != get(w, A_REQUEST) or get(w, OBS + 48) != get(w, A_PARENT_SEQUENCE) or get(w, OBS + 56) != 1",
 "get(w, OBS + 32) != get(w, A_YIELD_SEQUENCE) or get(w, OBS + 40) != get(w, A_REQUEST) or get(w, OBS + 48) != get(w, A_PARENT_SEQUENCE) or get(w, OBS + 56) != get(w, A_RESULT_POLICY)")
publication=ast.parse(changed["publication_step"])
class PublicationWidths(ast.NodeTransformer):
    def visit_Name(self,node):
        if isinstance(node.ctx,ast.Load) and node.id in ("A_TEXT1_BYTES","A_TEXT2_BYTES","A_TEXT3_BYTES"):
            return ast.copy_location(ast.Call(func=ast.Name(id="publication_text_bytes",ctx=ast.Load()),
                args=[ast.Name(id="w",ctx=ast.Load()),ast.Constant(int(node.id[6]))],keywords=[]),node)
        return node
changed["publication_step"]=ast.unparse(ast.fix_missing_locations(PublicationWidths().visit(publication)))+"\n"
root_nodes=[]
for name,node in original_nodes.items():
    root_nodes.append(ast.parse(changed[name]).body[0] if name in changed else copy.deepcopy(node))
EXPECTED_CHANGED={"program_service","service_begin","admission_step","parser_row","start_result","result_step","publication_step"}
assert set(changed)==EXPECTED_CHANGED
for node in root_nodes:
    if node.name not in EXPECTED_CHANGED:
        assert ast.dump(node,include_attributes=False)==ast.dump(original_nodes[node.name],include_attributes=False)
extra=base.literal_functions()
extra=one(extra,"def publication_literals(w:mutbuf) -> u64:",
          "def program_publication_literals(w:mutbuf) -> u64:")
assembly,constants=control.literal_source()
CONSTANTS=dict(base.CONSTANTS)
for name,value in constants.items():
    assert name not in CONSTANTS or CONSTANTS[name]==value,name
    CONSTANTS[name]=value
assert CONSTANTS["MIN_WORK"]==1<<20
assert CONSTANTS["AS_CODE"]+64<=CONSTANTS["AS_ERROR_LITERAL"]<CONSTANTS["MIN_WORK"]
new_slots={CONSTANTS[n] for n in ("AS_COMMAND","AS_RENDER_WORK","AS_SYNTAX_WORK",
    "AS_OBJECT_OUTPUT","AS_OBJECT_WORK","AS_CANONICAL","AS_FINAL_CORE","AS_JSON_OUTPUT")}
assert len(new_slots)==8 and all(50<slot<64 for slot in new_slots)
for name in ("B_PROGRAM","B_PROGRAM_FRAME","B_CORE","B_CONTROLLER","B_ARGV","B_PARSER",
             "B_RESULT","B_PUBLIC_JSON","B_PUBLIC_RECEIPT"):
    assert CONSTANTS[name] not in new_slots,name
for name in CONSTANTS:
    if name.startswith("B_SHA"):
        assert CONSTANTS[name] not in new_slots,name
WRAPPERS=r'''
def assembly_publication_action(w:mutbuf) -> u64:
    action = get(w, A_ACTION)
    if action == 3 or action == 4 or action == 8:
        return 1
    return 0

def assembly_publication_policy(w:mutbuf) -> u64:
    if get(w, A_ACTION) == 4:
        return 3
    return 1

def publication_literals(w:mutbuf) -> u64:
    if get(w, A_ACTION) == 4:
        return assembly_publication_literals(w)
    return program_publication_literals(w)
'''
ROOT_SOURCE=ast.unparse(ast.Module(body=root_nodes,type_ignores=[]))+"\n"
ALL_SOURCE="\n".join((ROOT_SOURCE,assembly,base.ADMISSION,base.HASH,base.HEX,
                       base.HELPERS,base.COMMON,extra,WRAPPERS))
def expanded(entry):
    tree=ast.parse(ALL_SOURCE);functions={node.name:node for node in tree.body}
    assert len(functions)==len(tree.body)
    live={entry};queue=[entry]
    while queue:
        node=functions[queue.pop()]
        for item in ast.walk(node):
            if isinstance(item,ast.Call) and isinstance(item.func,ast.Name) and item.func.id in functions:
                if item.func.id not in live:live.add(item.func.id);queue.append(item.func.id)
    tree.body=[functions[entry]]+[node for node in tree.body if node.name in live and node.name!=entry]
    # These object/spool cache owners are not part of either assembly context.
    # Their unrelated historical state offsets do not make them reachable.
    forbidden={"opaque_step","object_step","stream_step","outer_step","helper_step"}
    assert not (live&forbidden)
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            if isinstance(node.ctx,ast.Load) and node.id in CONSTANTS:
                return ast.copy_location(ast.Constant(CONSTANTS[node.id]),node)
            return node
    tree=ast.fix_missing_locations(Expand().visit(tree))
    for node in tree.body:
        if node.name!=entry:
            assert node.returns.id in ("u32","u64")
            node.returns.id="u64"
    return ast.unparse(tree)+"\n",sorted(live)

def generate(destination):
    destination=Path(destination);destination.mkdir(parents=True,exist_ok=False)
    records={}
    for entry,label in (("program_service","assembly_A_root"),("assembly_service","assembly_control")):
        text,live=expanded(entry)
        target=destination/(label+".authoring.py");target.write_text(text)
        doc=base.document(text);doc["module"]=label
        raw=base.render_assembly(doc).encode();base.assemble_program(raw)
        path=destination/(label+".hiaasm");path.write_bytes(raw)
        profile=dict(functions=len(doc["functions"]),blocks=sum(len(f["blocks"]) for f in doc["functions"]),
            max_blocks=max(len(f["blocks"]) for f in doc["functions"]),
            ops=sum(len(b["ops"]) for f in doc["functions"] for b in f["blocks"]),
            max_block_params=max(len(b["params"]) for f in doc["functions"] for b in f["blocks"]),
            source_bytes=len(raw),source_sha256=sha256(raw).hexdigest())
        assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["max_blocks"]<=256
        assert profile["ops"]<=8192 and profile["max_block_params"]<=16 and len(raw)<=1<<20
        records[label]=dict(entry=entry,source=str(path),authoring=str(target),reachable=live,profile=profile)
    assert all(path.read_bytes()==raw for path,raw in INPUTS.items())
    assert all(path.read_bytes()==raw for path,raw in base.RAW.items())
    proof=dict(schema="hia-assembly-service-generation-v1",status="GENERATED_ONLY",
        records=records,changed_A_methods=sorted(EXPECTED_CHANGED),
        other_original_A_method_AST_equal=True,original_A_source_sha256=BASE_SHA,
        new_control_sha256=CONTROL_SHA,second_service_E_table_modified=False,
        native_compilations=0,native_entries=0,
        source_pins=[dict(path=str(p),bytes=len(raw),sha256=sha256(raw).hexdigest())
                     for p,raw in {**base.RAW,**INPUTS}.items()])
    (destination/"generation.json").write_text(json.dumps(proof,indent=2,sort_keys=True)+"\n")
    print(json.dumps(proof,sort_keys=True),flush=True)
    return proof
if __name__=="__main__":
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument("--out",required=True)
    args=parser.parse_args();generate(args.out)
