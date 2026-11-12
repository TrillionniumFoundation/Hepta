"""Full-publication parent extended to the three original assembly actions.
The old A/E paths and all filesystem primitives remain exact source inputs.
Only A action selection and assembly publication policy three are added here.
"""
from pathlib import Path
from hashlib import sha256
import ast,copy
import cli_publication_parent_reference as old
assert sha256(Path(old.__file__).read_bytes()).hexdigest()=="1d6ef4b512a81377ec2d54e2b9fdc4bbe748ffaa47c6e7670abf2172ed362460"
CONSTANTS=dict(old.CONSTANTS);COMMON=old.COMMON;literals=old.literals
tree=ast.parse(old.BODY);original={n.name:copy.deepcopy(n) for n in tree.body}
functions={n.name:n for n in tree.body}
def exact_if(name,text):
    expected=ast.dump(ast.parse(text,mode="eval").body,include_attributes=False)
    matches=[n for n in ast.walk(functions[name]) if isinstance(n,ast.If) and
             ast.dump(n.test,include_attributes=False)==expected]
    assert len(matches)==1,(name,text,len(matches))
    return matches[0]
node=exact_if("business_begin_step","action >= 6 and action <= 8")
node.test=ast.parse("action >= 3 and action <= 8",mode="eval").body
node=exact_if("business_result","get(w, B_FORMAT) > 2")
node.test=ast.parse("get(w, B_FORMAT) > 3",mode="eval").body
node=exact_if("publication_path","get(w, B_FORMAT) < 1 or get(w, B_FORMAT) > 2 or get(w, B_PAYLOAD_BYTES) == 0")
node.test=ast.parse(
    "get(w, B_FORMAT) < 1 or get(w, B_FORMAT) > 3 or get(w, B_PAYLOAD_BYTES) == 0 or "
    "(get(w, B_FORMAT) == 3 and (get(w, B_SERVICE) != 1 or get(w, S_ACTION) != 4))",mode="eval").body
# Fixed message codes 1..18 retain their original values. New policy-three
# destination refusals use the two appended presentation messages 19 and 20.
target=ast.parse("code = code + (get(w, PP_POLICY) - 1) * 2").body[0]
expected=ast.dump(target,include_attributes=False)
class PolicyMessage(ast.NodeTransformer):
    def __init__(self):self.hits=0
    def visit_Assign(self,node):
        if ast.dump(node,include_attributes=False)==expected:
            self.hits+=1
            return ast.parse(
              "if get(w, PP_POLICY) == 3:\n    code = code + 18\n"
              "else:\n    code = code + (get(w, PP_POLICY) - 1) * 2").body[0]
        return node
transform=PolicyMessage();functions["publication_path"]=transform.visit(functions["publication_path"])
assert transform.hits==1
tree.body=[functions[n.name] for n in tree.body]
changed={"business_begin_step","business_result","publication_path"}
for node in tree.body:
    if node.name not in changed:
        assert ast.dump(node,include_attributes=False)==ast.dump(original[node.name],include_attributes=False)
BODY=ast.unparse(ast.fix_missing_locations(tree))+"\n"
