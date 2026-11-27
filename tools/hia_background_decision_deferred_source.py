"""Private decision/verifier Value custody; legacy domains stay unchanged."""
import ast
from tools import hia_background_deferred_value_source as D
from tools import hia_background_managed_value_source as M

def symbolic(module):
    old = module.C
    try:
        module.C = {key: key for key in old}
        return module.source_program()
    finally:
        module.C = old

def decision_symbolic(module):
    old, parent = module.C, module.original.C
    try:
        module.C = {key: key for key in old}
        module.original.C = {key: key for key in parent}
        return module.source_program()
    finally:
        module.C, module.original.C = old, parent

def apply(text):
    text = D.deferred_policy(text)
    text = M.replace_def(text, "deferred_packet", M.PACKET)
    text = M.replace(text, "    if get(o,RP+8)!=0 and get(o,RP+112)==0:",
        "    if get(o,RP+8)==6 and get(o,RP+112)!=0:\n"
        "        put(o,D_UNKNOWN,1)\n        return 0\n"
        "    if get(o,RP+8)!=0 and get(o,RP+8)!=6 and get(o,RP+112)==0:")
    node = next(n for n in ast.parse(text).body
                if isinstance(n, ast.FunctionDef) and n.name == "request")
    request = ast.get_source_segment(text, node)
    request = M.replace(request, "    return 0",
        "    if magic==VREQUEST or magic==VALUE_DROP_INPUT:\n"
        "        deferred_packet(o,op)\n    return 0")
    text = M.replace_def(text, "request", request)
    node = next(n for n in ast.parse(text).body
                if isinstance(n, ast.FunctionDef) and n.name == "value")
    value = ast.get_source_segment(text, node)
    value = M.replace(value, "    return invoke",
                      "    managed_packet(o)\n    return invoke")
    text = M.replace_def(text, "value", value)
    return text + M.HELPERS + """
def managed_local_pending(o:mutbuf) -> u64:
    if get(o,VALUE_PENDING)!=0 or get(o,NESTED_PENDING)!=0:
        return 1
    return 0
"""
