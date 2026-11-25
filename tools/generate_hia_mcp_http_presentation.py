"""HTTP default SDK presentation; original catalog validation and schemas stay intact."""
import ast
from pathlib import Path
from tools import generate_hia_mcp_catalog as catalog
from tools import generate_hia_mcp_service_dispatch as dispatch
from tools import generate_hia_mcp_service_reply as reply
from tools.generate_hia_mcp_service import document
from hepta.hia_agent_assembly import render_assembly

def cloned(module, field, replacement):
    tree=ast.parse(Path(module.__file__).read_text())
    count=0
    for node in ast.walk(tree):
        if isinstance(node,ast.Dict):
            for index,key in enumerate(node.keys):
                if isinstance(key,ast.Constant) and key.value==field:
                    node.values[index]=ast.Constant(replacement)
                    count+=1
    assert count==1,(module.__file__,field,count)
    ns={'__name__':'http_presentation_author','__file__':module.__file__}
    exec(compile(ast.fix_missing_locations(tree),module.__file__,'exec'),ns)
    return ns

def dispatch_source():
    return cloned(dispatch,'control_modern','"ttlMs":0,"resultType":"complete"')['source']()

def render_reply():
    return cloned(reply,'modern_fields',b'"resultType":"complete"')['render']()

def render_catalog():
    names=catalog.tool_names()
    order=tuple(names.index(name)+1 for name in sorted(names))
    code=catalog.POLICY
    needle='        row = 64 + offset * 72'
    assert code.count(needle)==2
    at=code.rindex(needle)
    before="""        selected = http_catalog_ordinal(ordinal)
        offset = get(w, tools + 24)
        index = 1
        while index < selected:
            offset = get(w, 64 + offset * 72 + 16)
            index = index + 1
"""
    code=code[:at]+before+code[at:]
    code+='\ndef http_catalog_ordinal(index:u64) -> u64:\n'
    for index,value in enumerate(order,1):
        code+=f'    if index == {index}:\n        return {value}\n'
    code+='    return 0\n'
    ns={'__name__':'http_catalog_author','__file__':catalog.__file__}
    exec(compile(Path(catalog.__file__).read_text(),catalog.__file__,'exec'),ns)
    ns['POLICY']=code
    return ns['render']()

if __name__=='__main__':
    root=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap'
    values={'mcp_http_reply_policy.hepta':render_reply(),
            'mcp_http_catalog_policy.hepta':render_catalog(),
            'mcp_http_dispatch.hepta':render_assembly(document(dispatch_source(),'mcp_http_dispatch'))}
    for name,raw in values.items():
        (root/name).write_text(raw)
        print(name,len(raw.encode()))
