"""Read-only source-bound Core primitive inventory; no HIA/native generation."""
from pathlib import Path
import ast
import collections
import dataclasses
import hashlib
import importlib.util
import json
import sys
import time

ROOT = Path(__file__).resolve().parent
def pin(path):
    data = path.read_bytes()
    return {'size':len(data), 'sha256':hashlib.sha256(data).hexdigest(),
            'git_blob_sha1':hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()}

def main():
    started=time.monotonic()
    pins=json.loads((ROOT/'SOURCE-PINS.json').read_text())
    for row in pins:
        actual=pin(ROOT/'sources'/row['path'])
        assert all(actual[key]==row[key] for key in actual), row['path']
    path=ROOT/'sources/tools/hia_core_lowering_ir.py'
    name='core_frozen_946_ir_inventory_only'
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module
    spec.loader.exec_module(module)
    source=(ROOT/'sources/tools/hia_core_lowering_policy.py').read_text()
    literals, functions, entries, instructions=module.compile_policy(source)
    names={number:name for name,number in module.OPS.items()}
    counts=collections.Counter()
    operations=collections.defaultdict(collections.Counter)
    per_function=collections.defaultdict(collections.Counter)
    sites=[]
    def operand(value):
        if isinstance(value,module.Raw):return {'raw':value.value}
        if isinstance(value,module.Ref):
            result={'reference':value.kind,'index':value.index}
            if value.kind=='constant':
                constant=literals.values[value.index]
                result.update(constant_type=type(constant).__name__,constant=constant)
            return result
        raise TypeError(type(value).__name__)
    for item in instructions:
        if item['kind']!='effect':continue
        name=names[item['opcode']]
        counts[name]+=1
        per_function[item['function']][name]+=1
        if name in ('BINARY','UNARY','COMPARE','PACK','IMPORT'):
            operations[name][item['arguments'][0].value]+=1
        if name=='UNPACK':operations[name][item['arguments'][1].value]+=1
        sites.append({'pc':item['pc'],'function':item['function'],'primitive':name,
                      'arguments':[operand(x) for x in item['arguments']],
                      'results':len(item['destinations']),
                      'vector_count':len(item.get('vector',()))})
    bare=collections.Counter(node.func.id for node in ast.walk(ast.parse(source))
         if isinstance(node,ast.Call) and isinstance(node.func,ast.Name))
    result={'schema':'hepta.core-hosted-primitives.static-ir-inventory.v2',
            'scope':'New read-only authoring IR scan after environment reset; no HIA or native generation',
            'candidate':'946f3fd08b63846305d3cbf920b61ceed1e696f0',
            'source_pins':pins,'python':sys.version,'primitive_kinds':len(module.OPS),
            'modes':len(entries),'ir_instructions':len(instructions),
            'literal_count':len(literals.values),'static_effect_sites':dict(counts),
            'constant_suboperations':{k:dict(v) for k,v in operations.items()},
            'per_function':{k:dict(v) for k,v in per_function.items()},
            'bare_call_names_in_policy_ast':dict(sorted(bare.items())),
            'sites':sites,'not_runtime_frequencies':True,
            'HIA_generated':False,'native_compiled':False,'product_tests_executed':False}
    target=ROOT/'IR-INVENTORY.json'
    with target.open('x',encoding='utf-8') as stream:
        json.dump(result,stream,ensure_ascii=True,indent=2)
        stream.write('\n')
    for row in pins:
        actual=pin(ROOT/'sources'/row['path'])
        assert all(actual[key]==row[key] for key in actual), row['path']
    summary={'status':'STATIC_IR_INVENTORY_RECORDED','seconds':time.monotonic()-started,
             'result':pin(target),'script':pin(Path(__file__)),'primitive_kinds':len(module.OPS),
             'modes':len(entries),'ir_instructions':len(instructions),
             'effect_sites':sum(counts.values()),'source_before_after_equal':True,
             'HIA_generated':False,'native_compiled':False,'product_tests_executed':False}
    print(json.dumps(summary,sort_keys=True))
if __name__=='__main__':main()
