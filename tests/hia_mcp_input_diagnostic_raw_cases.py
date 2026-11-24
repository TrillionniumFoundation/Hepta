"""Raw JSON variants for unchanged Rust Value/schema diagnostic observations."""
from __future__ import annotations
import copy
import json
import math
from tests.hia_mcp_input_diagnostic_cases import cases,valid

MAX_INPUT=8<<20

def raw_text(value, *, escaped_keys=False):
    if type(value) is dict:
        rows=[]
        for key in sorted(value,reverse=True):
            encoded=json.dumps(key,ensure_ascii=False)
            if escaped_keys and key and 32<=ord(key[0])<127 and key[0] not in '\\"':
                encoded='"\\u%04x'%ord(key[0])+encoded[2:]
            rows.append(encoded+':'+raw_text(value[key],escaped_keys=escaped_keys))
        return '{'+','.join(rows)+'}'
    if type(value) is list:
        return '['+','.join(raw_text(v,escaped_keys=escaped_keys) for v in value)+']'
    if type(value) is float and value==0 and math.copysign(1.0,value)<0:
        return '-0'
    return json.dumps(value,separators=(',',':'),ensure_ascii=False,allow_nan=False)


def raw_cases(catalog, *, stress=True):
    serial=0
    for record in cases(catalog,stress=stress):
        text=raw_text(record['arguments'],escaped_keys=record['id']%2==0)
        if len(text.encode())>MAX_INPUT:text=raw_text(record['arguments'])
        if len(text.encode())+2<=MAX_INPUT:text='\t'+text+' '
        serial+=1
        yield {'id':serial,'tool':record['tool'],'label':'raw/'+record['label'],'raw_arguments':text}
    tools=json.loads(catalog)['tools']
    for tool in tools:
        value=valid(tool['inputSchema'])
        if type(value) is dict:
            value['z-raw-unknown']=0;value['a-raw-unknown']=False
            serial+=1
            yield {'id':serial,'tool':tool['name'],'label':'raw/multiple-unknown-order',
                   'raw_arguments':raw_text(value,escaped_keys=True)}
    verify=next(t['inputSchema'] for t in tools if t['name']=='hia_verify')
    base=valid(verify);base['claims']=[]
    template=json.dumps(base,ensure_ascii=False,separators=(',',':'))
    assert template.count('"claims":[]')==1
    pairs=(
        '[1e2,100.0]','[1e2,100]','[-0,0.0]','[-0,0]','[-0.0,0.0]',
        '[18446744073709551616,18446744073709551617]',
        '[18446744073709551615,18446744073709551616]',
        '[-9223372036854775809,-9.223372036854776e18]',
        '[-9223372036854775808,-9.223372036854776e18]',
        '[5e-324,4.9406564584124654e-324]',
        '[1e-400,0.0]',
        '[1.7976931348623157e308,1.7976931348623158e308]',
        '[{"z":2,"a":1},{"a":1,"z":2}]',
        '[{"x":-0},{"x":0.0}]',
        '[{"x":18446744073709551617},{"x":1.8446744073709552e19}]',
    )
    for index,pair in enumerate(pairs):
        serial+=1
        yield {'id':serial,'tool':'hia_verify','label':'raw/number-or-object-unique-'+str(index),
               'raw_arguments':template.replace('"claims":[]','"claims":'+pair)}
    for index,number in enumerate(('512.0','5.12e2','0.512e3','512e0','-0',
                                  '18446744073709551616','-9223372036854775809',
                                  '1e-400','5e-324','65536.00000000000001')):
        serial+=1
        yield {'id':serial,'tool':'hia_describe','label':'raw/number-bound-'+str(index),
               'raw_arguments':'{"section":"manifest","max_bytes":'+number+'}'}
    if stress:
        serial+=1
        small='{"section":"manifest"}'
        yield {'id':serial,'tool':'hia_describe','label':'raw/whitespace-eight-mib',
               'raw_arguments':' '*(MAX_INPUT-len(small))+small}
        serial+=1
        # The raw request stays below the original 8 MiB/262144-node gate;
        # serde expands the finite floats beyond 8 MiB. The first schema
        # refusal must still name the sorted long key before serialization.
        value='{"zz":['+','.join(['1e15']*200000)+'],"section":"manifest","'+'a'*(6<<20)+'":0}'
        assert len(value.encode())<=MAX_INPUT
        yield {'id':serial,'tool':'hia_describe','label':'raw/canonical-expansion-over-eight-mib',
               'raw_arguments':value}
