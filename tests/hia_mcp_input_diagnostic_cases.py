"""Independent input mutations for the original MCP contract diagnostic oracle."""
from __future__ import annotations
import copy
import json


def valid(schema):
    if type(schema) is bool:
        if schema:return None
        raise ValueError('no witness for false schema')
    if 'const' in schema:return schema['const']
    if 'enum' in schema:return schema['enum'][0]
    for name in ('oneOf','anyOf'):
        if name in schema:return valid(schema[name][0])
    kind=schema.get('type')
    if kind=='object':
        return {key:valid(schema['properties'][key]) for key in schema.get('required',[])}
    if kind=='array':
        return [valid(schema['items']) for _ in range(schema.get('minItems',0))]
    if kind=='null':return None
    if kind=='boolean':return False
    if kind=='integer':return schema.get('minimum',0)
    if kind=='string':
        pattern=schema.get('pattern','')
        if '[0-9a-f]{64}' in pattern:return 'a'*64
        if 'hia://artifacts' in pattern:return 'hia://artifacts/id'
        if pattern.startswith('^(0|'):return '0'
        return 'x'*max(1,schema.get('minLength',0))
    return {}


def mutations(schema):
    base=valid(schema)
    yield 'witness',base
    for index,value in enumerate((None,False,True,0,1.5,'',[],{})):
        yield 'type-'+str(index),value
    if type(schema) is bool:return
    for branch in ('oneOf','anyOf'):
        for index,sub in enumerate(schema.get(branch,[])):
            for label,value in mutations(sub):
                yield branch+'-'+str(index)+'/'+label,value
    kind=schema.get('type')
    if kind=='object':
        for key in schema.get('required',[]):
            value=copy.deepcopy(base);value.pop(key)
            yield 'missing-'+key,value
        for key in ('','0-unknown','z-unknown','.[]','Ω','"\\\n\u0000'):
            value=copy.deepcopy(base);value[key]=None
            yield 'extra-'+repr(key),value
        for key,sub in schema.get('properties',{}).items():
            for label,value in mutations(sub):
                result=copy.deepcopy(base);result[key]=value
                yield key+'/'+label,result
        if schema.get('required'):
            value=copy.deepcopy(base);value.pop(schema['required'][0]);value['0-unknown']=False
            yield 'missing-priority-over-unknown',value
    elif kind=='array':
        witness=valid(schema.get('items',{}))
        for count in sorted({0,1,schema.get('minItems',0),schema.get('maxItems',2),schema.get('maxItems',2)+1}):
            yield 'length-'+str(count),[copy.deepcopy(witness) for _ in range(count)]
        for label,item in mutations(schema.get('items',{})):
            value=copy.deepcopy(base) or [copy.deepcopy(witness)]
            value[-1]=item
            yield 'item/'+label,value
        if schema.get('uniqueItems'):
            pairs=((0,0),(0.0,-0.0),(0,0.0),(1,1.0),('wrong','wrong'),
                   ({},{}),({'k':1},{'k':1.0}),([{'a':1}],[{'a':1}]),
                   ({'b':2,'a':1},{'a':1,'b':2}),({'a':[]},{'a':{}}))
            for index,pair in enumerate(pairs):
                yield 'unique-structural-'+str(index),list(pair)
            deep={'key':'value'}
            for _ in range(90):deep=[deep]
            yield 'unique-nested-90',[deep,copy.deepcopy(deep)]
    elif kind=='string':
        for value in ('x','0','01','+1','-1','18446744073709551615','18446744073709551616',
                      '99999999999999999999','1\n','1\r','a'*64,'a'*64+'\n','A'*64,
                      'hia://artifacts/id','hia://artifacts/id\n','Ω','😀','\u0000','x\n'):
            yield 'text-'+repr(value[:24]),value
        for name in ('minLength','maxLength'):
            if name in schema:
                bound=schema[name]
                for count in sorted({max(0,bound-1),bound,bound+1}):
                    yield name+'-ascii-'+str(count),'x'*count
                if name=='maxLength':
                    yield name+'-unicode','😀'*bound
                    yield name+'-control','\x01'*bound
    elif kind=='integer':
        values={-1,0,1,512,65536,1<<64,(1<<64)-1, -(1<<63)-1}
        for name in ('minimum','maximum'):
            if name in schema:
                bound=schema[name]
                values.update((bound-1,bound,bound+1))
        for value in sorted(values):
            yield 'integer-'+str(value),value
            yield 'integral-float-'+str(value),float(value)
        for value in (0.5,-0.0,511.5,65535.5,1e100,-1e100,5e-324,-5e-324,1.0000000000000002):
            yield 'float-'+repr(value),value


def cases(raw, *, stress=True):
    tools=json.loads(raw)['tools'];seen=set();serial=0
    def unique(tool,label,value):
        nonlocal serial
        encoded=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
        key=(tool,encoded)
        if key in seen:return None
        seen.add(key);serial+=1
        return {'id':serial,'tool':tool,'label':label,'arguments':value}
    for tool in tools:
        for label,value in mutations(tool['inputSchema']):
            row=unique(tool['name'],label,value)
            if row:yield row
    verify=next(t for t in tools if t['name']=='hia_verify')['inputSchema']
    base=valid(verify)
    for claims in (['core_admission'],['behavior_equivalence'],['lowering_refinement'],
                   ['encoding_check'],['behavior_equivalence','lowering_refinement'],
                   ['encoding_check','core_admission'],[],['wrong','wrong'],[{},{}],[0.0,-0.0],
                   [0,0.0],['lowering_refinement','lowering_refinement']):
        for subject in verify['properties']['subject']['oneOf']:
            for prior in (None,valid(verify['properties']['base_program'])):
                value=copy.deepcopy(base);value.update(claims=claims,subject=valid(subject),base_program=prior)
                row=unique('hia_verify','conditional-combination',value)
                if row:yield row
    if stress:
        exact_key_size=(8<<20)-len(json.dumps({"section":"manifest","":None},separators=(",",":"),ensure_ascii=False).encode())
        for size in (524288,1048576,exact_key_size):
            value={'section':'manifest','z'*size:None}
            row=unique('hia_describe','long-unknown-key-'+str(size),value)
            if row:yield row
        for unit in ('\u0000','"','\\','😀'):
            value={'section':'manifest',unit*150000:None}
            row=unique('hia_describe','escaped-unknown-key-'+repr(unit),value)
            if row:yield row
