"""Author explicit HIA byte stores with word reads in the existing seed profile.

No new opcode, machine capsule or memory capability is introduced.  Invalid
views and forward-overlap distances below eight retain the original byte loop,
including partial writes before a trap.
"""
import ast


def replace_function(source,name,replacement):
    node=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name==name)
    return source.replace(ast.get_source_segment(source,node),replacement,1)


def stores(buffer,at,value,indent='    '):
    return '\n'.join(f'{indent}store({buffer}, {at}'+(f' + {i}' if i else '')+f', ({value} >> {i*8}) & 255)' for i in range(8))


def accelerate(source):
    definitions={n.name:n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef)}
    if 'put' in definitions:
        source=replace_function(source,'put','def put(w:mutbuf, at:u64, value:u64) -> u64:\n'+stores('w','at','value')+'\n    return 0')
    if 'copyw' in definitions:
        body='''def copyw(w:mutbuf, target:u64, source:u64, count:u64) -> u64:
    i = 0
    if target <= length(w) and source <= length(w) and count <= length(w) - target and count <= length(w) - source and (target <= source or target - source >= 8):
        while i + 8 <= count:
            value = word_load(w, source + i)
            out = target + i
STORES
            i = i + 8
    while i < count:
        store(w, target + i, byte(w, source + i))
        i = i + 1
    return 0'''.replace('STORES',stores('w','out','value','            '))
        source=replace_function(source,'copyw',body)
    if 'same' in definitions:
        source=replace_function(source,'same','''def same(w:mutbuf, a:u64, b:u64, count:u64) -> u64:
    i = 0
    if a <= length(w) and b <= length(w) and count <= length(w) - a and count <= length(w) - b:
        while i + 8 <= count:
            if word_load(w, a + i) != word_load(w, b + i):
                return 0
            i = i + 8
    while i < count:
        if byte(w, a + i) != byte(w, b + i):
            return 0
        i = i + 1
    return 1''')
    if 'same_input' in definitions:
        source=replace_function(source,'same_input','''def same_input(s:readbuf, w:mutbuf, a:u64, b:u64, count:u64) -> u64:
    i = 0
    if a <= length(s) and b <= length(w) and count <= length(s) - a and count <= length(w) - b:
        while i + 8 <= count:
            if word_load(s, a + i) != word_load(w, b + i):
                return 0
            i = i + 8
    while i < count:
        if byte(s, a + i) != byte(w, b + i):
            return 0
        i = i + 1
    return 1''')
    if 'uint' in definitions and len(definitions['uint'].args.args)==2:
        source=replace_function(source,'uint','def uint(s:readbuf, at:u64) -> u64:\n    return word_load(s, at)')
    return source
