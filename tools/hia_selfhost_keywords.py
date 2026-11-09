"""Authoring helper: exact packed-byte keyword lookup without per-keyword CFG."""

def keyword_source(words):
    lines = ['def keyword(s:readbuf, begin:u64, size:u64) -> u64:',
             '    if size > 32:', '        return 0',
             '    a = 0', '    b = 0', '    c = 0', '    d = 0', '    i = 0', '    value = 0',
             '    while i < size:', '        value = byte(s, begin + i)',
             '        if i < 8:', '            a = a | (value << (i * 8))',
             '        else:', '            if i < 16:', '                b = b | (value << ((i - 8) * 8))',
             '            else:', '                if i < 24:', '                    c = c | (value << ((i - 16) * 8))',
             '                else:', '                    d = d | (value << ((i - 24) * 8))',
             '        i = i + 1', '    result = 0']
    for word, token in words.items():
        raw = word.encode('ascii')
        if not 0 < len(raw) <= 32 or b'\0' in raw:
            raise ValueError('keyword must be nonempty ASCII without NUL, at most 32 bytes')
        padded = raw.ljust(32, b'\0')
        chunks = [int.from_bytes(padded[i:i+8], 'little') for i in range(0, 32, 8)]
        condition = ' and '.join([f'size == {len(raw)}', *[f'{name} == {value}' for name,value in zip('abcd',chunks)]])
        lines.append(f'    result = choose({condition}, {token}, result)')
    lines.append('    return result')
    return '\n'.join(lines) + '\n'


def keyword_function():
    """Lower exactly the current keyword body, not all unrelated functions."""
    import ast
    from tools.generate_hia_selfhost import Builder, source_program
    node = next(n for n in ast.parse(source_program()).body if n.name == "keyword")
    builder = Builder(node, {"keyword": "f1"}, {})
    builder.statements(node.body)
    return {"name": "f1", "params": [builder.param(p) for p in builder.params],
            "returns": ["u64"], "effects": ["read", "write", "trap"],
            "entry": "b0", "blocks": builder.blocks}


def lookup_program(offset=0):
    """Expose the exact authored keyword function through the public byte ABI."""
    from hepta.hia_agent_assembly import render_assembly, assemble_program
    from tools.hia_selfhost_bulk import Body
    from tools.hia_selfhost_cases import HEADER
    keyword = keyword_function()
    body = Body()
    begin = body.const("u64", offset)
    size = body.value("usize", "buffer.len", ["v0"])
    wide = body.value("u64", "int.cast", [size], {"mode": "wrap"})
    remaining = body.value("u64", "int.sub.wrap", [wide, begin])
    token = body.value("u64", "call", ["v0", begin, remaining], {"function": "f1"})
    result = body.value("u32", "int.cast", [token], {"mode": "wrap"})
    helper = render_assembly({"schema": "hepta.hia.program.v8", "module": "selfhost",
                              "functions": [keyword]}).split("\n", 1)[1]
    source = HEADER + body.text() + "  ret(" + result + ")\nend\n" + helper
    assemble_program(source.encode())
    return source



def cases():
    from tools.generate_hia_selfhost import W
    values = [(word.encode(), token) for word, token in W.items()]
    values += [(word.encode() + b'x', 0) for word in W]
    values += [(word.encode()[:-1] + b'!', 0) for word in W]
    values += [(b'', 0), (b'\0', 0), (b'x' * 32, 0), (b'x' * 33, 0), (b'x' * 256, 0), (b'fn\0', 0)]
    rows = []
    for offset in (0, 3):
        source = lookup_program(offset)
        for index, (data, token) in enumerate(values):
            rows.append({"id": str(offset) + "-" + str(index), "program": "keyword-offset-" + str(offset),
                         "source": source, "source_hex": (b'?' * offset + data).hex(),
                         "initial_hex": "a5", "expected_hex": "a5", "expected_result": token,
                         "expected_values": [], "owned_elf_only": False})
    return rows


def independent_reference():
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    from tools.hia_selfhost_loans import reference_source
    rows, batches, groups, harnesses = [], [], {}, {}
    for case in cases():
        groups.setdefault(case["program"], []).append(case)
    for program, group in groups.items():
        short = [c for c in group if len(bytes.fromhex(c["source_hex"])) <= 32]
        for start in range(0, len(short), 16):
            chunk = short[start:start+16]
            key = (program, len(chunk))
            if key not in harnesses:
                params = []
                for i in range(len(chunk)):
                    params += ["v"+str(i*5+j)+":"+("usize" if j==4 else "u64") for j in range(5)]
                signature = ",".join(params)
                returns = ",".join(["u32", "u8"] * len(chunk))
                entry = "fn reference_batch("+signature+") -> ("+returns+") effects(alloc,read,write,trap) entry(b0)\nblock b0("+signature+")\n"
                outputs = []
                for i in range(len(chunk)):
                    first = len(params)+i*2
                    a,b = "v"+str(first),"v"+str(first+1)
                    arguments = ",".join("v"+str(i*5+j) for j in range(5))
                    entry += "  "+a+":u32,"+b+":u8 = call("+arguments+') {"function":"reference_one"}\n'
                    outputs += [a,b]
                entry += "  ret("+",".join(outputs)+")\nend\n"
                helper = REFERENCE_WRAPPER.replace("fn reference_entry(","fn reference_one(",1)
                harnesses[key] = assemble_program((chunk[0]["source"]+helper+entry).encode())
            checked = harnesses[key]
            arguments, expected = [], []
            for case in chunk:
                data = bytes.fromhex(case["source_hex"])
                padded = data.ljust(32,b"\0")
                arguments += [int.from_bytes(padded[i:i+8],"little") for i in range(0,32,8)]+[len(data)]
                expected += [case["expected_result"],165]
            result = execute_program(checked,"reference_batch",arguments)
            if result.get("status")!="returned" or result["values"]!=expected:
                raise AssertionError({"program":program,"start":start,"result":result})
            batch_index = len(batches)
            batches.append({"program":program,"start":start,"case_ids":[c["id"] for c in chunk],
                "core_sha256":checked.sha256,"arguments":arguments,"result":result})
            for i,case in enumerate(chunk):
                rows.append({**case,"reference_result":{"status":"returned","values":result["values"][i*2:i*2+2],
                    "batch_result_projection":True,"batch_index":batch_index},
                    "reference_sha256":checked.sha256,"reference_arguments":arguments[i*5:i*5+5],
                    "reference_wrapper":"batched-scalar-materialized-exact-input"})
        for case in group:
            if len(bytes.fromhex(case["source_hex"]))<=32:continue
            checked=assemble_program(reference_source(case))
            result=execute_program(checked,"reference_entry",[])
            if result.get("status")!="returned" or result["values"]!=[case["expected_result"],165]:
                raise AssertionError({"case":case["id"],"result":result})
            rows.append({**case,"reference_result":result,"reference_sha256":checked.sha256,
                "reference_arguments":[],"reference_wrapper":"literal-exact-input"})
    native_cases=native_banks(rows)
    for bank in native_cases:
        checked=assemble_program(reference_source(bank))
        result=execute_program(checked,"reference_entry",[])
        if result.get("status")!="returned" or result["values"]!=[0,*bytes.fromhex(bank["expected_hex"])]:
            raise AssertionError({"bank":bank["id"],"result":result})
        bank["reference_result"]=result
        bank["reference_sha256"]=checked.sha256
    compact_rows=[{k:v for k,v in row.items() if k!="source"} for row in rows]
    return {"cases":native_cases,"keyword_cases":compact_rows,"refusals":[],"reference_batches":batches,"before_B0":True,
            "lookup_uses_exact_bytes_not_hashes":True,"all_input_correctness_proved":False}


def qualify(directory, compilers, checks, reference):
    from tools.hia_selfhost_multi_results import qualify as qualify_observations
    return qualify_observations(directory, compilers, checks, reference, family="keyword")


# Independent VM-only harness. Scalar arguments carry the actual input bytes;
# the loop materializes exactly that length, not a padded source allocation.
# General Core checks this ordinary wrapper once; it is never successor code.
REFERENCE_WRAPPER = '''fn reference_entry(v0:u64,v1:u64,v2:u64,v3:u64,v4:usize) -> (u32,u8) effects(alloc,read,write,trap) entry(b0)
block b0(v0:u64,v1:u64,v2:u64,v3:u64,v4:usize)
  v5:buffer = buffer.new(v4)
  v6:mutbuf = borrow.mut(v5)
  v7:usize = const() {"value":0}
  jump b1(v0,v1,v2,v3,v4,v5,v6,v7)
block b1(v8:u64,v9:u64,v10:u64,v11:u64,v12:usize,v13:buffer,v14:mutbuf,v15:usize)
  v16:bool = compare.lt(v15,v12)
  branch v16 b2(v8,v9,v10,v11,v12,v13,v14,v15) b3(v13,v14)
block b2(v17:u64,v18:u64,v19:u64,v20:u64,v21:usize,v22:buffer,v23:mutbuf,v24:usize)
  v25:usize = const() {"value":3}
  v26:usize = int.shr.checked(v24,v25)
  v27:usize = const() {"value":1}
  v28:usize = const() {"value":2}
  v29:bool = compare.eq(v26,v27)
  v30:bool = compare.eq(v26,v28)
  v31:bool = compare.eq(v26,v25)
  v32:u64 = select(v29,v18,v17)
  v33:u64 = select(v30,v19,v32)
  v34:u64 = select(v31,v20,v33)
  v35:usize = const() {"value":7}
  v36:usize = bit.and(v24,v35)
  v37:usize = int.shl.checked(v36,v25)
  v38:u64 = int.cast(v37) {"mode":"wrap"}
  v39:u64 = int.shr.checked(v34,v38)
  v40:u8 = int.cast(v39) {"mode":"wrap"}
  _ = buffer.store(v23,v24,v40)
  v41:usize = int.add.wrap(v24,v27)
  jump b1(v17,v18,v19,v20,v21,v22,v23,v41)
block b3(v42:buffer,v43:mutbuf)
  _ = loan.end(v43)
  v44:readbuf = borrow.read(v42)
  v45:usize = const() {"value":1}
  v46:buffer = buffer.new(v45)
  v47:mutbuf = borrow.mut(v46)
  v48:usize = const() {"value":0}
  v49:u8 = const() {"value":165}
  _ = buffer.store(v47,v48,v49)
  v50:buffer = buffer.new(v48)
  v51:mutbuf = borrow.mut(v50)
  v52:u32 = call(v44,v47,v51) {"function":"f0"}
  v53:u8 = buffer.load(v47,v48)
  _ = loan.end(v44)
  _ = loan.end(v47)
  _ = loan.end(v51)
  _ = owner.drop(v42)
  _ = owner.drop(v46)
  _ = owner.drop(v50)
  ret(v52,v53)
end
'''


def bank_program(offset=0):
    import ast
    from tools.generate_hia_selfhost import Builder
    from hepta.hia_agent_assembly import render_assembly,assemble_program
    text='''def compile(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    cursor = 0
    at = 0
    n = length(s)
    size = 0
    begin = 0
    token = 0
    i = 0
    while cursor < n:
        size = byte(s, cursor) | (byte(s, cursor + 1) << 8)
        begin = cursor + 2
        if size < OFFSET:
            return 4294967295
        if begin > n or size > n - begin:
            return 4294967295
        token = keyword(s, begin + OFFSET, size - OFFSET)
        i = 0
        while i < 8:
            store(o, at + i, (token >> (i * 8)) & 255)
            i = i + 1
        at = at + 8
        cursor = begin + size
    return 0
'''.replace('OFFSET',str(offset))
    node=ast.parse(text).body[0]
    builder=Builder(node,{'compile':'f0','keyword':'f1'},{'keyword':(['readbuf','u64','u64'],'u64')})
    builder.statements(node.body)
    entry={'name':'f0','params':[builder.param(p) for p in builder.params],'returns':['u32'],
           'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks}
    keyword=keyword_function()
    source=render_assembly({'schema':'hepta.hia.program.v8','module':'selfhost',
        'functions':[entry,{**keyword,'name':'f1'}]})
    # render_assembly verified the complete document and parsed round trip.
    return source


def native_banks(rows):
    groups={}
    for row in rows:groups.setdefault(row['program'],[]).append(row)
    result=[]
    for program,group in groups.items():
        offset=int(program.rsplit('-',1)[1]);source=bank_program(offset)
        for start in range(0,len(group),31):
            chunk=group[start:start+31]
            raw=b''.join(len(bytes.fromhex(c['source_hex'])).to_bytes(2,'little')+bytes.fromhex(c['source_hex']) for c in chunk)
            output=b''.join(c['expected_result'].to_bytes(8,'little') for c in chunk)
            result.append({'id':program+'-bank-'+str(start//31),'program':program+'-bank','source':source,
                'source_hex':raw.hex(),'initial_hex':(b'\xa5'*len(output)).hex(),'expected_hex':output.hex(),
                'expected_result':0,'expected_values':[c['expected_result'] for c in chunk],'owned_elf_only':False,
                'input_cases':[{k:v for k,v in c.items() if k not in ('source','reference_result')} for c in chunk]})
    return result
