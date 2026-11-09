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


def lookup_program(offset=0):
    """Expose the exact authored keyword function through the public byte ABI."""
    from tools.generate_hia_selfhost import document
    from hepta.hia_agent_assembly import render_assembly, assemble_program
    from tools.hia_selfhost_bulk import Body
    from tools.hia_selfhost_cases import HEADER
    doc, names = document()
    keyword = next(fn for fn in doc["functions"] if fn["name"] == names["keyword"])
    keyword = {**keyword, "name": "f1"}
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
    rows = []
    for case in cases():
        checked = assemble_program(reference_source(case))
        result = execute_program(checked, "reference_entry", [])
        if result.get("status") != "returned" or result["values"] != [case["expected_result"], 165]:
            raise AssertionError({"case": case["id"], "result": result})
        rows.append({**case, "reference_result": result, "reference_sha256": checked.sha256})
    return {"cases": rows, "refusals": [], "before_B0": True,
            "lookup_uses_exact_bytes_not_hashes": True, "all_input_correctness_proved": False}


def qualify(directory, compilers, checks, reference):
    from tools.hia_selfhost_multi_results import qualify as qualify_observations
    return qualify_observations(directory, compilers, checks, reference, family="keyword")
