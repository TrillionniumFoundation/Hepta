"""Small development-only checks of the existing selfhost compiler loan gate.

Uses the already produced B3 image; never builds a seed/compiler or edits the
frozen repository. Trap-only negative callees isolate admission of the caller's
declared returned loans from rejection inside a callee's normal return body.
"""
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path('/workspace/scratch/623459b0e1bc/Hepta')
OUT = Path('/workspace/scratch/623459b0e1bc/selfhost-returned-loan-audit')
B3 = Path('/workspace/scratch/623459b0e1bc/dev-bootstrap/B3.image.bin')
sys.path.insert(0, str(ROOT))
from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program import HIAProgramRejected
from tools.qualify_hia_selfhost import invoke

OUT.mkdir(exist_ok=False)
paths = ['tools/generate_hia_selfhost.py', 'tools/hia_selfhost_multi_results.py',
         'tools/hia_selfhost_returned_loans.py', 'examples/hia_bootstrap/selfhost.hepta',
         'tools/generate_hia_agent_stdio.py', 'tools/hia_selfhost_child.py']
before = {p: sha256((ROOT / p).read_bytes()).hexdigest() for p in paths}
b3_receipt = json.loads(B3.with_name('B3.receipt.json').read_bytes())
b3_sha = sha256(B3.read_bytes()).hexdigest()
assert b3_receipt['produced_sha256'] == b3_sha
assert b3_receipt['input_sha256'] == before['examples/hia_bootstrap/selfhost.hepta']
assert B3.with_name('B3.input.bin').read_bytes() == (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes()


def source(types, *, valid, parent='mutbuf'):
    call_outputs = ','.join(f'v{i+3}:{t}' for i, t in enumerate(types))
    origin = 'v1' if parent == 'mutbuf' else 'v0'
    text = ('hia-asm.v1 hepta.hia.program.v8 selfhost\n'
            'fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(read,write,trap) entry(b0)\n'
            'block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)\n'
            f'  {call_outputs} = call({origin}) {{"function":"f1"}}\n')
    for i, typ in enumerate(types):
        if typ in ('readbuf', 'mutbuf'):
            text += f'  _ = loan.end(v{i+3})\n'
    text += '  v10:u32 = const() {"value":0}\n  ret(v10)\nend\n'
    loans = ['v0' if typ in ('readbuf', 'mutbuf') else None for typ in types]
    text += (f'fn f1(v0:{parent}) -> ({",".join(types)}) effects(read,write,trap) entry(b0) '
             f'return_loans({json.dumps(loans,separators=(",", ":"))})\n'
             f'block b0(v0:{parent})\n')
    if valid:
        for i, typ in enumerate(types):
            if typ == 'u32':
                text += f'  v{i+1}:u32 = const() {{"value":17}}\n'
            else:
                text += f'  v{i+1}:{typ} = borrow.read(v0)\n'
        text += '  ret(' + ','.join(f'v{i+1}' for i in range(len(types))) + ')\n'
    else:
        text += '  trap user\n'
    return (text + 'end\n').encode()


definitions = [
    ('mut-mut', ('mutbuf', 'mutbuf'), False, 'mutbuf'),
    ('mut-read', ('mutbuf', 'readbuf'), False, 'mutbuf'),
    ('read-mut', ('readbuf', 'mutbuf'), False, 'mutbuf'),
    ('mut-scalar-mut', ('mutbuf', 'u32', 'mutbuf'), False, 'mutbuf'),
    ('mut-scalar-read', ('mutbuf', 'u32', 'readbuf'), False, 'mutbuf'),
    ('read-scalar-mut', ('readbuf', 'u32', 'mutbuf'), False, 'mutbuf'),
    ('shared-two-mut-parent', ('readbuf', 'readbuf'), True, 'mutbuf'),
    ('shared-scalar-shared', ('readbuf', 'u32', 'readbuf'), True, 'mutbuf'),
    ('shared-three', ('readbuf', 'readbuf', 'readbuf'), True, 'mutbuf'),
    ('shared-two-read-parent', ('readbuf', 'readbuf'), True, 'readbuf'),
]
rows = []
for label, types, valid, parent in definitions:
    raw = source(types, valid=valid, parent=parent)
    try:
        checked = assemble_program(raw)
        host = {'accepted': True, 'canonical_sha256': checked.sha256}
    except HIAProgramRejected as error:
        host = {'accepted': False, 'code': error.code, 'message': str(error)}
    receipt, output = invoke(OUT, label, B3, raw, capacity=1 << 16)
    actual_accepted = (receipt.get('status') == 'returned' and receipt.get('abi_status') == 0
                       and type(receipt.get('core_u32')) is int
                       and 0 < receipt['core_u32'] <= len(output))
    native_refusal = (receipt.get('status') == 'returned' and receipt.get('abi_status') == 0
                      and receipt.get('core_u32') == 0xffffffff
                      and receipt.get('workspace_header', {}).get('40') == 62)
    good = (host['accepted'] is valid and actual_accepted is valid
            and (valid or (host.get('code') == 'E_HIA_LOAN' and native_refusal))
            and receipt.get('source_unchanged') is True
            and receipt.get('forbidden_compiler_modules_loaded') == [])
    rows.append({'case': label, 'return_types': types, 'parent': parent,
                 'expected_accepted': valid, 'host': host,
                 'native_accepted': actual_accepted, 'native_receipt': receipt,
                 'pass': good})
    print(json.dumps({'case': label, 'host': host, 'native_core_u32': receipt.get('core_u32'),
                      'native_resource_error': receipt.get('workspace_header', {}).get('40'),
                      'pass': good}), flush=True)

after = {p: sha256((ROOT / p).read_bytes()).hexdigest() for p in paths}
result = {'schema': 'hepta.hia.selfhost-returned-loan-development-audit.v1',
          'status': 'DEVELOPMENT_CONTROLS_PASS' if all(r['pass'] for r in rows) and after == before else 'HOLD',
          'cases': rows, 'source_sha256': before, 'source_preserved': before == after,
          'compiler_sha256': b3_sha, 'compiler_source_sha256': b3_receipt['input_sha256'],
          'compiler_receipt': str(B3.with_name('B3.receipt.json')),
          'compiler_rebuilt': False, 'fresh_cold_qualification': False,
          'raw_stdio_executable_executed': False,
          'candidate_programs_executed': False,
          'scope': 'actual existing B3 admission of <=3 result assembly; host reference comparison; stdio source review only'}
(OUT / 'result.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
print(json.dumps({'status': result['status'], 'cases': len(rows), 'source_preserved': before == after}), flush=True)
raise SystemExit(0 if result['status'] == 'DEVELOPMENT_CONTROLS_PASS' else 1)
