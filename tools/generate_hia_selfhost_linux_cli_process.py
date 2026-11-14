"""Independent fixed CLI resident-call compiler; ordinary profiles stay unchanged.

Three literal operations invoke only the three immutable, builder-pinned CLI
images published by the matching HIA ELF packer. No integer is accepted as a
code pointer or file descriptor. Existing read/write/startup operations retain
their profile-local semantics; the CLI entry alone has three mutable buffers.
"""
from pathlib import Path
import ast
import hashlib
import json
import sys
import types

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import generate_hia_selfhost as original
from tools import generate_hia_selfhost_linux_process as process
from tools.generate_hia_selfhost_linux_stdio import build, strict

MODULE = 'selfhost_linux_cli_process'
OPS = ('linux.cli.control', 'linux.cli.format', 'linux.cli.discovery')
EFFECT = 'linux_cli'
CAP = 0x600000
MAGIC = int.from_bytes(b'HCLICAP1', 'little')

HELPER = r'''
def cli_resident(o:mutbuf, w:mutbuf, op:u64, n:u64, a:u64, b:u64, at:u64, bt:u64, t:u64) -> u64:
    if get(w, 232) != 5 or n != 9 or t != 3:
        return fail(w, 94)
    loan_call(w, n)
    i = 0
    while i < 9:
        view = get(w, ARGS + i * 8)
        off = get(w, ARGS + (i + 1) * 8)
        extent = get(w, ARGS + (i + 2) * 8)
        vt = variable(w, view)
        if i == 0:
            if vt != 6 and vt != 7:
                return fail(w, 94)
        else:
            if vt != 7:
                return fail(w, 94)
        if variable(w, off) != 2 or variable(w, extent) != 2:
            return fail(w, 94)
        loan_access(w, view)
        bulk_range_guard(o, w, view, off, extent)
        i = i + 3
    # Verify the separate fixed-link capability. A plain process ELF cannot
    # supply this capability merely by having the startup page's old magic.
    emit_bytes(o, w, 0xba48, 2)
    emit8(o, w, CLI_MAGIC)
    emit_bytes(o, w, 0x25143948, 4)
    emit4(o, w, CLI_CAP + 56)
    emit_bytes(o, w, 0x0b0f0274, 4)
    # All borrowed ranges are proved before staging any SysV argument. Local
    # SSA values stay in rbp slots; resident calls may clobber all caller-saved
    # registers. Their wrapper preserves rbp and uses the same u32 return ABI.
    load_var(o, w, 7, a, 0)
    load_var(o, w, 0, b, 0)
    emit_bytes(o, w, 0xc70148, 3)
    load_var(o, w, 6, get(w, ARGS + 16), 0)
    load_var(o, w, 2, get(w, ARGS + 24), 0)
    load_var(o, w, 0, get(w, ARGS + 32), 0)
    emit_bytes(o, w, 0xc20148, 3)
    load_var(o, w, 1, get(w, ARGS + 40), 0)
    # The original mem/load_var encoder admits the eight legacy registers.
    # Move through RAX before the explicit REX.B encodings for R8 and R9.
    load_var(o, w, 0, get(w, ARGS + 48), 0)
    emit_bytes(o, w, 0xc08949, 3)
    load_var(o, w, 0, get(w, ARGS + 56), 0)
    emit_bytes(o, w, 0xc00149, 3)
    load_var(o, w, 0, get(w, ARGS + 64), 0)
    emit_bytes(o, w, 0xc18949, 3)
    emit_bytes(o, w, 0x25048b48, 4)
    emit4(o, w, CLI_CAP + 64 + (op - CLI_CONTROL) * 8)
    emit_bytes(o, w, 0xd0ff, 2)
    return 0
'''


def extension_source():
    # Give the original lexical author its exact old vocabulary plus the fixed
    # new names before it emits keyword tables; never patch opaque image bytes.
    values = dict(vars(original))
    words = dict(original.W)
    for name in (MODULE, EFFECT, *OPS):
        assert name not in words
        words[name] = 300 + len(words)
    values['W'] = words
    clone = types.SimpleNamespace(**values)
    scope = dict(vars(process)); scope['original'] = clone
    text, words, proof = types.FunctionType(process.extension_source.__code__, scope)()
    process_id = words[process.PROFILE]
    cli_id = words[MODULE]
    old = f'''        if state_get32(w, 8) == {process_id}:
            store(w, 232, 4)
'''
    new = old + f'''        if state_get32(w, 8) == {cli_id}:
            store(w, 232, 5)
'''
    text = strict(text, old, new)
    old = '''        if get(w, fb + 48) != 6 or get(w, fb + 56) != 7 or get(w, fb + 64) != 7:
            fail(w, 5)
'''
    new = '''        first_type = 6
        if get(w, 232) == 5:
            first_type = 7
        if get(w, fb + 48) != first_type or get(w, fb + 56) != 7 or get(w, fb + 64) != 7:
            fail(w, 5)
'''
    text = strict(text, old, new)
    # The previously proved output-mode projection stays valid: only 0,4,5 can
    # reach functions. The two old special output modes/exports still refuse.
    tree = ast.parse(text)
    revised = []
    class BothPhysicalProfiles(ast.NodeTransformer):
        def visit_Compare(self, node):
            node = self.generic_visit(node)
            expected = ast.parse('byte(w, 232) != 4', mode='eval').body
            if ast.dump(node, include_attributes=False) == ast.dump(expected, include_attributes=False):
                revised.append(ast.unparse(node))
                return ast.copy_location(ast.parse('byte(w, 232) != 4 and byte(w, 232) != 5', mode='eval').body, node)
            return node
    tree = BothPhysicalProfiles().visit(tree); ast.fix_missing_locations(tree)
    assert len(revised) == 3, revised
    text = ast.unparse(tree) + '\n'
    io = words[process.IO_EFFECT]; startup = words[process.STARTUP_EFFECT]
    old = f'''        if token == {io} or token == {startup}:
'''
    new = f'''        if token == {words[EFFECT]}:
            if get(w, 232) != 5:
                return fail(w, 65)
            flag = 64
        elif token == {io} or token == {startup}:
'''
    text = strict(text, old, new)
    old = 'def instruction_effects(op: u64) -> u64:\n'
    new = old + f'''    if op >= {words[OPS[0]]} and op <= {words[OPS[2]]}:
        return 78
'''
    text = strict(text, old, new)
    old = 'def operation_dispatch(o: mutbuf, w: mutbuf, op: u64, n: u64, a: u64, b: u64, at: u64, bt: u64, t: u64) -> u64:\n'
    new = old + f'''    if op >= {words[OPS[0]]} and op <= {words[OPS[2]]}:
        return cli_resident(o, w, op, n, a, b, at, bt, t)
'''
    text = strict(text, old, new)
    helper = HELPER.replace('CLI_MAGIC', str(MAGIC)).replace('CLI_CAP', str(CAP))
    helper = helper.replace('CLI_CONTROL', str(words[OPS[0]])).replace('ARGS', str(original.ARGS))
    text += helper
    proof.update(new_profile_values=[0, 4, 5], fixed_resident_words={name: words[name] for name in OPS},
        new_effect_word=words[EFFECT], three_existing_profile_refusals_revised=revised,
        new_entry_signature=['mutbuf', 'mutbuf', 'mutbuf'],
        unchanged_ordinary_entry_signature=['readbuf', 'mutbuf', 'mutbuf'])
    return text, proof


def generated():
    text, proof = extension_source()
    raw, _, _ = build(text, True)
    return raw


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description='Generate fixed Linux CLI process compiler')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--report')
    args = parser.parse_args(argv)
    source, proof = extension_source()
    raw, expanded, generation = build(source, True)
    if isinstance(raw, str): raw = raw.encode()
    counts = generation['counts']
    assert len(raw) <= 1048576 and counts['functions'] <= 128 and counts['blocks'] <= 1536 and counts['operations'] <= 8192
    target = ROOT / 'examples/hia_bootstrap/selfhost_linux_cli_process.hepta'
    if args.check:
        if target.read_bytes() != raw: raise SystemExit('Linux CLI process compiler source differs')
    else:
        target.write_bytes(raw)
    report = {'schema': 'hia.linux-cli-process-compiler-generation.v1', 'counts': counts,
        'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'projection': proof,
        'native_executed': False, 'matching_cold': False, 'whole': False}
    if args.report: Path(args.report).write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'projection'}, sort_keys=True))


if __name__ == '__main__':
    main()
