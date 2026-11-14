"""Explicit fixed read-only Linux-file compiler; no default compiler changes.

The six finite file primitives use a private descriptor cell issued only by
this profile's HIA ELF entry. No source operand chooses a syscall or descriptor.
All HIA values remain in the existing stack slots across rcx/r11 clobbers.
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

MODULE = 'selfhost_linux_file'
EFFECT = 'linux_file'
OPS = ('linux.file.open', 'linux.file.stat', 'linux.file.read',
       'linux.file.close', 'linux.file.fdflags', 'linux.file.statusflags')
CAP = 0x600000
STATE = 0x601000
MAGIC = int.from_bytes(b'HIALFIL1', 'little')
OPEN_FLAGS = 0x20000 | 0x800 | 0x80000

HELPER = r'''
def file_capability(o:mutbuf, w:mutbuf) -> u64:
    # Actual read-only entry capability; a serialized provider is not authority.
    emit_bytes(o, w, 0xb848, 2)
    emit8(o, w, FILE_MAGIC)
    emit_bytes(o, w, 0x25043948, 4)
    emit4(o, w, FILE_CAP + 56)
    emit_bytes(o, w, 0x0b0f0274, 4)
    return 0

def file_descriptor(o:mutbuf, w:mutbuf) -> u64:
    # The only active descriptor comes from this entry's own successful open.
    emit_bytes(o, w, 0x253c8b48, 4)
    emit4(o, w, FILE_STATE)
    emit_bytes(o, w, 0x0b0f0279ff8548, 7)
    return 0

def file_primitive(o:mutbuf, w:mutbuf, op:u64, n:u64, a:u64, b:u64, at:u64, bt:u64, t:u64) -> u64:
    if get(w, 232) != 6 or t != 11:
        return fail(w, 95)
    command = op - FILE_OPEN
    if command < 3:
        if n != 3 or bt != 2:
            return fail(w, 95)
        c = get(w, ARGS + 16)
        if variable(w, c) != 2:
            return fail(w, 95)
        loan_access(w, a)
        if command == 0:
            if at != 6 and at != 7:
                return fail(w, 95)
        else:
            if at != 7:
                return fail(w, 95)
        bulk_range_guard(o, w, a, b, c)
        load_var(o, w, 6, a, 0)
        load_var(o, w, 0, b, 0)
        emit_bytes(o, w, 0xc60148, 3)
        load_var(o, w, 2, c, 0)
        file_capability(o, w)
        if command == 0:
            # A second open cannot replace a live capability or leak its fd.
            emit_bytes(o, w, 0x25048b48, 4)
            emit4(o, w, FILE_STATE)
            emit_bytes(o, w, 0x0b0f0274fff88348, 8)
            # The borrowed range must contain its terminating NUL. The kernel
            # can never scan beyond an admitted view, even for an empty name.
            emit_bytes(o, w, 0x0b0f0275d28548, 7)
            emit_bytes(o, w, 0x027400ff167c80, 7)
            emit_bytes(o, w, 0x0b0f, 2)
            emit_bytes(o, w, 0xffffff9cbf, 5)
            emit_bytes(o, w, 186 + (FILE_FLAGS << 8), 5)
            emit_bytes(o, w, 0xd23145, 3)
            emit_bytes(o, w, 0x00000101b8, 5)
            emit_bytes(o, w, 0x050f, 2)
            # A failed open never publishes an active fd. Store only a real
            # nonnegative kernel return; no host manufactures a capability.
            emit_bytes(o, w, 0x0878c08548, 5)
            emit_bytes(o, w, 0x25048948, 4)
            emit4(o, w, FILE_STATE)
        else:
            if command == 1:
                # Fixed x86-64 struct stat extent, no caller-chosen request.
                emit_bytes(o, w, 0x00000090fa8148, 7)
                emit_bytes(o, w, 0x0b0f0274, 4)
            file_descriptor(o, w)
            number = 0
            if command == 1:
                number = 5
            emit_bytes(o, w, 184 + (number << 8), 5)
            emit_bytes(o, w, 0x050f, 2)
    else:
        if n != 0:
            return fail(w, 95)
        file_capability(o, w)
        file_descriptor(o, w)
        if command == 3:
            # Revoke before close. EINTR/unknown close never authorizes retry.
            emit_bytes(o, w, 0x2504c748, 4)
            emit4(o, w, FILE_STATE)
            emit4(o, w, 4294967295)
            emit_bytes(o, w, 0x00000003b8, 5)
        else:
            flag_command = 1
            if command == 5:
                flag_command = 3
            emit_bytes(o, w, 190 + (flag_command << 8), 5)
            emit_bytes(o, w, 0xd231, 2)
            emit_bytes(o, w, 0x00000048b8, 5)
        emit_bytes(o, w, 0x050f, 2)
    return 0
'''


def extension_source():
    values = dict(vars(original)); words = dict(original.W)
    for name in (MODULE, EFFECT, *OPS):
        assert name not in words
        words[name] = 300 + len(words)
    values['W'] = words
    scope = dict(vars(process)); scope['original'] = types.SimpleNamespace(**values)
    text, words, proof = types.FunctionType(process.extension_source.__code__, scope)()
    old = f'''        if state_get32(w, 8) == {words[process.PROFILE]}:
            store(w, 232, 4)
'''
    text = strict(text, old, old + f'''        if state_get32(w, 8) == {words[MODULE]}:
            store(w, 232, 6)
''')
    revised = []
    class ExtendPhysicalProfile(ast.NodeTransformer):
        def visit_Compare(self, node):
            node = self.generic_visit(node)
            expected = ast.parse('byte(w, 232) != 4', mode='eval').body
            if ast.dump(node, include_attributes=False) == ast.dump(expected, include_attributes=False):
                revised.append(ast.unparse(node))
                return ast.copy_location(ast.parse('byte(w, 232) != 4 and byte(w, 232) != 6', mode='eval').body, node)
            return node
    tree = ExtendPhysicalProfile().visit(ast.parse(text)); ast.fix_missing_locations(tree)
    assert len(revised) == 3, revised
    text = ast.unparse(tree) + '\n'
    old = f'        if token == {words[process.IO_EFFECT]} or token == {words[process.STARTUP_EFFECT]}:\n'
    text = strict(text, old, f'''        if token == {words[EFFECT]}:
            if get(w, 232) != 6:
                return fail(w, 65)
            flag = 64
        elif token == {words[process.IO_EFFECT]} or token == {words[process.STARTUP_EFFECT]}:
''')
    anchor = 'def instruction_effects(op: u64) -> u64:\n'
    text = strict(text, anchor, anchor + f'''    if op == {words[OPS[0]]}:
        return 74
    if op == {words[OPS[1]]} or op == {words[OPS[2]]}:
        return 76
    if op >= {words[OPS[3]]} and op <= {words[OPS[5]]}:
        return 72
''')
    anchor = 'def operation_dispatch(o: mutbuf, w: mutbuf, op: u64, n: u64, a: u64, b: u64, at: u64, bt: u64, t: u64) -> u64:\n'
    text = strict(text, anchor, anchor + f'''    if op >= {words[OPS[0]]} and op <= {words[OPS[5]]}:
        return file_primitive(o, w, op, n, a, b, at, bt, t)
''')
    helper = HELPER
    for name, value in {'FILE_MAGIC': MAGIC, 'FILE_CAP': CAP, 'FILE_STATE': STATE,
                        'FILE_FLAGS': OPEN_FLAGS, 'FILE_OPEN': words[OPS[0]],
                        'ARGS': original.ARGS}.items():
        helper = helper.replace(name, str(value))
    text += helper
    proof.update(new_profile_values=[0,4,6], file_words={x:words[x] for x in OPS},
                 file_effect_word=words[EFFECT], original_profile_comparisons=revised,
                 file_permission='one private read-only descriptor; no caller fd/syscall',
                 borrowed_file_result_limit=8388609, compiler_image_limit=1048576)
    return text, proof


def generated():
    return build(extension_source()[0], True)[0]


def main(argv=None):
    import argparse
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--check',action='store_true');p.add_argument('--report',type=Path)
    args=p.parse_args(argv)
    source, proof=extension_source();raw,author,report=build(source,True)
    target=ROOT/'examples/hia_bootstrap/selfhost_linux_file.hepta'
    if args.check:
        if target.read_text()!=raw:raise SystemExit('Linux file compiler source differs')
    else:target.write_text(raw)
    report.update(projection=proof,source_bytes=len(raw.encode()),
                  source_sha256=hashlib.sha256(raw.encode()).hexdigest(),matching_cold=False,whole=False)
    if args.report:args.report.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:report[k] for k in ('counts','source_bytes','source_sha256','matching_cold','whole')},sort_keys=True))

if __name__=='__main__':main()
