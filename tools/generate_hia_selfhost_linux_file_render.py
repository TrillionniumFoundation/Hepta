"""Independent file/render compiler: one file capability and two fixed residents.

The ordinary compiler, old file profile and old CLI profiles are unchanged.
Only the explicit new module admits the new entry and resident operations.
"""
from pathlib import Path
import ast
import hashlib
import json
import sys
import types

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import generate_hia_selfhost_linux_file as file
from tools.generate_hia_selfhost_linux_cli_process import HELPER as RESIDENT_HELPER
from tools.generate_hia_selfhost_linux_stdio import build, strict

MODULE = 'selfhost_linux_file_render'
EFFECT = 'linux_render'
OPS = ('linux.render.frontend', 'linux.render.compiler')
CAP = file.CAP
FILE_MAGIC = int.from_bytes(b'HIALFRD1', 'little')
CALL_MAGIC = int.from_bytes(b'HIALFRS1', 'little')


def extension_source():
    original = dict(vars(file.original))
    words = dict(original['W'])
    for name in (EFFECT, *OPS):
        assert name not in words
        words[name] = 300 + len(words)
    original['W'] = words
    namespace = dict(vars(file))
    namespace.update(original=types.SimpleNamespace(**original), MODULE=MODULE, MAGIC=FILE_MAGIC)
    text, proof = types.FunctionType(file.extension_source.__code__, namespace)()
    changes = []

    class NewMode(ast.NodeTransformer):
        def visit_Compare(self, node):
            node = self.generic_visit(node)
            if (len(node.comparators) == 1 and isinstance(node.comparators[0], ast.Constant)
                    and node.comparators[0].value == 6
                    and ast.unparse(node.left) in ('get(w, 232)', 'byte(w, 232)')):
                changes.append(ast.unparse(node))
                node.comparators[0] = ast.Constant(7)
            return node

        def visit_Call(self, node):
            node = self.generic_visit(node)
            if ast.unparse(node) == 'store(w, 232, 6)':
                changes.append(ast.unparse(node))
                node.args[-1] = ast.Constant(7)
            return node

    tree = NewMode().visit(ast.parse(text))
    ast.fix_missing_locations(tree)
    assert len(changes) == 6, changes
    text = ast.unparse(tree) + '\n'
    old = '''        if get(w, fb + 48) != 6 or get(w, fb + 56) != 7 or get(w, fb + 64) != 7:
            fail(w, 5)
'''
    text = strict(text, old, '''        first_type = 6
        if get(w, 232) == 7:
            first_type = 7
        if get(w, fb + 48) != first_type or get(w, fb + 56) != 7 or get(w, fb + 64) != 7:
            fail(w, 5)
''')
    old = f'        if token == {proof["file_effect_word"]}:\n'
    text = strict(text, old, f'''        if token == {words[EFFECT]}:
            if get(w, 232) != 7:
                return fail(w, 96)
            flag = 128
        elif token == {proof['file_effect_word']}:
''')
    old = 'def instruction_effects(op: u64) -> u64:\n'
    text = strict(text, old, old + f'''    if op == {words[OPS[0]]} or op == {words[OPS[1]]}:
        return 142
''')
    old = 'def operation_dispatch(o: mutbuf, w: mutbuf, op: u64, n: u64, a: u64, b: u64, at: u64, bt: u64, t: u64) -> u64:\n'
    text = strict(text, old, old + f'''    if op == {words[OPS[0]]} or op == {words[OPS[1]]}:
        return render_resident(o, w, op, n, a, b, at, bt, t)
''')
    helper = RESIDENT_HELPER.replace('cli_resident', 'render_resident')
    helper = strict(helper, 'get(w, 232) != 5', 'get(w, 232) != 7')
    helper = strict(helper, 'CLI_CAP + 56', 'CLI_CAP + 80')
    for name, value in {'CLI_MAGIC': CALL_MAGIC, 'CLI_CAP': CAP,
                        'CLI_CONTROL': words[OPS[0]], 'ARGS': file.original.ARGS}.items():
        helper = helper.replace(name, str(value))
    text += helper
    proof.update(new_profile_values=[0, 4, 7], old_file_mode_six_rejected=True,
        mode_changes=changes, resident_words={name: words[name] for name in OPS},
        resident_effect_word=words[EFFECT], new_entry_signature=['mutbuf', 'mutbuf', 'mutbuf'],
        fixed_resident_source_roles=['core_json_frontend', 'ordinary_selfhost'],
        actual_call_slots=[CAP + 64, CAP + 72], call_magic_location=CAP + 80,
        file_magic_location=CAP + 56, file_magic=FILE_MAGIC, call_magic=CALL_MAGIC)
    return text, proof


def generated():
    return build(extension_source()[0], True)[0]


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--check', action='store_true')
    p.add_argument('--report', type=Path)
    args = p.parse_args(argv)
    source, proof = extension_source()
    raw, author, report = build(source, True)
    target = ROOT / 'examples/hia_bootstrap/selfhost_linux_file_render.hepta'
    if args.check:
        if target.read_text() != raw:
            raise SystemExit('Linux file/render compiler source differs')
    else:
        target.write_text(raw)
    report.update(projection=proof, source_bytes=len(raw.encode()),
                  source_sha256=hashlib.sha256(raw.encode()).hexdigest(),
                  matching_cold=False, whole=False)
    if args.report:
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({k: report[k] for k in ('counts', 'source_bytes', 'source_sha256', 'matching_cold', 'whole')}, sort_keys=True))


if __name__ == '__main__':
    main()
