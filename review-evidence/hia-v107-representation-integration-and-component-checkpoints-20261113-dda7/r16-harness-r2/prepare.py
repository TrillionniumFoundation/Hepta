"""Correct only the R16 harness documentation and its exact containing pins."""
from __future__ import annotations
import ast
import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
BEFORE = HERE.parent / 'formal-preparation-r1'
OUT = HERE / 'harness'


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode()


def pin(data):
    return {'mode': '100644', 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()}


def put(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(data)
    path.chmod(0o644)


def tree(files):
    children, leaves = {}, []
    for name, mode, oid in files:
        first, separator, rest = name.partition('/')
        if separator:
            children.setdefault(first, []).append((rest, mode, oid))
        else:
            leaves.append((first, mode, oid, False))
    for name, rows in children.items():
        leaves.append((name, '40000', tree(rows), True))
    leaves.sort(key=lambda row: row[0].encode() + (b'/' if row[3] else b''))
    raw = b''.join(mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(oid)
                   for name, mode, oid, _ in leaves)
    return hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


assert not OUT.exists()
prior = json.loads((BEFORE / 'HARNESS-PUBLICATION-INTENT.json').read_bytes())
before = {name: (BEFORE / 'harness' / name).read_bytes() for name in prior['files']}
assert {name: pin(raw) for name, raw in before.items()} == prior['files']
after = dict(before)
runner = 'tools/run_parser_bounded.py'
old_line = b'The Source runner and product workflow are unchanged; the fixed materializer adds only the reviewed fourth evidence location.'
new_line = b'The original Source runner and Native workflow fragment are unchanged; the fixed materializer adds only the reviewed fourth evidence location.'
assert before[runner].count(old_line) == 1
after[runner] = before[runner].replace(old_line, new_line)
old_ast, new_ast = ast.parse(before[runner]), ast.parse(after[runner])
assert all(ast.dump(a, include_attributes=False) == ast.dump(b, include_attributes=False)
           for a, b in zip(old_ast.body[1:], new_ast.body[1:]))
assert len(old_ast.body) == len(new_ast.body)
controls = 'inputs/PARSER-CONTROLS.json'
old_controls = json.loads(before[controls]); fixed = json.loads(before[controls])
fixed['harness_files'][runner] = pin(after[runner])
after[controls] = encoded(fixed)
projected = json.loads(after[controls]); projected['harness_files'][runner] = old_controls['harness_files'][runner]
assert projected == old_controls
workflow = '.github/workflows/hia-combined-source.yml'
old_pin, new_pin = pin(before[controls])['git_blob'].encode(), pin(after[controls])['git_blob'].encode()
assert before[workflow].count(old_pin) == 1
after[workflow] = before[workflow].replace(old_pin, new_pin)
changes = []
for name in sorted(after):
    if before[name] != after[name]:
        changes.append({'path': name, 'before': pin(before[name]), 'after': pin(after[name]),
            'diff': ''.join(difflib.unified_diff(before[name].decode().splitlines(True), after[name].decode().splitlines(True),
                                                fromfile='R16-R1/' + name, tofile='R16-R2/' + name))})
    put(OUT / name, after[name])
assert {r['path'] for r in changes} == {runner, controls, workflow}
manifest = {name: pin(raw) for name, raw in sorted(after.items())}
report = dict(prior)
report.update(files=manifest, expected_harness_tree=tree([(name, row['mode'], row['git_blob']) for name, row in manifest.items()]),
              parser_controls=pin(after[controls]),
              supersedes_harness_r1_intent='20e573ba5683f0c868f61cdd2cd8ddc7e787f4d4',
              r2_change='One accurate docstring sentence plus its two exact containing pins; all runtime definitions/limits unchanged',
              r2_changed_files=3, r2_unchanged_files=13)
put(HERE / 'HARNESS-PUBLICATION-INTENT.json', encoded(report))
put(HERE / 'EXACT-DIFFS.json', encoded({'schema': 'hepta.r16-harness-doc-correction.v1', 'changes': changes,
    'r1_preserved': True, 'runtime_definition_AST_equal': True, 'product_execution': 0}))
put(HERE / 'HARNESS-MANIFEST.json', encoded(manifest))
print(json.dumps({'tree': report['expected_harness_tree'], 'intent': pin(encoded(report)),
                  'runner': manifest[runner], 'controls': manifest[controls], 'workflow': manifest[workflow]}))
