"""Freeze the static correction and its already-materialized new request."""
from pathlib import Path
from hashlib import sha1, sha256
import ast
import json
import os

ROOT = Path('/workspace/scratch/e26ed3e2edcf/native-cli-json-graph-r1')
HERE = ROOT / 'implementation-r4b1'
OLD = ROOT / 'implementation-r4b'
REQUEST = ROOT / 'source-authoring-r4b1'
PARENT = '60e30e1bd5ad5a7434ea0019767e5c9210e32be7'


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def create(path, value):
    raw = wire(value)
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    assert path.read_bytes() == raw


def authoring(path):
    tree = ast.parse(path.read_bytes())
    value = next(node.value.value for node in tree.body if isinstance(node, ast.Assign)
                 and any(isinstance(target, ast.Name) and target.id == 'SOURCE' for target in node.targets))
    return ast.parse(value)


def main():
    name = 'inputs/tools/generate_hia_cli_json_scalar.py'
    before = (OLD / name).read_bytes()
    after = (HERE / name).read_bytes()
    old_ast, new_ast = authoring(OLD / name), authoring(HERE / name)
    old_div = [dict(lineno=node.lineno, operator=type(node.op).__name__)
               for node in ast.walk(old_ast) if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.FloorDiv))]
    new_div = [node for node in ast.walk(new_ast) if isinstance(node, (ast.Div, ast.FloorDiv, ast.Mod))]
    assert len(old_div) == 4 and not new_div
    old_functions = {node.name: node for node in old_ast.body}
    new_functions = {node.name: node for node in new_ast.body}
    assert set(new_functions) - set(old_functions) == {'divide_small'}
    changed_functions = [name for name in old_functions
                         if ast.dump(old_functions[name], include_attributes=False) != ast.dump(new_functions[name], include_attributes=False)]
    assert changed_functions == ['observe_scalar', 'integer_policy', 'packet']
    original_module = ast.parse(before)
    corrected_module = ast.parse(after)
    original_module.body = [node for node in original_module.body
                            if not (isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'SOURCE' for t in node.targets))]
    corrected_module.body = [node for node in corrected_module.body
                             if not (isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'SOURCE' for t in node.targets))]
    assert ast.dump(original_module, include_attributes=False) == ast.dump(corrected_module, include_attributes=False)
    inputs = {path.relative_to(HERE / 'inputs').as_posix(): pin(path.read_bytes())
              for path in sorted((HERE / 'inputs').rglob('*')) if path.is_file()}
    assert len(inputs) == 13
    unchanged = []
    for relative in inputs:
        if relative != 'tools/generate_hia_cli_json_scalar.py':
            assert (HERE / 'inputs' / relative).read_bytes() == (OLD / 'inputs' / relative).read_bytes()
            unchanged.append(relative)
    preexec = json.loads((REQUEST / 'PREEXEC.json').read_bytes())
    materialization = json.loads((REQUEST / 'MATERIALIZATION.json').read_bytes())
    assert materialization['changed_source_paths'] == ['tools/generate_hia_cli_json_scalar.py']
    assert not (REQUEST / 'actual').exists()
    assert not any((REQUEST / 'guardian' / name).exists() for name in ('guardian.json', 'child.stdout.log', 'child.stderr.log'))
    correction = {
        'schema': 'hia.cli-json.r4b1.scalar-correction.v1',
        'status': 'STATIC_AST_VERIFIED_NOT_AUTHORED_OR_EXECUTED',
        'prior_failed_request_commit': '6ae4d8765678fe1e8c54c365c595d1528655ea62',
        'prior_actual_failure_commit': PARENT,
        'old_scalar': pin(before), 'new_scalar': pin(after),
        'original_ast_divisions': old_div,
        'new_division_modulo_ast_nodes': 0,
        'changed_embedded_functions': changed_functions,
        'added_embedded_function': 'divide_small',
        'outer_authoring_python_ast_unchanged': True,
        'other_12_implementation_files_wholebytes_unchanged': unchanged,
        'official_reference': {'url': 'https://raw.githubusercontent.com/python/cpython/v3.12.14/Objects/longobject.c',
                               'local_path': 'reference/cpython-v3.12.14/Objects/longobject.c',
                               **pin((HERE / 'reference/cpython-v3.12.14/Objects/longobject.c').read_bytes())},
        'arithmetic_reasoning': [
            'The original digit representation admits only (shift,width)=(15,2) or (30,4) before the threshold. C positive integer division gives floor(6400/45)+2=144 and floor(6400/90)+2=73.',
            'The early limit remains read only after that threshold. limit>0 is evaluated before count-11. A valid phase100 has count>=73 or144; an explicit count>=11 guard prevents unsigned underflow for an invalid workspace.',
            'divide_small is called only with divisors10,45,90. It processes exactly64 input bits from63 down to0. The invariant is processed_prefix=quotient*divisor+remainder, with 0<=remainder<divisor. A step doubles the remainder then appends one input bit; the intermediate remainder is below180, so the shift cannot overflow u64. Conditional subtraction restores the invariant.',
            'Each quotient shift appends one binary digit. Before any iteration the quotient fits the number of bits already processed, which is at most63; no shift loses a high bit. The final quotient equals floor(value/divisor). No host division or changed integer-text algorithm is introduced.',
            'Unicode width is validated as1,2,4; division of byte length is the corresponding shift0,1,2. The count-versus-quotient comparison short-circuits before count*width; therefore the multiplication is bounded by the buffer length. The subsequent exact equality remains.',
        ],
        'scope_preserved': {'components': preexec['components'], 'source_files': 167, 'input_pins': 174,
                            'source_bytes': preexec['source_bytes'], 'owner_seconds': 180, 'cleanup_seconds': 3,
                            'structural_caps': 9, 'original_cli_17_executed': 0, 'trace_46_executed': 0,
                            'compiler_line_gate_executed': False, 'private_c_compiled': False},
        'original_failure_reclassified': False,
        'old_request_replayed': False,
        'new_request_executed': False,
        'remaining_obligations': ['Two complete new source components must actually generate, roundtrip and meet the original nine caps.',
                                  'Native compilation still enforces the original line gate and all compiler limits.',
                                  'Owned CALL, live generator frames, non-string final join, full17 CLI methods and46 trace cases remain unexecuted.'],
    }
    create(HERE / 'CORRECTION.json', correction)
    handoff = {'schema': 'hia.cli-json.r4b1.source-request.handoff.v1',
               'status': 'FROZEN_NOT_EXECUTED', 'parent_commit': PARENT,
               'implementation_prefix': 'experiments/hia_cli_json_graph_20261112/implementation-r4b1/',
               'request_prefix': 'experiments/hia_cli_json_graph_20261112/source-authoring-r4b1/',
               'local_implementation': str(HERE), 'local_request': str(REQUEST),
               'source_inputs': inputs, 'preexec': pin((REQUEST / 'PREEXEC.json').read_bytes()),
               'request': pin((REQUEST / 'guardian/REQUEST.json').read_bytes()),
               'exact_command': preexec['command'], 'cwd': preexec['cwd'], 'environment': preexec['environment'],
               'python': preexec['python'], 'components': preexec['components'],
               'source_files': 167, 'source_bytes': preexec['source_bytes'], 'input_pins': 174,
               'owner_seconds': 180, 'cleanup_seconds': 3, 'caps': 9,
               'source_materialization_only_executed': True,
               'generation_or_owner_or_native_executed': False,
               'preserved_17_46_not_executed': True,
               'original_failure_evidence_commit': PARENT,
               'correction': pin((HERE / 'CORRECTION.json').read_bytes()),
               'original_launcher_reporting_bug': 'The prior outer wrapper included atime in its read identity. Its missing return receipt stays missing. This request is independent and does not reconstruct or replay it.'}
    create(HERE / 'HANDOFF.json', handoff)
    files = []
    for local, prefix in [(HERE, handoff['implementation_prefix']), (REQUEST, handoff['request_prefix'])]:
        for path in sorted(local.rglob('*')):
            if path.is_file() and path.name not in ('PUBLICATION-PACKET.json', 'PUBLICATION.json', 'GIT-BLOB-LEDGER.jsonl'):
                files.append(dict(path=prefix + path.relative_to(local).as_posix(), local_path=str(path), **pin(path.read_bytes())))
    packet = {'parent_commit': PARENT, 'parent_tree': '53dd566581c587e9c0649572efdb74bca93c2eb4', 'files': files}
    create(HERE / 'PUBLICATION-PACKET.json', packet)
    print(json.dumps({'new_files': len(files), 'bytes': sum(row['bytes'] for row in files),
                      'scalar': pin(after), 'handoff': pin((HERE / 'HANDOFF.json').read_bytes()),
                      'request': handoff['request']}, sort_keys=True))


if __name__ == '__main__':
    main()
