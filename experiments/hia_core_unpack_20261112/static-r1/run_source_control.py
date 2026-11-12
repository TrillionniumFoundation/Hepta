"""Create-only source/Core/cap evidence; never native or product qualification."""
from __future__ import annotations
import argparse
import ast
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import sys
import time
import traceback


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--author', type=Path, required=True)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    args = parser.parse_args()
    args.evidence_dir.mkdir(mode=0o700)
    root = args.source_root.resolve()
    author = args.author.resolve()
    dependencies = [root / name for name in ('tools/generate_hia_selfhost.py',
        'tools/hia_selfhost_limits.py', 'hepta/hia_agent_assembly.py',
        'hepta/hia_program.py', 'tools/hia_selfhost_process_owner.py')]
    files = [Path(__file__).resolve(), author, *dependencies]
    before = {str(path): sha256(path.read_bytes()).hexdigest() for path in files}
    report = {'schema': 'hepta.hia.core-unpack-source-control.v1', 'status': 'HOLD',
              'source_before': before, 'python': sys.version,
              'native_compilation': False, 'product_tests': False}
    started = time.monotonic()
    try:
        sys.path.insert(0, str(root))
        spec = importlib.util.spec_from_file_location('core_unpack_author', author)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        text = module.source()
        (args.evidence_dir / 'authored-source.py.txt').write_text(text)
        ast.parse(text)
        document = module.document()
        (args.evidence_dir / 'document.json').write_text(json.dumps(document, indent=2, sort_keys=True) + '\n')
        from hepta.hia_agent_assembly import render_assembly, assemble_program
        from hepta.hia_program import verify_program
        from tools import hia_selfhost_limits as limits
        checked = verify_program(document)
        assembly = render_assembly(checked.as_dict()).encode('utf-8')
        (args.evidence_dir / 'core_unpack.hiaasm').write_bytes(assembly)
        assert assemble_program(assembly).canonical_bytes == checked.canonical_bytes
        functions = checked.as_dict()['functions']
        counts = {'source_bytes': len(assembly), 'functions': len(functions),
                  'blocks': sum(len(f['blocks']) for f in functions),
                  'max_blocks': max(len(f['blocks']) for f in functions),
                  'instructions': sum(len(b['ops']) for f in functions for b in f['blocks'])}
        names = []
        arities = []
        for function in functions:
            values = {p['name'] for p in function['params']}
            arities.append(len(function['params']))
            for block in function['blocks']:
                values.update(p['name'] for p in block['params'])
                arities.append(len(block['params']))
                for instruction in block['ops']:
                    values.update(p['name'] for p in instruction['out'])
                    if instruction['op'] == 'call':
                        arities.append(len(instruction['args']))
            names.append(len(values))
        counts['max_ssa_names'] = max(names)
        counts['max_arity'] = max(arities)
        report['counts'] = counts
        gates = {'source': counts['source_bytes'] <= 1048576,
                 'functions': counts['functions'] <= limits.MAX_FUNCTIONS,
                 'blocks': counts['blocks'] <= limits.MAX_BLOCKS,
                 'per_function_blocks': counts['max_blocks'] <= 256,
                 'ssa_names': counts['max_ssa_names'] <= 2048,
                 'arity': counts['max_arity'] <= 16,
                 'instructions': counts['instructions'] <= limits.MAX_INSTRUCTIONS}
        report['gates'] = gates
        report['assembly_sha256'] = sha256(assembly).hexdigest()
        if not all(gates.values()):
            raise ValueError('unchanged native compiler source limits exceeded')
        report['status'] = 'SOURCE_CORE_CAPS_PASS'
    except BaseException as error:
        report['status'] = 'HOLD'
        report['error'] = {'type': type(error).__name__, 'message': str(error)}
        (args.evidence_dir / 'traceback.txt').write_text(traceback.format_exc())
    finally:
        try:
            report['source_after'] = {str(path): sha256(path.read_bytes()).hexdigest() for path in files}
            report['source_stable'] = report['source_after'] == before
            if not report['source_stable']:
                report['status'] = 'HOLD'
        except BaseException as error:
            report['status'] = 'HOLD'
            report['preservation_error'] = repr(error)
        report['seconds'] = time.monotonic() - started
        (args.evidence_dir / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'status': report['status'], 'report': str(args.evidence_dir / 'report.json')}))
    return 0 if report['status'] == 'SOURCE_CORE_CAPS_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
