"""Generate only the fixed primitive shapes in the two Store lifecycle bodies."""
from __future__ import annotations
import argparse
import ast
from hashlib import sha256
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

PREFIX = '''"""Fixed CPython CALL/IMPORT/name-error ports, without Store policy.

HIA chooses the operation, operands, order and one-use effect permission.
No Store body or SQLite policy is interpreted or compiled by this bridge.
"""
from __future__ import annotations
import dis
import sys
from types import FunctionType

def _profile():
    if sys.implementation.name != 'cpython' or sys.version_info[:2] not in ((3, 12), (3, 13), (3, 14)):
        raise RuntimeError('store-lifecycle ports require a reviewed CPython ABI')

'''


def source():
    from tools.generate_hia_native_build_foreign import IMPORT_SUPPORT
    from tools.generate_hia_service_artifacts_foreign import reviewed_import_support
    from tools.hia_store_lifecycle_control import compile_policy
    from tools.generate_hia_store_lifecycle import table
    text = (ROOT / 'tools/hia_store_lifecycle_policy.py').read_text()
    policy = ast.parse(text)
    compiled = compile_policy(text)
    shapes = sorted({(len(node.args), tuple(keyword.arg for keyword in node.keywords))
                     for node in ast.walk(policy) if isinstance(node, ast.Call)})
    if any(None in keys for _, keys in shapes):
        raise ValueError('lifecycle has no mapping or starred call port')
    groups = sorted({(node.module, tuple(alias.name for alias in node.names))
                     for node in ast.walk(policy) if isinstance(node, ast.ImportFrom)})
    names = tuple(sorted({name for _, fields in groups for name in fields}))
    imports = reviewed_import_support(IMPORT_SUPPORT).replace('native-build', 'store-lifecycle').replace(
        '_native_build', '_store_lifecycle')
    layout = tuple((fn.mode, fn.kind, fn.next_slot, len(fn.parameters), len(fn.captures))
                   for fn in compiled.functions)
    if len(layout) != 2 or any(row[1] != 'function' or row[4] for row in layout):
        raise ValueError('lifecycle must contain exactly two non-capturing bodies')
    lines = [PREFIX, '\nTABLE_SHA256 = ' + repr(sha256(table(compiled)).hexdigest()) + '\n',
             '\nFUNCTION_LAYOUT = ' + repr(layout) + '\n',
             'IMPORT_NAMES = ' + repr(names) + '\n', imports]
    for index, (module, fields) in enumerate(groups):
        lines.append('def _import_template_' + str(index) + '():\n    from .' +
                     module + ' import ' + ', '.join(fields) + '\n\n')
    lines.append('def import_ports(namespace):\n    return ({\n')
    for index, (module, fields) in enumerate(groups):
        lines.append('        ' + repr((module, fields)) + ': _import_name_port(_import_template_' +
                     str(index) + ', namespace, ' + repr(module) + ', ' + repr(fields) + ', 1),\n')
    lines.append('    }, {name: _import_from_port(name, namespace) for name in IMPORT_NAMES})\n\n')
    inventory = []
    for index, (positional, keywords) in enumerate(shapes):
        if positional > 2 or len(keywords) > 3:
            raise ValueError('lifecycle call shape differs from its original inventory')
        operands = ['frame._move(slots[' + str(i + 1) + '])' for i in range(positional)]
        operands.extend(key + '=frame._move(slots[' + str(positional + i + 1) + '])'
                        for i, key in enumerate(keywords))
        name = '_call_' + str(index)
        lines.append('def ' + name + '(frame, slots):\n    return frame._move(slots[0])(' +
                     ', '.join(operands) + ')\n\n')
        inventory.append('    ' + repr((positional, keywords)) + ': ' + name + ',\n')
    lines.append('CALLS = {\n' + ''.join(inventory) + '}\n')
    return ''.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    path = ROOT / 'hepta/hia_store_lifecycle_foreign.py'
    raw = source().encode()
    if args.check:
        if path.read_bytes() != raw:
            raise AssertionError('fixed lifecycle ports differ')
    else:
        path.write_bytes(raw)
    print(path)


if __name__ == '__main__':
    main()
