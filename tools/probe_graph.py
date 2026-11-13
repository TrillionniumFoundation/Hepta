"""Observe the exact CLI constructor prefix on actual CPython 3.14.4.

This is a bounded authoring diagnostic, not a reconstructed product checkout,
not an HIA execution, and not a substitute for the original 43 or new controls.
"""
from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import stat
import sys
import traceback
import types
from unittest.mock import patch


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def encoded(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode()


def capture(cli):
    class Captured(BaseException):
        def __init__(self, parser):
            self.parser = parser

    def stop(parser, *_args, **_kwargs):
        raise Captured(parser)

    with patch.object(argparse.ArgumentParser, 'parse_args', stop):
        try:
            cli._reference_hia_main(['capabilities'])
        except Captured as observation:
            return observation.parser
    raise AssertionError('exact original parser boundary was not reached')


def graph(value):
    seen, nodes, objects = {}, [], []
    unknown = []

    def visit(item):
        key = id(item)
        if key in seen:
            return seen[key]
        index = len(nodes)
        seen[key] = index
        nodes.append(None)
        objects.append(item)
        kind = type(item)
        if item is None:
            row = ['none']
        elif kind is bool:
            row = ['bool', item]
        elif kind is int:
            row = ['int', str(item)]
        elif kind is str:
            row = ['str', item]
        elif kind is bytes:
            row = ['bytes', item.hex()]
        elif kind is list:
            row = ['list', [visit(child) for child in item]]
        elif kind is tuple:
            row = ['tuple', [visit(child) for child in item]]
        elif kind is dict:
            row = ['dict', [[visit(k), visit(v)] for k, v in item.items()]]
        elif kind is set:
            row = ['set', [visit(child) for child in item]]
        elif kind is types.FunctionType:
            row = ['function', item.__module__, item.__qualname__,
                   hashlib.sha256(item.__code__.co_code).hexdigest(),
                   visit(item.__defaults__), visit(item.__kwdefaults__),
                   visit(item.__closure__), visit(item.__dict__), visit(item.__annotations__)]
        elif kind is types.BuiltinMethodType:
            row = ['builtin-bound-method', item.__module__, item.__name__,
                   item.__qualname__, visit(item.__self__)]
        elif kind is types.MethodType:
            row = ['method', visit(item.__func__), visit(item.__self__)]
        elif kind is types.CellType:
            try:
                row = ['cell', visit(item.cell_contents)]
            except ValueError:
                row = ['empty-cell']
        elif kind is re.Pattern:
            row = ['pattern', visit(item.pattern), visit(item.flags)]
        elif isinstance(item, type):
            row = ['shared-type', item.__module__, item.__qualname__,
                   type(item).__module__, type(item).__qualname__]
        elif kind.__module__ in ('argparse', '_colorize'):
            row = ['object', kind.__module__, kind.__qualname__,
                   type(kind).__module__, type(kind).__qualname__, visit(vars(item))]
        elif kind is types.ModuleType:
            row = ['shared-module', item.__name__]
        else:
            row = ['UNKNOWN', kind.__module__, kind.__qualname__]
            unknown.append({'node': index, 'type': row[1:]})
        nodes[index] = row
        return index

    root = visit(value)
    return {'root': root, 'nodes': nodes, 'unknown': unknown}, objects, seen


def main():
    root = Path(__file__).resolve().parents[1]
    output = Path(os.environ['PROBE_OUTPUT']).absolute()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    config = json.loads((root / 'inputs.json').read_bytes())
    originals = {}
    for row in config['files']:
        path = root / 'source' / row['path']
        raw = path.read_bytes()
        assert identity(raw) == {k: row[k] for k in ('bytes', 'sha256', 'git_blob')}
        assert stat.S_IMODE(path.stat().st_mode) == 0o644
        originals[row['path']] = raw
    result = {'schema': 'hia.cli-parser314-real-construction-observation.v1',
        'scope': config['scope'], 'status': 'FAIL', 'python': sys.version,
        'full_source_reconstruction': False, 'HIA_compiles': 0, 'HIA_entries': 0,
        'original43_or_new10_executed': False, 'cases': [], 'failures': []}
    try:
        assert sys.implementation.name == 'cpython' and tuple(sys.version_info[:3]) == (3, 14, 4)
        sys.path.insert(0, str(root / 'source'))
        from hepta import cli
        expected = originals['hepta/cli.py']
        assert Path(cli.__file__).read_bytes() == expected
        result['reference_source_sha256'] = hashlib.sha256(inspect.getsource(cli._reference_hia_main).encode()).hexdigest()
        parser = capture(cli)
        sys.path.insert(0, str(root / 'tools'))
        from export_interpreter import export_interpreter
        result['interpreter_export'] = export_interpreter(output)
        import _colorize
        for module in (argparse, _colorize):
            raw = Path(module.__file__).read_bytes()
            (output / (module.__name__ + '.py')).write_bytes(raw)
            result[module.__name__ + '_source'] = identity(raw)
        variants = [('default', {}), ('columns_10', {'COLUMNS': '10'}),
                    ('columns_1000', {'COLUMNS': '1000'}),
                    ('force_color', {'FORCE_COLOR': '1'}),
                    ('no_color', {'NO_COLOR': '1'}),
                    ('invalid_columns', {'COLUMNS': 'invalid'})]
        clean = {k: v for k, v in os.environ.items()
                 if k not in ('COLUMNS', 'LINES', 'TERM', 'PYTHON_COLORS', 'NO_COLOR', 'FORCE_COLOR')}
        for label, environment in variants:
            with patch.dict(os.environ, {**clean, **environment}, clear=True):
                parser = capture(cli)
                document, objects, seen = graph(parser)
                (output / (label + '-graph.json')).write_bytes(encoded(document))
                cached = []
                palettes = []
                for index, item in enumerate(objects):
                    kind = type(item)
                    if kind is argparse.ArgumentParser:
                        formatter = item._cached_formatter
                        cached.append({'node': index, 'prog': item.prog,
                            'formatter_node': None if formatter is None else seen[id(formatter)],
                            'formatter_attrs': None if formatter is None else {
                                k: v for k, v in vars(formatter).items() if type(v) in (int, str, bool, type(None))}})
                    if kind is _colorize.Argparse:
                        fields = vars(item)
                        getter = fields.get('_name_to_value')
                        palettes.append({'node': index, 'metaclass': type(kind).__module__ + '.' + type(kind).__qualname__,
                            'is_no_color': item is _colorize.theme_no_color.argparse,
                            'is_default': item is _colorize.default_theme.argparse,
                            'is_current': item is _colorize._theme.argparse,
                            'ordered_fields': list(fields),
                            'plain_fields': {k: v for k, v in fields.items() if type(v) is str},
                            'getter_type': type(getter).__module__ + '.' + type(getter).__qualname__,
                            'getter_name': getattr(getter, '__name__', None),
                            'getter_owner_node': seen.get(id(getattr(getter, '__self__', None)))})
                result['cases'].append({'label': label, 'environment': environment,
                    'nodes': len(document['nodes']), 'unknown': document['unknown'],
                    'cached_formatters': cached, 'palettes': palettes})
        assert all(not row['unknown'] for row in result['cases'])
        result['status'] = 'OBSERVATIONS_COMPLETE_NOT_QUALIFICATION'
    except BaseException as error:
        result['failures'].append({'type': type(error).__name__, 'error': str(error), 'traceback': traceback.format_exc()})
    finally:
        result['input_source_bytes_and_modes_unchanged'] = all(
            (root / 'source' / name).read_bytes() == raw
            and stat.S_IMODE((root / 'source' / name).stat().st_mode) == 0o644
            for name, raw in originals.items())
        if not result['input_source_bytes_and_modes_unchanged']:
            result['status'] = 'FAIL'
        (output / 'RESULT.json').write_bytes(encoded(result))
        manifest = [{'path': path.relative_to(output).as_posix(), **identity(path.read_bytes()),
                     'mode': stat.S_IMODE(path.stat().st_mode)}
                    for path in sorted(output.rglob('*')) if path.is_file()]
        (output / 'MANIFEST.json').write_bytes(encoded(manifest))
        print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result['status'] == 'OBSERVATIONS_COMPLETE_NOT_QUALIFICATION' else 1


if __name__ == '__main__':
    raise SystemExit(main())
