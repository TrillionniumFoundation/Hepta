"""Verified fact transport for exact HIA static graph and resource owners.

The HIA image owns stable DAG ordering, cycle and dependency refusal, exact
integer event propagation, frame depths and v7/v8 reviewed profile selection.
This adapter preserves names, opcodes and integer magnitudes; it does not
perform topological sorting, path maxima or resource arithmetic.
"""
from __future__ import annotations
import ctypes
import os
import struct
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/static_budget.hepta')
SCHEMA = 'hepta.hia.static-budget-native.v1'
SELECTOR = 'HEPTA_HIA_STATIC_BUDGET_MANIFEST'
REQUEST_MAGIC = int.from_bytes(b'HIASBG01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIASBR01', 'little')


def _text(value):
    raw = value.encode('utf-8') if type(value) is str else value
    return struct.pack('<Q', len(raw)) + raw


def _magnitude(value):
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), 'little')


def sizes(mode, count, children=0, width=8):
    if mode in (3, 4):
        return 32, 128
    metric = 2 * width + 8
    workspace = 128 + children * 48 + count * 64 + count * ((count + 7) // 8) + count * metric
    return (24 + 2 * width if mode == 1 else 16 + count * 8), workspace


def graph_packet(names, edges, mode=0):
    unique = list(dict.fromkeys(names))
    keys = struct.pack('<2Q', len(names), len(edges)) + b''.join(_text(key) for key in edges)
    parts = [struct.pack('<5Q', REQUEST_MAGIC, mode, len(unique), 0, 8), _text(keys)]
    for name in unique:
        targets = edges.get(name, ())
        parts.extend((_text(name), struct.pack('<Q', len(targets))))
        parts.extend(_text(target) for target in targets)
        parts.append(struct.pack('<Q', int(name not in edges)))
    return b''.join(parts)


def function_packet(fn, calculated):
    # Project only bindings actually named by operation metadata. HIA still
    # decides whether an opcode is a call and owns all sums/maxima. Repeating
    # every previously calculated function here creates cubic transport/sort
    # work on an admitted 1024-function chain without adding any observation.
    referenced = dict.fromkeys(op['attrs'].get('function', '')
                               for block in fn['blocks'] for op in block['ops'])
    bank = [(name, _magnitude(calculated[name]['max_allocator_interactions']),
             _magnitude(calculated[name]['max_vm_ticks']), calculated[name]['max_call_depth'])
            for name in referenced if name in calculated]
    # Capacity only: a complete verified Core has <=262144 nodes. Eight more
    # bytes exceed the possible sum of all child counts and local events.
    # Each multiplication level adds <=19 bits and there are <=1024 levels;
    # the native 4096-byte maximum is above the whole original Core domain.
    width = max((len(value) for _, a, b, _ in bank for value in (a, b)), default=1) + 8
    parts = [struct.pack('<5Q', REQUEST_MAGIC, 1, len(fn['blocks']), len(bank), width), _text(fn['entry'])]
    for name, a, b, depth in bank:
        parts.extend((_text(name), _text(a), _text(b), struct.pack('<Q', depth)))
    for block in fn['blocks']:
        term = block['term']
        paths = ([term['target']] if term['op'] == 'jump' else
                 [term['then']['target'], term['else']['target']] if term['op'] == 'branch' else [])
        parts.extend((_text(block['id']), struct.pack('<Q', len(paths))))
        parts.extend(_text(target) for target in paths)
        parts.append(struct.pack('<Q', len(block['ops'])))
        for op in block['ops']:
            parts.extend((_text(op['op']), _text(op['attrs'].get('function', ''))))
    return b''.join(parts), width


def profile_packet(document, schema, allow_chain):
    parts = [struct.pack('<2Q', REQUEST_MAGIC, 3), _text(schema), _text(document.get('schema', '')),
             struct.pack('<2Q', bool(allow_chain), len(document['functions']))]
    for fn in document['functions']:
        declared = [p['type'] for p in fn['params']] + fn['returns']
        parts.append(struct.pack('<Q', len(fn['blocks'])))
        for block in fn['blocks']:
            declared.extend(p['type'] for p in block['params'])
            parts.extend((_text(block['term']['op']), struct.pack('<Q', len(block['ops']))))
            for op in block['ops']:
                parts.append(_text(op['op']))
                declared.extend(p['type'] for p in op['out'])
        parts.append(struct.pack('<Q', len(declared)))
        parts.extend(_text(typ) for typ in declared)
    return b''.join(parts)


class _MissingGraphSource(KeyError):
    pass


class NativeStaticBudget(NativeHiaJsonImage):
    def _run(self, raw, mode, count, children=0, width=8, context='HIA call graph'):
        from .hia_static_budget import _reject
        output_size, workspace_size = sizes(mode, count, children, width)
        source = ctypes.create_string_buffer(raw, max(1, len(raw)))
        initial = b'\xa5' * output_size
        output = ctypes.create_string_buffer(initial, output_size)
        workspace = ctypes.create_string_buffer(workspace_size)
        code = self._entry(source, len(raw), output, output_size, workspace, workspace_size)
        if source.raw != raw or type(code) is not int or code not in (0, 1, 2, 3, 5, 6):
            raise RuntimeError('invalid static-budget ABI or changed verified facts')
        if code:
            if output.raw != initial:
                raise RuntimeError('refused static budget published output')
            if code == 6:
                raise _MissingGraphSource(struct.unpack_from('<Q', workspace.raw)[0])
            if code == 2:
                _reject('E_HIA_BUDGET_UNBOUNDED', context + ': recursion or CFG cycle requires a separate invariant')
            if code == 3:
                _reject('E_HIA_BUDGET_GRAPH', context + ': unknown dependency')
            raise RuntimeError('native static budget refused its verified-fact transport')
        magic, size = struct.unpack_from('<2Q', output.raw)
        if magic != RESULT_MAGIC or size != (width if mode == 1 else count):
            raise RuntimeError('invalid static budget result identity')
        return output.raw

    def topological(self, names, edges, context):
        raw = graph_packet(names, edges)
        names = list(dict.fromkeys(names))
        try:
            result = self._run(raw, 0, len(names), context=context)
        except _MissingGraphSource as error:
            if not 0 <= error.args[0] < len(names):
                raise RuntimeError('invalid missing graph source index') from error
            raise KeyError(names[error.args[0]]) from None
        indices = list(struct.unpack_from('<' + 'Q' * len(names), result, 16))
        if set(indices) != set(range(len(names))):
            raise RuntimeError('invalid native topological result permutation')
        return [names[i] for i in indices]

    def function(self, fn, calculated):
        raw, width = function_packet(fn, calculated)
        children, = struct.unpack_from('<Q', raw, 24)
        result = self._run(raw, 1, len(fn['blocks']), children, width,
                           context=fn['name'] + ' control flow')
        depth, = struct.unpack_from('<Q', result, 16)
        if not 1 <= depth <= 1024:
            raise RuntimeError('invalid native resource call depth')
        return {'function': fn['name'], 'max_allocator_interactions': int.from_bytes(result[24:24+width], 'little'),
                'max_vm_ticks': int.from_bytes(result[24+width:], 'little'), 'max_call_depth': depth}

    def depths(self, functions, edges):
        names = [fn['name'] for fn in functions]
        result = self._run(graph_packet(names, edges, 2), 2, len(names), context='synchronous HIA call graph')
        depths = struct.unpack_from('<' + 'Q' * len(names), result, 16)
        if any(not 1 <= value <= len(names) for value in depths):
            raise RuntimeError('invalid native frame bounds')
        return [{'function': name, 'max_call_depth': value} for name, value in zip(names, depths)]

    def first_exceeded(self, rows, limits, fields):
        parts = [struct.pack('<4Q', REQUEST_MAGIC, 4, len(fields), len(rows))]
        parts.extend(_text(b'' if limits[key] is None else _magnitude(limits[key])) for key in fields)
        for row in rows:
            parts.extend(_text(_magnitude(row.get(key, 0))) for key in fields)
        result = self._run(b''.join(parts), 4, len(rows))
        offender, field = struct.unpack_from('<2Q', result, 16)
        if offender > len(rows) or field >= len(fields):
            raise RuntimeError('invalid native resource policy refusal')
        return None if offender == len(rows) else (rows[offender]['function'], fields[field])

    def audit_profile(self, document, *, schema, allow_chain):
        from .hia_static_budget import _reject
        result = self._run(profile_packet(document, schema, allow_chain), 3, len(document['functions']))
        reason, offender = struct.unpack_from('<2Q', result, 16)
        if reason > 4 or offender >= max(1, len(document['functions'])):
            raise RuntimeError('invalid native resource profile refusal')
        if reason:
            detail = (f'resource profile requires {schema}' if reason == 1 else
                      f'unreviewed {schema} terminator' if reason == 2 else
                      document['functions'][offender]['name'] + ': ' +
                      ('opcode lacks this ' if reason == 3 else 'resource type lacks this ') +
                      schema + ' resource-event review')
            _reject('E_HIA_BUDGET_PROFILE', detail)


def installed_static_budget(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeStaticBudget)


def selected_static_budget():
    selected = os.environ.get(SELECTOR)
    if selected is None:
        return None
    if not selected:
        raise ValueError('static-budget selector must not be empty')
    return installed_static_budget(selected)
