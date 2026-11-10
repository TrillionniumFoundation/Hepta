"""Host fact/JSON transport around mandatory HIA Core module graph policy.

Not the high-level Hepta module resolver. The HIA image, never Python, resolves
local/imported calls, import visibility, name collisions and dependency order.
JSON admission, copying, Core checking and filesystem/build custody remain host
bridges; this is not a native-only workspace compiler or release.
"""
from __future__ import annotations
import copy
import ctypes
from hashlib import sha256
from pathlib import Path
import struct
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image
from .hia_program import verify_program
from .hia_program_tools import bounded_json_wire, decode_json
from .hia_schema import PRIMITIVE_SCHEMAS

from .hia_json_preflight_native import _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/core_module_graph.hiaasm')
SCHEMA = 'hepta.hia.core-module-graph-native.v1'
WORKSPACE_SCHEMA = 'hepta.hia.core-workspace.v1'
MAGIC = int.from_bytes(b'HIAMOD01', 'little')
RESULT = int.from_bytes(b'HIAMOR01', 'little')
NONE = (1 << 64) - 1
MAX_BYTES = 8 << 20
ERRORS = {
    0xffffffff: 'invalid normalized module facts or identifiers',
    0xfffffffe: 'insufficient result or workspace buffers',
    0xfffffffd: 'duplicate module', 0xfffffffc: 'duplicate local function',
    0xfffffffb: 'import alias collides with local function or prior alias',
    0xfffffffa: 'imported module not found', 0xfffffff9: 'imported function not found',
    0xfffffff8: 'entry module not found', 0xfffffff7: 'exported function not found',
    0xfffffff6: 'duplicate exported function', 0xfffffff5: 'imported function is private',
    0xfffffff2: 'unresolved call', 0xfffffff1: 'module dependency cycle',
}

class CoreModuleRejected(ValueError):
    pass

def keys(value, expected):
    if type(value) is not dict or set(value) != set(expected):
        raise CoreModuleRejected('invalid Core workspace framing')

def encode_workspace(value):
    # Capture a bounded immutable JSON value once, before traversing caller data.
    if type(value) in (str, bytes) and len(value) > MAX_BYTES:
        raise CoreModuleRejected('Core workspace exceeds 8 MiB')
    raw = value.encode() if type(value) is str else value if type(value) is bytes else bounded_json_wire(value, MAX_BYTES)
    if len(raw) > MAX_BYTES:
        raise CoreModuleRejected('Core workspace exceeds 8 MiB')
    doc = decode_json(raw)
    keys(doc, ('schema', 'entry', 'modules'))
    if doc['schema'] != WORKSPACE_SCHEMA or type(doc['modules']) is not list or not 1 <= len(doc['modules']) <= 1024:
        raise CoreModuleRejected('outside Core workspace module profile')
    strings, modules, functions, imports, calls, exports = bytearray(), [], [], [], [], []
    definitions, callsites = [], []
    def name(s):
        # Only transport a string. HIA validates identifier spelling and compares
        # the original bytes; no host interning/equality/regex resolves names.
        if type(s) is not str:
            raise CoreModuleRejected('Core module names must be strings')
        try: b = s.encode('utf-8')
        except UnicodeError as exc: raise CoreModuleRejected('invalid name Unicode') from exc
        if len(strings) + len(b) > MAX_BYTES:
            raise CoreModuleRejected('Core module name bytes exceed profile')
        at = len(strings)
        strings.extend(b)
        return at, len(b)
    entry = name(doc['entry'])
    schema = None
    for mi, module in enumerate(doc['modules']):
        keys(module, ('core', 'imports', 'exports'))
        core = module['core']
        keys(core, ('schema', 'module', 'functions'))
        if (type(core['schema']) is not str or core['schema'] not in PRIMITIVE_SCHEMAS
                or schema is not None and core['schema'] != schema):
            raise CoreModuleRejected('workspace needs one primitive Core feature version; nominal type linking remains OPEN')
        schema = core['schema']
        if (type(core['functions']) is not list or type(module['imports']) is not list
                or type(module['exports']) is not list):
            raise CoreModuleRejected('invalid Core module inventories')
        modules.append((*name(core['module']), len(functions), len(core['functions'])))
        for fn in core['functions']:
            if type(fn) is not dict or type(fn.get('blocks')) is not list:
                raise CoreModuleRejected('invalid Core function framing')
            fi = len(functions)
            functions.append((mi, *name(fn.get('name')), 0))
            definitions.append(fn)
            for bi, block in enumerate(fn['blocks']):
                if type(block) is not dict or type(block.get('ops')) is not list:
                    raise CoreModuleRejected('invalid Core block framing')
                for oi, operation in enumerate(block['ops']):
                    if type(operation) is not dict:
                        raise CoreModuleRejected('invalid Core operation framing')
                    if operation.get('op') == 'call':
                        attrs = operation.get('attrs')
                        if type(attrs) is not dict:
                            raise CoreModuleRejected('invalid Core call framing')
                        calls.append((fi, *name(attrs.get('function'))))
                        callsites.append((fi, bi, oi))
        for item in module['imports']:
            keys(item, ('alias', 'module', 'symbol'))
            imports.append((mi, *name(item['alias']), *name(item['module']), *name(item['symbol'])))
        for symbol in module['exports']:
            exports.append((mi, *name(symbol)))
        if len(functions) > 1024 or len(imports) > 4096 or len(calls) > 16384 or len(exports) > 1024:
            raise CoreModuleRejected('outside Core workspace fact profile')
    size = 80 + 32 * (len(modules) + len(functions)) + 56 * len(imports) + 24 * (len(calls) + len(exports)) + len(strings)
    if size > MAX_BYTES:
        raise CoreModuleRejected('Core workspace fact packet exceeds 8 MiB')
    wire = bytearray(struct.pack('<10Q', MAGIC, len(modules), len(functions), len(imports), len(calls), len(exports), len(strings), *entry, 0))
    for rows, width in ((modules, 4), (functions, 4), (imports, 7), (calls, 3), (exports, 3)):
        for row in rows: wire.extend(struct.pack('<' + str(width) + 'Q', *row))
    wire.extend(strings)
    assert len(wire) == size
    return bytes(wire), doc, definitions, callsites, raw

class NativeCoreModuleGraph(NativeHiaJsonImage):
    def run(self, wire):
        if type(wire) is not bytes or not 80 <= len(wire) <= MAX_BYTES:
            raise CoreModuleRejected('outside native Core module fact profile')
        _, nm, nf, ni, nc, nx, *_ = struct.unpack_from('<10Q', wire)
        if nm > 1024 or nf > 1024 or ni > 4096 or nc > 16384 or nx > 1024:
            raise CoreModuleRejected('invalid native Core module allocation counts')
        size = 64 + 8 * (nm + ni + nc + nx)
        source = ctypes.create_string_buffer(wire, len(wire))
        output = ctypes.create_string_buffer(size)
        state = ctypes.create_string_buffer(size + 8 * (nf + nm))
        status = self._entry(source, len(wire), output, size, state, len(state))
        if status in ERRORS:
            raise CoreModuleRejected('E_HIA_CORE_MODULE: ' + ERRORS[status])
        if status != size:
            raise CoreModuleRejected('invalid native Core module return')
        return output.raw

def installed_module_graph(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeCoreModuleGraph)

def link_workspace(document, *, native):
    """Compose every declared function, resolving names only through HIA.

    Module exports are import visibility, not ABI exports. Only entry-module
    exports become public scalar exports; internal cross-module calls can carry
    resource loans. The ordinary whole-Core verifier still checks all resources,
    effects, types, recursion and returned-loan interfaces after substitution.
    """
    wire, doc, definitions, callsites, source_raw = encode_workspace(document)
    result = native.run(wire)
    _, nm, nf, ni, nc, nx, *_ = struct.unpack_from('<10Q', wire)
    size = 64 + 8 * (nm + ni + nc + nx)
    if len(result) != size:
        raise CoreModuleRejected('invalid Core module result size')
    magic, rm, rf, ri, rc, rx, entry, reserved = struct.unpack_from('<8Q', result)
    if (magic, rm, rf, ri, rc, rx, reserved) != (RESULT, nm, nf, ni, nc, nx, 0) or entry >= nm:
        raise CoreModuleRejected('invalid Core module result header')
    order = struct.unpack_from('<' + str(nm) + 'Q', result, 64)
    targets = struct.unpack_from('<' + str(ni + nc) + 'Q', result, 64 + 8 * nm)
    public_targets = struct.unpack_from('<' + str(nx) + 'Q', result, 64 + 8 * (nm + ni + nc))
    if (sorted(order) != list(range(nm)) or any(t >= nf for t in targets)
            or any(t != NONE and t >= nf for t in public_targets)):
        raise CoreModuleRejected('invalid Core module result indexes')
    # HIA selected the entry-module public targets using exact source names.
    # Copy those declarations verbatim through Core and the native ELF emitter;
    # do not turn a source ABI into a caller-visible generated fN ABI. Internal
    # names are only capture-avoiding materialization, never a second resolver.
    public_indexes = [t for t in public_targets if t != NONE]
    public_names = {t: definitions[t]['name'] for t in public_indexes}
    used_names = set(public_names.values())
    linked_names = []
    for fi in range(nf):
        if fi in public_names:
            linked_names.append(public_names[fi])
            continue
        suffix = fi
        while 'f' + str(suffix) in used_names:
            suffix += 1
        name = 'f' + str(suffix)
        used_names.add(name)
        linked_names.append(name)
    linked = copy.deepcopy(definitions)
    for fi, fn in enumerate(linked): fn['name'] = linked_names[fi]
    for (fi, bi, oi), target in zip(callsites, targets[ni:]):
        linked[fi]['blocks'][bi]['ops'][oi]['attrs']['function'] = linked_names[target]
    public = [linked_names[t] for t in public_indexes]
    candidate = {'schema': doc['modules'][0]['core']['schema'], 'module': 'core_workspace', 'functions': linked, 'exports': public}
    verified = verify_program(candidate)
    return verified, {
        'schema': 'hepta.hia.core-workspace-link.v1', 'status': 'VERIFIED_UNPUBLISHED',
        'workspace_sha256': sha256(source_raw).hexdigest(), 'linked_core_sha256': verified.sha256,
        'module_order': list(order), 'entry_module_index': entry, 'native_image_sha256': native.image_sha256,
        'function_names': [{'module_index': row[0], 'source_name': fn['name'], 'linked_name': linked_names[i]}
                           for i, (row, fn) in enumerate(zip(struct.iter_unpack('<4Q', wire[80 + nm * 32:80 + (nm + nf) * 32]), definitions))],
        'public_export_names': public,
        'original_external_export_names_preserved': True,
        'host_JSON_Core_materialization_verification_and_build_bridge': True,
        'high_level_Hepta_resolver_used': False, 'reference_module_policy_fallback': False,
        'nominal_type_linking_package_filesystem_locks_native_install': 'OPEN',
        'whole_native_workspace_qualified': False, 'production_activated': False,
    }
