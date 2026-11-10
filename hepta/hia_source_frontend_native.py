"""One explicit, byte-bound selection of the native source grammar components.

This is manifest custody and Python object transport, not HIA declaration or
statement recognition. The complete frontend and toolchain remain unfinished.
"""
from __future__ import annotations
from hashlib import sha256
import json
from pathlib import Path
import re

SCHEMA = 'hepta.hia.source-frontend-native.v1'
MANIFESTS = (
    'names/manifest.json', 'names/source-lexer/manifest.json',
    'clauses/manifest.json', 'clauses/source-lexer/manifest.json',
    'expressions/manifest.json', 'expressions/source-types/manifest.json',
    'expressions/source-types/source-lexer/manifest.json',
)
INDIVIDUAL_SELECTORS = (
    'HEPTA_HIA_SOURCE_NAMES_MANIFEST', 'HEPTA_HIA_SOURCE_CLAUSES_MANIFEST',
    'HEPTA_HIA_SOURCE_EXPRESSIONS_MANIFEST', 'HEPTA_HIA_SOURCE_TYPES_MANIFEST',
    'HEPTA_HIA_SOURCE_LEXER_MANIFEST',
)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate HIA frontend manifest field')
        result[key] = value
    return result


def _read(path, maximum, label):
    with path.open('rb') as handle:
        raw = handle.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError('HIA frontend ' + label + ' exceeds its byte limit')
    return raw


def _components():
    from . import hia_source_names_native as names
    from . import hia_source_clauses_native as clauses
    from . import hia_source_expressions_native as expressions
    from . import hia_source_types_native as types
    from . import hia_source_lexer_native as lexer
    return {
        'names/manifest.json': (names, names.NativeSourceNames),
        'names/source-lexer/manifest.json': (lexer, lexer.NativeSourceLexer),
        'clauses/manifest.json': (clauses, clauses.NativeSourceClauses),
        'clauses/source-lexer/manifest.json': (lexer, lexer.NativeSourceLexer),
        'expressions/manifest.json': (expressions, expressions.NativeSourceExpressions),
        'expressions/source-types/manifest.json': (types, types.NativeSourceTypes),
        'expressions/source-types/source-lexer/manifest.json': (lexer, lexer.NativeSourceLexer),
    }


def _snapshot(path):
    """Capture the selected manifests and executable bytes exactly once.

    Subsequent loading uses these authenticated bytes, never another lookup of
    their filenames. A temporary replacement followed by restoration cannot
    substitute a different image between admission and immutable code mapping.
    """
    from .hia_json_preflight_native import MAX_IMAGE_BYTES
    path = Path(path).resolve(strict=True)
    value = json.loads(_read(path, 16384, 'manifest'), object_pairs_hook=_object)
    if (type(value) is not dict or set(value) != {'schema', 'compiler_sha256', 'manifests'}
            or value['schema'] != SCHEMA or type(value['compiler_sha256']) is not str
            or re.fullmatch('[0-9a-f]{64}', value['compiler_sha256']) is None
            or type(value['manifests']) is not dict or set(value['manifests']) != set(MANIFESTS)):
        raise ValueError('invalid HIA source frontend manifest')
    records, images = {}, {}
    root = path.parent
    components = _components()
    for relative in MANIFESTS:
        selected = (root / relative).resolve(strict=True)
        if not selected.is_relative_to(root):
            raise ValueError('HIA frontend component escapes its bundle')
        raw = _read(selected, 16384, 'component manifest')
        if sha256(raw).hexdigest() != value['manifests'][relative]:
            raise ValueError('HIA frontend component manifest identity mismatch')
        item = json.loads(raw, object_pairs_hook=_object)
        module, factory = components[relative]
        if (type(item) is not dict or set(item) != {
                'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
                or item['schema'] != module.SCHEMA or type(item['image_path']) is not str
                or any(type(item[key]) is not str or re.fullmatch('[0-9a-f]{64}', item[key]) is None
                       for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
            raise ValueError('invalid HIA frontend component manifest')
        if item['compiler_sha256'] != value['compiler_sha256']:
            raise ValueError('HIA frontend mixes compiler identities')
        if item['source_sha256'] != sha256(module.SOURCE.read_bytes()).hexdigest():
            raise ValueError('HIA frontend component source identity mismatch')
        image_path = (selected.parent / item['image_path']).resolve(strict=True)
        if not image_path.is_relative_to(root):
            raise ValueError('HIA frontend image escapes its bundle')
        image = _read(image_path, MAX_IMAGE_BYTES, 'image')
        if not image or sha256(image).hexdigest() != item['image_sha256']:
            raise ValueError('HIA frontend image identity mismatch')
        records[relative] = item
        images[relative] = (factory, image, item['image_sha256'])
    lexers = [records[name] for name in MANIFESTS if name.endswith('source-lexer/manifest.json')]
    if len({(row.get('source_sha256'), row.get('image_sha256')) for row in lexers}) != 1:
        raise ValueError('HIA frontend mixes lexer identities')
    return path, value, images


def read_manifest(path):
    selected, value, _ = _snapshot(path)
    return selected, value


def _load_snapshot(images):
    return {name: factory(image, identity) for name, (factory, image, identity) in images.items()}


def installed_source_frontend(path):
    _, _, snapshot = _snapshot(path)
    images = _load_snapshot(snapshot)
    return (images['names/manifest.json'], images['clauses/manifest.json'],
            images['expressions/manifest.json'], images['expressions/source-types/manifest.json'],
            images['expressions/source-types/source-lexer/manifest.json'])
