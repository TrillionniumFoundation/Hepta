"""Explicit qualification-only arguments for the installed Core child.

The original no-companion and positional UNPACK forms stay byte-compatible.
Numeric qualification uses a named, exact two-companion schema. It cannot
silently disable the original UNPACK observations by changing argv length.
No selector is admitted and no executable image is loaded by this module.
"""
from __future__ import annotations

import json
from pathlib import Path


def parse_installed_companions(arguments):
    schema = 'hepta.hia.core-lowering-installed-companions.v1'
    keys = {'schema', 'unpack_manifest', 'numeric_compare_manifest'}
    if type(arguments) is not list or any(type(item) is not str for item in arguments):
        raise ValueError('installed companion arguments must be actual strings')
    if not arguments:
        return {'schema': schema, 'unpack_manifest': None, 'numeric_compare_manifest': None}
    if len(arguments) == 1 and arguments[0] != '--companions-json':
        if not arguments[0] or '\0' in arguments[0]:
            raise ValueError('legacy installed UNPACK manifest is empty or invalid')
        return {'schema': schema, 'unpack_manifest': arguments[0], 'numeric_compare_manifest': None}
    if len(arguments) != 2 or arguments[0] != '--companions-json':
        raise ValueError('installed companions require the named JSON argument')
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ValueError('duplicate installed companion field')
            result[key] = value
        return result
    value = json.loads(arguments[1], object_pairs_hook=pairs)
    if type(value) is not dict or set(value) != keys or value.get('schema') != schema:
        raise ValueError('installed companion schema differs')
    for key in ('unpack_manifest', 'numeric_compare_manifest'):
        item = value[key]
        if type(item) is not str or not item or '\0' in item or not Path(item).is_absolute():
            raise ValueError('both installed companions require explicit absolute manifests')
    return value


def installed_companion_arguments(unpack_manifest=None, numeric_compare_manifest=None):
    if numeric_compare_manifest is None:
        result = [] if unpack_manifest is None else [unpack_manifest]
    else:
        value = {'schema': 'hepta.hia.core-lowering-installed-companions.v1',
                 'unpack_manifest': unpack_manifest,
                 'numeric_compare_manifest': numeric_compare_manifest}
        result = ['--companions-json', json.dumps(value, sort_keys=True, separators=(',', ':'))]
    parse_installed_companions(result)
    return result
