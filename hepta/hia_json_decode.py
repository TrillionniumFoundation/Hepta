"""Explicit HIA arena selection for existing bounded JSON consumers.

Default decoding remains the independent Python reference. Native selection
replaces payload parsing, not the host object ABI, Core checks or canonicalizer.
"""
from __future__ import annotations
import json
import os
from .hia_json_preflight import preflight_hia_json


def decode_hia_json(text: str, *, max_nodes: int, max_depth: int,
                    object_pairs_hook=None, parse_int=None, parse_constant=None):
    if (type(text) is not str or type(max_nodes) is not int or max_nodes < 1
            or type(max_depth) is not int or max_depth < 0):
        raise ValueError('invalid HIA JSON decoder input/budgets')
    manifest = os.environ.get('HEPTA_HIA_JSON_DECODE_MANIFEST')
    if manifest and max_nodes <= 1048576 and max_depth <= 128:
        try:
            wire = text.encode('utf-8')
        except UnicodeEncodeError:
            pass
        else:
            if len(wire) <= 8388608:
                from .hia_json_decode_native import installed_decoder
                return installed_decoder(manifest).decode(
                    wire, max_nodes=max_nodes, max_depth=max_depth,
                    object_pairs_hook=object_pairs_hook, parse_int=parse_int)
    preflight_hia_json(text, max_nodes=max_nodes, max_depth=max_depth)
    options = {}
    for name, value in (('object_pairs_hook', object_pairs_hook),
                        ('parse_int', parse_int), ('parse_constant', parse_constant)):
        if value is not None:
            options[name] = value
    return json.loads(text, **options)
