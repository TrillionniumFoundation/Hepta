"""Admit five additional helpers in the same exact CPython 3.12 mapping.

The original eleven-function table and the control table use one strict ELF
parser and the same physical mapping proof. No C leaf or generator body is
called here. ET_EXEC absolute values and ET_DYN relocation bias are distinct
from the loader's image mapping base; live full-function bytes remain required.
"""
from __future__ import annotations

import sys

from hepta.hia_cli_json_runtime312 import (
    _live_symbols, _symbol_records, admit_runtime, read_runtime,
)

CONTROL_SYMBOLS = (
    '_PyEval_EvalFrameDefault', '_Py_Instrument',
    '_Py_call_instrumentation_arg', '_Py_HandlePending', '_PyErr_ChainStackItem',
)


def control_symbol_table(raw):
    return _symbol_records(raw, CONTROL_SYMBOLS)[0]


def admit_runtime_control(path, *, sha256_pin, bytes_pin):
    """Bind the unchanged base table and five additional live functions."""
    if sys.implementation.name != 'cpython' or tuple(sys.version_info[:3]) != (3, 12, 14):
        raise ValueError('the additional private table requires exact CPython 3.12.14')
    base_words, base_binding = admit_runtime(path, sha256_pin=sha256_pin, bytes_pin=bytes_pin)
    raw, before = read_runtime(path, sha256_pin, bytes_pin)
    if before != base_binding['runtime'] or before != base_binding['runtime_after']:
        raise ValueError('base and additional tables do not share one unchanged runtime')
    records, layout = _symbol_records(raw, CONTROL_SYMBOLS)
    words, mapping = _live_symbols(raw, before, records, layout,
                                  required_mapping=base_binding['mapping'])
    if words[1] != base_words[1]:
        raise ValueError('the additional table has a different live evaluator address')
    after_raw, after = read_runtime(path, sha256_pin, bytes_pin)
    if after != before or after_raw != raw:
        raise ValueError('the additional runtime changed during its actual-byte admission')
    return words, {
        'schema': 'hia.cli-json.cpython312-control-runtime-binding.v1',
        'profile': 31214, 'runtime': before, 'runtime_after': after,
        'load_base': mapping['image_mapping_base'],
        'relocation_bias': mapping['relocation_bias'], 'mapping': mapping,
        'symbols': records, 'base_words': base_words, 'base_binding': base_binding,
        'activation_executed': False, 'body_driver_qualified': False,
        'original17_executed': False, 'original46_executed': False,
    }
