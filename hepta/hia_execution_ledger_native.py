"""Exact byte transport for execution reports produced by the HIA VM."""

import struct

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_opcodes import ExecutionObservationRejected

SELECTOR = 'HEPTA_HIA_EXECUTION_LEDGER_MANIFEST'
SOURCE = _source_resource_path('examples/hia_bootstrap/execution_ledger.hepta')
SCHEMA = 'hepta.hia.execution-ledger-native.v1'
FRAME = struct.Struct('<8s26Q')
WORD_MAX = (1 << 64) - 1
RESOURCES = ('allocations', 'frees', 'allocation_attempts', 'owners_created', 'owners_dropped',
             'live_owners', 'live_bytes', 'peak_bytes', 'loans_started', 'loans_ended',
             'live_local_loans')
CHAINS = ('chains_created', 'chains_consumed', 'live_chains', 'chain_nodes_created',
          'chain_nodes_dropped', 'live_chain_nodes')
LEDGER_FIELDS = (frozenset(RESOURCES), frozenset(RESOURCES + CHAINS))
STATUSES = {'returned': 1, 'trapped': 2, 'budget_exceeded': 3}
ERRORS = {name: code for code, name in enumerate((
    'user', 'overflow', 'division_by_zero', 'bounds', 'allocation', 'steps', 'heap', 'calls',
    'host_memory'), 1)}
REJECTIONS = (
    'unknown execution outcome',
    'exact profile flags required',
    'external root count must be an exact unsigned u64 integer',
    'resource field inventory differs',
    'resource counters must be exact unsigned u64 integers',
    'invalid explicit evaluator limits',
    'allocation and owner conservation differ',
    'live payload is inconsistent with live allocation/owner counts',
    'local loan conservation differs',
    'a live loan has no live byte owner',
    'live/peak payload exceeds the explicit heap policy',
    'recursive chain conservation differs',
    'chain nodes have missing byte owners',
    'ordinary return cannot carry an error outcome',
    'ordinary scalar return retains resources',
    'unknown or misclassified stop code',
    'tick count contradicts the execution outcome',
)


def _word(value, fallback=0):
    return value if type(value) is int and 0 <= value <= WORD_MAX else fallback


class NativeExecutionLedger(NativeHiaJsonImage):
    def validate(self, status, ledger, *, steps, max_steps, max_heap_bytes, error_code=None,
                 with_chains=False, allow_host_memory=False, live_external_roots=0):
        chained = with_chains is True
        fields = RESOURCES + CHAINS if chained else RESOURCES
        inventory = type(ledger) is dict and ledger.keys() == LEDGER_FIELDS[chained]
        words = tuple(ledger[name] for name in fields) if inventory else ()
        flags = (int(_word(live_external_roots, None) is None)
                 | (int(not inventory) << 1)
                 | (int(any(_word(value, None) is None for value in words)) << 2)
                 | (int(type(steps) is not int) << 3))
        if error_code is None:
            error = 0
        else:
            error = ERRORS.get(error_code, 10) if type(error_code) is str else 10
        controls = (STATUSES.get(status, 0) if type(status) is str else 0,
                    int(with_chains) if type(with_chains) is bool else 2,
                    int(allow_host_memory) if type(allow_host_memory) is bool else 2,
                    _word(live_external_roots), _word(steps, WORD_MAX), _word(max_steps),
                    _word(max_heap_bytes, WORD_MAX), error, flags)
        counters = tuple(map(_word, words)) + (0,) * (17 - len(words))
        packet = FRAME.pack(b'HIAELO01', *controls, *counters)
        result = self._entry(packet, len(packet), None, 0, None, 0)
        if result == 0:
            return
        if 1 <= result <= len(REJECTIONS):
            raise ExecutionObservationRejected('E_HIA_EXECUTION_CONTRACT: ' + REJECTIONS[result - 1])
        raise ValueError('invalid native execution ledger response')


def installed_execution_ledger(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeExecutionLedger)
