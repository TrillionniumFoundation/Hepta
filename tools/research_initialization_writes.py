"""Finite VM observations of explicit writes, never a zero-elision proof.

The VM's ordinary zero initialization is retained. This records whether a
successful load is preceded by a program store to the same dynamic owner/index.
A missing program store is NOT an uninitialized Core read: zero-initialized Core
is safe. It is a counterexample to claiming program writes cover that read.
"""
from copy import deepcopy
from unittest.mock import patch
from hepta.hia_program import verify_program
from hepta import hia_program_runtime as vm


def observe_explicit_writes(program, arguments, *, function="calculate", **limits):
    checked = verify_program(program)
    written, owners, loads, stores = {}, {}, [], []
    operation = vm._Machine.operation
    def owner(value):
        return vm._underlying(value)
    def key(value):
        value = owner(value)
        # Retain the owner itself so Python object ids cannot be reused between
        # allocations during this observation. Report stable VM ids instead.
        ident = id(value)
        owners[ident] = value
        written.setdefault(ident, set())
        return ident
    def watched(machine, ins, env, depth):
        tracked = ins['op'] in {'buffer.load', 'buffer.store'}
        if tracked:
            allocation = key(env[ins['args'][0]])
            index = env[ins['args'][1]]
            prior = index in written[allocation]
        result = operation(machine, ins, env, depth)
        if ins['op'] == 'buffer.store':
            written[allocation].add(index)
            stores.append({'owner': owners[allocation].ident, 'index': index})
        elif ins['op'] == 'buffer.load':
            loads.append({'owner': owners[allocation].ident, 'index': index,
                          'preceded_by_program_store': prior})
        return result
    with patch.object(vm._Machine, 'operation', watched):
        try:
            outcome = vm.execute_program(checked, function, arguments, **limits)
        except (vm.HIAProgramTrap, vm.HIAProgramBudgetExceeded) as error:
            outcome = error.report
    return {'schema': 'hepta.hia.explicit-write-observation.v1', 'core_sha256': checked.sha256,
            'function': function, 'arguments': deepcopy(arguments), 'limits': deepcopy(limits), 'vm_outcome': outcome, 'stores': stores, 'loads': loads,
            'missing_program_writes': [row for row in loads if not row['preceded_by_program_store']],
            'ordinary_zero_initialization_retained': True, 'finite_observation_only': True,
            'authority': 'DENY_ALL', 'initialization_elision_authorized': False,
            'production_admission': False, 'native_admission': False,
            'performance_qualified': False, 'quota_equivalence': False}
