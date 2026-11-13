"""Hosted object transport for the HIA execution-result ledger policy.

Python objects, exceptions and lazy iterator frames remain hosted. No retained
execution-ledger predicate or public VM implementation is called here.
"""
from __future__ import annotations

from .hia_machine_object_native import NativeMachineObject


def _unpack_seven(value):
    a, b, c, d, e, f, g = value
    return a, b, c, d, e, f, g


class NativeExecutionObservation(NativeMachineObject):
    ABI_SCHEMA = 'hepta.hia.execution-observation-abi.v1'

    def global_value(self, name):
        if name == '_hia_observation_unpack_seven':
            return _unpack_seven
        if name == 'need':
            def need(condition, message):
                return self.invoke('need', (condition, message))
            return need
        return super().global_value(name)
