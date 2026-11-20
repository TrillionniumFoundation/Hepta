"""Instrumentation around the actual installed, unmodified worker main.

Authoring imports are rejected. The handler request still uses the real worker,
real AgentStore, original request journal and selected Slot public descriptors.
"""
from __future__ import annotations
import argparse
import ctypes
import importlib.abc
import json
import os
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.hia_slot_worker_terminal import SourceAuthority, TerminalObservation


class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name == 'tools' or name.startswith('tools.'):
            raise AssertionError('installed Slot runtime imported authoring tools')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--installed', type=Path, required=True)
    parser.add_argument('--mode', choices=('normal', 'lost-execute-ack'), required=True)
    options, worker_arguments = parser.parse_known_args()
    authority = SourceAuthority(ROOT)
    installed = options.installed.resolve(strict=True)
    sys.path.insert(0, str(installed))
    sys.meta_path.insert(0, NoAuthoring())
    from hepta import hia_slot_operations_native as controller
    from hepta import hia_slot_ledger_native as ledger
    from hepta import hia_agent_store as store
    from hepta import hia_agent_service as service
    from hepta import hia_native_delivery as delivery
    from hepta import hia_agent_worker as worker
    worker_main = worker.main
    from hepta.hia_native_helpers import HELPERS
    for module in (controller, ledger, store, service, delivery):
        if not Path(module.__file__).resolve().is_relative_to(installed):
            raise AssertionError('worker imported checkout instead of installed wheel')
    assert controller.SOURCE.resolve().is_relative_to(installed / 'hepta/_data')
    assert HELPERS[controller.SELECTOR] == ('hia_slot_operations_native', 'NativeSlotOperations')
    counts = {'startup': {}, 'request': {}, 'request_modes': {}, 'decision_request': 0,
              'retained_calls': [], 'close_calls': 0, 'lost_ack_injected': False}
    active = False
    terminal = TerminalObservation(worker, service, delivery, controller)
    assert terminal.profile == authority.profile

    def forbidden(*arguments, **keywords):
        counts['retained_calls'].append('actual retained Slot method')
        raise AssertionError('installed selected worker used retained Slot control')

    for name, method in tuple(ledger.NativeSlotLedgerStore._hia_slot_reference_methods.items()):
        ledger.NativeSlotLedgerStore._hia_slot_reference_methods[name] = (
            staticmethod(forbidden) if type(method) is staticmethod else forbidden)

    original_call = service.HIAAgentService._reference_call
    def request(self, *arguments, **keywords):
        nonlocal active
        active = True
        try:
            return original_call(self, *arguments, **keywords)
        finally:
            active = False
    service.HIAAgentService._reference_call = request

    initializer = controller.NativeSlotOperations.__init__
    def initialize(image, *arguments, **keywords):
        initializer(image, *arguments, **keywords)
        original = image._entry
        def observed(source, size, output, capacity, state, extent):
            raw = ctypes.string_at(source, size)
            words = struct.unpack('<16Q', raw)
            code = original(source, size, output, capacity, state, extent)
            assert words[0] == controller.REQUEST_MAGIC and code == controller.OUTPUT_BYTES
            bucket = counts['request' if active else 'startup']
            key = str(words[1])
            bucket[key] = bucket.get(key, 0) + 1
            if active:
                key = str(words[5])
                counts['request_modes'][key] = counts['request_modes'].get(key, 0) + 1
            if (active and options.mode == 'lost-execute-ack'
                    and words[5] == 2 and words[1] == controller.SUCCEEDED
                    and words[3] == controller.PORT['execute_call']
                    and not counts['lost_ack_injected']):
                counts['lost_ack_injected'] = True
                error = ValueError('actual SQL execute returned; controller acknowledgement withheld')
                terminal.injected(error)
                try:
                    raise error
                finally:
                    del error
            return code
        image._entry = observed
    controller.NativeSlotOperations.__init__ = initialize

    decision_init = ledger.NativeSlotLedger.__init__
    def initialize_decision(image, *arguments, **keywords):
        decision_init(image, *arguments, **keywords)
        original = image._entry
        def observed(*values):
            code = original(*values)
            if active:
                counts['decision_request'] += 1
            return code
        image._entry = observed
    ledger.NativeSlotLedger.__init__ = initialize_decision

    close = store._NATIVE_STORE_CLOSE_REFERENCE
    def closed(self):
        counts['close_calls'] += 1
        return close(self)
    store._NATIVE_STORE_CLOSE_REFERENCE = closed
    try:
        status = worker_main(worker_arguments)
    finally:
        counts['terminal'] = terminal.report()
        counts['unknown_records'] = sum(row['lost'] for row in delivery.custody_snapshot())
        counts['unknown_resource_observations'] = len(delivery._RESOURCE_OBSERVATIONS)
        counts['installed_modules'] = {module.__name__: str(Path(module.__file__).resolve())
                                      for module in (controller, ledger, store, service, delivery)}
        counts['source_resource'] = str(controller.SOURCE.resolve())
        print('SLOT_OPERATIONS_INSTALLED=' + json.dumps(counts, ensure_ascii=True, sort_keys=True),
              file=sys.stderr, flush=True)
    authority.finish()
    return status


if __name__ == '__main__':
    raise SystemExit(main())
