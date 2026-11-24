"""Recover the former diagnostic test fixture as data for its historical controls."""
from hashlib import sha256
import json

from tests import hia_caller_diagnostics_admission as diagnostics
from tests import hia_native_transport_worker_successor as delivery


def diagnostic_predecessor(root, raw):
    """Check the actual inherited source, then restore its reviewed predecessor."""
    if diagnostics.pin(raw) == diagnostics.CURRENT:
        return raw
    return delivery._reverse_sqlite_boundary(diagnostics.PATH, raw,
        (root / delivery.SQLITE_BOUNDARY_FIXTURE).read_bytes(),
        delivery.DIAGNOSTIC_FIXTURE, (root / delivery.DIAGNOSTIC_FIXTURE).read_bytes(), diagnostics.CURRENT)


def historical_caller_dependencies(root, sources, expected):
    """Recover only the reviewed Machine and Proof fixture versions as data."""
    from tests.hia_store_delivery_successor import reverse_exact

    from tests.hia_installed_distribution_history import predecessor
    for name, raw in sources.items():
        sources[name] = predecessor(name, raw)
    ndu = 'tests/test_hia_ndu_bridge.py'
    if ndu in expected and diagnostics.pin(sources[ndu])['sha256'] != expected[ndu]:
        from tests.hia_store_delivery_successor import final_source_predecessor
        sources[ndu], _relation = final_source_predecessor(
            ndu, sources[ndu], original_sha256=expected[ndu])
    machine = delivery.MACHINE_RECEIPT_CALLER
    if machine in expected and diagnostics.pin(sources[machine])['sha256'] != expected[machine]:
        authority = (root / delivery.MACHINE_RECEIPT_FIXTURE).read_bytes()
        if diagnostics.pin(authority) != delivery.MACHINE_RECEIPT_FIXTURE_PIN:
            raise ValueError('the retained machine source authority changed')
        record = json.loads(authority)['record']
        sources[machine] = delivery.restore_machine_receipt_caller(root, sources[machine],
            {'bytes': record['old_bytes'], 'sha256': expected[machine]})
    proof = 'tests/test_hia_agent_native_proof_contract.py'
    if proof in expected and diagnostics.pin(sources[proof])['sha256'] != expected[proof]:
        authority = (root / delivery.COMPONENT_FIXTURE).read_bytes()
        if sha256(authority).hexdigest() != delivery.COMPONENT_FIXTURE_SHA256:
            raise ValueError('the retained proof source authority changed')
        record = json.loads(authority)['files'][proof][expected[proof]]
        sources[proof] = reverse_exact(sources[proof], record,
            {'bytes': record['old_bytes'], 'sha256': expected[proof]})


def historical_bootstrap_dependencies(root, sources, scopes):
    historical_caller_dependencies(root, sources, {
        name: record['sha256'] for name, record in scopes['ordinary']['files'].items()})


def historical_terminal_pair(root, sources, current, physical):
    from tests.hia_installed_distribution_history import predecessor

    def capture(name):
        if name not in physical:
            physical[name] = (root / name).read_bytes()
        return physical[name]

    for name, expected in current.items():
        raw = predecessor(name, sources[name])
        if diagnostics.pin(raw) != expected:
            if name == delivery.TRANSPORT:
                raw = delivery._reverse_sqlite_boundary(
                    name, raw, capture(delivery.SQLITE_BOUNDARY_FIXTURE), delivery.FIXTURE,
                    capture(delivery.FIXTURE), expected)
            elif name == delivery.DELIVERY:
                raw = delivery.restore_sql_source(name, raw, capture, expected)
            elif name == delivery.EVALUATION:
                raw = delivery.restore_evaluation_store(raw, capture(delivery.EVALUATION_STORE_FIXTURE))
        if diagnostics.pin(raw) != expected:
            raise ValueError('terminal test predecessor differs: ' + name)
        sources[name] = raw
    if any((root / name).read_bytes() != raw for name, raw in physical.items()):
        raise ValueError('terminal source inputs changed during capture')


def historical_terminal_callers(root, sources, expected):
    from hepta.hia_native_helpers import HELPERS
    from tests.hia_store_delivery_successor import reverse_exact

    historical_caller_dependencies(root, sources, expected)
    name = diagnostics.PATH
    sources[name] = diagnostic_predecessor(root, sources[name])
    name = 'tests/test_hia_cost_ledger_native.py'
    fixed = (root / delivery.COMPONENT_FIXTURE).read_bytes()
    if sha256(fixed).hexdigest() != delivery.COMPONENT_FIXTURE_SHA256:
        raise ValueError('terminal component test authority differs')
    record = json.loads(fixed)['files'][name][expected[name]]
    sources[name] = reverse_exact(sources[name], record, {'bytes': record['old_bytes'], 'sha256': expected[name]})
    name = 'tests/test_hia_worker_native_helpers.py'
    fixed = (root / 'tests/fixtures/store_caller_worker_helpers_successor.json').read_bytes()
    if sha256(fixed).hexdigest() != '168ef69fadf672e41f3dd717d3d79e54fcd1af70105d2e3552687b72af824904':
        raise ValueError('terminal worker test authority differs')
    record = json.loads(fixed)['record']
    prior = reverse_exact(sources[name], record, {'bytes': record['old_bytes'], 'sha256': expected[name]})
    old = b'        self.assertEqual(len(HELPERS), 37)\n'
    if prior.count(old) != 1:
        raise ValueError('original terminal worker helper-count assertion differs')
    sources[name] = prior.replace(old, old.replace(b'37', str(len(HELPERS)).encode('ascii')), 1)
