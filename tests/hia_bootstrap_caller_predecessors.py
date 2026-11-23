"""Read fixed outer caller revisions before the independent original-source checks."""
from hashlib import sha256
import json

from tests import hia_installed_distribution_history as installed
from tests import hia_native_transport_worker_successor as delivery
from tests.hia_store_delivery_successor import reverse_exact


_REVIEWED = {
    'tests/test_hia_agent_journal_native.py':
        '97dec702780d755cc5c2ffa59e5a798c98dc48a17735f9b8983bfdb610d2f263',
    'tests/test_hia_agent_native_machine_validation.py':
        '0c03b958462d2d2b8f7304b52bf419a9832037c3db4e51fa940053176fad0cbb',
    'tests/test_hia_agent_native_proof_contract.py':
        'cb958dfdac9ae83b421a55c34109247dbda64af85171525969da55ad3a6d1f03',
    'tests/test_hia_agent_native_tools.py':
        '64462e8735d8be3838396808dc05391e4437b2dba093fcc265468df6abb4cb70',
    'tests/test_hia_service_context_native.py':
        '94bba1ba99cfeb29baa9eb34072514803af288a11d964f950c46bea431e92c1b',
}


def bootstrap_caller_predecessor(root, name, raw, expected, capture):
    """A recognized complete file must invert under its own fixed byte authority."""
    if name not in _REVIEWED or sha256(raw).hexdigest() != _REVIEWED[name]:
        return raw
    if name in ('tests/test_hia_agent_journal_native.py', 'tests/test_hia_service_context_native.py'):
        record = installed._parse_records(capture(installed.FIXTURE))[name]
        return installed._restore(raw, record)
    if name == delivery.MACHINE_RECEIPT_CALLER:
        capture(delivery.MACHINE_RECEIPT_FIXTURE)
        return delivery.restore_machine_receipt_caller(root, raw, expected)
    if name == 'tests/test_hia_agent_native_proof_contract.py':
        fixed = capture(delivery.COMPONENT_FIXTURE)
        if sha256(fixed).hexdigest() != delivery.COMPONENT_FIXTURE_SHA256:
            raise ValueError('bootstrap proof caller provenance differs')
        return reverse_exact(raw, json.loads(fixed)['files'][name][expected['sha256']], expected)
    fixed = capture(delivery.SQLITE_BOUNDARY_FIXTURE)
    if delivery._pin(fixed) != delivery.SQLITE_BOUNDARY_FIXTURE_PIN:
        raise ValueError('bootstrap diagnostic caller authority differs')
    item = json.loads(fixed)['files'][name]
    prior = capture(delivery.DIAGNOSTIC_FIXTURE)
    if item['predecessor_fixture'] != {'path': delivery.DIAGNOSTIC_FIXTURE, **delivery._pin(prior)}:
        raise ValueError('bootstrap diagnostic predecessor authority differs')
    record = item['record']
    return reverse_exact(raw, record, {'bytes': record['old_bytes'], 'sha256': record['old_sha256']})
