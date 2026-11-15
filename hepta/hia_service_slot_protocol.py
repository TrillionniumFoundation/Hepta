"""Fixed observations for complete service rollback and adoption control.

The two modes preserve the original private method APIs. SQL operations and
native resource obligations of their providers remain separate owners.
"""
SELECTOR = 'HEPTA_HIA_SERVICE_SLOT_MANIFEST'
SCHEMA = 'hepta.hia.service-slot.v1'
SOURCE_NAME = 'examples/hia_bootstrap/service_slot.hepta'
REQUEST_MAGIC = int.from_bytes(b'HSSREQ01', 'little')
RESULT_MAGIC = int.from_bytes(b'HSSRSP01', 'little')
STATE_MAGIC = int.from_bytes(b'HSSSTA01', 'little')
REQUEST_BYTES = 80
OUTPUT_BYTES = 96
STATE_BYTES = 128

ROLLBACK = 1
ADOPT = 2
INITIALIZE = 0
CLAIM = 1
SUCCEEDED = 2
RAISED = 3
FINALIZE = 4
ISSUED = 1
CLAIMED = 2
READY_RETURN = 3
READY_PROPAGATE = 6
RETURNED = 4
PROPAGATE = 5
REFUSED = 8

PORTS = (
    "rollback_validate_ledger_present",
    "rollback_ledger_validate",
    "rollback_reference_validate",
    "rollback_snapshot",
    "rollback_ledger_present",
    "rollback_ledger_call",
    "rollback_reference_call",
    "rollback_receipt",
    "rollback_result",
    "rollback_release_locals",
    "adopt_context",
    "adopt_evaluation",
    "adopt_context_differs",
    "adopt_candidate_differs",
    "adopt_installation_differs",
    "adopt_reject_binding",
    "adopt_build_receipt",
    "adopt_objective",
    "adopt_evaluation_ledger_present",
    "adopt_ledger_evaluation",
    "adopt_reference_evaluation",
    "adopt_measurements",
    "adopt_full_cost_ledger",
    "adopt_net_ledger_present",
    "adopt_ledger_net",
    "adopt_reference_net",
    "adopt_native_candidate",
    "adopt_native_baseline",
    "adopt_signatures_differ",
    "adopt_reject_abi",
    "adopt_snapshot",
    "adopt_abi",
    "adopt_ledger_present",
    "adopt_ledger_call",
    "adopt_reference_call",
    "adopt_receipt",
    "adopt_result",
    "adopt_release_locals",
)
PORT = {name: index + 1 for index, name in enumerate(PORTS)}
