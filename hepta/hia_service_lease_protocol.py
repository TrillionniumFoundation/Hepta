"""Four complete service lease control graphs; fixed continuation ABI."""
SELECTOR = 'HEPTA_HIA_SERVICE_LEASE_MANIFEST'
SCHEMA = 'hepta.hia.service-lease.v1'
SOURCE_NAME = 'examples/hia_bootstrap/service_lease.hepta'
REQUEST_MAGIC = int.from_bytes(b'HSLREQ01', 'little')
RESULT_MAGIC = int.from_bytes(b'HSLRSP01', 'little')
STATE_MAGIC = int.from_bytes(b'HSLSTA01', 'little')
REQUEST_BYTES = 80
OUTPUT_BYTES = 96
STATE_BYTES = 128
ACQUIRE = 1
LEASE = 2
INVOKE = 3
RELEASE = 4
INITIALIZE = 0
CLAIM = 1
SUCCEEDED = 2
RAISED = 3
FINALIZE = 4
ISSUED = 1
CLAIMED = 2
READY_RETURN = 3
RETURNED = 4
PROPAGATE = 5
READY_PROPAGATE = 6
LEAVE_HANDLER = 7
REFUSED = 8
PORTS = (
    "cm_create",
    "cm_lookup_next",
    "cm_lookup_enter",
    "cm_lookup_exit",
    "cm_enter",
    "ledger_present",
    "acquire_ledger",
    "acquire_reference",
    "lease_ledger",
    "lease_reference",
    "release_ledger",
    "release_reference",
    "cm_exit_normal",
    "cm_exit_exception",
    "cm_exit_truth",
    "cm_stack_release",
    "cm_suppressed_release",
    "implicit_none",
    "import_runner",
    "import_validator",
    "invoke_lease_lookup",
    "invoke_native",
    "output_kind_differs",
    "reject_kind",
    "function_is_str",
    "signature_get",
    "signature_none",
    "signature_missing",
    "reject_signature",
    "snapshot_prefix",
    "snapshot_list",
    "snapshot_identity",
    "snapshot_wire",
    "snapshot_decode",
    "validate_arguments",
    "context_lookup",
    "run_native",
    "buffers_init",
    "captured_iter",
    "captured_next",
    "captured_data",
    "captured_append",
    "captured_iter_release",
    "signature_abi",
    "external_buffers",
    "external_empty",
    "result_returned",
    "observation_lookup",
    "observation_returned",
    "return_values",
    "return_observation",
    "return_status",
    "normal_release",
    "exception_stack_release",
)
PORT = {name: index + 1 for index, name in enumerate(PORTS)}
