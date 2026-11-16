"""Opaque transaction effects; HIA owns sequencing and exception policy."""

SELECTOR = 'HEPTA_HIA_STORE_TRANSACTION_MANIFEST'
SCHEMA = 'hepta.hia.store-transaction.v1'
SOURCE_NAME = 'examples/hia_bootstrap/store_transaction.hepta'
REQUEST_MAGIC = int.from_bytes(b'HTXREQ01', 'little')
RESULT_MAGIC = int.from_bytes(b'HTXRSP01', 'little')
STATE_MAGIC = int.from_bytes(b'HTXSTA01', 'little')
REQUEST_BYTES = 80
OUTPUT_BYTES = 96
STATE_BYTES = 128

INITIALIZE = 0
CLAIM = 1
SUCCEEDED = 2
RAISED = 3
BODY_RETURNED = 4
BODY_RAISED = 5

ISSUED = 1
CLAIMED = 2
RETURNED = 4
PROPAGATE = 5
BODY_WAIT = 6
LEAVE_HANDLER = 7
REFUSED = 8

PORTS = (
    'lock_lookup', 'context_lookup_next', 'context_lookup_enter',
    'context_lookup_exit', 'lock_enter', 'begin', 'body_exception_match',
    'rollback', 'commit', 'lock_exit_normal', 'lock_exit_exception',
    'lock_exit_truth', 'terminal_release',
)
PORT = {name: index + 1 for index, name in enumerate(PORTS)}
