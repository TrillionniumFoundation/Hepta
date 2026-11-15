"""Opaque discovery effects; HIA owns the complete describe handler control."""

SELECTOR = 'HEPTA_HIA_SERVICE_DESCRIBE_MANIFEST'
SCHEMA = 'hepta.hia.service-describe.v1'
SOURCE_NAME = 'examples/hia_bootstrap/service_describe.hepta'
REQUEST_MAGIC = int.from_bytes(b'HSDREQ01', 'little')
RESULT_MAGIC = int.from_bytes(b'HSDRSP01', 'little')
STATE_MAGIC = int.from_bytes(b'HSDSTA01', 'little')
REQUEST_BYTES = 80
OUTPUT_BYTES = 96
STATE_BYTES = 128

INITIALIZE = 0
CLAIM = 1
SUCCEEDED = 2
RAISED = 3

ISSUED = 1
CLAIMED = 2
RETURNED = 4
PROPAGATE = 5
REFUSED = 8

PORTS = (
    'import_catalog', 'has_cursor', 'reject_cursor', 'has_backend_profile',
    'backend_differs', 'reject_profile', 'language_schema', 'language',
    'profile_pair', 'section', 'resources', 'result', 'release_locals',
)
PORT = {name: index + 1 for index, name in enumerate(PORTS)}
