"""Opaque artifact effects; HIA owns the complete service handler control."""

SELECTOR = 'HEPTA_HIA_SERVICE_ARTIFACT_MANIFEST'
SCHEMA = 'hepta.hia.service-artifact.v1'
SOURCE_NAME = 'examples/hia_bootstrap/service_artifact.hepta'
REQUEST_MAGIC = int.from_bytes(b'HSAREQ01', 'little')
RESULT_MAGIC = int.from_bytes(b'HSARSP01', 'little')
STATE_MAGIC = int.from_bytes(b'HSASTA01', 'little')
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
    'profile', 'source', 'kind_is_utf8', 'utf8_data', 'capture_data',
    'expected', 'expected_is_not_none', 'digest_differs', 'reject_changed',
    'put', 'result', 'release_locals',
)
PORT = {name: index + 1 for index, name in enumerate(PORTS)}
