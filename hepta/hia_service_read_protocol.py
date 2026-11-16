"""Foreign operations for the complete original service read control flow.

HIA owns cursor admission, format selection, both trim loops, the repeated
wire budget, cursor publication, exception transitions and local retirement.
The original object, codec, wire, digest and SQLite expressions are hosted.
"""

SELECTOR = 'HEPTA_HIA_SERVICE_READ_MANIFEST'
SCHEMA = 'hepta.hia.service-read-native.v1'
SOURCE_NAME = 'examples/hia_bootstrap/service_read.hepta'
REQUEST_MAGIC = int.from_bytes(b'HSRDRQ01', 'little')
RESULT_MAGIC = int.from_bytes(b'HSRDRS01', 'little')
STATE_MAGIC = int.from_bytes(b'HSRDST01', 'little')
REQUEST_BYTES, OUTPUT_BYTES, STATE_BYTES = 80, 96, 128
INITIALIZE, CLAIM, SUCCEEDED, RAISED = 0, 1, 2, 3
ISSUED, CLAIMED, RETURNED, PROPAGATE, UNWIND = 1, 2, 4, 5, 7

PORTS = (
    'artifact_argument', 'artifact_get', 'offset_zero', 'cursor_present',
    'cursor_select', 'cursor_missing', 'cursor_id_test',
    'cursor_sha_test', 'cursor_reject', 'cursor_offset',
    'limit', 'initial_chunk', 'encoding_utf8', 'whole_data_decode',
    'first_chunk_decode', 'first_exception_match', 'first_chunk_trim',
    'outer_exception_match', 'initial_base64',
    'budget_test',
    'budget_chunk_halve', 'later_base64', 'later_chunk_decode',
    'later_exception_match', 'later_chunk_trim',
    'next_cursor_none', 'end_test',
    'next_cursor_digest', 'cursor_insert', 'result',
    'release_locals', 'return',
)
PORT = {name: index + 1 for index, name in enumerate(PORTS)}
MODES = {'read': 1}
