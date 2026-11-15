"""Complete discovery handlers ABI; provider objects remain opaque."""
SELECTOR = "HEPTA_HIA_SERVICE_DISCOVERY_MANIFEST"
SCHEMA = "hepta.hia.service-discovery.v1"
SOURCE_NAME = "examples/hia_bootstrap/service_discovery.hepta"
REQUEST_MAGIC = int.from_bytes(b"HSDREQ01", "little")
RESULT_MAGIC = int.from_bytes(b"HSDRSP01", "little")
STATE_MAGIC = int.from_bytes(b"HSDSTA01", "little")
REQUEST_BYTES, OUTPUT_BYTES, STATE_BYTES = 128, 96, 192
INITIALIZE, CLAIM, SUCCEEDED, RAISED, FINALIZE = 0, 1, 2, 3, 4
ISSUED, CLAIMED, RETURNED, PROPAGATE = 1, 2, 4, 5
READY_RETURN, READY_PROPAGATE, REFUSED = 6, 7, 8
DESCRIBE, EXAMPLES = 1, 2
PORTS = (
    'describe_import',
    'describe_cursor',
    'describe_reject_cursor',
    'describe_backend_present',
    'describe_backend_differs',
    'describe_reject_backend',
    'describe_language_schema',
    'describe_language',
    'describe_profile',
    'describe_section',
    'describe_resources',
    'describe_result',
    'describe_release',
    'examples_import',
    'examples_params',
    'examples_document',
    'examples_program',
    'examples_assembly',
    'examples_roundtrip_differs',
    'examples_raise_roundtrip',
    'examples_result',
    'examples_release',
)
PORT = {name: index + 1 for index, name in enumerate(PORTS)}
MODE_RANGES = {DESCRIBE: (1, 13), EXAMPLES: (14, 22)}
BOOLEAN_PORTS = frozenset(PORT[name] for name in ['describe_cursor', 'describe_backend_present', 'describe_backend_differs', 'examples_roundtrip_differs'])
ERROR_PORTS = frozenset()
LOCAL_NAMES = {
    DESCRIBE: ('self', 'args', 'opcode_catalog', 'language_schema', 'language', 'profile', 'language_ref', 'section', 'resources'),
    EXAMPLES: ('assemble_program', 'render_assembly', 'params', 'document', 'program', 'assembly'),
}
