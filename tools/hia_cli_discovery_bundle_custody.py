"""Hosted input custody for the optional five-image CLI discovery bundle.

These checks grant no cold authority themselves.  Authority comes only from
the original current-source cold replay, including its real B1/B2/B3 bytes.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from tools import hia_cli_discovery_custody as original
from tools.build_hia_cli_native import OWNER_FILES as CLI_OWNER_FILES

ROOT = Path(__file__).resolve().parents[1]
CAPACITY = original.CAPACITY
SOURCES = {
    'control': 'examples/hia_bootstrap/cli_control.hepta',
    'format': 'examples/hia_bootstrap/cli_format.hepta',
    'discovery': 'examples/hia_bootstrap/cli_discovery_json.hepta',
    'routing': 'examples/hia_bootstrap/cli_discovery_routing.hepta',
    'parser_context': 'examples/hia_bootstrap/cli_parser_context.hepta',
}
SCHEMAS = {
    'control': 'hepta.hia.cli-control-native.v1',
    'format': 'hepta.hia.cli-format-native.v1',
    'discovery': 'hepta.hia.cli-discovery-json-native.v1',
    'routing': 'hepta.hia.cli-discovery-routing-native.v1',
    'parser_context': 'hepta.hia.cli-parser-context-native.v1',
}
LABELS = {name: 'cli-' + name.replace('_', '-') for name in SOURCES}
BUNDLE_SCHEMA = 'hepta.hia.cli-discovery-bundle.v3'
RETAINED = 'tests/fixtures/hia_cli_routing_retained.json'
OWNER_FILES = tuple(dict.fromkeys((*original.OWNER_FILES, *CLI_OWNER_FILES,
    *SOURCES.values(),
    'hepta/hia_cli_discovery_facts.py',
    'hepta/hia_cli_discovery_routing_native.py',
    'hepta/hia_cli_parser_context_native.py',
    'hepta/hia_cli_parser_context_foreign.py',
    'hepta/hia_cli_parser_context_data.py',
    'tools/generate_hia_cli_discovery_routing.py',
    'tools/generate_hia_cli_parser_context.py',
    'tools/hia_cli_parser_graph.py',
    'tools/hia_cli_discovery_bundle_custody.py',
    'tools/build_hia_cli_discovery_bundle.py',
    'tools/qualify_hia_cli_discovery_bundle.py',
    'tools/hia_cli_discovery_routing_controls.py',
    'tests/test_hia_cli_discovery_routing_native.py',
    RETAINED, 'docs/HIA_CLI_DISCOVERY_ROUTING.md',
)))

require = original.require
read_json = original.read_json
encoded = original.encoded
publish = original.publish
binding = original.binding
check_bindings = original.check_bindings
admit_compilation = original.admit_compilation


def owner_sources():
    return {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in OWNER_FILES}


def require_owner_sources(sources):
    require(type(sources) is dict, 'complete CLI bundle source map required')
    for name, digest in owner_sources().items():
        require(sources.get(name) == digest, 'CLI bundle input is outside current cold closure: ' + name)


def admit_cold(path):
    authority = original.admit_cold(path)
    require_owner_sources(authority['source_manifest'])
    return authority


def guard_authority(authority):
    original.guard_authority(authority)
    require_owner_sources(authority['source_manifest'])


def retained_inputs():
    value = read_json((ROOT / RETAINED).read_bytes())
    require(type(value) is dict and value.get('schema') == 'hepta.hia.cli-routing-retained-inputs.v1',
            'exact retained CLI inputs required')
    for name, row in value['original_tests'].items():
        raw = row['text'].encode('utf-8')
        require(len(raw) == row['bytes'] and sha256(raw).hexdigest() == row['sha256']
                and (ROOT / name).read_bytes() == raw, 'original CLI test bytes changed: ' + name)
    require(len(value['original_ids']) == len(set(value['original_ids'])) == 43,
            'all original 43 CLI IDs are required')
    return value


def retained_module_bytes(name, current):
    """Exact two-byte-stream admission, never an AST-equivalence whitelist."""
    value = retained_inputs()
    row = value['integration_projections'].get(name)
    if row is None:
        return current
    before, after = row['before']['text'].encode(), row['after']['text'].encode()
    for side, raw in (('before', before), ('after', after)):
        require(len(raw) == row[side]['bytes'] and sha256(raw).hexdigest() == row[side]['sha256'],
                'retained CLI projection identity changed')
    require(current in (before, after), 'unapproved CLI integration bytes: ' + name)
    return before
