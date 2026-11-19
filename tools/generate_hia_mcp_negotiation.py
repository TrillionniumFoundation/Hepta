"""Author early MCP protocol selection from an immutable request.

The HIA wire classifier still determines the request's identity and typed
method. This companion extends its private descriptor with bootstrap action,
requested version and negotiated version. Transport state and effect
authorization are not inputs the remote caller can select.
"""
from __future__ import annotations

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_mcp_request import KEYS, METHODS, ROOT, comparison_table, source_program

SOURCE = 'examples/hia_bootstrap/mcp_negotiation.hepta'
METHODS_WITH_DISCOVERY = (*METHODS, 'server/discover')
VERSIONS = ('2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25', '2026-07-28')
LEGACY_FALLBACK = '2025-11-25'
NONE = (1 << 64) - 1
DESCRIPTOR = 112
(NO_BOOTSTRAP_ACTION, LEGACY_INITIALIZE, PING, DISCOVER, INLINE,
 INVALID_METADATA, UNSUPPORTED_INLINE) = range(7)

_EXTRA_KEYS = (
    'protocolVersion', 'capabilities', 'clientInfo', 'version', '_meta',
    'io.modelcontextprotocol/protocolVersion', 'io.modelcontextprotocol/clientCapabilities',
)

POLICY = r'''
def negotiation(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    route_result = widen(route(s, o, w))
    if route_result != 88:
        return route_result
    role = get(o, 8)
    params = lookup(w, 64, 4)
    version = 0
    selected = 0
    action = 0
    if get(o, 16) != 0:
        if role == 1:
            action = 5
            if is_kind(w, params, 6) != 0:
                version_node = lookup(w, params, 7)
                capabilities = lookup(w, params, 8)
                client = lookup(w, params, 9)
                if is_kind(w, version_node, 4) != 0 and is_kind(w, capabilities, 6) != 0:
                    if client_identity(w, client) != 0:
                        action = 1
                        version = version_of(w, version_node)
                        selected = version
                        if version == 0 or version > FALLBACK:
                            selected = FALLBACK
        elif role == 3:
            action = 2
        else:
            action = 5
            meta = NONE
            if is_kind(w, params, 6) != 0:
                meta = lookup(w, params, 11)
            if is_kind(w, meta, 6) != 0:
                inline_version = lookup(w, meta, 12)
                client_capabilities = lookup(w, meta, 13)
                if is_kind(w, inline_version, 4) != 0 and is_kind(w, client_capabilities, 6) != 0:
                    version = version_of(w, inline_version)
                    if role == 10:
                        action = 3
                    elif version != 0:
                        action = 4
                        selected = version
                    else:
                        action = 6
    put(o, 88, action)
    put(o, 96, version)
    put(o, 104, selected)
    return DESCRIPTOR

def client_identity(w:mutbuf, client:u64) -> u64:
    if is_kind(w, client, 6) == 0:
        return 0
    name = lookup(w, client, 5)
    version = lookup(w, client, 10)
    if is_kind(w, name, 4) == 0 or is_kind(w, version, 4) == 0:
        return 0
    return 1

def is_kind(w:mutbuf, value:u64, kind:u64) -> u64:
    if value == NONE:
        return 0
    return choose(get(w, value) == kind, 1, 0)

def version_of(w:mutbuf, node:u64) -> u64:
    return protocol_version(w, get(w, node + 24), get(w, node + 32))
'''


def render():
    policy = (POLICY.replace('NONE', str(NONE))
              .replace('FALLBACK', str(VERSIONS.index(LEGACY_FALLBACK) + 1))
              .replace('DESCRIPTOR', str(DESCRIPTOR)))
    source = '\n'.join((policy, comparison_table('protocol_version', VERSIONS),
                       source_program(methods=METHODS_WITH_DISCOVERY, keys=(*KEYS, *_EXTRA_KEYS))))
    return render_assembly(document(source, 'mcp_negotiation'))


def main():
    path = ROOT / SOURCE
    path.write_text(render(), encoding='utf-8')
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
