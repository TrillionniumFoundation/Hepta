"""Author native Worker binding of all installed discovery profiles."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_agent_discovery_native import PROFILE_NAMES
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS, comparison_table
from tools.generate_hia_worker_artifact_authority import source_program as authority
from tools.generate_hia_worker_context_request import POLICY as CONTEXT, literal_match
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/worker_profile_bindings.hepta')
PROFILES = tuple(sorted(PROFILE_NAMES))
KEYS = (*PROFILES, 'catalog_sha256', 'installation', 'profiles', 'profile_manifests', 'schema', 'id', 'sha256')

POLICY = r'''
# Canonical [installed catalog identity, installed implementation, retained
# manifest]. The manifest enters only after native Store and file custody.
def profile_bindings(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 2 or length(s) > 32768 or length(o) < 32768 or length(w) < 65536:
        return INVALID
    put(o, 48, 4096)
    put(o, 56, 32)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5 or get(w, 96) != 3:
        return INVALID
    catalog = 64 + get(w, 88) * 72
    install = 64 + get(w, catalog + 16) * 72
    manifest = 64 + get(w, install + 16) * 72
    if digest_text(w, catalog, False) == False or get(w, install) != 6 or get(w, manifest) != 6:
        return INVALID
    if manifest_schema(w, lookup(w, manifest, K_schema)) == False:
        return INVALID
    observed_catalog = lookup(w, manifest, K_catalog_sha256)
    observed_install = lookup(w, manifest, K_installation)
    if digest_text(w, observed_catalog, False) == False or map_node(w, observed_install) == False:
        return INVALID
    if equal_span(s, w, catalog, observed_catalog) == False or equal_span(s, w, install, observed_install) == False:
        return STALE
    profiles = lookup(w, manifest, K_profiles)
    files = lookup(w, manifest, K_profile_manifests)
    if map_node(w, profiles) == False or map_node(w, files) == False:
        return INVALID
    if get(w, profiles + 32) != PROFILE_COUNT or get(w, files + 32) != PROFILE_COUNT:
        return INVALID
    put(o, 0, RESULT)
    put(o, 8, PROFILE_COUNT)
    at = 16
    kind = 1
    while kind <= PROFILE_COUNT:
        profile = lookup(w, profiles, kind)
        issued = lookup(w, files, kind)
        if bound_profile(s, w, profile, issued, kind) == False:
            return INVALID
        at = fragment(s, w, o, profile, at)
        at = fragment(s, w, o, issued, at)
        kind = kind + 1
    return at

def bound_profile(s:readbuf, w:mutbuf, profile:u64, issued:u64, role:u64) -> bool:
    if map_node(w, profile) == False or get(w, profile + 32) != 2 or map_node(w, issued) == False:
        return False
    if get(w, issued + 32) != 3 or get(w, issued + 64) != 176 or artifact_reference(s, get(w, issued + 56)) == False:
        return False
    name = lookup(w, profile, K_id)
    if profile_id(w, name, role) == False:
        return False
    pin = lookup(w, profile, K_sha256)
    content = lookup(w, issued, K_sha256)
    if digest_text(w, pin, False) == False or digest_text(w, content, False) == False:
        return False
    return equal_span(s, w, pin, content)

def map_node(w:mutbuf, node:u64) -> bool:
    return node != NONE and get(w, node) == 6
'''


def program():
    tags={f'K_{name}': ordinal for ordinal, name in enumerate(KEYS, 1)}
    tags.update(PROFILE_COUNT=len(PROFILES), RESULT=int.from_bytes(b'HIAEPR01', 'little'),
                NONE=(1 << 64) - 1, INVALID=4294967293, STALE=4294967286)
    policy=re.sub(r'\b('+'|'.join(tags)+r')\b', lambda m: str(tags[m[0]]), POLICY)
    dispatch=['def profile_id(w:mutbuf, node:u64, role:u64) -> bool:']
    for ordinal, name in enumerate(PROFILES, 1):
        dispatch.extend((f'    if role == {ordinal}:', f'        return is_{name}(w, node)'))
    dispatch.append('    return False')
    custody=authority()
    return '\n'.join((
        policy, '\n'.join(dispatch),
        *(literal_match(f'is_{name}', 'hia-' + name + '-v1') for name in PROFILES),
        literal_match('manifest_schema', 'hepta.hia.agent.manifest.v1'),
        *(function(CONTEXT, name).replace('NONE', str(tags['NONE']))
          for name in ('digest_text', 'equal_span', 'fragment', 'copy_value')),
        *(function(custody, name) for name in ('artifact_reference', 'artifact_start',
                                               'artifact_digest', 'artifact_uri', 'valid_hex')),
        WIRE_HELPERS.split('\ndef signed_id', 1)[0].replace('NONE', str(tags['NONE'])),
        comparison_table('key_id', KEYS), json_decoder(wire_spans=True),
    ))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
