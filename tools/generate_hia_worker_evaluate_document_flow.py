"""Issue or reopen one digest-bound Evaluate document through the sealed Store ports."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_discovery_artifact import EVALUATE_FIRST_KIND, EVALUATE_LAST_KIND
from tools.generate_hia_worker_adopt_proof import reachable_policy
from tools.generate_hia_worker_artifact_flow import ENTRY_POLICY
from tools.generate_hia_worker_context_flow import flow_source, function
from tools.generate_hia_worker_verify_publication_flow import recipe as verification_publication

SOURCE = Path('examples/hia_bootstrap/worker_evaluate_document_flow.hepta')
# Ordered descriptors provisioned by the parent, each a distinct sealed ELF.
ROLES = ('hia-agent-store', 'hia-agent-store-ready', 'hia-agent-store-unique', 'hia-artifact',
         'hia-agent-discovery-artifact', 'hia-agent-publication-observation', 'hia-agent-native-artifact-metadata')

ENTRY = r'''
def evaluate_document(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != EMIT_WORK_BYTES or length(o) != 2048:
        return BAD
    state = get(w, 0)
    if state == 0:
        if input_word(s, 0) != ENTRY or admit_entry(s, o) != 344:
            return BAD
        size = input_word(s, 8)
        if size <= 96:
            return BAD
        keep(w, ORIGINAL, 0, size)
        i = 0
        while i < ROLE_COUNT:
            put(w, ROLE_BASE + 8 * i, input_word(s, ENTRY_HEAD + DOSSIER_HEAD + DESCRIPTOR_BYTES * i))
            i = i + 1
        return read_span(o, w, DOC_HEADER, 0, 0, 96)
    OBSERVE_REQUEST
    if state == DOC_HEADER:
        kind = input_word(s, 80)
        operation = input_word(s, 72)
        size = input_word(s, 88)
        if length(s) != 160 or input_word(s, 64) != DOC_REQUEST or operation > 1:
            return BAD
        if kind < EVAL_FIRST or kind > EVAL_LAST or size != slot_bytes(w, ORIGINAL) - 96:
            return BAD
        i = 0
        while i < 64:
            if is_hex(byte(s, 96 + i)) == False:
                return BAD
            store(w, EMIT_PUBLIC_AUTHORITY + i, byte(s, 96 + i))
            i = i + 1
        put(w, VERIFY_REPLAYING, operation)
        put(w, DOC_KIND, kind)
        hold(w, DOC_BODY, 0, 96, size)
        put(o, HEADER, 32123)
        return action(o, w, DOC_METADATA, MAKE, 0, 0, 0, 2)
    if state == DOC_METADATA:
        if size != 2:
            return BAD
        hold(w, EMIT_EMPTY_METADATA, input_word(s, 32), 0, 2)
        return emit_publish(o, w, get(w, DOC_KIND), DOC_BODY, EMIT_EMPTY_METADATA)
    if state == INSPECTION_HASH_RETURNED:
        if size < 88 or size > 105:
            return BAD
        return read_span(o, w, INSPECTION_HASH_FRAME, input_word(s, 32), 0, size)
    if state == INSPECTION_HASH_FRAME:
        return inspection_hash_result(s, o, w)
    if state >= PEER_STARTED and state <= PEER_CLOSED:
        return observe_store(s, o, w, state)
    if state >= EMIT_PUB_QUERY and state <= EMIT_PUB_COMPARE:
        return emit_publication_state(s, o, w, state)
    if state == DOC_PUBLISHED and length(s) == 64:
        return action(o, w, DOC_PUBLISHED, FINISHED, 0, 0, 0, 0)
    return BAD

def inspection_hash_bound(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    return emit_publication_hash(s, o, w, at, get(w, INSPECTION_HASH_RESUME))

def emit_publication_complete(o:mutbuf, w:mutbuf) -> u64:
    ref = EMIT_ARTIFACT_REFS + 24 * (get(w, EMIT_PUB_KIND) - EVAL_FIRST)
    if get(w, ref + 16) != 176:
        return BAD
    use_span(w, o, ref, 0)
    return action(o, w, DOC_PUBLISHED, PUBLISH, 0, 0, 1, 0)
'''

def program(*, entry=ENTRY, roles=ROLES, root='evaluate_document', extra=None, adjust=None):
    constants, parent, controls = verification_publication()
    constants.update(ROLE_COUNT=len(roles), ENTRY_BYTES=376 + 40 * len(roles), MAX_INPUT=67108864,
                     STORE_ROLE=0, READY_ROLE=1, UNIQUE_ROLE=2, PUBLISHER_ROLE=3,
                     DOCUMENT_PLAN_ROLE=4, EMIT_PUBLICATION_ROLE=5, EMIT_NATIVE_ARTIFACT_ROLE=6,
                     EVAL_FIRST=EVALUATE_FIRST_KIND, EVAL_LAST=EVALUATE_LAST_KIND,
                     DOC_REQUEST=int.from_bytes(b'HIAEDU01', 'little'), DOC_KIND=12080,
                     DOC_BODY=12088, DOC_HEADER=1600, DOC_METADATA=1601, DOC_PUBLISHED=1602)
    constants.update(extra or {})
    # Preserve the same action/observation ownership checks as Verify.
    observation = parent[parent.index('    if (length(s) < 64'):parent.index('    if state == INSPECTION_HASH_RETURNED:')]
    entries = [entry.replace('    OBSERVE_REQUEST\n', observation)]
    replaced = ('inspection_hash_bound', 'emit_publication_complete')
    for control in controls:
        name = control.split('(', 1)[0].strip().removeprefix('def ')
        if name in replaced:
            continue
        if name == 'emit_publish':
            control = control.replace('kind < 16 or kind > VERIFY_CERTIFICATE_KIND',
                                      'kind < EVAL_FIRST or kind > EVAL_LAST')
        if name == 'emit_publication_observed':
            control = control.replace('(kind - 16)', '(kind - EVAL_FIRST)')
        if name == 'emit_publication_hash':
            line = '        copy_span(s, w, at, EMIT_PUB_CONTENT_HASH, 64)\n'
            assert control.count(line) == 1
            control = control.replace(line, line + '        if emit_authorized_digest(w, EMIT_PUBLIC_AUTHORITY) == False:\n            return BAD\n')
        entries.append(adjust(name, control) if adjust is not None else control)
    entries += [function(ENTRY_POLICY, name) for name in ('admit_entry', 'dossier_identity', 'trusted_descriptors')]
    entry, helpers = reachable_policy('\n'.join(entries), root)
    return flow_source(entry, helpers, constants)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
