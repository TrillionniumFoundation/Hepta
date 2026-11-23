"""Author native authority for the installed Worker routes."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_read_capsule import DOSSIER_MAGIC, MAX_ROLE_BYTES, ROLES as READ_ROLES
from tools.generate_hia_sha256 import source_program as sha256_program

SOURCE = 'examples/hia_bootstrap/worker_readonly_capsule.hepta'
NATIVE_SOURCE = 'examples/hia_bootstrap/worker_native_capsule.hepta'
REPLAY_SOURCE = 'examples/hia_bootstrap/worker_evaluate_replay_capsule.hepta'
REPLAY_OWNER = 'hia-agent-evaluate-replay-worker-carrier'
INTAKE_OWNER = 'hia-agent-evaluate-intake-worker-carrier'
INTAKE_SOURCE = 'examples/hia_bootstrap/worker_evaluate_intake_capsule.hepta'
NATIVE_MANIFEST = b'HIANCP01'
ARTIFACT_CONFIG = b'HIARAC01'
MANIFEST_MAGIC = b'HIADCP01'
BOOTSTRAP_MAGIC = b'HIADBQ01'
RESOURCES_MAGIC = b'HIADBF01'
DESCRIBE_ROLES = (
    'hia-worker-admit', 'hia-worker-journal-call', 'hia-agent-worker-arguments',
    'hia-agent-mcp-input-schema', 'hia-agent-journal-read-workflow', 'hia-agent-journal',
    'hia-agent-read-carrier', 'hia-agent-store', 'hia-agent-store-ready',
    'hia-agent-discovery-effect', 'hia-agent-describe-request', 'hia-agent-discovery',
    'hia-agent-describe-bind', 'hia-artifact', 'hia-agent-store-unique',
    'hia-worker-response', 'hia-agent-mcp-response-schema', 'hia-agent-journal-cost',
    'hia-worker-terminal', 'hia-agent-discovery-carrier', 'hia-agent-discovery-artifact',
    'hia-agent-describe-answer',
)
BOOTSTRAP_ROLES = (
    'hia-agent-discovery-bootstrap-plan', 'hia-agent-discovery',
    'hia-agent-discovery-bootstrap-assemble', 'hia-agent-discovery-carrier',
    'hia-agent-store-init', 'hia-agent-store', 'hia-agent-store-ready', 'hia-agent-store-unique',
    'hia-artifact', 'hia-agent-discovery-artifact', 'hia-agent-discovery-effect',
)
DESCRIBE_OWNER = 'hia-agent-describe-worker-carrier'
BOOTSTRAP_OWNER = 'hia-agent-discovery-bootstrap-carrier'
ROLES = tuple(dict.fromkeys((*READ_ROLES, *DESCRIBE_ROLES, *BOOTSTRAP_ROLES, DESCRIBE_OWNER, BOOTSTRAP_OWNER)))
ARTIFACT_OWNER = 'hia-agent-artifact-worker-carrier'
ARTIFACT_ROLES = (
    'hia-worker-admit', 'hia-worker-journal-call', 'hia-agent-worker-arguments',
    'hia-agent-mcp-input-schema', 'hia-agent-artifact-journal', 'hia-agent-journal',
    'hia-agent-store', 'hia-agent-store-ready', 'hia-agent-store-unique',
    'hia-agent-journal-records', 'hia-agent-journal-observation', 'hia-agent-artifact-capture',
    'hia-agent-artifact-authority', 'hia-artifact', 'hia-agent-artifact-request',
    'hia-agent-input-carrier', 'hia-agent-discovery-artifact', 'hia-agent-discovery-effect',
    'hia-worker-response', 'hia-agent-mcp-response-schema', 'hia-agent-journal-cost',
    'hia-worker-terminal', 'hia-agent-artifact-diagnostic',
)
CONTEXT_OWNER = 'hia-agent-context-worker-carrier'
CONTEXT_ROLES = (
    'hia-worker-admit', 'hia-worker-journal-call', 'hia-agent-worker-arguments',
    'hia-agent-mcp-input-schema', 'hia-agent-context-journal', 'hia-agent-journal',
    'hia-agent-store', 'hia-agent-store-ready', 'hia-agent-store-unique',
    'hia-agent-context-journal-records', 'hia-agent-context-journal-observation',
    'hia-agent-artifact-capture', 'hia-agent-artifact-authority', 'hia-artifact',
    'hia-agent-context-request', 'hia-agent-discovery-carrier', 'hia-agent-discovery-artifact',
    'hia-agent-discovery-effect', 'hia-worker-response', 'hia-agent-mcp-response-schema',
    'hia-agent-journal-cost', 'hia-worker-terminal', 'hia-agent-context-diagnostic',
    'hia-agent-context-control-launcher', 'hia-agent-context-effect', 'hia-agent-context-store',
    'hia-agent-context-record', 'hia-agent-context-payload', 'hia-agent-context-workload',
    'hia-agent-context-cost', 'hia-nominal-constructor',
)
INSPECTION_OWNER = 'hia-agent-inspection-worker-carrier'
INSPECTION_ROLES = (
    'hia-worker-admit', 'hia-worker-journal-call', 'hia-agent-worker-arguments',
    'hia-agent-mcp-input-schema', 'hia-agent-inspection-journal', 'hia-agent-journal',
    'hia-agent-store', 'hia-agent-store-ready', 'hia-agent-store-unique',
    'hia-agent-inspection-journal-records', 'hia-agent-inspection-journal-observation',
    'hia-agent-artifact-capture', 'hia-agent-artifact-authority', 'hia-artifact',
    'hia-agent-context-request', 'hia-agent-discovery-carrier',
    'hia-agent-discovery-artifact', 'hia-agent-discovery-effect', 'hia-worker-response',
    'hia-agent-mcp-response-schema', 'hia-agent-journal-cost', 'hia-worker-terminal',
    'hia-agent-inspection-diagnostic', 'hia-agent-context-control-launcher',
    'hia-agent-context-effect', 'hia-agent-context-store', 'hia-agent-context-record',
    'hia-agent-context-payload', 'hia-agent-context-workload', 'hia-agent-context-cost',
    'hia-nominal-constructor', 'hia-agent-inspection-request', 'hia-agent-inspection-effect',
    'hia-agent-context-request', 'hia-agent-inspection-wire', 'hia-agent-worker-canonical',
    'hia-prepare-edit-query', 'hia-emit-object', 'hia-agent-inspection-lowering-elf',
    'hia-agent-inspection-lowering-frames',
)
CANDIDATE_OWNER = 'hia-agent-candidate-worker-carrier'
CANDIDATE_ROLES = (
    *(name.replace("inspection-", "candidate-") if name.startswith("hia-agent-inspection-") else name
      for name in INSPECTION_ROLES[:31]),
    'hia-agent-candidate-request', 'hia-agent-candidate-effect', 'hia-agent-context-request',
    'hia-import-assembly', 'hia-patch-result', 'hia-agent-candidate-json-ingress',
    'hia-agent-candidate-admission-diagnostic',
)
ROLLBACK_OWNER = 'hia-agent-rollback-worker-carrier'
ROLLBACK_ROLES = (
    *(name.replace('inspection-', 'rollback-') if name.startswith('hia-agent-inspection-') else name
      for name in INSPECTION_ROLES[:31]),
    'hia-agent-worker-rollback', 'hia-agent-native-artifact-metadata',
    'hia-agent-context-request', 'hia-agent-borrowed-export-wire',
)
EMIT_OWNER = 'hia-agent-emit-worker-carrier'
EMIT_ROLES = (
    *(name.replace('inspection-', 'emit-') if name.startswith('hia-agent-inspection-') else name
      for name in INSPECTION_ROLES[:31]),
    'hia-agent-emit-request', 'hia-agent-native-artifact-metadata', 'hia-agent-context-request',
    'hia-agent-emit-effect', 'hia-agent-emit-receipt', 'hia-agent-emit-build-observation',
    'hia-agent-worker-profile-bindings', 'hia-agent-candidate-request', 'hia-build-object',
    'hia-agent-borrowed-export-wire', 'hia-agent-retained-build', 'hia-agent-publication-observation',
    'hia-agent-worker-build-custody', 'hia-agent-emit-verification', 'hia-agent-worker-proof-scope',
    'hia-agent-worker-block-layout', 'hia-emit-object', 'hia-agent-inspection-lowering-elf',
    'hia-agent-inspection-lowering-frames', 'hia-agent-worker-canonical', 'hia-agent-worker-object-inventory',
    'hia-elf-link-direct-shared', 'hia-build-object', 'hia-agent-worker-borrowed-build-report',
    'hia-worker-scalar-implementation', 'hia-agent-worker-register-layout',
    'hia-agent-worker-finite-observation', 'hia-agent-worker-finite-reference', 'hia-reference-wire',
    'hia-agent-worker-finite-domain', 'hia-agent-worker-finite-batch', 'hia-agent-worker-finite-transcript',
    'hia-agent-worker-machine-replay', 'hia-safe-core-prove', 'hia-agent-worker-compositional-skeleton',
    'hia-agent-worker-compositional-replay', 'hia-agent-worker-compositional-barrier', 'hia-proof-cnf',
)
PROOF_TRUST_MAGIC = b'HIAPTK02'
PROOF_TRUST_NATIVE_OFFSET = 224
PROOF_TRUST_NATIVE_BYTES = 135
PROOF_TRUST_BYTES = PROOF_TRUST_NATIVE_OFFSET + PROOF_TRUST_NATIVE_BYTES
PROOF_TRUST_CHECKERS = ('hia-nominal-constructor', 'hia-agent-worker-verify-evidence')
PROOF_TRUST_RUNTIME_MAX = 128
ADOPT_OWNER = 'hia-agent-adopt-worker-carrier'
ADOPT_ROLES = (
    *(name.replace('emit-', 'adopt-') if name in (
        'hia-agent-emit-journal', 'hia-agent-emit-journal-records', 'hia-agent-emit-journal-observation',
        'hia-agent-emit-diagnostic',
    ) else name for name in EMIT_ROLES),
    'hia-agent-worker-adopt-claims', 'hia-agent-worker-adopt-authority', 'hia-agent-worker-rollback',
)
VERIFY_OWNER = 'hia-agent-verify-worker-carrier'
VERIFY_ROLES = (
    *(name.replace('emit-journal', 'verify-journal') if name.startswith('hia-agent-emit-journal')
      else 'hia-agent-mcp-proof-schema' if name == 'hia-agent-mcp-response-schema'
      else name for name in EMIT_ROLES),
    'hia-agent-worker-verify-request', 'hia-agent-worker-verify-evidence',
    'hia-agent-worker-verify-finding', 'hia-agent-worker-verify-documents',
    'hia-agent-worker-verify-receipt', 'hia-agent-worker-verify-replay',
    'hia-agent-worker-verify-machine-finding',
)
NATIVE_ROLES = tuple(dict.fromkeys((*ROLES, *ARTIFACT_ROLES, ARTIFACT_OWNER,
                                  *CONTEXT_ROLES, CONTEXT_OWNER,
                                  *INSPECTION_ROLES, INSPECTION_OWNER, *CANDIDATE_ROLES, CANDIDATE_OWNER,
                                  *ROLLBACK_ROLES, ROLLBACK_OWNER, *EMIT_ROLES, EMIT_OWNER,
                                  *ADOPT_ROLES, ADOPT_OWNER, *PROOF_TRUST_CHECKERS,
                                  *VERIFY_ROLES, VERIFY_OWNER)))
CAPSULE_MAX = 4 << 20
HEADER_BYTES = 56
ROW_BYTES = 48
DOSSIER_HEADER = 312
DOSSIER_OFFSET = HEADER_BYTES + len(ROLES) * ROW_BYTES

POLICY = r'''
def authenticate(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 88 or length(w) < 1088:
        return 0
    extent = get(o, 80)
    if extent < 2 or extent > ROLE_LIMIT or length(s) != extent:
        return 0
    operation = get(o, 64)
    role = get(o, 72)
    if operation == 3:
        if role != 0:
            return 0
        return route(s)
    if operation == 1:
        if role != 0 or manifest_shape(s) == False:
            return 0
    elif operation == 2:
        if role == 0 or role > ROLE_COUNT or extent < 64:
            return 0
        if capsule_word(s, 0) & 4294967295 != 1179403647:
            return 0
        if byte(s, 4) != 2 or byte(s, 5) != 1 or byte(s, 18) != 62 or byte(s, 19) != 0:
            return 0
    else:
        return 0
    if widen(sha256(s, o, w)) != 32:
        return 0
    at = 0
    while at < 32:
        if byte(o, at) != byte(o, at + 32):
            return 0
        at = at + 1
    return 1

def manifest_shape(s:readbuf) -> bool:
    if length(s) <= DOSSIER_OFFSET + DOSSIER_HEADER or length(s) > CAPSULE_MAX:
        return False
    if capsule_word(s, 0) != MANIFEST or capsule_word(s, 8) != 1:
        return False
    if capsule_word(s, 16) != ROLE_COUNT or capsule_word(s, 48) != 0:
        return False
    dossier = capsule_word(s, 24)
    config = capsule_word(s, 32)
    documents = capsule_word(s, 40)
    if dossier <= DOSSIER_HEADER or dossier > length(s) - DOSSIER_OFFSET:
        return False
    after = DOSSIER_OFFSET + dossier
    if config < 179 or config > 4274 or config > length(s) - after:
        return False
    if documents < 16 or documents != length(s) - after - config:
        return False
    pack = after + config
    if capsule_word(s, pack) != RESOURCES or capsule_word(s, pack + 8) != 10:
        return False
    if dossier_shape(s, dossier, after, config) == False:
        return False
    index = 0
    while index < ROLE_COUNT:
        row = HEADER_BYTES + index * ROW_BYTES
        extent = capsule_word(s, row + 8)
        if capsule_word(s, row) != index + 1 or extent < 64 or extent > ROLE_LIMIT:
            return False
        index = index + 1
    return True

def dossier_shape(s:readbuf, dossier:u64, config_at:u64, config_size:u64) -> bool:
    at = DOSSIER_OFFSET
    if capsule_word(s, at) != DOSSIER or capsule_word(s, at + 48) != 0:
        return False
    if capsule_word(s, at + 16) != 1:
        return False
    digits = capsule_word(s, at + 8)
    if digits > 2147483647 or (digits != 0 and digits < 640):
        return False
    catalog = capsule_word(s, at + 24)
    actual = capsule_word(s, at + 32)
    selected = capsule_word(s, at + 40)
    remaining = dossier - DOSSIER_HEADER
    if catalog == 0 or actual < 2 or actual > 4096 or selected != actual or catalog > remaining:
        return False
    if actual > remaining - catalog or selected != remaining - catalog - actual:
        return False
    if capsule_word(s, config_at) != BOOTSTRAP or capsule_word(s, config_at + 8) != 0:
        return False
    if capsule_word(s, config_at + 16) != actual:
        return False
    root_digits = capsule_word(s, config_at + 24)
    if root_digits < 1 or root_digits > 2 or config_size != 176 + actual + root_digits:
        return False
    if capsule_word(s, config_at + 32) != 0 or capsule_word(s, config_at + 40) != 0:
        return False
    identities = at + DOSSIER_HEADER + catalog
    if byte(s, identities) != 123 or byte(s, identities + actual - 1) != 125:
        return False
    return same_range(s, at + 56, config_at + 48, 64) and same_range(s, identities, identities + actual, actual) and same_range(s, identities, config_at + 176, actual)

def same_range(s:readbuf, a:u64, b:u64, count:u64) -> bool:
    index = 0
    while index < count:
        if byte(s, a + index) != byte(s, b + index):
            return False
        index = index + 1
    return True

def capsule_word(s:readbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(s, at + index) << (8 * index))
        index = index + 1
    return value

def widen(value:u32) -> u64:
    return value
'''


def evaluate_route(*, intake=False):
    if intake:
        from tools.generate_hia_worker_evaluate_intake_flow import ROLES
        return INTAKE_OWNER, '--worker-evaluate-intake', tuple(name for _, name in ROLES)
    from tools.generate_hia_worker_evaluate_replay_flow import ROLES
    return REPLAY_OWNER, '--worker-evaluate-replay', tuple(name for _, name in ROLES)


def replay_inventory(*, intake=False):
    owner, _, roles = evaluate_route(intake=intake)
    return tuple(dict.fromkeys((*NATIVE_ROLES, *roles, owner)))


def routing(*, artifact=False, evaluate_replay=False):
    # Only the response of the pinned admit process enters this mode. Its
    # canonical serialization guarantees sorted keys and an unescaped tool.
    source = '\ndef route(s:readbuf) -> u32:\n    if byte(s, 0) != 123:\n        return 0\n'
    schema = b',"schema":"hia-agent-worker-request-v1","tool":"'
    methods = ((1, b'hia_read'), (2, b'hia_describe'))
    if artifact:
        methods += ((3, b'hia_artifact'), (4, b'hia_context'), (5, b'hia_inspect'),
                    (6, b'hia_candidate'), (7, b'hia_rollback'), (8, b'hia_emit'), (9, b'hia_adopt'),
                    (10, b'hia_verify'))
    if evaluate_replay:
        methods += ((11, b'hia_evaluate'),)
    for result, method in methods:
        suffix = schema + method + b'"}'
        source += f'    if length(s) > {len(suffix)} and match_{result}(s, length(s) - {len(suffix)}):\n'
        source += f'        return {result}\n'
    source += '    return 0\n'
    if artifact:
        # Check the same canonical suffix without duplicating its fixed prefix
        # in every native route. The cold compiler bounds the authority IR.
        def matches(raw, start=0):
            words, tail = divmod(len(raw), 8)
            full = [f'capsule_word(s, at + {start + 8 * i}) == {int.from_bytes(raw[8 * i:8 * i + 8], "little")}'
                    for i in range(words)]
            rest = [f'byte(s, at + {start + 8 * words + i}) == {value}'
                    for i, value in enumerate(raw[len(raw) - tail:])]
            return ' and '.join(full + rest)

        source += '\ndef route_prefix(s:readbuf, at:u64) -> bool:\n    return ' + matches(schema) + '\n'
        for result, method in methods:
            source += f'\ndef match_{result}(s:readbuf, at:u64) -> bool:\n    return '
            source += 'route_prefix(s, at) and ' + matches(method + b'"}', len(schema)) + '\n'
    else:
        for result, method in methods:
            suffix = schema + method + b'"}'
            source += f'\ndef match_{result}(s:readbuf, at:u64) -> bool:\n    return '
            source += ' and '.join(f'byte(s, at + {i}) == {value}' for i, value in enumerate(suffix))
            source += '\n'
    return source


ARTIFACT_POLICY = r'''
def artifact_shape(s:readbuf, at:u64, extent:u64, bootstrap:u64) -> bool:
    if extent < 88 + PROFILE_BYTES or extent > 132000 or capsule_word(s, at) != ARTIFACT or capsule_word(s, at + 72) != PROFILE_BYTES:
        return False
    profile = at + 88
    if profile_prefix(s, profile) == False or byte(s, profile + PROFILE_BYTES - 2) != 34 or byte(s, profile + PROFILE_BYTES - 1) != 125:
        return False
    digest = profile + PROFILE_PREFIX_BYTES
    if same_range(s, digest, at + 8, 64) == False:
        return False
    index = 0
    while index < 64:
        unit = byte(s, digest + index)
        if (unit < 48 or unit > 57) and (unit < 97 or unit > 102):
            return False
        index = index + 1
    roots = capsule_word(s, at + 80)
    digits = capsule_word(s, bootstrap + 24)
    observed = bootstrap + 176 + capsule_word(s, bootstrap + 16)
    if roots > 32 or roots != root_count(s, observed, digits):
        return False
    offset = profile + PROFILE_BYTES
    limit = at + extent
    index = 0
    while index < roots:
        if offset > limit or limit - offset < 9:
            return False
        size = capsule_word(s, offset)
        offset = offset + 8
        if size == 0 or size > 4095 or size > limit - offset or byte(s, offset) != 47:
            return False
        stop = offset + size
        while offset < stop:
            if byte(s, offset) == 0:
                return False
            offset = offset + 1
        index = index + 1
    return offset == limit

def root_count(s:readbuf, at:u64, digits:u64) -> u64:
    count = 0
    index = 0
    while index < digits:
        n = byte(s, at + index)
        if n < 48 or n > 57:
            return 33
        count = count * 10 + n - 48
        index = index + 1
    return count
'''


PROOF_TRUST_POLICY = r"""
def proof_trust(s:readbuf, at:u64) -> bool:
    if capsule_word(s, at) != PROOF_TRUST_MAGIC or at + PROOF_TRUST_BYTES > length(s):
        return False
    count = capsule_word(s, at + 8)
    if count < 2 or count > PROOF_TRUST_RUNTIME_MAX or byte(s, at + 16) != 34 or byte(s, at + 81) != 34:
        return False
    index = 17
    while index < 81:
        value = byte(s, at + index)
        if (value < 48 or value > 57) and (value < 97 or value > 102):
            return False
        index = index + 1
    if byte(s, at + 82) != 123 or byte(s, at + 81 + count) != 125:
        return False
    index = 82 + count
    while index < PROOF_TRUST_NATIVE_OFFSET:
        if byte(s, at + index) != 0:
            return False
        index = index + 1
    native = at + PROOF_TRUST_NATIVE_OFFSET
    if byte(s, native) != 91 or byte(s, native + 1) != 34 or byte(s, native + 66) != 34:
        return False
    if byte(s, native + 67) != 44 or byte(s, native + 68) != 34 or byte(s, native + 133) != 34 or byte(s, native + 134) != 93:
        return False
    return checker_digest(s, native + 2, CORE_CHECKER_ROW) and checker_digest(s, native + 69, OBSERVER_CHECKER_ROW)

def checker_digest(s:readbuf, text:u64, digest:u64) -> bool:
    index = 0
    while index < 32:
        value = byte(s, digest + index)
        high = value >> 4
        low = value & 15
        if byte(s, text + 2 * index) != choose(high < 10, high + 48, high + 87):
            return False
        if byte(s, text + 2 * index + 1) != choose(low < 10, low + 48, low + 87):
            return False
        index = index + 1
    return True
"""

def native_policy():
    inventory = POLICY.replace(' or capsule_word(s, 48) != 0', '')
    inventory = inventory.replace(
        '    if documents < 16 or documents != length(s) - after - config:',
        '    artifact = capsule_word(s, 48)\n'
        '    if artifact > length(s) - after - config or documents < 16 or documents != length(s) - after - config - artifact:')
    inventory = inventory.replace(
        '    if dossier_shape(s, dossier, after, config) == False:',
        '    if dossier_shape(s, dossier, after, config) == False or artifact_shape(s, pack + documents, artifact, after) == False:')
    prefix = b'{"id":"hia-artifact-v1","sha256":"'
    profile = ARTIFACT_POLICY.replace('PROFILE_PREFIX_BYTES', str(len(prefix)))
    profile = profile.replace('PROFILE_BYTES', str(len(prefix) + 66))
    profile += '\ndef profile_prefix(s:readbuf, at:u64) -> bool:\n    return '
    profile += ' and '.join(f'byte(s, at + {index}) == {value}' for index, value in enumerate(prefix))
    inventory = inventory.replace(
        '    remaining = dossier - DOSSIER_HEADER',
        '    if dossier <= DOSSIER_HEADER + PROOF_TRUST_BYTES or proof_trust(s, config_at - PROOF_TRUST_BYTES) == False:\n'
        '        return False\n'
        '    remaining = dossier - DOSSIER_HEADER - PROOF_TRUST_BYTES')
    return inventory + profile + PROOF_TRUST_POLICY


def source_program(*, artifact=False, evaluate_replay=False, evaluate_intake=False):
    tags = {'MANIFEST': NATIVE_MANIFEST if artifact else MANIFEST_MAGIC, 'DOSSIER': DOSSIER_MAGIC,
            'BOOTSTRAP': BOOTSTRAP_MAGIC, 'RESOURCES': RESOURCES_MAGIC}
    if artifact:
        tags.update(ARTIFACT=ARTIFACT_CONFIG, PROOF_TRUST_MAGIC=PROOF_TRUST_MAGIC)
    constants = {name: int.from_bytes(raw, 'little') for name, raw in tags.items()}
    roles = NATIVE_ROLES if artifact else ROLES
    if evaluate_replay or evaluate_intake:
        roles = replay_inventory(intake=evaluate_intake)
    constants.update(PROOF_TRUST_BYTES=PROOF_TRUST_BYTES, PROOF_TRUST_RUNTIME_MAX=PROOF_TRUST_RUNTIME_MAX,
                     CAPSULE_MAX=CAPSULE_MAX, HEADER_BYTES=HEADER_BYTES, ROW_BYTES=ROW_BYTES,
                     DOSSIER_HEADER=DOSSIER_HEADER, DOSSIER_OFFSET=HEADER_BYTES + len(roles) * ROW_BYTES,
                     ROLE_COUNT=len(roles), ROLE_LIMIT=MAX_ROLE_BYTES)
    if artifact:
        core, observer = PROOF_TRUST_CHECKERS
        constants.update(PROOF_TRUST_NATIVE_OFFSET=PROOF_TRUST_NATIVE_OFFSET,
                         CORE_CHECKER_ROW=HEADER_BYTES + ROW_BYTES * roles.index(core) + 16,
                         OBSERVER_CHECKER_ROW=HEADER_BYTES + ROW_BYTES * roles.index(observer) + 16)
    source = native_policy() if artifact else POLICY
    for name, value in constants.items():
        source = re.sub(rf'\b{name}\b', str(value), source)
    return source + routing(artifact=artifact, evaluate_replay=evaluate_replay or evaluate_intake) + '\n' + sha256_program()


if __name__ == '__main__':
    Path(SOURCE).write_text(render_assembly(document(source_program(), 'worker_readonly_capsule')),
                            encoding='utf-8')
    Path(NATIVE_SOURCE).write_text(render_assembly(document(source_program(artifact=True), 'worker_native_capsule')),
                                   encoding='utf-8')
