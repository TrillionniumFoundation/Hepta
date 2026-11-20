"""Author the HIA policy that admits a worker's terminal report.

The owner supplies its prepared identities and the actual exit code. Only the
wire span of the terminal response may leave this filter. The owner separately
checks the result schema. HIA also checks domain fields against the original request.
"""
from __future__ import annotations

import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import (
    INVALID_ENVELOPE, LIMIT, OUTPUT_BYTES, ROOT, WIRE_HELPERS, comparison_table, tool_names,
)

SOURCE = 'examples/hia_bootstrap/mcp_terminal_admission.hepta'
IDENTITIES = ('tool', 'request_sha256', 'profile_sha256', 'catalog_sha256',
              'worker_sha256', 'backend_sha256', 'native_helpers_sha256')
KEYS = (
    'expected', 'exit_code', 'report', *IDENTITIES, 'schema', 'complete', 'response', 'status',
    'arguments', 'result', 'artifact', 'compiler_profile', 'target_profile', 'program',
    'candidate', 'subject', 'backend_profile', 'baseline_artifact', 'candidate_artifact',
    'target_slot', 'uri', 'change', 'kind', 'base_program', 'previous', 'expected_current',
    'active_artifact', 'claims', 'checks', 'claim', 'context', 'base_core_sha256', 'property',
    'id', 'profile', 'validator', 'validation_profile', 'checker', 'installation',
)

POLICY = r'''
def admit_terminal(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 2 or length(s) > WIRE_LIMIT or length(o) < OUTPUT_LIMIT or length(w) < 128:
        return 4294967293
    put(o, 48, 262144)
    put(o, 56, 128)
    status = widen(decode_json(s, w, o))
    if status >= 4294967292:
        return status
    if get(w, 64) != 6 or get(w, 64 + 32) != 3:
        return BAD_ENVELOPE
    expected = lookup(w, 64, 1)
    exit_code = lookup(w, 64, 2)
    report = lookup(w, 64, 3)
    if expected == NONE or exit_code == NONE or report == NONE:
        return BAD_ENVELOPE
    if get(w, exit_code) != 3 or get(w, exit_code + 32) != 1:
        return BAD_ENVELOPE
    if byte(s, get(w, exit_code + 24)) != 48:
        return BAD_ENVELOPE
    if get(w, expected) != 6 or get(w, expected + 32) != 8 or get(w, report) != 6:
        return BAD_ENVELOPE
    if matching_identities(w, expected, report) == 0:
        return BAD_ENVELOPE
    schema = lookup(w, report, 11)
    complete = lookup(w, report, 12)
    response = lookup(w, report, 13)
    if schema == NONE or complete == NONE or response == NONE:
        return BAD_ENVELOPE
    if get(w, schema) != 4 or get(w, complete) != 2 or get(w, response) != 6:
        return BAD_ENVELOPE
    if terminal_schema(w, get(w, schema + 24), get(w, schema + 32)) == 0:
        return BAD_ENVELOPE
    outcome = lookup(w, response, 14)
    if outcome == NONE or get(w, outcome) != 4:
        return BAD_ENVELOPE
    terminal = terminal_status(w, get(w, outcome + 24), get(w, outcome + 32))
    if terminal == 0:
        return BAD_ENVELOPE
    args = lookup(w, expected, KEY_ARGUMENTS)
    if args == NONE or get(w, args) != 6:
        return BAD_ENVELOPE
    if terminal == 1 and bound_result(w, expected, args, response) == 0:
        return BAD_ENVELOPE
    start = get(w, response + 56)
    size = get(w, response + 64)
    offset = 0
    while offset < size:
        store(o, offset, byte(s, start + offset))
        offset = offset + 1
    return size

def matching_identities(w:mutbuf, expected:u64, report:u64) -> u64:
    helpers = lookup(w, report, 10)
    if get(w, report + 32) != choose(helpers == NONE, 9, 10):
        return 0
    field = 4
    while field < 10:
        left = lookup(w, expected, field)
        right = lookup(w, report, field)
        if same_string(w, left, right) == 0:
            return 0
        field = field + 1
    pinned_helpers = lookup(w, expected, 10)
    if pinned_helpers == NONE:
        return 0
    if get(w, pinned_helpers) == 0:
        if helpers == NONE:
            return 1
        return choose(get(w, helpers) == 0, 1, 0)
    return same_string(w, pinned_helpers, helpers)

def same_string(w:mutbuf, left:u64, right:u64) -> u64:
    if left == NONE or right == NONE:
        return 0
    if get(w, left) != 4 or get(w, right) != 4:
        return 0
    return same_text(w, get(w, left + 24), get(w, left + 32), get(w, right + 24), get(w, right + 32))
'''


DOMAIN = r'''
def bound_result(w:mutbuf, expected:u64, args:u64, response:u64) -> u64:
    tool = lookup(w, expected, KEY_TOOL)
    role = tool_role(w, get(w, tool + 24), get(w, tool + 32))
    result = lookup(w, response, KEY_RESULT)
    if result == NONE or get(w, result) != 6:
        return 0
    if role == TOOL_HIA_DESCRIBE:
        return same_string(w, lookup(w, expected, KEY_CATALOG_SHA256), lookup(w, result, KEY_CATALOG_SHA256))
    if role == TOOL_HIA_ARTIFACT:
        return 1
    if role == TOOL_HIA_RESOURCE_READ:
        asset = lookup(w, result, KEY_ARTIFACT)
        if asset == NONE or get(w, asset) != 6:
            return 0
        return same_string(w, lookup(w, args, KEY_URI), lookup(w, asset, KEY_URI))
    if role == TOOL_HIA_READ:
        return bound_field(w, args, result, KEY_ARTIFACT)
    if role == TOOL_HIA_CONTEXT:
        if bound_field(w, args, result, KEY_COMPILER_PROFILE) == 0:
            return 0
        return bound_field(w, args, result, KEY_TARGET_PROFILE)
    if role == TOOL_HIA_INSPECT:
        return bound_field(w, args, result, KEY_PROGRAM)
    if role == TOOL_HIA_CANDIDATE:
        change = lookup(w, args, KEY_CHANGE)
        if change == NONE or get(w, change) != 6:
            return 0
        kind = lookup(w, change, KEY_KIND)
        if kind == NONE or get(w, kind) != 4:
            return 0
        chosen = NONE
        if patch_kind(w, get(w, kind + 24), get(w, kind + 32)) != 0:
            chosen = lookup(w, change, KEY_BASE_PROGRAM)
        return same_reference(w, chosen, lookup(w, result, KEY_BASE_PROGRAM))
    if role == TOOL_HIA_VERIFY:
        return bound_verification(w, expected, args, result)
    if role == TOOL_HIA_EMIT:
        if bound_field(w, args, result, KEY_CANDIDATE) == 0:
            return 0
        return bound_field(w, args, result, KEY_BACKEND_PROFILE)
    if role == TOOL_HIA_EVALUATE:
        if bound_field(w, args, result, KEY_BASELINE_ARTIFACT) == 0:
            return 0
        return bound_field(w, args, result, KEY_CANDIDATE_ARTIFACT)
    if role == TOOL_HIA_ADOPT or role == TOOL_HIA_ROLLBACK:
        if bound_field(w, args, result, KEY_TARGET_SLOT) == 0:
            return 0
        if same_reference(w, lookup(w, args, KEY_EXPECTED_CURRENT), lookup(w, result, KEY_PREVIOUS)) == 0:
            return 0
        if role == TOOL_HIA_ADOPT:
            return same_reference(w, lookup(w, args, KEY_CANDIDATE_ARTIFACT), lookup(w, result, KEY_ACTIVE_ARTIFACT))
        return 1
    return 0

def bound_verification(w:mutbuf, expected:u64, args:u64, result:u64) -> u64:
    if bound_field(w, args, result, KEY_CANDIDATE) == 0:
        return 0
    subject = lookup(w, args, KEY_SUBJECT)
    actual = lookup(w, result, KEY_SUBJECT)
    if same_subject(w, subject, actual, True) == 0:
        return 0
    claims = lookup(w, args, KEY_CLAIMS)
    checks = lookup(w, result, KEY_CHECKS)
    if claims == NONE or checks == NONE or get(w, claims) != 5 or get(w, checks) != 5:
        return 0
    count = get(w, claims + 32)
    if count < 1 or count > 4 or count != get(w, checks + 32):
        return 0
    claim = get(w, claims + 24)
    while claim != NONE:
        claim_node = 64 + claim * 72
        occurrences = 0
        check = get(w, checks + 24)
        while check != NONE:
            check_node = 64 + check * 72
            if get(w, check_node) != 6:
                return 0
            if same_string(w, claim_node, lookup(w, check_node, KEY_CLAIM)) != 0:
                occurrences = occurrences + 1
                if bound_check(w, expected, args, subject, check_node, claim_node) == 0:
                    return 0
            check = get(w, check_node + 16)
        if occurrences != 1:
            return 0
        claim = get(w, claim_node + 16)
    return 1

def bound_check(w:mutbuf, expected:u64, args:u64, subject:u64, check:u64, claim:u64) -> u64:
    scope = lookup(w, check, KEY_SUBJECT)
    if same_subject(w, subject, scope, False) == 0:
        return 0
    if bound_field(w, args, scope, KEY_CANDIDATE) == 0 or bound_field(w, args, scope, KEY_CONTEXT) == 0:
        return 0
    if bound_field(w, args, scope, KEY_BASE_PROGRAM) == 0:
        return 0
    if nullish(w, lookup(w, scope, KEY_BASE_CORE_SHA256)) != nullish(w, lookup(w, args, KEY_BASE_PROGRAM)):
        return 0
    property = lookup(w, check, KEY_PROPERTY)
    if property == NONE or get(w, property) != 6:
        return 0
    if same_string(w, claim, lookup(w, property, KEY_ID)) == 0:
        return 0
    selected = lookup(w, args, KEY_VALIDATION_PROFILE)
    if same_reference(w, selected, lookup(w, check, KEY_PROFILE)) == 0:
        return 0
    if same_reference(w, selected, lookup(w, check, KEY_VALIDATOR)) == 0:
        return 0
    checker = lookup(w, check, KEY_CHECKER)
    if checker == NONE or get(w, checker) != 6:
        return 0
    return bound_installation(w, expected, lookup(w, checker, KEY_INSTALLATION))

def bound_installation(w:mutbuf, expected:u64, installation:u64) -> u64:
    if installation == NONE or get(w, installation) != 6:
        return 0
    helper = lookup(w, expected, KEY_NATIVE_HELPERS_SHA256)
    observed = lookup(w, installation, KEY_NATIVE_HELPERS_SHA256)
    if nullish(w, helper) != 0:
        if observed != NONE or get(w, installation + 32) != 3:
            return 0
    elif get(w, installation + 32) != 4 or same_string(w, helper, observed) == 0:
        return 0
    if bound_field(w, expected, installation, KEY_WORKER_SHA256) == 0:
        return 0
    if bound_field(w, expected, installation, KEY_BACKEND_SHA256) == 0:
        return 0
    return bound_field(w, expected, installation, KEY_CATALOG_SHA256)

def bound_field(w:mutbuf, expected:u64, observed:u64, key:u64) -> u64:
    return same_reference(w, lookup(w, expected, key), lookup(w, observed, key))

def nullish(w:mutbuf, node:u64) -> u64:
    if node == NONE:
        return 1
    return choose(get(w, node) == 0, 1, 0)

def named_child(w:mutbuf, parent:u64, key:u64) -> u64:
    child = get(w, parent + 24)
    while child != NONE:
        row = 64 + child * 72
        if same_text(w, get(w, row + 40), get(w, row + 48), get(w, key + 40), get(w, key + 48)) != 0:
            return row
        child = get(w, row + 16)
    return NONE

def same_reference(w:mutbuf, left:u64, right:u64) -> u64:
    if nullish(w, left) != 0:
        return nullish(w, right)
    if nullish(w, right) != 0:
        return 0
    if get(w, left) == 4:
        return same_string(w, left, right)
    if get(w, left) != 6 or get(w, right) != 6 or get(w, left + 32) != get(w, right + 32):
        return 0
    # Artifact, profile and slot references contain only scalar string fields.
    child = get(w, left + 24)
    while child != NONE:
        row = 64 + child * 72
        if same_string(w, row, named_child(w, right, row)) == 0:
            return 0
        child = get(w, row + 16)
    return 1

def same_subject(w:mutbuf, left:u64, right:u64, exact:bool) -> u64:
    if left == NONE or right == NONE or get(w, left) != 6 or get(w, right) != 6:
        return 0
    if exact and get(w, left + 32) != get(w, right + 32):
        return 0
    # The extended proof subject adds context and Core digest fields. Its
    # requested projection has the same nested profile and artifact identities.
    child = get(w, left + 24)
    while child != NONE:
        row = 64 + child * 72
        candidate = named_child(w, right, row)
        if candidate == NONE or same_reference(w, row, candidate) == 0:
            return 0
        child = get(w, row + 16)
    return 1

def same_text(w:mutbuf, start:u64, size:u64, other:u64, other_size:u64) -> u64:
    if size != other_size:
        return 0
    offset = 0
    while offset < size:
        if byte(w, start + offset) != byte(w, other + offset):
            return 0
        offset = offset + 1
    return 1
'''


def render():
    tools = (*tool_names(), 'hia_resource_read')
    constants = {f'KEY_{name.upper()}': str(index) for index, name in enumerate(KEYS, 1)}
    constants.update({f'TOOL_{name.upper()}': str(index) for index, name in enumerate(tools, 1)})
    policy = re.sub(r'\b(?:KEY|TOOL)_[A-Z_0-9]+\b',
                    lambda match: constants[match[0]], POLICY + DOMAIN + WIRE_HELPERS)
    for name, value in {
        'WIRE_LIMIT': LIMIT, 'OUTPUT_LIMIT': OUTPUT_BYTES,
        'BAD_ENVELOPE': INVALID_ENVELOPE, 'NONE': (1 << 64) - 1,
    }.items():
        policy = policy.replace(name, str(value))
    layout = '\n'.join((
        policy, comparison_table('key_id', KEYS), comparison_table('tool_role', tools),
        comparison_table('patch_kind', ('patch',)),
        comparison_table('terminal_schema', ('hia-agent-worker-report-v1',)),
        comparison_table('terminal_status', ('completed', 'rejected')),
        json_decoder(wire_spans=True),
    ))
    return render_assembly(document(layout, 'mcp_terminal_admission'))


def main():
    path = ROOT / SOURCE
    path.write_text(render(), encoding='utf-8')
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
