"""Author the HIA policy that admits a worker's terminal report.

The owner supplies its prepared identities and the actual exit code. Only the
wire span of the terminal response may leave this filter. The owner separately
checks the result schema and binds domain fields to the original request.
"""
from __future__ import annotations

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import (
    INVALID_ENVELOPE, LIMIT, OUTPUT_BYTES, ROOT, WIRE_HELPERS, comparison_table,
)

SOURCE = 'examples/hia_bootstrap/mcp_terminal_admission.hepta'
IDENTITIES = ('tool', 'request_sha256', 'profile_sha256', 'catalog_sha256',
              'worker_sha256', 'backend_sha256', 'native_helpers_sha256')
KEYS = ('expected', 'exit_code', 'report', *IDENTITIES, 'schema', 'complete', 'response', 'status')

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
    if get(w, expected) != 6 or get(w, expected + 32) != 7 or get(w, report) != 6:
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
    if terminal_status(w, get(w, outcome + 24), get(w, outcome + 32)) == 0:
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
    size = get(w, left + 32)
    if size != get(w, right + 32):
        return 0
    start = get(w, left + 24)
    other = get(w, right + 24)
    offset = 0
    while offset < size:
        if byte(w, start + offset) != byte(w, other + offset):
            return 0
        offset = offset + 1
    return 1
'''


def render():
    policy = POLICY + WIRE_HELPERS
    for name, value in {
        'WIRE_LIMIT': LIMIT, 'OUTPUT_LIMIT': OUTPUT_BYTES,
        'BAD_ENVELOPE': INVALID_ENVELOPE, 'NONE': (1 << 64) - 1,
    }.items():
        policy = policy.replace(name, str(value))
    layout = '\n'.join((
        policy, comparison_table('key_id', KEYS),
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
