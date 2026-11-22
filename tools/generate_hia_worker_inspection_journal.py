"""Author Inspection's exact schema boundary and typed Journal closeout."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_artifact_diagnostic import document as diagnostic
from tools.generate_hia_worker_artifact_journal import source_program as flow
from tools.generate_hia_worker_journal_observation import source_program as observation
from tools.generate_hia_worker_journal_records import source_program as records

TOOL = b'hia_inspect'

# Ordinary completion uses the existing cost wire after a strict private
# sideband. The sideband never appears in the public response.
INSPECTION_COST = r"""
    observed = input_word(s, 16)
    if length(s) < 584 or observed < 560 or observed > length(s) - 24:
        return 0
    end = 24 + observed
    context = 0
    if end != length(s):
        if length(s) - end < 70 or input_word(s, end) != OUTCOME:
            return 0
        context = input_word(s, end + 16)
        if context != 0 and context != 36:
            return 0
        if input_word(s, end + 24) != length(s) - end - 68:
            return 0
        if context == 36 and input_word(s, end + 32) & 4294967295 != CONTEXT_PREFIX:
            return 0
        index = 0
        while index < 36:
            digit = byte(s, end + 32 + index)
            if context == 0 and digit != 0:
                return 0
            if context == 36 and index >= 4 and (digit < 48 or digit > 57) and (digit < 97 or digit > 102):
                return 0
            index = index + 1
"""

INSPECTION_RESPONSE_MATCH = r"""
    # Both the typed Journal owner and the private inspection continuation
    # must have reached the same outcome for this exact response payload.
    if end == length(s):
        # The Journal's terminal stage clears scratch route words. A missing
        # effect receipt is allowed only for exact pre-dispatch diagnostics.
        if status == 1 or admission_refusal(s, 72 + REFUSED_BODY_AT, response) == False:
            return 0
    else:
        if input_word(s, end + 8) != status:
            return 0
        payload = input_word(s, end + 24)
        body_at = choose(status == 1, COMPLETED_BODY_AT, REFUSED_BODY_AT)
        suffix = choose(status == 1, COMPLETED_SUFFIX, REFUSED_SUFFIX)
        if response != body_at + payload + suffix or same_fields(s, 72 + body_at, end + 68, payload) == False:
            return 0
"""

def context_bound_flow(tool, ordinal, context_plan, outcome, *, inline_transaction=False):
    program = flow(tool, ordinal)
    start = program.index('def artifact_cost(')
    before, cost = program[:start], program[start:]
    # Bind the exact retained Context plan selected by the native Journal.
    route = {
        'input_word(s, 568) == 0 and actual != 0':
            'input_word(s, 568) == choose(stage == 12, 1, 0) and actual != 0',
        'phase == 4) and input_word(s, state + 320) == 0':
            f'phase == 4) and input_word(s, state + 320) == {context_plan}',
    }
    if inline_transaction:
        # Slot writes use the shared Journal's inline authorization. The
        # Worker commits the exact terminal in the transaction that changes
        # the slot; the later cost closeout must not write a second terminal.
        route.update({
            'input_word(s, at + 32) != 0': 'input_word(s, at + 32) != 1',
            'return phase == 10 and action == 1 and reason == 0':
                'return phase == 10 and action == 8 and reason == 0',
            'if stage == 5 and action == 1 and phase == 10':
                'if stage == 5 and action == 8 and phase == 10',
            'and action == 1 and reason == 0) or (action == 11 and reason != 0)':
                'and (action == 1 or action == 8) and reason == 0) or (action == 11 and reason != 0)',
        })
    for old, new in route.items():
        assert before.count(old) == 1, old
        before = before.replace(old, new)
    opening = """    if length(s) < 584 or input_word(s, 16) != length(s) - 24:
        return 0"""
    assert cost.count(opening) == 1
    width = len(tool)
    once = {
        opening: INSPECTION_COST.rstrip(),
        f'if length(s) != state + 512 or length(o) < 122 + {width} + cost:':
            f'if end != state + 512 or length(o) < 122 + {width} + cost + context:',
        '    put(o, 0, ': INSPECTION_RESPONSE_MATCH.rstrip() + '\n    put(o, 0, ',
        '    put(o, 24, 0)': '    put(o, 24, context)',
        '    put(o, 56, ': '    copy_cost_bytes(s, o, end + 32, context, 56)\n    put(o, 56 + context, ',
        '    put(o, 64, ': '    put(o, 64 + context, ',
        f'56 + {width})': f'56 + context + {width})',
        f'122 + {width})': f'122 + context + {width})',
        f'    return 122 + {width} + cost': f'    return 122 + context + {width} + cost',
    }
    # Constants in the existing generic role have already been specialized.
    # Limit string edits to the cost function and check each one exactly.
    stop = cost.index('\ndef ', len('def artifact_cost('))
    body, rest = cost[:stop], cost[stop:]
    for old, new in once.items():
        assert body.count(old) == 1, old
        body = body.replace(old, new)
    constants = {
        'OUTCOME': int.from_bytes(outcome, 'little'),
        'CONTEXT_PREFIX': int.from_bytes(b'ctx-', 'little'),
        'COMPLETED_BODY_AT': len(b'{"contract_version":"hepta.hia.agent-native.v1","request_id":"' + b'r-' + b'0'*64 + b'","result":'),
        'REFUSED_BODY_AT': len(b'{"contract_version":"hepta.hia.agent-native.v1","error":'),
        'COMPLETED_SUFFIX': len(b',"status":"completed"}'),
        'REFUSED_SUFFIX': len(b',"request_id":"' + b'r-' + b'0'*64 + b'","status":"rejected"}'),
    }
    for name, value in constants.items():
        body = body.replace(name, str(value))
    return before + body + rest + early_refusal_program(constants['REFUSED_BODY_AT'])


def inspection_flow():
    return context_bound_flow(TOOL, 5, 1, b'HIAIND01')


def early_refusal_program(body_offset):
    codes = ('E_HIA_SCHEMA', 'E_HIA_CATALOG_STALE', 'E_HIA_IMPLEMENTATION_STALE',
             'E_HIA_REQUEST_CONFLICT', 'E_HIA_REQUEST_UNKNOWN')
    lines = ['def admission_refusal(s:readbuf, at:u64, response:u64) -> bool:']
    for code in codes:
        tag = f'{{"code":"{code}","'.encode('ascii')
        clauses = [f'response >= {body_offset + len(tag)}']
        for index in range(0, len(tag), 8):
            chunk = tag[index:index+8]
            if len(chunk) == 8:
                clauses.append(f'input_word(s, at + {index}) == {int.from_bytes(chunk, "little")}')
            else:
                clauses.extend(f'byte(s, at + {index + i}) == {unit}' for i, unit in enumerate(chunk))
        lines.extend(('    if ' + ' and '.join(clauses) + ':', '        return True'))
    return '\n' + '\n'.join((*lines, '    return False', ''))
SOURCES = {
    'worker_inspection_journal': inspection_flow,
    'worker_inspection_journal_observation': lambda: observation(TOOL),
    'worker_inspection_journal_records': lambda: records(TOOL),
}


if __name__ == '__main__':
    root = Path('examples/hia_bootstrap')
    for name, program in SOURCES.items():
        (root / (name + '.hepta')).write_text(render_assembly(document(program(), name)), encoding='utf-8')
    name = 'worker_inspection_diagnostic'
    (root / (name + '.hepta')).write_text(render_assembly(diagnostic(TOOL.decode('ascii'), module=name)),
                                         encoding='utf-8')
