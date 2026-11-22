"""Author Verify's durable Context-bound Journal and replay routing."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_journal import TOOLS
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_emit_journal import ERRORS as CONTEXT_ERRORS
from tools.generate_hia_worker_inspection_journal import context_bound_flow
from tools.generate_hia_worker_journal_observation import source_program as observation
from tools.generate_hia_worker_journal_records import source_program as records
from tools.generate_hia_worker_request import replace_once

TOOL = 'hia_verify'
ROOT = Path('examples/hia_bootstrap')
ERRORS = (*[item for item in CONTEXT_ERRORS if item[:2] in ((7, 1), (7, 2), (8, 1), (8, 2), (8, 3))],
          (8, 5, 'E_HIA_MACHINE_PLAN', 'the retained machine plan is invalid for the admitted Core',
           'correct_input', 'verification'))


def verify_journal(raw):
    program = context_bound_flow(raw, TOOLS.index(TOOL) + 1, 2, b'HIAIND01', extra_errors=ERRORS)
    # The shared Journal selects action 6 only for a completed Verify.
    # A rejected cached response has no proof and follows ordinary replay.
    return replace_once(
        program,
        '    if stage == 3:\n        if action == 5 and phase == 6 and reason == 0 and arena >= 64:',
        '    if stage == 3:\n'
        '        if phase == 6 and reason == 0 and arena >= 64 and action == 6:\n'
        '            return 21\n'
        '        if action == 5 and phase == 6 and reason == 0 and arena >= 64:',
    )


def sources():
    raw = TOOL.encode('ascii')
    programs = {
        'worker_verify_journal': verify_journal(raw),
        'worker_verify_journal_observation': observation(raw),
        'worker_verify_journal_records': records(raw),
    }
    return {name: document(program, name) for name, program in programs.items()}


if __name__ == '__main__':
    for name, program in sources().items():
        (ROOT / (name + '.hepta')).write_text(render_assembly(program), encoding='utf-8')
