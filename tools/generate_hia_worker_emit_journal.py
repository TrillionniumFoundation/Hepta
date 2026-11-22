"""Specialize the durable Context-bound Journal for Emit."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_journal import TOOLS
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_artifact_diagnostic import document as diagnostic
from tools.generate_hia_worker_inspection_journal import context_bound_flow
from tools.generate_hia_worker_journal_observation import source_program as observation
from tools.generate_hia_worker_journal_records import source_program as records

TOOL = 'hia_emit'
ROOT = Path('examples/hia_bootstrap')


def sources():
    raw = TOOL.encode('ascii')
    return {
        'worker_emit_journal': document(context_bound_flow(raw, TOOLS.index(TOOL) + 1, 2, b'HIAIND01'),
                                        'worker_emit_journal'),
        'worker_emit_journal_observation': document(observation(raw), 'worker_emit_journal_observation'),
        'worker_emit_journal_records': document(records(raw), 'worker_emit_journal_records'),
        'worker_emit_diagnostic': diagnostic(TOOL, module='worker_emit_diagnostic'),
    }


if __name__ == '__main__':
    for name, program in sources().items():
        (ROOT / (name + '.hepta')).write_text(render_assembly(program), encoding='utf-8')
