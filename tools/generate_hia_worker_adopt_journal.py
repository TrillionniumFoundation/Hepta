"""Specialize the durable, inline Context-bound Journal for Adopt."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_journal import TOOLS
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_artifact_diagnostic import document as diagnostic
from tools.generate_hia_worker_emit_journal import ERRORS as CONTEXT_ERRORS
from tools.generate_hia_worker_inspection_journal import context_bound_flow
from tools.generate_hia_worker_journal_observation import source_program as observation
from tools.generate_hia_worker_journal_records import source_program as records

TOOL = 'hia_adopt'
ROOT = Path('examples/hia_bootstrap')
ERRORS = tuple(item for item in CONTEXT_ERRORS if item[:2] in ((7, 1), (7, 2), (8, 1), (8, 2), (8, 3)))


if __name__ == '__main__':
    raw = TOOL.encode('ascii')
    sources = {
        'worker_adopt_journal': context_bound_flow(raw, TOOLS.index(TOOL) + 1, 2, b'HIAIND01',
                                                   inline_transaction=True, extra_errors=ERRORS),
        'worker_adopt_journal_observation': observation(raw),
        'worker_adopt_journal_records': records(raw),
    }
    for name, source in sources.items():
        (ROOT / (name + '.hepta')).write_text(render_assembly(document(source, name)), encoding='utf-8')
    name = 'worker_adopt_diagnostic'
    (ROOT / (name + '.hepta')).write_text(render_assembly(diagnostic(TOOL, module=name)), encoding='utf-8')
