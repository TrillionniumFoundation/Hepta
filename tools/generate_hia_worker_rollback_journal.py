"""Specialize the existing Context-bound Journal for the Rollback tool."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_artifact_diagnostic import document as diagnostic
from tools.generate_hia_worker_inspection_journal import context_bound_flow
from tools.generate_hia_worker_journal_observation import source_program as observation
from tools.generate_hia_worker_journal_records import source_program as records

TOOL = b'hia_rollback'
ROOT = Path('examples/hia_bootstrap')

if __name__ == '__main__':
    sources = {
        'worker_rollback_journal': context_bound_flow(TOOL, 11, 1, b'HIAIND01', inline_transaction=True),
        'worker_rollback_journal_observation': observation(TOOL),
        'worker_rollback_journal_records': records(TOOL),
    }
    for name, source in sources.items():
        (ROOT / (name + '.hepta')).write_text(render_assembly(document(source, name)), encoding='utf-8')
    name = 'worker_rollback_diagnostic'
    (ROOT / (name + '.hepta')).write_text(
        render_assembly(diagnostic(TOOL.decode('ascii'), module=name)), encoding='utf-8')
