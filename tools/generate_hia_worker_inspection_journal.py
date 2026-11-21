"""Author Inspection's exact schema boundary and typed Journal closeout."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_artifact_diagnostic import document as diagnostic
from tools.generate_hia_worker_artifact_journal import source_program as flow
from tools.generate_hia_worker_journal_observation import source_program as observation
from tools.generate_hia_worker_journal_records import source_program as records

TOOL = b'hia_inspect'
SOURCES = {
    'worker_inspection_journal': lambda: flow(TOOL, 5),
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
