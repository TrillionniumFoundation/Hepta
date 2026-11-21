"""Author the native durable Context reservation, observation and closeout."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_artifact_journal import CONTEXT_ERRORS, source_program as flow
from tools.generate_hia_worker_journal_observation import source_program as observation
from tools.generate_hia_worker_journal_records import source_program as records

TOOL = b'hia_context'
SOURCES = {
    'worker_context_journal': lambda: flow(TOOL, 4, CONTEXT_ERRORS),
    'worker_context_journal_observation': lambda: observation(TOOL),
    'worker_context_journal_records': lambda: records(TOOL),
}

if __name__ == '__main__':
    for name, program in SOURCES.items():
        path = Path('examples/hia_bootstrap', name + '.hepta')
        path.write_text(render_assembly(document(program(), name)), encoding='utf-8')
