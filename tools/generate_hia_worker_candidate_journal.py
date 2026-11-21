"""Author Candidate's typed reservation, exact diagnostics, and closeout."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_journal import TOOLS
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_artifact_diagnostic import document as diagnostic
from tools.generate_hia_worker_inspection_journal import context_bound_flow
from tools.generate_hia_worker_journal_observation import source_program as observation
from tools.generate_hia_worker_journal_records import source_program as records

TOOL = b'hia_candidate'
SOURCE = Path('examples/hia_bootstrap')


def main():
    name = TOOL.decode('ascii')
    programs = {
        'worker_candidate_journal': context_bound_flow(TOOL, TOOLS.index(name) + 1, 3, b'HIACND01'),
        'worker_candidate_journal_observation': observation(TOOL),
        'worker_candidate_journal_records': records(TOOL),
    }
    for module, program in programs.items():
        (SOURCE / (module + '.hepta')).write_text(render_assembly(document(program, module)), encoding='utf-8')
    module = 'worker_candidate_diagnostic'
    (SOURCE / (module + '.hepta')).write_text(render_assembly(diagnostic(name, module=module)), encoding='utf-8')


if __name__ == '__main__':
    main()
