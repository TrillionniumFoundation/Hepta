"""Author native first-error diagnostics for retained Context cost policies."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_agent_contract import COST_POLICY_SCHEMA
from tools.generate_hia_worker_artifact_diagnostic import diagnostic_document

SOURCE = Path('examples/hia_bootstrap/worker_context_cost_diagnostic.hepta')


if __name__ == '__main__':
    program = diagnostic_document(COST_POLICY_SCHEMA, module=SOURCE.stem, label='cost_policy')
    SOURCE.write_text(render_assembly(program), encoding='utf-8')
