"""Author the first published hia_context schema rejection."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_worker_artifact_diagnostic import document

SOURCE = Path('examples/hia_bootstrap/worker_context_diagnostic.hepta')

if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document('hia_context', module=SOURCE.stem)), encoding='utf-8')
