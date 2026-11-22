"""Author Verify receipt and response projections from admitted fragments."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_identity import VERIFICATION_RECORD, VERIFICATION_RESULT
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_emit_receipt import program

SOURCE = Path('examples/hia_bootstrap/worker_verify_receipt.hepta')
TEMPLATES = (('verification_record', VERIFICATION_RECORD), ('verification_result', VERIFICATION_RESULT))


def source_program():
    return program(TEMPLATES, tag=b'HIAVRC01', entry='verify_receipt')


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(source_program(), SOURCE.stem)), encoding='utf-8')
