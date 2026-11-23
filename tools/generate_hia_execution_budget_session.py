"""Author the cold HIA packer for the persistent execution-budget stdio role."""
from pathlib import Path
from tempfile import TemporaryDirectory

from hepta.hia_agent_assembly import render_assembly
from tools.build_hia_agent_batch_commit import adapter_layout
from tools.generate_hia_native_filter import bind_adapter, document, elf_header

ADAPTER = 'tools/hia_execution_budget_session.S'
PACKER = 'examples/hia_bootstrap/execution_budget_session_packer.hepta'
PACK_MAGIC = int.from_bytes(b'HIAEPS01', 'little')


def packer_document():
    source = Path(ADAPTER).read_bytes()
    with TemporaryDirectory(prefix='hia-execution-budget-session-') as tmp:
        code, offsets, _ = adapter_layout(Path(tmp), ADAPTER, source, {'budget': 'budget_call_hole'})
    header = elf_header()
    offset = offsets['budget']
    packer = document(magic=PACK_MAGIC, module=Path(PACKER).stem,
                      image_template=(header + code, (len(header) + offset,)))
    return bind_adapter(packer, source, code, (offset,))


if __name__ == '__main__':
    Path(PACKER).write_text(render_assembly(packer_document()), encoding='utf-8')
