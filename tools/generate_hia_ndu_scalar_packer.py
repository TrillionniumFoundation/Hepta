"""Bind the mechanical NDU transport to an ordinary HIA ELF packer."""
from pathlib import Path
from tempfile import TemporaryDirectory

from hepta.hia_agent_assembly import render_assembly
from tools.build_hia_agent_batch_commit import adapter_layout
from tools.generate_hia_native_filter import bind_adapter, document, elf_header

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = 'tools/hia_ndu_scalar_syscalls.S'
PACKER = 'examples/hia_bootstrap/ndu_scalar_packer.hepta'
MAGIC = int.from_bytes(b'HIANDU01', 'little')


def render():
    source = (ROOT / ADAPTER).read_bytes()
    with TemporaryDirectory(prefix='hia-ndu-adapter-') as tmp:
        stub, holes, _ = adapter_layout(Path(tmp), ADAPTER, source, {'ndu': 'ndu_call_hole'})
    header = elf_header()
    hole = holes['ndu']
    packer = document(magic=MAGIC, module='ndu_scalar_packer',
        image_template=(header + stub, (len(header) + hole,)))
    return render_assembly(bind_adapter(packer, source, stub, (hole,)))


if __name__ == '__main__':
    path = ROOT / PACKER
    path.write_text(render(), encoding='utf-8')
    print(path.name, path.stat().st_size)
