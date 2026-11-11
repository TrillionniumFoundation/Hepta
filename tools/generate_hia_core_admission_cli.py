"""Author the syscall-only ELF packer for complete raw Core admission.

Only fixed descriptor/syscall adaptation is literal machine code. HIA writes
the executable headers, resolves the image call and copies the native verifier.
"""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_native_filter import document as filter_document

MAGIC = int.from_bytes(b'HIACV001', 'little')
# Full Core maximum: 2^20 hash slots * 24, 4096 blocks * 40,
# 262144 nodes * (112 capability-state + 8 live-index) and 128 header bytes.
# No native compiler function/arity profile is substituted for Core admission.
STATE_BYTES = 64 << 20
ARENA_BYTES = 32 << 20


def document():
    return filter_document(output_bytes=STATE_BYTES, workspace_bytes=ARENA_BYTES,
                           magic=MAGIC, module='core_admission_cli_packer')


if __name__ == '__main__':
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/core_admission_cli_packer.hepta'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)
