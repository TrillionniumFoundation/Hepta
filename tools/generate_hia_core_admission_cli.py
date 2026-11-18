"""Author syscall-only ELF packers for raw Core admission and normalization.

Only fixed descriptor/syscall adaptation is literal machine code. HIA writes
the executable headers, resolves the image call and copies the native verifier.
"""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_native_filter import document as filter_document

MAGIC = int.from_bytes(b'HIACV001', 'little')
NORMALIZE_MAGIC = int.from_bytes(b'HIACN001', 'little')
# Full Core maximum: 2^20 hash slots * 24, 4096 blocks * 40,
# 262144 nodes * (112 capability-state + 8 live-index) and 128 header bytes.
# No native compiler function/arity profile is substituted for Core admission.
STATE_BYTES = 64 << 20
ARENA_BYTES = 32 << 20
# Pretty JSON adds at most 2*64+1 bytes before a value or closing delimiter.
# Two such lines per node plus colon space and final newline fit within 80 MiB
# even when the original input occupies the full 8 MiB.
NORMALIZE_OUTPUT_BYTES = 80 << 20


def document(*, normalize=False):
    if normalize:
        return filter_document(output_bytes=NORMALIZE_OUTPUT_BYTES, workspace_bytes=ARENA_BYTES,
                               magic=NORMALIZE_MAGIC, module='core_normalize_cli_packer',
                               formatter=True)
    return filter_document(output_bytes=STATE_BYTES, workspace_bytes=ARENA_BYTES,
                           magic=MAGIC, module='core_admission_cli_packer')


if __name__ == '__main__':
    folder = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap'
    for name, normalize in (('core_admission_cli_packer', False), ('core_normalize_cli_packer', True)):
        path = folder / f'{name}.hepta'
        path.write_text(render_assembly(document(normalize=normalize)))
        print(path.name, path.stat().st_size)
