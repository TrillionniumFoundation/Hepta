"""HIA packer for the complete inline primitive-workspace JSON linker.

The syscall envelope only supplies private buffers and bounded byte transport.
It neither admits Core resource flow nor replaces the general Core verifier.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_native_filter import document as filter_document

MAGIC = int.from_bytes(b'HIAWJS01', 'little')
# Full original 8-MiB wire / 1M-node / depth-128 transport, not a smaller CLI
# profile. JSON decoding uses the output region for its key hash table.
OUTPUT_BYTES = 16 << 20
ARENA_BYTES = 64 + (1 << 20) * 56 + (8 << 20)
PRIVATE_BYTES = (8 << 20) + 64 + 8*(1024+4096+16384+1024+1024+1024) + 48*1024 + 8*16384 + 8
WORKSPACE_BYTES = ARENA_BYTES + PRIVATE_BYTES


def document():
    return filter_document(output_bytes=OUTPUT_BYTES, workspace_bytes=WORKSPACE_BYTES,
                           magic=MAGIC, module='core_workspace_json_packer')


def main():
    target = Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/core_workspace_json_packer.hepta'
    target.write_text(render_assembly(document()))
    print(target.name, target.stat().st_size)


if __name__ == '__main__':
    main()
