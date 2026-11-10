"""HIA-authored packer for the standalone, JSON-input snapshot filter."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_native_filter import document as filter_document

MAGIC = int.from_bytes(b'HIAJSN01', 'little')
ARENA_BYTES = (64 << 20) + 4096
WORKSPACE_BYTES = 16 << 20


def document():
    return filter_document(output_bytes=ARENA_BYTES, workspace_bytes=WORKSPACE_BYTES,
                           magic=MAGIC, module='agent_snapshot_json_packer')


def main():
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/agent_snapshot_json_packer.hiaasm'
    path.write_text(render_assembly(document())); print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
