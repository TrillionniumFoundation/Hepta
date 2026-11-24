"""The shared serde Value algorithm with original root jobctl file budgets.

The source has the same parsing, number conversion, sorting and last-wins
semantics as MCP canonical. A 1 MiB (+1 growth byte) original JSON file can
contain 524289 value nodes, so this profile allocates that actual domain.

The pure six-buffer ABI has output[0:8] mode on entry: 0 means the Value field
inside typed Exit (126 remaining container levels), 1 means the complete
retained-scratch Value (127 levels). The HIA caller owns this private mode.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_worker_config_json import document
from tools.generate_hia_mcp_canonical import source_program as canonical_source
from tools.generate_hia_worker_request import replace_once

ROOT=Path(__file__).resolve().parents[1]
MAXIMUM_NODES=524289
OUTPUT_BYTES=8388608
WORKSPACE_BYTES=64+MAXIMUM_NODES*56+OUTPUT_BYTES+16384

def source_program():
    source=canonical_source(maximum_nodes=MAXIMUM_NODES,maximum_depth=127,sdk_validation=False)
    return replace_once(source,'    put(o, 56, 127)',
        '    mode = get(o, 0)\n'
        '    if mode > 1:\n'
        '        return 4294967293\n'
        '    put(o, 56, 126 + mode)')

def main():
    path=ROOT/'examples/hia_bootstrap/system_jobctl_value.hepta'
    path.write_text(render_assembly(document(source_program(),'system_jobctl_value')))
    print(path.name,path.stat().st_size,flush=True)

if __name__=='__main__':main()
