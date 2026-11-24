"""Packet facade for the linked observer's original 30M-step VM profile."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_cold_export_reference import SOURCE
ROOT=Path(__file__).resolve().parents[1]
def main():
    original='steps == 0 or steps > 10000000'
    assert SOURCE.count(original)==1
    source=SOURCE.replace(original,'steps == 0 or steps > 30000000')
    for key,value in [('INPUT_MAGIC',b'HIAEVP01'),('PROJECT_MAGIC',b'HIAERW02'),('PROGRAM_MAGIC',b'HIARPG02')]:source=source.replace(key,str(int.from_bytes(value,'little')))
    p=ROOT/'examples/hia_bootstrap/cold_export_reference_prepare_30m.hepta';p.write_text(render_assembly(document(source,'cold_export_reference_prepare_30m')));print(p.name,p.stat().st_size)
if __name__=='__main__':main()
