"""Execute the emitted HIA Unicode diagnostic decision tree over every scalar."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_mcp_history_diagnostic import RANGES, RANGES_SHA256, source_program
from tools.generate_hia_mcp_service import document
from tools.generate_hia_mcp_service_owner_common import authored
from tools.qualify_hia_mcp_request_history_seed import HistorySeeds, native_call

ROOT=Path(__file__).resolve().parents[1]
ENTRY = """def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o) != 1114112:
        return 4294967295
    history_debug_init(w)
    point = 0
    while point < 1114112:
        store(o,point,choose(history_debug_escape(w,point),1,0))
        point = point+1
    return 1114112
"""


def qualify(bootstrap,output):
    code=authored(ENTRY+source_program(),extra={'SCRATCH':0})
    raw=render_assembly(document(code,'request_history_debug_classifier')).encode()
    seeds=HistorySeeds(ROOT,bootstrap,output)
    report={'schema':'hepta.hia.request-history-diagnostic-scalar.v1','passed':False,
            'whole_cold_qualified':False,'rust_unicode_table_sha256':RANGES_SHA256,
            'valid_scalar_count':1112064,'all_code_points':1114112}
    try:
        assert sha256(RANGES.read_bytes()).hexdigest()==RANGES_SHA256
        table=json.loads(RANGES.read_bytes())
        expected=bytearray(1114112)
        for low,high in table['ranges']:
            expected[low:high+1]=bytes([1])*(high-low+1)
        flat=seeds.compile(raw,'div-word')
        status,result=native_call(flat,b'',1114112,workspace_bytes=8192)
        assert status==1114112 and result==expected
        for capacity in (0,1,1114111,1114113):
            status,result=native_call(flat,b'',capacity,workspace_bytes=8192)
            assert status==4294967295 and result==b''
        (output/'classifier.hepta').write_bytes(raw)
        (output/'classifier.flat').write_bytes(flat)
        report.update(passed=True,source_sha256=sha256(raw).hexdigest(),
                      flat_sha256=sha256(flat).hexdigest(),flat_bytes=len(flat),
                      native_classification_sha256=sha256(expected).hexdigest(),
                      malformed_capacity_refusals=4)
        return report
    finally:
        seeds.save()
        (output/'qualification.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bootstrap',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(qualify(args.bootstrap.resolve(),args.output.resolve()),sort_keys=True))


if __name__=='__main__':
    main()
