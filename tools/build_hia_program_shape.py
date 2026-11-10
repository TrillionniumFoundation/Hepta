"""Build explicit whole primitive declaration admission from exact cold source."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
from tools.build_hia_json_preflight import build as build_candidate
from tools.hia_selfhost_contract import CONTRACT_PATH,PROFILE,validate_contract
ROOT=Path(__file__).resolve().parents[1]

def build(output,compiler,cold_report):
    report=json.loads(cold_report.read_bytes());contract=validate_contract()
    expected={**contract['source_identity']['files'],CONTRACT_PATH:sha256((ROOT/CONTRACT_PATH).read_bytes()).hexdigest()}
    if type(report) is not dict or report.get('profile')!=PROFILE or report.get('source_manifest')!=expected:
        raise ValueError('cold qualification source identity does not match current source')
    return build_candidate(output,compiler,cold_report,candidate='program-shape')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--compiler',type=Path,required=True)
    p.add_argument('--cold-report',type=Path,required=True)
    a=p.parse_args();print(build(a.output.resolve(),a.compiler.resolve(),a.cold_report.resolve()))
