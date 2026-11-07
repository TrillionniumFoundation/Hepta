"""Create-only finite-experiment evidence, not production attestation."""
from __future__ import annotations
import argparse,hashlib,json,platform,sys
from pathlib import Path
try:
    from .hx_fp32_local_sign_collision import collision_evidence
except ImportError:
    from hx_fp32_local_sign_collision import collision_evidence

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    d=collision_evidence()
    d['python']=sys.version.split()[0]
    d['platform']=platform.platform()
    d['executed_source_sha256']={}
    for name in ('hx_fp32_local_sign_collision.py','test_hx_fp32_local_sign_collision.py',
                 'p0_fp32_local_sign_evidence.py','hx_local_obstacle_mp_reference.py'):
        file=Path(__file__).with_name(name)
        d['executed_source_sha256'][name]=hashlib.sha256(file.read_bytes()).hexdigest()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8') as out:
        json.dump(d,out,indent=2,sort_keys=True,allow_nan=False)
        out.write('\n')
    print(json.dumps({'tax_zero_cashflow':d['tax_zero_cashflow'],
                     'positive_net_negative_curvature':d['positive_net_negative_curvature']['net_cashflow'],
                     'negative_net_positive_curvature':d['negative_net_positive_curvature']['net_cashflow'],
                     'same_fp32_inputs':d['same_fp32_inputs'],'output':str(args.output)},indent=2))
if __name__=='__main__':main()
