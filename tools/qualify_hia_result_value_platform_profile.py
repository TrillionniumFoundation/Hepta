"""Bind the new fixed bridge identity to unchanged behavioral qualifiers.

Only the exact expected native bridge/module is selected. The original
fault controller, system-call site uniqueness, input/output assertions,
failure budgets and behavior sources remain unchanged.
"""
from pathlib import Path
import argparse,hashlib,importlib,json,sys
from tools import generate_hia_result_value_platform_packer as profile
ALLOWED=('exceptions','invocation_custody','truth_protocols',
         'deferred_capture','deferred_snapshot','deferred_import')
def main():
    p=argparse.ArgumentParser()
    p.add_argument('--case',choices=ALLOWED,required=True)
    p.add_argument('--binding-report',type=Path,required=True)
    a,args=p.parse_known_args()
    if args and args[0]=='--':args=args[1:]
    import tools.qualify_hia_result_value_invocation_custody as custody
    custody.values_pack=profile
    module=importlib.import_module('tools.qualify_hia_result_value_'+a.case)
    if a.case=='exceptions':module.invocation_pack=profile
    else:module.values_pack=profile
    raw=Path(module.__file__).read_bytes()
    row=dict(schema='hia.platform.qualifier-profile-binding.v1',
      qualifier=dict(path=module.__file__,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),
      bridge=dict(bytes=len(profile.BRIDGE),sha256=hashlib.sha256(profile.BRIDGE).hexdigest()),
      original_fault_controller_and_assertions_unchanged=True)
    a.binding_report.write_text(json.dumps(row,indent=2)+'\n')
    sys.argv=[module.__file__,*args]
    module.main()
if __name__=='__main__':main()
