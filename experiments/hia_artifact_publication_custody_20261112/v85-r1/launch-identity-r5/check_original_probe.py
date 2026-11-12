"""Read back the terminated real probe with the original, unfixed archiver."""
import argparse
import json
from pathlib import Path
import sys
import types
sys.path.insert(0,str(Path(__file__).resolve().parent))
from probe_launch_identity import load

def main():
    p=argparse.ArgumentParser();p.add_argument('--module-root',type=Path,required=True)
    p.add_argument('--probe',type=Path,required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    tools=types.ModuleType('tools');tools.__path__=[str(args.module_root/'tools')];sys.modules['tools']=tools
    c=load('tools.hia_artifact_publication_custody',args.module_root/'tools/hia_artifact_publication_custody.py')
    r=load('tools.qualify_hia_artifact_publication_tests',args.module_root/'tools/qualify_hia_artifact_publication_tests.py')
    original=json.loads((args.probe/'PROBE.json').read_bytes());quiet=r.quiescence(args.probe/'records')
    args.output.mkdir(mode=0o700)
    archive_returncode=r.archive_evidence(args.probe/'records',args.output/'archive')
    checks={'known_direct_children_reaped_must_be_false':original['producer_RUN']['known_direct_children_reaped'] is False,
            'unobserved_launch_must_not_admit_fixture_read':quiet['ready_for_fixture_read'] is False,
            'archive_must_hold_unknown_identity':archive_returncode==1}
    result={'status':'CONTROL_PASS' if all(checks.values()) else 'HOLD_EXPECTED_REFUSAL_NOT_OBSERVED',
            'checks':checks,'actual_quiescence':quiet,'actual_archive_returncode':archive_returncode,
            'real_child_was_live_when_RUN_frozen':original['control_observed_os_identity'] is not None
                and original['actual_child_returncode_before_finish'] is None,
            'test_harness_later_reaped_child':original['control_cleanup_identity_absent'],
            'later_cleanup_not_rewritten_into_original_RUN':True,'product_39_or_HIA_executed':False}
    c.write_json(args.output/'REPORT.json',result);print(json.dumps(result,sort_keys=True))
    return 0 if result['status']=='CONTROL_PASS' else 1
if __name__=='__main__':raise SystemExit(main())
