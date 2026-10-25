"""Compiler-free local publisher/profile controls, explicitly not native cases."""
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def main():
    suite=unittest.TestSuite()
    counts={}
    for pattern in ('test_c_project_publish.py','test_c_project_publication_probe_policy.py'):
        found=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern=pattern)
        counts[pattern]=found.countTestCases();suite.addTests(found)
    if counts['test_c_project_publish.py']!=50 or counts['test_c_project_publication_probe_policy.py']<10:
        raise RuntimeError('Local profile/control test inventory changed')
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    report={'schema':'hepta.publisher-local-profile.v1','counts':counts,'tests':result.testsRun,
            'skipped':len(result.skipped),'failures':len(result.failures),'errors':len(result.errors),
            'optimization':sys.flags.optimize,'compiler_invocations':0,'native_executions':0,
            'scope':'Filesystem/profile and mocked frontend controls, not native C qualification',
            'ok':result.wasSuccessful() and not result.skipped}
    output=ROOT/'artifacts/c-project-publisher-profile';output.mkdir(parents=True,exist_ok=True)
    name='optimized' if sys.flags.optimize else 'normal'
    (output/(name+'.json')).write_text(json.dumps(report,indent=2)+'\n')
    return 0 if report['ok'] else 1


if __name__=='__main__':raise SystemExit(main())
