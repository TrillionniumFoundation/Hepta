"""Run deliberately synthetic formal receipt controls; never invokes Lean."""
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def main():
    suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='test_formal_receipts.py')
    if suite.countTestCases()!=58:
        raise RuntimeError('Reviewed formal synthetic test inventory changed')
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    report={'schema':'hepta.formal-receipt-synthetic-controls.v1','tests':result.testsRun,
            'skipped':len(result.skipped),'errors':len(result.errors),'failures':len(result.failures),
            'optimization':sys.flags.optimize,'lean_executions':0,'native_executions':0,
            'scope':'Deliberately synthetic receipt validation; not formal proof execution',
            'ok':result.wasSuccessful() and not result.skipped}
    output=ROOT/'artifacts/formal-receipt-controls';output.mkdir(parents=True,exist_ok=True)
    name='optimized' if sys.flags.optimize else 'normal'
    (output/(name+'.json')).write_text(json.dumps(report,indent=2)+'\n')
    return 0 if report['ok'] else 1


if __name__=='__main__':raise SystemExit(main())
