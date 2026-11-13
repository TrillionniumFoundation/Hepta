"""One read-only three-reference operation. No retry or product execution."""
from pathlib import Path
import argparse
import importlib.util
import json
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
if 'v92_view_common' in sys.modules:
    c = sys.modules['v92_view_common']
else:
    spec = importlib.util.spec_from_file_location('v92_view_common', ROOT / 'control/common.py')
    c = importlib.util.module_from_spec(spec); sys.modules[spec.name] = c; spec.loader.exec_module(c)
io, require = c.io, c.require
op = c.module('v92_view_operation', ROOT / 'control/operation.py')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider-references-sha256', required=True)
    parser.add_argument('--proxy-configuration-sha256', required=True)
    args = parser.parse_args()
    policy, policy_pin, _ = c.policy_read(); roots = op.volume_roots(policy)
    clock, clock_pin, _ = c.document(roots['workspace'] / 'CLOCK.json')
    deadline = c.fixed_clock(clock, policy_pin['sha256'])
    report = {'schema': 'hia.v92-three-part-view-worker.v1', 'status': 'HOLD',
              'clock': clock, 'policy': policy_pin, 'parts': [], 'errors': [],
              'original_CI_failure_preserved': True, 'original_receiver_HOLD_preserved': True,
              'product_execution': False, 'whole_reconstructed_file_written': False,
              'source_inputs_preserved': False}
    budgets = {key: c.VolumeBudget(root, policy['volumes'][key]['limits']) for key, root in roots.items()}
    # Root-created owner metadata consumes its separately reserved parent quota.
    result_path = roots['workspace'] / 'WORKER-RESULT.json'
    try:
        refs, refs_pin, proxy, proxy_pin = c.private_inputs(policy, args.provider_references_sha256, args.proxy_configuration_sha256)
        report['private_refs'] = refs_pin; report['private_proxy'] = proxy_pin
        before = c.inputs(policy, deadline)
        c.create(roots['workspace'] / 'INPUTS-BEFORE.json', before, budget=budgets['workspace'], category='parent', deadline=deadline)
        op.prior_originals(policy, deadline)
        for item, reference in zip(policy['parts'], refs):
            io.check_deadline(deadline)
            for budget in budgets.values(): budget.capacity()
            folder = op.part_directory(policy, item); c.mkdir(folder)
            adapter = c.DownloadBudget(budgets[item['volume']], folder, item['artifact']['bytes'])
            path, download = io.download(reference['url'], item['artifact'], folder, adapter, deadline, proxy)
            adapter.finish(path)
            report['parts'].append({'ordinal': item['ordinal'], 'download': download})
        containers, specs = op.read_containers(policy, roots, deadline)
        report['containers'] = containers
        report['original'] = op.read_original(policy, roots, budgets, specs, deadline)
        after = c.inputs(policy, deadline); require(before == after, 'frozen source inputs changed')
        refs_after, rp, proxy_after, pp = c.private_inputs(policy, args.provider_references_sha256, args.proxy_configuration_sha256)
        require(refs_after == refs and rp == refs_pin and proxy_after == proxy and pp == proxy_pin,
                'private fixed network inputs changed')
        c.create(roots['workspace'] / 'INPUTS-AFTER.json', after, budget=budgets['workspace'], category='parent', deadline=deadline)
        report.update(status='COMPLETE_THREE_CONTAINER_VIEW_READ_NOT_QUALIFICATION', source_inputs_preserved=True)
    except BaseException as error:
        report['status'] = 'HOLD'; report['errors'].append(io.safe_error(error))
    report['elapsed_from_single_clock'] = time.monotonic() - clock['start']
    try:
        c.create(result_path, report, budget=budgets['workspace'], category='parent',
                 deadline=deadline if not report['errors'] else None)
        if not report['errors']: io.check_deadline(deadline)
    except BaseException as error:
        report['status'] = 'HOLD'; report['errors'].append(io.safe_error(error))
        c.create(roots['workspace'] / 'WORKER-FINALIZATION-HOLD.json', report,
                 budget=budgets['workspace'], category='parent')
    print(json.dumps({'status': report['status'], 'get_attempts': sum(x['download']['get_attempts'] for x in report['parts']),
                      'product_executed': False, 'original_failures_preserved': True}), flush=True)
    return 0 if report['status'] == 'COMPLETE_THREE_CONTAINER_VIEW_READ_NOT_QUALIFICATION' and not report['errors'] else 1

if __name__ == '__main__':
    try: raise SystemExit(main())
    except SystemExit: raise
    except BaseException as error:
        print(json.dumps({'status': 'PRE_OR_POST_WORKER_HOLD', 'error': io.safe_error(error)}), flush=True)
        raise SystemExit(1)
