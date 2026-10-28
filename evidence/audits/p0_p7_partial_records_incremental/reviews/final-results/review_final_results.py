#!/usr/bin/python3
"""Read-only review of staged final results and their exact source attribution."""
from pathlib import Path
import collections
import datetime
import difflib
import hashlib
import json
import re
import subprocess
import time

ROOT = Path('/workspace/scratch/4bc91e0ee48c/hepta-followup-integration')
STAGE = Path('/tmp/hepta-next-evidence-staging-20261028')
AUDIT = STAGE / 'evidence/audits/p0_p7_partial_records_incremental'
OUT = Path(__file__).resolve().parent
COMMIT = 'd942f18b07c8811aa1418b6f67fabc23212317d1'
TREE = '44823c1858d52e9043edebb83f2414d91087d743'
TESTED = '4a64e1a353585d0ee88985e4942c008bd82ec1482be7ce1158a60f24f550e8db'
DELIVERY = '02048763eb93a39418e5ae2b64f3b1ce8acae9bb92dccb45cdd95f70a6f57e22'
DOC = 'docs/HIA_INCREMENTAL_VERIFICATION.md'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def load(path):
    return json.loads(Path(path).read_bytes())


def descriptor(path):
    path = Path(path)
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': sha(data)}


def check_copy(path, receipt):
    observed = descriptor(path)
    need(observed['bytes'] == receipt['bytes'] and observed['sha256'] == receipt['sha256'], 'copied receipt identity mismatch')


def main():
    start = time.monotonic()
    review = {'schema': 'hepta.independent-final-staged-results-review.v1', 'passed': False,
              'new_tests_or_application_executions': 0, 'repository_or_staging_mutated': False,
              'archives_and_copy_map_review': 'Owned independently by P1; not repeated by this reviewer.',
              'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    reviewed_paths = [AUDIT / name for name in (
        'README.md', 'current-status.json', 'source/executed-source.json', 'source/local-freeze.json',
        'source/documentation-clarification-plan.json', 'integrated/summary.json',
        'integrated/execution-completion.json', 'integrated/progress-observer-clarification.json',
        'integrated/unit.stderr.log', 'integrated/unit.stdout.log', 'integrated/cargo.stdout.log',
        'integrated/cargo.stderr.log', 'integrated/canonical-unittest-ids.txt',
        'native/partial-records.json', 'native/partial-records-outer.json',
        'native/cpp-constexpr.json', 'native/cpp-constexpr-outer.json',
        'native/two-owner-cancel.json', 'native/two-owner-final-seal.json',
        'reviews/independent-native.json', 'reviews/independent-two-owner.json')]
    reviewed_paths += [STAGE / DOC, OUT / 'pr338-live.json']
    before = [descriptor(path) for path in reviewed_paths]
    try:
        status = load(AUDIT / 'current-status.json')
        completion = load(AUDIT / 'integrated/execution-completion.json')
        summary = load(AUDIT / 'integrated/summary.json')
        executed = load(AUDIT / 'source/executed-source.json')
        local = load(AUDIT / 'source/local-freeze.json')
        doc_plan = load(AUDIT / 'source/documentation-clarification-plan.json')
        source = executed['source_snapshot']
        need(executed['remote_commit'] == COMMIT and executed['remote_tree'] == TREE
             and executed['fetch_returncode'] == 0 and executed['clean'] and executed['tree_equal'], 'executed source receipt differs')
        need(local['local_tree'] == TREE and local['local_commit'] == executed['local_commit_preserved']
             and local['source_snapshot'] == source, 'local/remote implementation tree or snapshot differs')
        need(len(source['files']) == 1065 and sha(canonical(source['files'])) == source['sha256'] == TESTED,
             'tested snapshot inventory/digest mismatch')
        for name, digest in source['files'].items():
            path = ROOT / name
            need(path.resolve().is_relative_to(ROOT) and sha(path.read_bytes()) == digest, 'current executed-source bytes changed')
        git_state = {name: subprocess.check_output(['git', *args], cwd=ROOT, text=True).strip()
                     for name, args in [('commit', ['rev-parse', 'HEAD']), ('tree', ['rev-parse', 'HEAD^{tree}']),
                                        ('status', ['status', '--porcelain'])]}
        need(git_state == {'commit': COMMIT, 'tree': TREE, 'status': ''}, 'current repository not frozen clean source')
        review['tested_source'] = {'commit': COMMIT, 'tree': TREE, 'snapshot_sha256': TESTED,
                                   'source_files_checked': 1065, 'git_state': git_state}

        unit = completion['unit']
        text = (AUDIT / 'integrated/unit.stderr.log').read_text()
        starts = list(re.finditer(r'^(test_[A-Za-z0-9_]+) \(([A-Za-z0-9_.]+)\)', text, re.M))
        canonical_ids = []
        footer_start = text.index('\n----------------------------------------------------------------------\nRan ', starts[-1].end())
        for index, match in enumerate(starts):
            method, inside = match.groups()
            ident = inside if inside.endswith('.' + method) else inside + '.' + method
            canonical_ids.append(ident)
            end = starts[index + 1].start() if index + 1 < len(starts) else footer_start
            statuses = re.findall(r'(?:\.\.\.\s+|^)(ok|ERROR|FAIL|skipped[^\n]*|expected failure|unexpected success)\s*$',
                                  text[match.start():end], re.M)
            need(statuses == ['ok'], 'method missing a unique successful terminal status: ' + ident)
        ids = (AUDIT / 'integrated/canonical-unittest-ids.txt').read_text().splitlines()
        need(len(canonical_ids) == len(set(canonical_ids)) == len(ids) == len(set(ids)) == 2548
             and set(ids) == set(canonical_ids), 'canonical unittest ID count or inventory differs')
        footer = re.search(r'Ran (\d+) tests in ([0-9.]+)s\n\nOK\s*\Z', text)
        need(footer is not None and footer.group(1) == '2548' and footer.group(2) == '2187.813', 'unittest footer mismatch')
        for key in ('failures', 'errors', 'skipped'):
            need(unit[key] == 0, 'completion has unsuccessful unittest outcomes')
        need(unit['tests_run'] == unit['canonical_method_count'] == unit['unique_canonical_method_count'] == 2548
             and unit['duplicate_canonical_methods'] == {} and unit['returncode'] == 0
             and unit['footer_elapsed_seconds'] == 2187.813, 'unittest completion summary mismatch')
        for target, key in [('unit.stderr.log', 'raw_stderr'), ('unit.stdout.log', 'raw_stdout'),
                            ('canonical-unittest-ids.txt', 'canonical_ids_file')]:
            check_copy(AUDIT / ('integrated/' + target), unit[key])
        review['unittest'] = {'canonical_unique_methods': 2548, 'raw_successful_terminal_statuses': 2548,
                              'skipped': 0, 'failures': 0, 'errors': 0, 'returncode': 0,
                              'footer_seconds': 2187.813, 'command_seconds': unit['command_duration_seconds'],
                              'footer': footer.group(0)}

        cargo = completion['cargo_test']
        cargo_text = (AUDIT / 'integrated/cargo.stdout.log').read_text()
        pattern = (r'^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; '
                   r'(\d+) measured; (\d+) filtered out; finished in ([0-9.]+s)$')
        matches = re.findall(pattern, cargo_text, re.M)
        harnesses = [{'result': m[0], 'passed': int(m[1]), 'failed': int(m[2]), 'ignored': int(m[3]),
                     'measured': int(m[4]), 'filtered_out': int(m[5]), 'duration_display': m[6]} for m in matches]
        need(len(harnesses) == 9 and harnesses == cargo['harness_summaries'], 'Cargo raw harness summaries differ')
        need(sum(row['passed'] for row in harnesses) == 54
             and all(row['result'] == 'ok' and row['failed'] == row['ignored'] == row['measured'] == row['filtered_out'] == 0
                     for row in harnesses), 'Cargo harness outcomes differ')
        need(len(re.findall(r'^test [^\n]+ \.\.\. ok$', cargo_text, re.M)) == 54, 'Cargo method-success count differs')
        need(cargo['returncode'] == 0 and cargo['passed'] == 54 and cargo['harness_summary_count'] == 9,
             'Cargo completion count/return differs')
        check_copy(AUDIT / 'integrated/cargo.stdout.log', cargo['raw_stdout'])
        check_copy(AUDIT / 'integrated/cargo.stderr.log', cargo['raw_stderr'])
        review['cargo'] = {'passed': 54, 'harnesses': 9, 'failed': 0, 'ignored': 0,
                           'returncode': 0, 'command_seconds': cargo['command_duration_seconds']}

        check_copy(AUDIT / 'integrated/summary.json', completion['summary'])
        launch_path = Path(completion['launch_completion']['path'])
        need(str(launch_path).startswith('/tmp/hepta-next-integrated-d942f18b-20261028-launch/'), 'unexpected launch receipt path')
        check_copy(launch_path, completion['launch_completion'])
        launch = load(launch_path)
        need(launch['runner_returncode'] == completion['observed_runner_returncode'] == 0
             and launch['runner_pid'] == completion['runner_pid']
             and completion['runner_and_validation_stages_completed'] is True, 'outer runner completion not successful')
        need(summary['ok'] is True and summary['not_started'] == [] and not summary['preflight_failed']
             and summary['completed_formal_gate_count'] == summary['planned_formal_gate_count'] == 2,
             'formal validation stages incomplete')
        need(len(summary['stages']) == 4 and all(stage['ok'] and stage['returncode'] == 0 for stage in summary['stages']),
             'preflight or formal stage not successful')
        need([x['name'] for x in summary['stages'] if x['classification'] == 'preflight'] == ['cargo-metadata', 'cargo-build']
             and [x['name'] for x in summary['stages'] if x['classification'] == 'formal_validation'] == ['unit-discovery', 'cargo-test'],
             'preflights relabeled as tests')
        for identity in (completion['source_before'], completion['source_after']):
            need(identity['git_commit'] == COMMIT and identity['git_tree'] == TREE and identity['git_status'] == ''
                 and identity['snapshot_sha256'] == TESTED and identity['snapshot_file_count'] == 1065
                 and identity['capture_errors'] == [], 'completion source binding differs')
        for identity in (summary['source_before'], summary['source_after']):
            need(identity['git_commit'] == COMMIT and identity['git_tree'] == TREE and identity['git_status'] == ''
                 and identity['official_snapshot'] == source and identity['capture_errors'] == [], 'summary source binding differs')
        need(summary['source_unchanged'] and summary['tools_unchanged']
             and completion['source_unchanged'] and completion['tools_unchanged'], 'source/tool stability flag false')
        clarification = load(AUDIT / 'integrated/progress-observer-clarification.json')
        need(clarification['source_commit'] == COMMIT and clarification['formal_and_independent_canonical_count'] == 2548
             and clarification['live_observer_final_strict_start_count'] == 2547
             and clarification['additional_tests_executed'] is False
             and len(clarification['missed_by_stricter_live_observer']) == 1, 'live observer clarification differs')
        missed = clarification['missed_by_stricter_live_observer'][0]
        need(missed['canonical_id'] in canonical_ids and missed['raw_start_line'] in text
             and missed['following_lines'][0] in text and ' ... ' not in missed['raw_start_line'],
             'described multiline unittest observation not present')
        review['completion'] = {'actual_outer_returncode': 0, 'launch_receipt': descriptor(launch_path),
                                'formal_gates': 2, 'preflights': 2, 'all_19_gates_rerun': False,
                                'multiline_method_observer_undercount_explained': True}

        partial = load(AUDIT / 'native/partial-records.json')
        partial_outer = load(AUDIT / 'native/partial-records-outer.json')
        cpp = load(AUDIT / 'native/cpp-constexpr.json')
        cpp_outer = load(AUDIT / 'native/cpp-constexpr-outer.json')
        two = load(AUDIT / 'native/two-owner-cancel.json')
        seal = load(AUDIT / 'native/two-owner-final-seal.json')
        for outer in (partial_outer, cpp_outer):
            need(outer['source_before'] == outer['source_after'] and outer['passed'] and outer['returncode'] == 0,
                 'native outer did not pass with fixed source')
            identity = outer['source_before']
            need(identity['commit'] == COMMIT and identity['tree'] == TREE and identity['status'] == ''
                 and identity['snapshot'] == source, 'native outer source attribution differs')
        need(partial['git_commit'] == COMMIT and partial['git_status'] == '' and partial['passed'], 'partial qualification attribution differs')
        need(len(partial['differential']) == 94 and len(partial['budgets']) == 11
             and sum(row['python']['status'] == 'budget_exceeded' for row in partial['budgets']) == 10
             and sum(row['python']['status'] == 'returned' for row in partial['budgets']) == 1
             and sum(len(row['cases']) for row in partial['native'].values()) == 188
             and len(partial['negative_controls']) == 2, 'partial native counts differ')
        need(cpp['ok'] and cpp['case_count'] == 80 and cpp['native_result_executions'] == 160
             and len(cpp['constexpr_selections']) == 13
             and sum(len(row['instances']) for row in cpp['template_instances']) == 7
             and cpp['original_cpp_link_inputs_in_target'] == [], 'C++ native scope/count differs')
        need(two['source_before'] == two['source_after'] and two['source_before']['commit'] == COMMIT
             and two['source_before']['tree'] == TREE and two['source_before']['snapshot'] == source
             and two['passed'] and two['production_compile_api_used'] is False, 'two-owner source/route differs')
        need(two['counts'] == {'requests': 32, 'python_executions': 64, 'rust_executions': 32,
                              'positive_native_executions': 64, 'negative_native_executions': 4}, 'two-owner counts differ')
        double = [case for group in two['native'].values() for case in group['cases'] if case['observed']['allocations'] == 2]
        need(len(double) == 24 and all(case['observed']['free_order'] == [2, 1] for case in double), 'two live payload observation count/order differs')
        need(len(two['negative_controls']) == 4, 'two-owner negative count differs')
        for control in two['negative_controls']:
            actual, wanted = control['observed'], control['expected']
            need(actual['free_order'] == [1, 2] and wanted['free_order'] == [2, 1]
                 and {k:v for k,v in actual.items() if k != 'free_order'}
                 == {k:v for k,v in wanted.items() if k != 'free_order'}
                 and control['detected'] and not control['equivalent_to_original'], 'wrong-order control scope differs')
        need(sha((AUDIT / 'native/two-owner-cancel.json').read_bytes()) == seal['report']['sha256'], 'two-owner seal report binding differs')
        review['native'] = {'partial_records': {'scenarios': 94, 'budget_stops': 10, 'budget_returns': 1,
                                               'native_positive': 188, 'negative_controls': 2, 'production_compile_api_used': True},
                            'cpp_constexpr': {'cases': 80, 'native_calls': 160, 'instances': 7, 'selections': 13},
                            'two_owner': {'inputs': 32, 'python': 64, 'rust': 32, 'native_positive': 64,
                                          'native_two_live_payloads': 24, 'wrong_order_controls': 4,
                                          'production_compile_api_used': False}}

        old_text, new_text = (ROOT / DOC).read_text(), (STAGE / DOC).read_text()
        old_paragraph = ('intermediate candidates are not admitted. A session serializes its operations,\n'
                         'so two patches for one expected baseline cannot both commit different results:\n'
                         'the later attempt observes a stale digest. Multiple sessions are independent.\n')
        new_paragraph = ('intermediate candidates are not admitted. A session serializes its operations\n'
                         "and checks each patch's expected digest against the current baseline under the\n"
                         'same lock. If the first accepted patch changes the digest, the next patch naming\n'
                         'the old digest is rejected as stale; an accepted canonical no-op leaves that\n'
                         'digest valid. Multiple sessions are independent.\n')
        need(old_text.count(old_paragraph) == 1 and old_text.replace(old_paragraph, new_paragraph) == new_text,
             'staged documentation changed beyond exact no-op paragraph')
        need(sha(old_text.encode()) == doc_plan['before_sha256'] and sha(new_text.encode()) == doc_plan['after_sha256']
             and doc_plan['applied_to_tested_worktree'] is False and doc_plan['executable_source_changes'] is False,
             'documentation plan identity or scope differs')
        new_files = dict(source['files'])
        new_files[DOC] = sha(new_text.encode())
        need(sha(canonical(new_files)) == doc_plan['expected_delivery_snapshot_sha256'] == DELIVERY
             and doc_plan['tested_snapshot_sha256'] == TESTED and TESTED != DELIVERY, 'delivery snapshot not distinctly derived')
        staged_production_paths = [str(p.relative_to(STAGE)) for p in STAGE.rglob('*')
                                   if p.is_file() and p.relative_to(STAGE).parts[0] != 'evidence']
        need(staged_production_paths == [DOC], 'staging contains unexpected non-evidence changes')
        delivery = status['delivery_source']
        need(delivery['documentation_only_differences'] == [DOC] and delivery['expected_snapshot_sha256'] == DELIVERY
             and not delivery['executable_source_tests_examples_tools_changed_after_validation']
             and not delivery['full_suite_relabelled_to_delivery_commit'], 'public delivery attribution overstates execution')
        need(status['tested_implementation']['commit'] == COMMIT and status['tested_implementation']['tree'] == TREE
             and status['tested_implementation']['source_snapshot_sha256'] == TESTED, 'public status tested identity differs')
        need(not status['all_p0_p7_stages_complete'] and not status['whole_project_blockers_closed']
             and all(value is False for value in status['claims'].values())
             and len(status['stages']) == 8 and all(stage['complete'] is False for stage in status['stages']),
             'public stage completion/qualification claims expanded')
        readme = (AUDIT / 'README.md').read_text()
        need('The complete P0–P7 product acceptance is still open.' in readme
             and '24 positive' in readme and 'four wrong-order controls' in readme
             and 'It does not\nclaim to have used the production compile/publication API' in readme
             and 'remote CI completion and a merge are not claimed.' in readme, 'README scope/attribution markers missing')
        review['documentation'] = {'only_changed_path': DOC, 'before_sha256': doc_plan['before_sha256'],
                                   'after_sha256': doc_plan['after_sha256'], 'tested_snapshot': TESTED,
                                   'expected_delivery_snapshot': DELIVERY, 'no_op_paragraph_only': True,
                                   'source_tests_examples_tools_unchanged': True,
                                   'full_suite_not_relabelled_to_delivery_snapshot': True}
        pr = load(OUT / 'pr338-live.json')
        need(pr['number'] == 338 and pr['state'] == 'open' and pr['draft'] is True and pr['merged'] is False
             and pr['merged_at'] is None and pr['head_sha'] == COMMIT and pr['mutation_performed'] is False,
             'live PR no longer matches draft/unmerged implementation review')
        review['pull_request'] = pr
        review['public_summary_scope_review'] = {
            'full_p0_p7_acceptance_left_open': True,
            'native_experiment_counts_not_added_to_unittest_count': True,
            'direct_clang_two_owner_route_not_relabelled_production_compile_api': True,
            'python_rust_do_not_claim_ordered_release_streams': True,
            'no_gpu_physical_board_real_model_benefit_or_performance_superiority_claim': True,
            'no_merge_or_remote_ci_completion_claim': True,
            'readme_manually_read_in_full': True}
        after = [descriptor(path) for path in reviewed_paths]
        need(before == after, 'reviewed staging input changed during review')
        review['reviewed_input_files'] = after
        review['reviewed_inputs_unchanged'] = True
        review['passed'] = True
    except BaseException as error:
        review['error'] = {'type': type(error).__name__, 'message': str(error)}
        raise
    finally:
        review['seconds'] = time.monotonic() - start
        review['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        review['review_script'] = descriptor(__file__)
        with (OUT / 'review.json').open('x') as stream:
            json.dump(review, stream, sort_keys=True, indent=2, allow_nan=False)
            stream.write('\n')
        with (OUT / 'manifest.json').open('x') as stream:
            json.dump({'schema': 'hepta.independent-final-staged-review-manifest.v1',
                       'files': [descriptor(__file__), descriptor(OUT / 'pr338-live.json'), descriptor(OUT / 'review.json')]},
                      stream, sort_keys=True, indent=2, allow_nan=False)
            stream.write('\n')
    print(json.dumps({'passed': review['passed'], 'unit_methods': 2548, 'cargo_passed': 54,
                      'cargo_harnesses': 9, 'native_two_live_payload_observations': 24,
                      'source': COMMIT, 'tested_snapshot': TESTED, 'delivery_snapshot': DELIVERY,
                      'seconds': review['seconds'], 'new_tests_or_application_executions': 0}, sort_keys=True))


if __name__ == '__main__':
    main()
