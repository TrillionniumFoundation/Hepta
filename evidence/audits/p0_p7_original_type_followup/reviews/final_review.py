"""Final limited delivery review: new receipts and claims, no project execution."""
from pathlib import Path
import datetime
import hashlib
import json
import re

ROOT = Path('/tmp/hepta-followup-public-review-20261027')
REPO = Path('/workspace/scratch/4bc91e0ee48c/hepta-followup-integration')
OUT = Path('/tmp/hepta-delivery-evidence-review-20261028/final-review.json')
COMMIT = 'e6379178a3e9a682f88c344aaa86b3d74932ffd7'
TREE = '66d0950ce0d41c0b705509b14ac97313052ec3ef'
SNAPSHOT = 'ce1f52a3f003cda6565de178942e4720e2386f8055c5aed54982fd9feaa6bc2c'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(name):
    return json.loads((ROOT / name).read_text())


def identity(name):
    raw = (ROOT / name).read_bytes()
    return {'path': name, 'bytes': len(raw), 'sha256': sha(raw)}


def main():
    checks = []
    failures = []
    def check(name, actual):
        checks.append({'name': name, 'passed': bool(actual)})
        if not actual:
            failures.append(name)

    readme_raw = (ROOT / 'README.md').read_bytes()
    readme = readme_raw.decode()
    status_raw = (ROOT / 'current-status.json').read_bytes()
    status = json.loads(status_raw)
    manifest = load('final-copied-receipts.json')
    check('exactly 34 new copied receipts declared', len(manifest['copied']) == 34)
    copies = []
    for row in manifest['copied']:
        target = ROOT / row['path']
        source = Path(row['source'])
        check('regular copied receipt: ' + row['path'], target.is_file() and not target.is_symlink())
        a, b = target.read_bytes(), source.read_bytes()
        matched = a == b and len(a) == row['bytes'] and sha(a) == row['sha256']
        check('exact original/copy identity: ' + row['path'], matched)
        copies.append({'path': row['path'], 'bytes': len(a), 'sha256': sha(a),
                       'original_matches': matched})

    summary = load('final-e6379178/summary.json')
    completion = load('final-e6379178/execution-completion.json')
    unit = load('final-e6379178/unit-discovery/report.json')
    cargo = load('final-e6379178/cargo-test/report.json')
    unit_text = (ROOT / 'final-e6379178/unit-discovery/stderr.log').read_text()
    footer = re.search(r'(?m)^Ran (\d+) tests in ([0-9.]+)s\s+OK\s*\Z', unit_text)
    check('unit terminal footer actually reports 2458 and OK',
          footer is not None and int(footer.group(1)) == 2458)
    parsed_ids = []
    # unittest prints a method's docstring on a second line when present;
    # the canonical method identity remains on the first line without "...".
    for name, context in re.findall(r'(?m)^(test\S+) \(([^\n)]+)\)(?: \.\.\.|$)', unit_text):
        parsed_ids.append(context if context.endswith('.' + name) else context + '.' + name)
    retained_ids = (ROOT / 'final-e6379178/canonical-unittest-ids.txt').read_text().splitlines()
    check('2458 canonical IDs independently parsed and all unique',
          len(parsed_ids) == len(set(parsed_ids)) == 2458)
    check('parsed canonical IDs match retained list', sorted(parsed_ids) == sorted(retained_ids))
    check('unit report zero errors/failures/skips and passed',
          unit['outcome'] == {'errors':0,'failures':0,'passed':True,'skipped':0,'tests_run':2458}
          and unit['returncode'] == 0 and unit['ok'])
    cargo_text = (ROOT / 'final-e6379178/cargo-test/stdout.log').read_text()
    rows = re.findall(r'(?m)^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; '
                      r'(\d+) ignored; (\d+) measured; (\d+) filtered out; finished in ([^\n]+)$', cargo_text)
    cargo_counts = {'passed':sum(int(r[1]) for r in rows),
                    'failed':sum(int(r[2]) for r in rows),
                    'ignored':sum(int(r[3]) for r in rows),
                    'measured':sum(int(r[4]) for r in rows),
                    'filtered_out':sum(int(r[5]) for r in rows)}
    check('nine Cargo footer records, 54 passed and zero others',
          len(rows) == 9 and all(r[0] == 'ok' for r in rows)
          and cargo_counts == {'passed':54,'failed':0,'ignored':0,'measured':0,'filtered_out':0})
    check('Cargo report passed with returncode zero', cargo['ok'] and cargo['returncode'] == 0
          and cargo['outcome']['passed'] and cargo['outcome']['total_passed'] == 54)
    check('summary and completion identify tested commit',
          summary['git_commit'] == completion['git_commit'] == COMMIT)
    check('summary passed; completion records actual runner exit zero',
          summary['ok'] and completion['observed_runner_returncode'] == 0
          and completion['runner_and_validation_stages_completed'])
    check('four stages include separate preflight and exactly two formal gates',
          len(summary['stages']) == 4 and summary['planned_formal_gate_count'] == 2
          and summary['completed_formal_gate_count'] == 2
          and not summary['preflight_failed'] and summary['not_started'] == [])
    check('complete source identities equal before and after',
          summary['source_before'] == summary['source_after'] and summary['source_unchanged'])
    # Initial discovery also records version-command output and timing.
    # Stable tool identity is path, resolved path, bytes and SHA, not whether
    # that informational command was repeated after the validation.
    version_probe_fields = {'version_argv','version_duration_seconds',
                            'version_returncode','version_stderr','version_stdout'}
    tool_identity_before = {name:{k:v for k,v in row.items() if k not in version_probe_fields}
                            for name,row in summary['tools_before'].items()}
    tool_identity_after = {name:{k:v for k,v in row.items() if k not in version_probe_fields}
                           for name,row in summary['tools_after'].items()}
    check('tool identities equal before and after',
          tool_identity_before == tool_identity_after and summary['tools_unchanged'])
    for side in ['source_before','source_after']:
        s = completion[side]
        check(side + ' exact commit/tree/snapshot/count and clean state',
              s['git_commit'] == COMMIT and s['git_tree'] == TREE
              and s['snapshot_sha256'] == SNAPSHOT and s['snapshot_file_count'] == 1050
              and s['git_status'] == '' and s['capture_errors'] == [])
    check('original manifest completion checks zero mismatches',
          completion['original_manifest_files_verified'] == 26
          and completion['original_manifest_mismatches'] == [])
    check('current status retains precise implementation identity',
          status['implementation_commit'] == COMMIT and status['implementation_tree'] == TREE
          and status['implementation_source_snapshot'] == SNAPSHOT)
    check('current status marks only current integrated run passed',
          status['final_integrated_run']['status'] == 'passed'
          and status['final_integrated_run']['full_unit_result']['tests_run'] == 2458
          and status['final_integrated_run']['full_unit_result']['passed']
          and status['final_integrated_run']['cargo_test_result']['tests_passed'] == 54
          and status['final_integrated_run']['cargo_test_result']['passed'])
    check('whole project, whole deliverables and new all-19 status remain false',
          status['whole_project_blockers_closed'] is False
          and status['full_seven_deliverables_complete'] is False
          and status['all_19_gates_requalified_on_this_implementation'] is False
          and summary['all_19_gates_requalified'] is False
          and completion['all_19_gates_requalified'] is False)
    check('no broad P0-P7 stage marked complete',
          len(status['stages']) == 8 and all(row['complete'] is False for row in status['stages']))
    check('README has no final-result or other uppercase placeholder',
          re.search(r'__[A-Z][A-Z0-9_]*__', readme) is None)
    check('README states actual unit and Cargo counts, identity and scope',
          '2,458 passed；0 skipped / failures / errors' in readme
          and '54 passed；0 failed / ignored / filtered out' in readme
          and COMMIT in readme and SNAPSHOT in readme and '1,050 个文件' in readme
          and '完整 P0–P7 验收仍未完成' in readme)
    check('runner-exit provenance wording corrected',
          'summary](final-e6379178/summary.json) 记录正式回归通过' in readme
          and 'execution-completion.json) 记录外层 runner 实际退出码 0' in readme
          and 'summary](final-e6379178/summary.json) 记录外层 runner 实际退出码 0' not in readme)

    links = []
    for target in re.findall(r'\]\(([^)]+)\)', readme):
        if re.match(r'^[a-zA-Z]+:', target) or target.startswith('#'):
            continue
        if target.startswith('../../../docs/'):
            resolved = (REPO / 'evidence/audits/p0_p7_original_type_followup' / target).resolve()
        else:
            resolved = (ROOT / target).resolve()
        check('relative link exists: ' + target, resolved.is_file())
        links.append({'target':target,'resolved':str(resolved),'exists':resolved.is_file()})

    bundle = (ROOT / 'sources/verified-component-sources.bundle').read_bytes()
    receipt = load('sources/bundle-receipt.json')
    replay = load('sources/bundle-replay.json')
    check('component bundle size and SHA agree with receipts/status',
          len(bundle) == 27417 == receipt['bundle']['bytes'] == status['component_source_bundle']['bytes']
          and sha(bundle) == receipt['bundle']['sha256'] == replay['bundle_sha256']
          == status['component_source_bundle']['sha256'])
    check('five component objects match recorded new-pack commits',
          len(receipt['included_commit_ids']) == 5
          and set(receipt['included_commit_ids']) == set(replay['new_pack_commit_objects'])
          and replay['all_five_component_commits_actually_in_pack'] is True
          and replay['unbundle']['returncode'] == replay['verify_pack']['returncode'] == 0)
    check('bundle scope excludes original archive and full repository',
          receipt['original_108762ba_archive_included'] is False
          and receipt['whole_repository_bundle'] is False)
    check('reviewed README and status remained stable during review',
          (ROOT/'README.md').read_bytes() == readme_raw
          and (ROOT/'current-status.json').read_bytes() == status_raw)
    result = {
        'schema':'hepta.audit.final-delivery-evidence-review.v1',
        'checked_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'readme':{'path':str(ROOT/'README.md'),'bytes':len(readme_raw),'sha256':sha(readme_raw)},
        'current_status':{'path':str(ROOT/'current-status.json'),'bytes':len(status_raw),'sha256':sha(status_raw)},
        'new_copy_manifest':identity('final-copied-receipts.json'),
        'new_copied_files_checked':len(copies),'new_copied_bytes_checked':sum(x['bytes'] for x in copies),
        'copies':copies,
        'summary':identity('final-e6379178/summary.json'),
        'completion':identity('final-e6379178/execution-completion.json'),
        'independent_unit_footer':None if footer is None else {'tests_run':int(footer.group(1)),
                         'elapsed_seconds':float(footer.group(2)),'status':'OK'},
        'independent_canonical_method_count':len(parsed_ids),
        'independent_unique_canonical_method_count':len(set(parsed_ids)),
        'independent_cargo_footer_count':len(rows),'independent_cargo_counts':cargo_counts,
        'relative_links':links,
        'component_bundle':{'bytes':len(bundle),'sha256':sha(bundle),
             'receipt':identity('sources/bundle-receipt.json'),
             'replay_receipt':identity('sources/bundle-replay.json'),
             'new_unpack_performed_in_this_review':False},
        'resolved_findings':[{'kind':'report-provenance-wording',
             'detail':'summary records ok=true; actual outer exit code belongs to execution-completion.observed_runner_returncode. README now links each statement to its actual record.',
             'resolved':True}],
        'checks':checks,'failures':failures,
        'review_parser_correction':{
            'initial_report_path':'/tmp/hepta-delivery-evidence-review-20261028/final-review-first-parser-attempt.json',
            'initial_report_sha256':'9fc31dfb553ef8f22fd5535929c9f03fc1cfe6e1586364027f83d6625beb033f',
            'initial_report_retained_unchanged':True,
            'initial_false_failures':[
                'One unittest method has a docstring and its ... ok appears on the following line; the first parser incorrectly required dots on the identity line.',
                'Initial tool records include informational version probes; final records contain stable tool identity only. The first parser incorrectly required equality of those ancillary fields.'
            ],
            'correction':'Independently parse both valid unittest display forms; compare all tool identity fields while excluding only the five explicitly named version-probe fields. No project execution was repeated or reclassified.'
        },
        'project_source_modified':False,'new_project_executions':0,
        'old_108_copied_receipts_reaudited':False,
        'scope':'Only the new 34 copied files were byte-recompared with original sources. Final raw footers/IDs, declared identities/scope, links and component-bundle receipt/hash consistency were checked. No old archive, complete older-copy audit, project test, compiler, native program, network request or Git unpack was executed.',
        'result':'passed' if not failures else 'findings_require_resolution'
    }
    raw=(json.dumps(result,indent=2,sort_keys=True,ensure_ascii=False)+'\n').encode()
    with OUT.open('xb') as stream:
        stream.write(raw)
    print(json.dumps({'report':str(OUT),'sha256':sha(raw),'result':result['result'],
                      'copied_files':len(copies),'copied_bytes':result['new_copied_bytes_checked'],
                      'checks':len(checks),'relative_links':len(links),'failures':failures}))


if __name__=='__main__':
    main()
