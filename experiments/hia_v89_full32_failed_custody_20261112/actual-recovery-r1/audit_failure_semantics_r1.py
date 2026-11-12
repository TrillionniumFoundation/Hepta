"""Join actual failed supply, full guardian and custody originals without execution."""
from pathlib import Path
import hashlib
import json
import stat

ROOT = Path('/workspace/scratch/e26ed3e2edcf/core-full32-failed-parts-recovery-r1')
INNER = ROOT / 'original-inner-selected'
OUTER = ROOT / 'original-outer' / 'hia-v87-full-public'
checks = []


def require(ok, text):
    if not ok:
        raise AssertionError(text)
    checks.append(text)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def pin(path):
    raw = path.read_bytes()
    return {'path': str(path.relative_to(ROOT)), 'bytes': len(raw), 'sha256': sha(raw)}


def raw_pin(path, expected):
    actual = pin(path)
    require(actual['bytes'] == expected['bytes'] and actual['sha256'] == expected['sha256'],
            'actual raw pin: ' + actual['path'])


def lifecycle(guardian, request, seconds, expected_rc):
    require(guardian['command'] == request['command'] and guardian['cwd'] == request['cwd'] and
            guardian['external_controller_seconds'] == request['controller_seconds'] == seconds and
            guardian['source_identities_before'] == request['source_identities'] == guardian['source_identities_after'] and
            guardian['input_identity_preserved'] is True and
            guardian['lifecycle_implementation_sha256'] == '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2',
            'bound %d second owner command, request and unchanged source identity set' % seconds)
    life = guardian['lifecycle']
    require(life['qualification_seconds'] == seconds and life['cleanup_seconds'] == 3 and
            life['returncode'] == expected_rc and life['timed_out'] is False and
            life['exit_observed_before_deadline'] is True and life['subreaper_enabled'] is True and
            life['event_overflow'] is False and life['interrupted_signals'] == [] and life.get('owner_error') is None,
            'actual %d/3 no timeout, expected original return code' % seconds)
    c = life['cleanup']
    require(c['attempted'] is True and c['complete'] is True and c['observed_echild'] is True and
            c['leader_reaped'] is True and c['deadline_exceeded'] is False and
            c['errors'] == [] and c['remaining_direct_children'] == [], 'actual %d bound ECHILD' % seconds)
    require(all(x['kind'] in ['qualification_started', 'owned_child_observed',
                             'qualification_exit_observed', 'owned_child_reaped'] for x in life['events']),
            'actual %d natural events without signal/kill' % seconds)
    return life


def main():
    physical = read(ROOT / 'ORIGINAL-PHYSICAL-AUDIT.json')
    require(physical['status'] == 'ALL_AVAILABLE_ORIGINAL_BODIES_VERIFIED_ORIGINAL_HOLD_PRESERVED',
            'full raw physical readback prerequisite')
    inventory = read(ROOT / 'ORIGINAL-INNER-INVENTORY.json')['members']
    members = {x['path']: x for x in inventory}
    require(len(members) == len(inventory) == 4797, 'complete unique actual archived population')
    catalog = read(OUTER / 'ORIGINAL-CATALOG.json')
    originals = {x['path']: x for x in catalog['originals']}
    final = read(OUTER / 'FINAL.json')
    custody = read(OUTER / 'CUSTODY.json')
    setup = read(INNER / 'control/SETUP.json')
    policy = read(INNER / 'control/policy.json')
    request = read(OUTER / 'GUARDIAN-REQUEST.json')
    guard = read(INNER / 'guard/guardian.json')
    require((OUTER / 'SETUP.json').read_bytes() == (INNER / 'control/SETUP.json').read_bytes(),
            'original setup public and private bytes identical')
    require(setup['context'] == final['context'] and setup['context']['run_id'] == 43283027193 and
            setup['context']['attempt'] == 1 and setup['context']['event'] == 'create' and
            setup['context']['control_commit'] == '7b184c92396cb2afcfd9667c9e520831cb3cd98d' and
            setup['context']['trigger_head'] == 'aa90c740a39d9437fc423dfb1f0545dc4da48e87',
            'actual original control versus workflow carrier identities')
    require(final['source']['commit'] == '784f088fcc5ad81c65de541d54e26d380c86293c' and
            final['source']['tree'] == 'd9e8407c70e44a3ea0152b8b4c5eb2ed3833d790',
            'actual product source differs explicitly from workflow carrier')
    require(request['command'] == setup['command'] and request['cwd'] == setup['cwd'] == setup['root'],
            'original driver request equals actual setup')
    for name, p in setup['control_files'].items():
        raw_pin(INNER / 'control' / name, p)
    raw_pin(INNER / 'control/policy.json', setup['policy'])
    for absolute, digest in request['source_identities'].items():
        if absolute == setup['python']['resolved_image']['path']:
            require(digest == setup['python']['resolved_image']['sha256'], 'original Python image identity')
            continue
        relative = absolute.removeprefix(setup['root'] + '/')
        require(relative in members and members[relative]['sha256'] == digest,
                'full physical archive binds original owner input: ' + relative)
    full_life = lifecycle(guard, request, 10800, 1)
    require(guard['status'] == 'HOLD' and full_life['status'] == 'QUALIFICATION_FAILED' and
            guard['qualification'] is None and final['original_qualification_status'] == 'MISSING_ORIGINAL_REPORT',
            'original full attempt failed before a qualification report')
    raw_pin(INNER / 'guard/guardian.json', final['qualification_guardian'])
    for name in ['guardian.json', 'request.json', 'child.stdout.log', 'child.stderr.log']:
        p = OUTER / 'qualification-guardian-originals' / name
        target = INNER / 'guard' / name
        if name == 'request.json':
            require(p.read_bytes() == (OUTER / 'GUARDIAN-REQUEST.json').read_bytes(),
                    'public original guardian request copy exact')
        else:
            require(p.read_bytes() == target.read_bytes(), 'public/private original guard copy: ' + name)
    for suffix in ['stdout', 'stderr']:
        p = INNER / ('guard/child.' + suffix + '.log')
        require(guard['logs'][setup['root'] + '/guard/child.' + suffix + '.log'] == sha(p.read_bytes()),
                'original driver raw ' + suffix)
    supply = read(INNER / 'supply/SUPPLY.json')
    negative = read(INNER / 'preparation-logs/fresh-prerequisite-supply.owner.json')
    apt = read(INNER / 'supply/requests/009-apt-install.json')
    require(supply['status'] == 'HOLD' and supply['error']['type'] == 'PermissionError' and
            supply['error']['message'] == '[Errno 1] Operation not permitted' and
            'workflow_process.py\", line 33' in supply['error']['traceback'] and
            'os.killpg(process.pid, 0)' in supply['error']['traceback'],
            'exact original failing call and EPERM traceback')
    require(supply['qualification_executed'] is False and supply['final_readback_complete'] is False and
            supply['apt_cache_ownership']['status'] == 'HOLD' and
            supply['full_process_tree_cleanup_claimed_by_supply'] is False,
            'supplier did not claim qualification, group closure, or cache repair')
    require(negative['returncode'] == 2 and negative['timed_out'] is False and
            negative['workflow_seconds'] == 3600 and negative['status'] == 'WORKFLOW_STEP_HOLD' and
            negative['cleanup']['complete'] is True and negative['cleanup']['signalled'] == [] and
            negative['cleanup']['errors'] == [], 'supplier outer step original nonzero, no timeout')
    require(apt['seconds'] == 900 and apt['command'][:5] == ['/usr/bin/sudo', '-n', '--', '/usr/bin/apt-get', '-o'] and
            apt['receipt'].endswith('/supply/logs/009-apt-install.receipt.json'), 'exact original apt sudo command and allowance')
    require('supply/logs/009-apt-install.receipt.json' not in originals and
            'supply/reports/009-apt-install.completed.json' not in originals,
            'failed postwait group probe did not publish an apt return-code receipt')
    workflow = INNER / 'control/workflow_process.py'
    workflow_sha = sha(workflow.read_bytes())
    require(members['source/experiments/hia_native_successor_runner_20261111/workflow_process.py']['sha256'] == workflow_sha and
            workflow.read_text().splitlines()[32].strip() == 'os.killpg(process.pid, 0)',
            'archived called helper and exact control copy same bytes; line33 observed')
    snapshot = read(INNER / 'supply/reports/source-before.snapshot.json')
    require(snapshot['head'] == final['source']['commit'] and snapshot['tree'] == final['source']['tree'] and
            snapshot['full_physical_read'] is True and snapshot['leaves'] == len(snapshot['files']) == 4076,
            'actual full source-before snapshot population/head/tree')
    source_names = {x['path'][7:] for x in inventory if x['path'].startswith('source/') and
                    not x['path'].startswith('source/.git/') and x['kind'] == 'regular'}
    require(source_names == set(snapshot['files']), 'all actual tracked-source bodies covered in archive')
    for name, p in snapshot['files'].items():
        m = members['source/' + name]
        require(m['bytes'] == p['bytes'] and m['sha256'] == p['sha256'] and m['mode'] == p['mode'],
                'source exact bytes/mode: ' + name)
    cg = read(OUTER / 'custody-guard/guardian.json')
    cr = read(OUTER / 'custody-guard/request.json')
    custody_life = lifecycle(cg, cr, 1800, 0)
    require(cg['status'] == 'EXTERNAL_OWNED_PROCESS_COMPLETED' and custody_life['status'] == 'OWNED_PROCESS_COMPLETED',
            'custody-only guardian natural success does not upgrade original qualification')
    raw_pin(OUTER / 'custody-guard/guardian.json', final['custody_guardian'])
    raw_pin(OUTER / 'CUSTODY.json', final['custody_report'])
    require(catalog['closed_original_guardian']['sha256'] == sha((INNER / 'guard/guardian.json').read_bytes()) and
            catalog['original_guardian_request']['sha256'] == sha((OUTER / 'GUARDIAN-REQUEST.json').read_bytes()),
            'typed catalog tied to actual closed failed original request/guardian')
    for absolute, digest in cr['source_identities'].items():
        if absolute == setup['python']['resolved_image']['path']:
            require(digest == setup['python']['resolved_image']['sha256'], 'custody Python image identity')
        elif absolute == setup['root'] + '/guard/guardian.json':
            require(digest == sha((INNER / 'guard/guardian.json').read_bytes()), 'custody binds actual failed guardian')
        else:
            relative = absolute.removeprefix(setup['public'] + '/')
            require((OUTER / relative).is_file() and sha((OUTER / relative).read_bytes()) == digest,
                    'custody actual original input: ' + relative)
    for suffix in ['stdout', 'stderr']:
        require(cg['logs'][setup['public'] + '/custody-guard/child.' + suffix + '.log'] ==
                sha((OUTER / ('custody-guard/child.' + suffix + '.log')).read_bytes()), 'custody raw ' + suffix)
    gaps = [originals[name] for name in ['supply/apt-cache/lock', 'supply/apt-cache/partial']]
    report = {
        'schema': 'hepta.failed-full32-exact-supply-cause.v1',
        'status': 'EXACT_ORIGINAL_FAILURE_AND_CUSTODY_GAPS_IDENTIFIED',
        'original_run_id': 43283027193, 'original_job_id': 131409039204,
        'artifact_id': 13974465966,
        'artifact_sha256': '9da285831263db03d5e24e26e427f867763f39d1d607ccf34f21ef519163785d',
        'workflow_carrier': setup['context']['trigger_head'],
        'actual_product_source': final['source'], 'actual_control_commit': setup['context']['control_commit'],
        'observed_failure': supply['error'],
        'original_supplier_seconds': supply['wall_seconds'],
        'supplier_step_returncode': negative['returncode'],
        'supplier_step_seconds': negative['seconds'],
        'exact_apt_request': apt,
        'apt_returncode_not_preserved': True,
        'apt_stdout_has_package_setting_up_and_trigger_output': True,
        'apt_warning_is_not_proof_of_apt_nonzero': True,
        'workflow_helper': pin(workflow),
        'source_observation': {'head': snapshot['head'], 'tree': snapshot['tree'],
                               'full_physical_source_files_joined': len(snapshot['files'])},
        'full_original_owner': {'seconds': 10800, 'cleanup_seconds': 3, 'returncode': 1,
                                'timed_out': False, 'event_count': len(full_life['events']),
                                'observed_echild': True, 'remaining_children': [],
                                'cleanup_errors': [], 'qualification_report_present': False},
        'custody_owner': {'seconds': 1800, 'cleanup_seconds': 3, 'returncode': 0,
                          'timed_out': False, 'event_count': len(custody_life['events']),
                          'observed_echild': True, 'remaining_children': [], 'cleanup_errors': []},
        'custody_gaps': gaps, 'original_final_status': 'HOLD',
        'original_complete_custody': False,
        'key_originals': [pin(INNER / n) for n in ['supply/SUPPLY.json',
            'supply/requests/009-apt-install.json', 'supply/logs/009-apt-install.stdout',
            'supply/logs/009-apt-install.stderr', 'preparation-logs/fresh-prerequisite-supply.owner.json',
            'guard/guardian.json', 'guard/child.stderr.log', 'control/supply_v87.py',
            'control/workflow_process.py']],
        'checks': checks, 'check_count': len(checks),
        'no_supplier_full32_native_rerun': True,
        'repair_not_implemented_or_executed_by_this_reader': True,
        'canonical_scope': 'Complete receiver metadata, all raw selected original controls/diagnostics and full byte-level archive inventories. Three official part ZIPs and reconstructed original ZIP are preserved locally and bound to official artifact size/SHA; their large payload bodies are not duplicated in this evidence commit.'}
    out = ROOT / 'EXACT-FAILURE-ANALYSIS.json'
    with out.open('xb') as f:
        f.write((json.dumps(report, indent=2, sort_keys=True) + '\n').encode())
    print(json.dumps({'status': report['status'], 'check_count': len(checks),
                      'source_files': len(snapshot['files']), 'report': str(out)}, sort_keys=True))


if __name__ == '__main__':
    main()
