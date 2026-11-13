"""Read-only audit of the actual failed recovery's small official artifact."""
from pathlib import Path
import hashlib
import json
import zipfile

ROOT = Path(__file__).resolve().parent
INPUTS = Path('/tmp/hia-v92-ci-failed-original-parts-r1-20261113-e26e')
checks = []

def check(ok, label):
    checks.append({'label': label, 'pass': bool(ok)})
    if not ok:
        raise AssertionError(label)

def pairs(rows):
    d = {}
    for key, value in rows:
        if key in d:
            raise ValueError('duplicate JSON key')
        d[key] = value
    return d

def parse(raw):
    return json.loads(raw, object_pairs_hook=pairs)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def pin(raw):
    return {'bytes': len(raw), 'sha256': sha(raw), 'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

def same_pin(record, raw):
    return record['bytes'] == len(raw) and record['sha256'] == sha(raw)

archive = ROOT / 'small-13998357240.original.zip'
zip_raw = archive.read_bytes()
check(len(zip_raw) == 468689 and sha(zip_raw) == '7eb88bd9b7ffc848e444573e63e73747967cfbeff40f6e5c89234497255596dd', 'official small artifact complete size/SHA')
raws = {}
with zipfile.ZipFile(archive) as z:
    check(len(z.infolist()) == 13 and len({x.filename for x in z.infolist()}) == 13, 'all 13 members unique')
    for row in z.infolist():
        check(not row.is_dir() and not row.flag_bits & 1, 'regular unencrypted member ' + row.filename)
        raw = z.read(row)
        check(len(raw) == row.file_size, 'whole body and CRC ' + row.filename)
        check((ROOT / 'small-members' / row.filename).read_bytes() == raw, 'persisted full body ' + row.filename)
        raws[row.filename] = raw
control_names = ['context.json', 'setup.json', 'guard/request.json', 'guard/guardian.json', 'guard/child.stdout.log', 'guard/child.stderr.log', 'supervisor.stdout.log', 'supervisor.stderr.log', 'recovery.json', 'recovery-terminal.json', 'api/artifact-13994959899.metadata.original.json']
check(set(raws) == {'FINAL.json', 'SMALL-READBACK.json'} | {'controls/' + n.replace('/', '--') for n in control_names}, 'exact public small original population')
def raw_control(name):
    return raws['controls/' + name.replace('/', '--')]
context = parse(raw_control('context.json'))
setup = parse(raw_control('setup.json'))
request = parse(raw_control('guard/request.json'))
guard = parse(raw_control('guard/guardian.json'))
worker = parse(raw_control('recovery-terminal.json'))
small = parse(raws['SMALL-READBACK.json'])
final = parse(raws['FINAL.json'])
policy_raw = (INPUTS / 'control/policy.json').read_bytes()
policy = parse(policy_raw)
policy_sha = sha(policy_raw)
check(policy_sha == 'c4171e09f97480c0ba4d1b7b31aac477590f579b6dcc370b4f8505d5e4dc7806', 'same frozen original policy bytes')
check(context['run_id'] == 43338002642 and context['run_attempt'] == 1 and context['event'] == 'create', 'exact recovery operation')
check(context['actual_control_checkout'] == '89aa086c8e345ecae66cb32a2dd9ff39fe1f35de' and context['actual_workflow_commit'] == '55225e8e954f19e0c6559a6e3d0c29bf16b70ba5', 'A/B binding')
check(context['policy_sha256'] == policy_sha and setup['context'] == context and final['context'] == context, 'raw context joined through setup and final')
check(context['original_product_commit'] == 'd96a5ae4783a123013351a511be9fc1a6d8f1c2c' and context['original_product_tree'] == '596ab07e8813e4811a8dca51800cd51eb397aeb2', 'original failed carrier source identity')
remote_root = context['root']
check(remote_root == '/home/runner/work/_temp/hia-v92-failed-ci-parts-r1', 'fixed current private root')
command = [context['python']['resolved'], '-I', '-S', '-B', remote_root + '/control/worker.py', '--root', remote_root, '--policy-sha256', policy_sha]
check(request['command'] == setup['command'] == guard['command'] == command, 'actual command exact through owner')
check(request['cwd'] == guard['cwd'] == remote_root and request['controller_seconds'] == setup['controller_seconds'] == guard['external_controller_seconds'] == 900 and setup['cleanup_seconds'] == 3, 'original 900/3 binding')
check(setup['guardian_config_sha256'] == sha(raw_control('guard/request.json')), 'raw guardian request SHA')
expected_sources = dict(context['control_sources'])
expected_sources[remote_root + '/context.json'] = sha(raw_control('context.json'))
for name in ['controller.py','diagnostics.py','guardian.py','original_receiver.py','policy.json','process_owner_impl.py','worker.py']:
    digest = sha((INPUTS / 'control' / name).read_bytes())
    expected_sources[remote_root + '/control/' + name] = digest
    original = '/home/runner/work/Hepta/Hepta/control/experiments/hia_v92_failed_ci_20261113/multipart-r1/' + name
    check(expected_sources[original] == digest, 'exact canonical control ' + name)
expected_sources[context['python']['resolved']] = context['python']['binary']['sha256']
check(request['source_identities'] == expected_sources, 'complete actual source identity set')
check(guard['source_identities_before'] == guard['source_identities_after'] == expected_sources and guard['input_identity_preserved'] is True, 'owner before-after complete identity')
check({k:v['sha256'] for k,v in final['source_inputs_final'].items()} == expected_sources and final['source_inputs_preserved'] is True, 'final complete source identities')
check(guard['lifecycle_implementation_sha256'] == '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2', 'original owner implementation')
life = guard['lifecycle']; cleanup = life['cleanup']
check(life['qualification_seconds'] == 900 and life['cleanup_seconds'] == 3, 'actual lifecycle budgets')
check(cleanup['complete'] is True and cleanup['observed_echild'] is True and cleanup['leader_reaped'] is True and cleanup['remaining_direct_children'] == [] and cleanup['errors'] == [] and cleanup['deadline_exceeded'] is False, 'actual bound ECHILD complete')
check(life['returncode'] == 0 and life['timed_out'] is False and life.get('owner_error') is None and life['exit_observed_before_deadline'] is True and life['interrupted_signals'] == [] and life['event_overflow'] is False, 'natural recovery worker exit only')
events = life['events']
check([r['kind'] for r in events] == ['qualification_started','owned_child_observed','qualification_exit_observed','owned_child_reaped'], 'four original actual lifecycle events')
check(len({r['pid'] for r in events}) == 1 and events[2]['si_code'] == 1 and events[2]['si_status'] == 0 and events[3]['returncode'] == 0, 'same actual child exit and reap')
owner_ns = events[2]['monotonic_ns'] - events[0]['monotonic_ns']
check(type(owner_ns) is int and 0 <= owner_ns < 900000000000, 'exact integer monotonic event duration')
for name in ['guard/child.stdout.log','guard/child.stderr.log']:
    check(guard['logs'][remote_root + '/' + name] == sha(raw_control(name)), 'actual owner log SHA ' + name)
check(raw_control('recovery.json') == raw_control('recovery-terminal.json'), 'worker checkpoint and terminal original bytes identical')
check(worker['status'] == 'SEALED_PARTS_PENDING_NATURAL_GUARDIAN' and worker['policy_sha256'] == policy_sha and worker['root'] == remote_root, 'actual worker identity and status')
check(type(worker['elapsed_ns']) is int and 0 <= worker['elapsed_ns'] <= 720000000000, 'actual worker elapsed bound')
check(worker['zip_before'] == worker['zip_after'] and worker['zip_before']['bytes'] == 656362802 and worker['zip_before']['sha256'] == 'f9d15287c668bd8d84f5d564b4829ba40813c9372de322d2f33bc65ecf40b105', 'reported same original full ZIP before and after')
check(len(worker['API_attempts']) == 2 and [r['status'] for r in worker['API_attempts']] == [200,302] and all(r['attempt'] == 1 and r['retries'] == 0 for r in worker['API_attempts']), 'reported bounded official API metadata and redirect')
check(len(worker['GET_attempts']) == 1 and worker['GET_attempts'][0]['attempt'] == 1 and worker['GET_attempts'][0]['retries'] == 0 and worker['GET_attempts'][0]['authorization_sent'] is False and worker['GET_attempts'][0]['cookies_sent'] is False, 'reported one anonymous original storage GET')
metadata = parse(raw_control('api/artifact-13994959899.metadata.original.json'))
check(metadata['id'] == 13994959899 and metadata['size_in_bytes'] == 656362802 and metadata['digest'] == 'sha256:f9d15287c668bd8d84f5d564b4829ba40813c9372de322d2f33bc65ecf40b105' and metadata['workflow_run']['id'] == 43324913647 and metadata['workflow_run']['head_sha'] == context['original_product_commit'], 'full official original metadata binding')
for item in worker['API_attempts']:
    if 'original_metadata' in item:
        check(same_pin(item['original_metadata'], raw_control('api/artifact-13994959899.metadata.original.json')), 'reported metadata original actual bytes')
parts = worker['partition']['parts']
check([(r['ordinal'],r['offset'],r['bytes']) for r in parts] == [(0,0,268435456),(1,268435456,268435456),(2,536870912,119491890)], 'reported complete contiguous ranges')
check(worker['partition']['total_bytes'] == 656362802 and worker['partition']['concatenated_sha256'] == metadata['digest'][7:], 'reported full partition SHA')
check(final['private_partition_readback'] == final['public_partition_readback'] == {'bytes':656362802,'exact_contiguous_partition':True,'sha256':metadata['digest'][7:]}, 'private/public recorded full readbacks agree; payloads not yet locally read')
check(final['closed_echild'] is True and final['status'] == 'FULL_ZIP_CUSTODY_HOLD' and final['complete_local_multipart_readback'] is False and final['complete_original_ZIP_member_read_verified'] is False, 'historical failed recovery kept HOLD')
for key,name in [('guardian','guard/guardian.json'),('setup','setup.json'),('worker','recovery-terminal.json')]:
    check(same_pin(final[key],raw_control(name)), 'final binds actual ' + name)
check(len(final['small_controls']) == 11, 'all eleven fixed current controls retained')
for row in final['small_controls']:
    raw = raw_control(row['name'])
    check(same_pin(row['original'],raw) and same_pin(row['retained'],raw), 'original-retained actual bytes ' + row['name'])
check(final['diagnostic_capture'] == small, 'full diagnostic refusal receipt joined')
check(small['status'] == 'HOLD' and small['complete'] is False and small['files'] == [], 'zero original diagnostic bodies published')
check(len(small['errors']) == 463 and all(r['type'] == 'Refusal' and r['refusal'] == 'only a fixed private slice may be relocated' for r in small['errors']), 'all 460 selected bodies plus three metadata files refused by slice-only relocation')
check(small['selected_count'] == 460 and small['selected_bytes'] == 3012789 and small['complete_members'] == 22385 and small['complete_expanded_bytes'] == 1987786640, 'reported original inventory facts retained without claiming local payload read')
check(len(small['missing_expected']) == 5, 'five expected missing outputs explicitly retained')
check(final['errors'] == [{'safe_refusal':'fixed diagnostic originals are incomplete; preserve HOLD','stage':'STEP42_DIAGNOSTIC_CAPTURE','type':'Refusal'}], 'top-level actual diagnostic refusal')
controller = (INPUTS / 'control/controller.py').read_text()
check("actual = relocate_slice(folder / name, destination / name, record)" in controller and "source.name.startswith('part-')" in controller and "and source.parent.name == 'parts', 'only a fixed private slice may be relocated'" in controller, 'exact code cause binds actual rejection')
report = {
    'schema':'hia.v92.failed-recovery-small-independent-audit.v1',
    'status':'PASS_READBACK_OF_ACTUAL_RECOVERY_HOLD_NOT_CUSTODY_OR_PRODUCT_PASS',
    'checks':checks,'check_count':len(checks),'errors':[],
    'recovery_run':43338002642,'recovery_job':131599001028,
    'small_artifact':{'id':13998357240,**pin(zip_raw)},
    'actual_members':{name:pin(raw) for name,raw in raws.items()},
    'raw_member_count':13,'raw_member_bytes':sum(map(len,raws.values())),
    'natural_receiver_owner_ns':owner_ns,'worker_elapsed_ns':worker['elapsed_ns'],
    'actual_failure':{'source':'controller.py','callee':'relocate_slice','call_line':755,'path_guard_lines':[539,540,541],'failed_diagnostic_file_count':463,'retained_diagnostic_bodies':0,'guard':'only parts/part-*.bin to slice.bin or unverified-range.bin','caller_incompatible_namespace':'diagnostics/{INDEX.json,DIRECTORY.jsonl,FULL-INVENTORY.jsonl,member-*.bin}'},
    'static_review_miss':'The author reviewed unchanged relocate_slice and new diagnostic path selection independently but missed their incompatible path contract at the new call site. This omission is now confirmed by the actual 463 original refusals, not a hypothetical failure.',
    'reported_original_member_count':22385,'reported_original_expanded_bytes':1987786640,
    'reported_selected_count':460,'reported_selected_bytes':3012789,
    'reported_missing_expected':small['missing_expected'],
    'original_v92_step42_owner_or_progress_bodies_locally_obtained':False,
    'three_large_part_GETs':0,'original_payload_complete_local_read':False,
    'historical_recovery_HOLD_retained':True,'original_native_failure_reclassified':False,
    'next_step':'A separate frozen local consumer may read the existing three complete official containers, validate each and expose a seekable stored-slice concatenation; no CI or receiver rerun.'}
with (ROOT/'SMALL-INDEPENDENT-AUDIT.json').open('x') as out:
    out.write(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps({'status':report['status'],'checks':len(checks),'raw_members':13,'raw_bytes':report['raw_member_bytes'],'owner_ns':owner_ns,'worker_ns':worker['elapsed_ns']}))
