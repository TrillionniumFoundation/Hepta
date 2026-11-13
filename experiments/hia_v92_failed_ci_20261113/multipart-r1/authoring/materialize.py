"""Create one new evidence-only control namespace from immutable references."""
from pathlib import Path
from hashlib import sha256, sha1
import ast
import difflib
import json

ROOT = Path(__file__).resolve().parents[1]
REF = ROOT / 'reference'
CONTROL = ROOT / 'control'
SOURCE = Path('/tmp/hia-core-integer-native-integration-v92-r1-20261112-e26e/source')
PREFIX = 'experiments/hia_v92_failed_ci_20261113/multipart-r1'
BRANCH = 'codex/hia-v92-failed-ci-original-parts-r1-20261113-e26e'
PRIVATE = 'hia-v92-failed-ci-parts-r1'
PUBLIC = 'hia-v92-failed-ci-parts-public-r1'
SCHEMA = 'hia.actions.v92-ci-failed-original-parts'

def wire(x):
    return (json.dumps(x, indent=2, sort_keys=True) + '\n').encode()

def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

def save(path, raw):
    if path.exists():
        assert path.read_bytes() == raw, str(path)
        return
    with path.open('xb') as f:
        f.write(raw)
    assert path.read_bytes() == raw

def one(text, old, new):
    assert text.count(old) == 1, (old[:120], text.count(old))
    return text.replace(old, new)

def common(text):
    text = text.replace('hia.actions.v88-full-original-parts', SCHEMA)
    text = text.replace('hia.v88-original', 'hia.v92-original')
    text = text.replace('312 << 20', '256 << 20')
    text = text.replace("'process_owner_impl.py', 'original_receiver.py'", "'process_owner_impl.py', 'original_receiver.py', 'diagnostics.py'")
    text = text.replace("'original_receiver.py', 'process_owner_impl.py'", "'original_receiver.py', 'process_owner_impl.py', 'diagnostics.py'")
    return text

worker = common((REF / 'worker.py').read_text())
worker = one(worker, 'Read and partition one frozen v88 historical artifact; never execute product payloads.',
             'Read one exact failed v92 CI artifact, every ZIP body and fixed diagnostic originals; never execute payloads.')
worker = one(worker, "        stage = 'FULL_ORIGINAL_AFTER'", """        stage = 'FULL_ZIP_AND_FIXED_DIAGNOSTICS'
        diagnostic_source = root / 'control/diagnostics.py'
        diagnostic_pin = policy['control_files']['diagnostics.py']
        diagnostic_raw = read(diagnostic_source, 1 << 20, diagnostic_pin['sha256'])
        require(len(diagnostic_raw) == diagnostic_pin['bytes'], 'fixed diagnostic source size differs')
        spec = importlib.util.spec_from_file_location('v92_full_zip_diagnostics', diagnostic_source)
        diagnostics = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(diagnostics)
        report['diagnostics'] = diagnostics.inspect_zip(path, pin, root, deadline, helper, policy['diagnostics'])
        report['original_ZIP_members_decompressed'] = True
        helper.checkpoint(report)
        stage = 'FULL_ORIGINAL_AFTER'""")
worker = one(worker, "        helper.checkpoint(report)\n        print(json.dumps({'status': report['status'], 'parts': len(parts),", "        helper.checkpoint(report)\n        deadline_check(deadline)\n        print(json.dumps({'status': report['status'], 'parts': len(parts),")
save(CONTROL / 'worker.py', worker.encode())

controller = common((REF / 'controller.py').read_text())
controller = one(controller, 'Deliver one to ten sealed contiguous parts of one historical ZIP; execute no product code.',
                 'Deliver three exact failed v92 CI ZIP ranges and fixed step42 originals; execute no product code.')
controller = one(controller, "            and report.get('original_ZIP_members_decompressed') is False", "            and report.get('original_ZIP_members_decompressed') is True\n            and type(report.get('elapsed_ns')) is int and 0 <= report['elapsed_ns'] <= 720 * 1000000000")
controller = one(controller, 'def closed_storage_observation(root, public, policy):',
                 (ROOT / 'authoring/extend_controller.py.txt').read_text() + '\n\ndef closed_storage_observation(root, public, policy):')
controller = one(controller, "    public_files = set()", """    public_files = set()
    small = public / 'small'
    small_controls = {small / 'controls' / name.replace('/', '--') for name in diagnostic_names}
    diagnostic_metadata = {'INDEX.json', 'DIRECTORY.jsonl', 'FULL-INVENTORY.jsonl'}
    def diagnostic_category(child):
        if child.parent in (root / 'diagnostics', small / 'originals'):
            if re.fullmatch(r'member-[0-9]{5}\\.bin', child.name):
                return 'step42_original'
            if child.name in diagnostic_metadata:
                return 'step42_metadata'
        if child in small_controls or child == small / 'SMALL-READBACK.json':
            return 'small_controls'
        return None""")
controller = one(controller, "                                    ('control', 'guard', 'original', 'parts', 'api')}", "                                    ('control', 'guard', 'original', 'parts', 'api', 'diagnostics')}\n    allowed_dirs |= {small, small / 'originals', small / 'controls'}")
controller = controller.replace('<= 512', '<= 4096')
controller = one(controller, "                                'public_diagnostic' if child in public_files else None)", "                                'public_diagnostic' if child in public_files else diagnostic_category(child))")
controller = one(controller, "             for key in ('payload', 'private_metadata', 'public_diagnostic')}", "             for key in ('payload', 'private_metadata', 'public_diagnostic',\n                         'step42_original', 'step42_metadata', 'small_controls')}")
controller = one(controller, "            and sizes['public_diagnostic'] <= len(parts) * MAX_DIAGNOSTIC_BYTES,", "            and sizes['public_diagnostic'] <= len(parts) * MAX_DIAGNOSTIC_BYTES\n            and sizes['step42_original'] <= 128 << 20\n            and sizes['step42_metadata'] <= 64 << 20\n            and sizes['small_controls'] <= 6 << 20,")
controller = one(controller, "    final_documents = len(parts) * (3 << 20)", "    final_documents = (len(parts) + 1) * (3 << 20)")
controller = one(controller, "    remaining_inode_reserve = 1024 + 2 * len(parts)", "    remaining_inode_reserve = 1024 + 2 * (len(parts) + 1)")
controller = one(controller, "        (directory / 'controls').mkdir(mode=0o700)\n    result =", "        (directory / 'controls').mkdir(mode=0o700)\n    (public / 'small').mkdir(mode=0o700)\n    (public / 'small/originals').mkdir(mode=0o700)\n    (public / 'small/controls').mkdir(mode=0o700)\n    result =")
controller = one(controller, "    storage_observed = False\n    copied = []", "    storage_observed = False\n    diagnostics_complete = False\n    report = None\n    copied = []")
controller = one(controller, "        fixed = ['context.json', 'setup.json', 'guard/request.json', 'guard/guardian.json',", """        try:
            diagnostic_capture = retain_diagnostics(root, public, policy, report)
            result['diagnostic_capture'] = diagnostic_capture
            diagnostics_complete = diagnostic_capture['complete']
            result['original_ZIP_members_decompressed'] = diagnostics_complete
            require(diagnostics_complete, 'fixed diagnostic originals are incomplete; preserve HOLD')
        except BaseException as exc:
            error('STEP42_DIAGNOSTIC_CAPTURE', exc)
        fixed = ['context.json', 'setup.json', 'guard/request.json', 'guard/guardian.json',""")
controller = one(controller, "        result['diagnostic_bytes_per_part'] = diagnostic_bytes", """        small_control_bytes = 0
        result['small_controls'] = []
        for name in fixed:
            try:
                source = root / name
                actual = file_record(source, 8 << 20)
                small_control_bytes += actual['bytes']
                require(small_control_bytes <= MAX_DIAGNOSTIC_BYTES, 'whole small control bound exceeded')
                copied_control = copy_original(source, public / 'small/controls' / name.replace('/', '--'), actual)
                result['small_controls'].append({'name': name, 'original': actual, 'retained': copied_control})
            except BaseException as exc:
                captures_complete = False
                error('SMALL_CONTROL_' + name, exc)
        result['small_control_bytes'] = small_control_bytes
        result['diagnostic_bytes_per_part'] = diagnostic_bytes""")
controller = one(controller, "    complete = (closed and natural and accepted and captures_complete and storage_observed", "    complete = (closed and natural and accepted and captures_complete and storage_observed and diagnostics_complete")
controller = one(controller, "    sync_dir(public)\n    print(json.dumps({'status': result['status'], 'parts': len(parts),", """    create(public / 'small/FINAL.json', final_raw)
    require(read(public / 'small/FINAL.json', 2 << 20) == final_raw,
            'identical small FINAL complete readback differs')
    small_records = []
    for path in sorted((public / 'small').rglob('*')):
        entry = path.lstat()
        require(not stat.S_ISLNK(entry.st_mode), 'small public symlink refused')
        if stat.S_ISDIR(entry.st_mode):
            require(entry.st_uid == os.geteuid(), 'small public directory ownership differs')
        else:
            small_records.append(file_record(path, 64 << 20))
    require(len(small_records) <= 1040 and sum(x['bytes'] for x in small_records) <= 224 << 20,
            'small complete public artifact exceeds its fixed bound')
    for folder in ('originals', 'controls'):
        sync_dir(public / 'small' / folder)
    sync_dir(public / 'small')
    sync_dir(public)
    print(json.dumps({'status': result['status'], 'parts': len(parts),""")
save(CONTROL / 'controller.py', controller.encode())

old_policy = json.loads((REF / 'policy.json').read_bytes())
policy = dict(old_policy)
artifact = json.loads((REF / 'ARTIFACT-13994959899.metadata.json').read_bytes())
policy['schema'] = SCHEMA + '-policy.v1'
policy['artifact'] = {'bytes': 656362802, 'checkout_commit': 'd96a5ae4783a123013351a511be9fc1a6d8f1c2c',
    'checkout_tree': '596ab07e8813e4811a8dca51800cd51eb397aeb2', 'event': 'push',
    'id': 13994959899, 'job_id': 131554853309, 'run_attempt': 1, 'run_id': 43324913647,
    'sha256': 'f9d15287c668bd8d84f5d564b4829ba40813c9372de322d2f33bc65ecf40b105',
    'workflow_terminal': 'failure'}
assert artifact['id'] == policy['artifact']['id'] and artifact['size_in_bytes'] == policy['artifact']['bytes']
assert artifact['digest'] == 'sha256:' + policy['artifact']['sha256']
assert artifact['workflow_run']['id'] == policy['artifact']['run_id'] and artifact['workflow_run']['head_sha'] == policy['artifact']['checkout_commit']
support_raw = (SOURCE / 'docs/HIA_SELFHOST_CORE_SUPPORT.json').read_bytes()
support = json.loads(support_raw)
files = dict(support['source_identity']['files'])
contract_sha = sha256((SOURCE / 'tools/hia_selfhost_contract.py').read_bytes()).hexdigest()
files['tools/hia_selfhost_contract.py'] = contract_sha
manifest_raw = json.dumps(files, sort_keys=True, separators=(',', ':')).encode()
save(REF / 'cold-source-manifest.canonical.json', manifest_raw)
save(REF / 'HIA_SELFHOST_CORE_SUPPORT.json', support_raw)
policy['source'] = {'cold_source_count': len(files), 'contract_sha256': contract_sha,
    'head': policy['artifact']['checkout_commit'], 'tree': policy['artifact']['checkout_tree'],
    'profile': support['profile'], 'source_manifest_canonical_sha256': sha256(manifest_raw).hexdigest()}
policy.pop('actual_full32_inputs')
policy['source_scope'] = 'The exact failed standard CI carrier and its existing source provenance only; no new product source or qualification execution.'
policy['artifact_carrier_scope'] = 'Current exact d96 failed standard CI artifact; source129 PASS and former native results are not upgraded by this read-only receiver.'
policy['control_prefix'] = PREFIX
policy['work_root_name'] = PRIVATE
policy['public_root_name'] = PUBLIC
policy['trigger_branch'] = BRANCH
policy['limits']['part_bytes'] = 256 << 20
policy['parts'] = []
offset = 0
while offset < policy['artifact']['bytes']:
    count = min(256 << 20, policy['artifact']['bytes'] - offset)
    policy['parts'].append({'ordinal': len(policy['parts']), 'offset': offset,
                            'bytes': count, 'name': 'part-%02d.bin' % len(policy['parts'])})
    offset += count
assert len(policy['parts']) == 3 and offset == policy['artifact']['bytes']
module = ast.parse((CONTROL / 'diagnostics.py').read_text())
policy['diagnostics'] = ast.literal_eval(next(node.value for node in module.body
     if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'LIMITS' for t in node.targets))) if False else {
     'maximum_members':65536,'maximum_expanded_bytes':8 << 30,'maximum_selected_files':1024,
     'maximum_selected_file_bytes':64 << 20,'maximum_selected_bytes':128 << 20,
     'maximum_metadata_bytes':64 << 20,'maximum_public_small_bytes':224 << 20}
policy['whole_ZIP_members_decompressed'] = True
policy['capacity_scope'] = 'Exact656362802 original + one complete raw partition; selected step42 originals <=128MiB and full ZIP metadata <=64MiB are relocated after bound ECHILD without a third copy. Three parts <=256MiB raw/320MiB public; small public <=224MiB. Original8GiB/100000 preflight and remaining512MiB filesystem reserve remain.'
policy['downstream_acceptance'] = 'Require unique current receiver run/attempt/head/control/policy and natural900/3; all3 official parts with identical FINAL and exact PART ranges, plus small originals/full directory and inventory. Reconstruct external656362802/SHA, never derive qualification or timeout from receipt status. Missing original reports remain explicit.'
policy['control_files'] = {name:pin((CONTROL / name).read_bytes()) for name in
    ['controller.py','worker.py','diagnostics.py','guardian.py','original_receiver.py','process_owner_impl.py']}
policy['unchanged_original_workflows'] = {name:pin(((SOURCE / name) if (SOURCE / name).exists() else (REF / Path(name).name)).read_bytes()) for name in old_policy['unchanged_original_workflows']}
save(CONTROL / 'policy.json', wire(policy))

template = (REF / 'workflow-template.yml').read_text()
for old,new in [('HIA v89 complete original ZIP in bounded artifacts','HIA v92 failed CI original ranges and step42 diagnostics'),
 ('codex/hia-v89-full32-failed-original-parts-run-r1-20261112-e26e',BRANCH),
 ('experiments/hia_v89_full32_failed_custody_20261112/multipart-r1',PREFIX),
 ('hia-v89-full32-failed-parts-public-r1',PUBLIC),('hia-v89-full32-failed-parts-r1',PRIVATE)]:template=template.replace(old,new)
small_upload="""      - name: Preserve available step42 original diagnostics and current closed owner first
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: hia-v92-failed-ci-step42-originals-${{ github.run_id }}-1
          path: '${{ runner.temp }}/hia-v92-failed-ci-parts-public-r1/small/'
          if-no-files-found: error
          include-hidden-files: false
          compression-level: 0
          retention-days: 14
          overwrite: false
"""
template=one(template,'UPLOAD_STEPS_PENDING_ACTUAL_COUNT',small_upload+'UPLOAD_STEPS_PENDING_ACTUAL_COUNT')
save(CONTROL / 'workflow-template.yml',template.encode())
renderer = common((REF / 'render_workflow.py').read_text())
for old,new in [('experiments/hia_v89_full32_failed_custody_20261112/multipart-r1',PREFIX),
 ('hia-v89-full32-failed-original-part-', 'hia-v92-failed-ci-original-part-'),
 ('hia-v89-full32-failed-parts-public-r1',PUBLIC)]:renderer=renderer.replace(old,new)
save(CONTROL / 'render_workflow.py',renderer.encode())
for name in ['worker.py','controller.py','render_workflow.py','workflow-template.yml']:
    raw=(CONTROL/name).read_bytes()
    if name.endswith('.py'):ast.parse(raw)
    diff=''.join(difflib.unified_diff((REF/name).read_text().splitlines(True),raw.decode().splitlines(True),fromfile='reviewed-original/'+name,tofile='new-v92/'+name))
    save(ROOT/'authoring'/(name+'.diff'),diff.encode())
ast.parse((CONTROL/'diagnostics.py').read_bytes())
print(json.dumps({'status':'STATIC_DRAFT_CREATED_NO_OWNER_NETWORK_OR_PRODUCT_EXECUTED',
                  'parts':policy['parts'],'controls':policy['control_files'],'policy':pin((CONTROL/'policy.json').read_bytes())},sort_keys=True))
