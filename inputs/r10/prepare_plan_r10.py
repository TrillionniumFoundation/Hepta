"""Normalize the reviewed R10 overlay without altering its frozen source."""
import ast
import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import zlib
import yaml

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent / 'v91-union-r9'
WORKFLOW = '.github/workflows/hia-core.yml'

def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode()

def identity(raw):
    return {'bytes': len(raw), 'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'sha256': hashlib.sha256(raw).hexdigest(), 'mode': '100644'}

def read_exact(root, manifest):
    out = {}
    for name, pin in manifest.items():
        path = root / name
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o644, name
        raw = path.read_bytes()
        assert identity(raw) == pin, name
        out[name] = raw
    return out

def tree(files):
    dirs = {'': []}
    for path, raw in files.items():
        parts = path.split('/')
        name = parts.pop()
        parent = '/'.join(parts)
        dirs.setdefault(parent, []).append((name, '100644', identity(raw)['git_blob']))
        while parts:
            parts.pop()
            dirs.setdefault('/'.join(parts), [])
    hashes = {}
    for path in sorted(dirs, key=lambda p: (p.count('/'), len(p)), reverse=True):
        entries = dirs[path]
        entries.sort(key=lambda e: (e[0] + ('/' if e[1] == '40000' else '')).encode())
        raw = b''.join(mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(sha) for name, mode, sha in entries)
        value = hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        hashes[path] = value
        if path:
            parts = path.split('/')
            name = parts.pop()
            dirs['/'.join(parts)].append((name, '40000', value))
    return hashes['']

def main():
    capsule_raw = (ROOT/'handoff/SOURCE-PACKET.zlib.json').read_bytes()
    assert identity(capsule_raw)['git_blob'] == '6cd814d1134d1031f250002d61240a976917a77f'
    capsule = json.loads(capsule_raw)
    decoded = zlib.decompress(base64.b64decode(capsule['payload'], validate=True))
    assert len(decoded) == capsule['raw_bytes']
    assert identity(decoded)['git_blob'] == capsule['raw_git_blob']
    assert identity(decoded)['sha256'] == capsule['raw_sha256']
    packet = json.loads(decoded)
    integration_raw = (ROOT/'INTEGRATION.json').read_bytes()
    assert identity(integration_raw)['git_blob'] == 'bf56e6e0ea636aaf0f1e7cfd07fa3dab7889b928'
    integration = json.loads(integration_raw)
    cache_raw = (ROOT/'SOURCE-CACHE-READBACK.json').read_bytes()
    assert identity(cache_raw)['git_blob'] == '8264bfd322ebc933c6937cd62255b3c4bad6e9ce'
    baseline = json.loads((ROOT/'BASELINE-MANIFEST.json').read_bytes())
    final = json.loads((ROOT/'SOURCE-MANIFEST.json').read_bytes())
    assert len(baseline) == 3074 and len(final) == 3083
    before = read_exact(BASE/'source', baseline)
    after = read_exact(ROOT/'source', final)
    actual = {p.relative_to(ROOT/'source').as_posix() for p in (ROOT/'source').rglob('*') if not p.is_dir()}
    assert actual == set(after)
    assert tree(before) == '4c3fa168a0bc4763ce1bb5bc608ace58c24c46ce'
    assert tree(after) == 'dc4babaa67f99d437ec602a073af3897d2f9aa37'
    changed = sorted(name for name in after if before.get(name) != after[name])
    new = sorted(set(after) - set(before))
    assert not set(before) - set(after)
    assert len(changed) == 24 and len(new) == 9
    assert set(changed) == set(integration['changes']) == {row['path'] for row in packet['files']}
    for row in packet['files']:
        name = row['path']
        if row['before'] is None:
            assert name not in before
        else:
            assert row['before']['text'].encode() == before[name], name
            assert {k:v for k,v in row['before'].items() if k != 'text'} == identity(before[name]), name
        assert row['after']['text'].encode() == after[name], name
        assert {k:v for k,v in row['after'].items() if k != 'text'} == identity(after[name]), name
        assert integration['changes'][name] == {'before':identity(before[name]) if name in before else None,'after':identity(after[name])}
    old_plan_raw = (BASE/'harness/inputs/MATERIALIZATION-R9.json').read_bytes()
    assert identity(old_plan_raw)['git_blob'] == 'bf8ef4c018f75f6ba2ca413988440c7bee223feb'
    plan = json.loads(old_plan_raw)
    authors = {row['path']:row for row in json.loads((BASE/'harness/inputs/AUTHORING-R9.json').read_bytes())}
    assert len(authors) == 421 and len(plan['packets']) == 56 and len(plan['allowed_overrides']) == 150
    assert not set(changed) & {r['path'] for r in plan['exact_retained'] + plan['regeneration_seeds']}
    for name in set(changed) & set(authors):
        assert authors[name]['sha'] == identity(before[name])['git_blob'], name
    workflow = after[WORKFLOW].decode()
    source, native = workflow.split('  native:\n',1)
    assert native == before[WORKFLOW].decode().split('  native:\n',1)[1]
    assert hashlib.sha256(native.encode()).hexdigest() == integration['native_section_sha256']
    jobs = yaml.safe_load(workflow)['jobs']
    assert len(jobs['native']['steps']) == 120
    generators = re.search(r'for component in (.*?)\s*;?\s*do\n', source).group(1).rstrip(';').split()
    assert generators == plan['generators'] + integration['new_generators']
    assert generators == plan['source_registration']['generators'] + integration['new_generators']
    assert len(generators) == 121
    test_run = next(row['run'] for row in jobs['source']['steps'] if row.get('name') == 'Core source and independent reference controls')
    body = ast.parse('\n'.join(test_run.splitlines()[1:-1])+'\n')
    assignment = next(n for n in body.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='names' for t in n.targets))
    selectors = list(ast.literal_eval(assignment.value))
    assert selectors == plan['source_registration']['selectors'] + [integration['new_source_selector']]
    assert len(selectors) == 228
    fragment = '  source:\n' + workflow.split('  source:\n',1)[1].split('  native:\n',1)[0]
    assert fragment.encode() == (ROOT/'SOURCE-R10-FRAGMENT.yml').read_bytes()
    for name in ('input-blobs','harness'):
        assert not (ROOT/name).exists()
        shutil.copytree(BASE/name, ROOT/name, ignore=shutil.ignore_patterns('__pycache__'))
    chunks, current = [], []
    for name in changed:
        row = {'path':name,'before':identity(before[name]) if name in before else None,
               'after':{**identity(after[name]),'text':after[name].decode()}}
        if current and len(encode({'files':current+[row]})) > 640000:
            chunks.append(current)
            current = [row]
        else:
            current.append(row)
    if current:
        chunks.append(current)
    new_packets = []
    for index, rows in enumerate(chunks):
        label = 'linux-cli-process-integration-r10-' + str(index).zfill(2)
        obj = {'schema':'hia.reviewed-joint-source-overlay.v1','label':label,
            'scope':'EXACT_NATIVE_CLI_PROFILE_AND_REGISTRATION_PENDING_FORMAL_SOURCE',
            'component_integration_packet':identity(capsule_raw),'component_integration_report':identity(integration_raw),
            'base_plan':identity(old_plan_raw),'original_native_steps_byte_identical':120,
            'old_source_ids_retained_as_ordered_projection':True,
            'component_limitations':['Only capabilities and catalog are implemented native business actions.',
              'The other thirteen valid file actions refuse before file or business effects.',
              'The new IO policy is not CPython closed-fd/startup exception equivalence.',
              'No matching-current-source CLI cold qualification, TTY, other locale, or Python 3.14 claim is inherited.'],
            'whole_native':False,'default_changed':False,'files':rows}
        raw = encode(obj)
        assert len(raw) <= 650000, (label,len(raw))
        pin = {'label':label,'blob':identity(raw)['git_blob'],'bytes':len(raw),
               'sha256':identity(raw)['sha256'],'layout':'array-after','files':len(rows)}
        (ROOT/'input-blobs'/(pin['blob']+'.blob')).write_bytes(raw)
        plan['packets'].append(pin)
        new_packets.append(pin)
        for row in rows:
            name, value = row['path'], row['after']
            if name in authors:
                previous = authors[name]
                plan['allowed_overrides'].append({'path':name,'from_packet':previous['packet'],'to_packet':label,
                    'from':previous['sha'],'to':value['git_blob']})
            authors[name] = {'path':name,'text':value['text'],'sha':value['git_blob'],'bytes':value['bytes'],
                'mode':value['mode'],'packet':label,'packet_blob':pin['blob']}
    assert len(authors) == 430 and len(plan['allowed_overrides']) == 165
    plan['expected_authored_files'] = 430
    plan['generators'] = generators
    registration = plan['source_registration']
    registration['prior_after_fragment_r9'] = deepcopy(registration['after_fragment'])
    registration['after_fragment'] = {**identity(fragment.encode()),'blob':identity(fragment.encode())['git_blob']}
    registration['generators'] = generators
    registration['selectors'] = selectors
    registration['extra_selectors'].append(integration['new_source_selector'])
    registration['authored_counts'] = {'generators':121,'owner_loop_generators':121,'selectors':228,
        'actual_loaded_test_ids':None,'actual_executed_tests':None}
    registration['required_support_actions'] = [s.replace('all118 owner','all121 owner').replace('actual227 selectors','actual228 selectors') for s in registration['required_support_actions']]
    registration['notes'].append('R10 preserves all 1306 prior Source IDs as an ordered projection, adds twelve CLI process Source methods and one suffix method, three owner generators and three exact ENTRY resources. All 120 prior Native steps and all original budgets remain byte-identical. Component development observations are not matching-current-source qualification.')
    plan['source_contract']['declared_paths'] = 1307
    plan['r10_integration'] = {'integration_packet':identity(capsule_raw),'integration_report':identity(integration_raw),
        'cache_exclusion_exact_path_readback':identity(cache_raw),'source_paths_changed':24,'new_source_paths':9,
        'source_files':3083,'source_tests_expected':1319,'prior_source_ids':1306,
        'prior_source_ids_required_as_ordered_projection':True,'new_component_source_ids':integration['new_component_declared_ids'],
        'new_suffix_id':integration['new_suffix_test'],'source_contract_paths':1307,'entry_resources':11,
        'all_resource_total':200,'native_resources':90,'semantic_core_roles':54,'mechanism_roles':52,
        'native_steps':120,'all_prior_native_steps_unchanged':True,'new_native_qualification_added':False,
        'default_changed':False,'matching_current_source_cold':False,'whole_native':False}
    driver = (ROOT/'harness/tools/materialize_candidate_r14.py').read_bytes()
    assert identity(driver)['git_blob'] == 'cfe319279641b124bcd724437857686f36d1aa07'
    inputs = ROOT/'harness/inputs'
    (inputs/'AUTHORING-R10.json').write_bytes(encode([authors[name] for name in sorted(authors)]))
    (inputs/'SOURCE-R10-FRAGMENT.yml').write_text(fragment)
    plan_raw = encode(plan)
    (inputs/'MATERIALIZATION-R10.json').write_bytes(plan_raw)
    report = {'schema':'hia.r10.plan-preparation.v1','status':'PREPARED_NOT_QUALIFIED','plan':identity(plan_raw),
        'driver':identity(driver),'packets':new_packets,'total_packets':len(plan['packets']),'authored_files':430,
        'explicit_overrides':165,'source_files':3083,'source_contract':1307,'generators':121,'selectors':228,
        'tests_expected':1319,'changed_paths':changed,'new_files':9,'all_old_source_ids_required_as_ordered_projection':True,
        'all120_native_steps_byte_identical':True,'source_bytes_changed_by_plan_preparation':False,
        'product_tests_executed':0,'matching_current_source_cold':False,'whole_native':False,'default_changed':False}
    (ROOT/'PREPARATION.json').write_bytes(encode(report))
    local = (BASE/'run_local_generation_r9.py').read_text()
    replacements = [('v91-union-r9','v92-union-r10'),
        ('bf8ef4c018f75f6ba2ca413988440c7bee223feb',identity(plan_raw)['git_blob']),
        ('MATERIALIZATION-R9.json','MATERIALIZATION-R10.json'),('AUTHORING-R9.json','AUTHORING-R10.json'),
        ('all_56_source_packets_checked','all_'+str(len(plan['packets']))+'_source_packets_checked'),
        ('len(authored) == 421','len(authored) == 430')]
    for old,new_value in replacements:
        assert local.count(old) == 1,(old,local.count(old))
        local = local.replace(old,new_value)
    (ROOT/'run_local_generation_r10.py').write_text(local)
    assert read_exact(ROOT/'source',final) == after
    print(json.dumps(report,sort_keys=True),flush=True)

if __name__ == '__main__':
    main()
