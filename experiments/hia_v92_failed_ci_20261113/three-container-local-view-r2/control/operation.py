"""Shared physical read algorithms; no import of original project modules."""
from pathlib import Path
import hashlib
import os
import stat
import v92_view_common as c
io, require = c.io, c.require
fmt = c.module('v92_view_format', c.ROOT / 'control/view_format.py')

def prior_originals(policy, deadline):
    final, final_pin, final_raw = c.document(c.ROOT / 'inputs/FINAL.json', deadline=deadline)
    request, _, _ = c.document(c.ROOT / 'inputs/controls--guard--request.json', deadline=deadline)
    guard, guard_pin, _ = c.document(c.ROOT / 'inputs/controls--guard--guardian.json', deadline=deadline)
    worker, worker_pin, _ = c.document(c.ROOT / 'inputs/controls--recovery-terminal.json', deadline=deadline)
    context, _, _ = c.document(c.ROOT / 'inputs/controls--context.json', deadline=deadline)
    life = guard['lifecycle']; cleanup = life['cleanup']
    require(final['status'] == 'FULL_ZIP_CUSTODY_HOLD' and final['closed_echild'] is True
            and final['artifact'] == policy['original_artifact'] and final['context'] == context
            and context['run_id'] == policy['receiver']['run_id'] and context['run_attempt'] == 1
            and context['actual_workflow_commit'] == policy['receiver']['workflow_commit']
            and context['actual_control_checkout'] == policy['receiver']['control_commit']
            and context['policy_sha256'] == policy['receiver']['policy_sha256'], 'prior actual context/FINAL differs')
    require(guard['schema'] == 'hepta.hia.external-qualification-guardian.v1'
            and guard['command'] == request['command'] and guard['cwd'] == request['cwd']
            and request['controller_seconds'] == guard['external_controller_seconds'] == 900
            and guard['lifecycle_implementation_sha256'] == policy['lifecycle_implementation_sha256']
            and guard['source_identities_before'] == guard['source_identities_after'] == request['source_identities']
            and guard['input_identity_preserved'] is True and guard['qualification'] is None
            and life['qualification_seconds'] == 900 and life['cleanup_seconds'] == 3
            and life['subreaper_enabled'] is True and life['event_overflow'] is False
            and life['returncode'] == 0 and life['status'] == 'OWNED_PROCESS_COMPLETED'
            and life['timed_out'] is False and life['exit_observed_before_deadline'] is True
            and life.get('owner_error') is None and life['interrupted_signals'] == []
            and cleanup['complete'] is True and cleanup['observed_echild'] is True
            and cleanup['leader_reaped'] is True and cleanup['remaining_direct_children'] == []
            and cleanup['deadline_exceeded'] is False and cleanup['errors'] == [], 'prior actual read owner is not bound closed/natural')
    require(all(final['source_inputs_final'][p]['sha256'] == digest for p, digest in request['source_identities'].items()),
            'prior complete source/input identities differ')
    for key, pin in (('guardian', guard_pin), ('worker', worker_pin)):
        require(final[key]['bytes'] == pin['bytes'] and final[key]['sha256'] == pin['sha256'],
                'prior final original control pin differs')
    require(worker['status'] == 'SEALED_PARTS_PENDING_NATURAL_GUARDIAN'
            and worker['artifact'] == policy['original_artifact'], 'prior worker source artifact differs')
    raw_controls = {}
    for row in final['captured_controls']:
        name = 'controls/' + row['name'].replace('/', '--')
        pin, raw = c.seal(c.ROOT / 'inputs' / name.replace('/', '--'), 2 << 20, body=True, deadline=deadline)
        require(name not in raw_controls and pin['bytes'] == row['original']['bytes']
                and pin['sha256'] == row['original']['sha256'] and len(row['copies']) == 3
                and all(p['bytes'] == pin['bytes'] and p['sha256'] == pin['sha256'] for p in row['copies']),
                'prior fixed original/copy SHA differs')
        raw_controls[name] = raw
    require(len(raw_controls) == 11 and len(final['parts']) == 3, 'prior complete control/range denominator differs')
    for part, old in zip(policy['parts'], final['parts']):
        require(all(part[k] == old[k] for k in ('ordinal', 'name', 'offset', 'bytes'))
                and old['source']['sha256'] == old['retained']['sha256'] == part['sha256'], 'prior whole part pin differs')
    return final_raw, raw_controls

def volume_roots(policy):
    return {key: Path(policy['volumes'][key]['root']) for key in ('tmp', 'workspace')}

def part_directory(policy, item):
    return Path(policy['volumes'][item['volume']]['root']) / ('part-%02d' % item['ordinal'])

def read_containers(policy, roots, deadline):
    final_raw, controls = prior_originals(policy, deadline)
    rows, specs = [], []
    for item in policy['parts']:
        path = part_directory(policy, item) / 'official-part.original.zip'
        row = fmt.outer_container(path, item, final_raw, controls, policy, deadline); rows.append(row)
        specs.append({'ordinal': item['ordinal'], 'path': str(path), 'offset': item['offset'], 'bytes': item['bytes'],
                      'data_offset': row['range']['physical_data_offset'], 'identity': row['container']['identity']})
    return rows, specs

def read_original(policy, roots, budgets, specs, deadline, *, verify=False):
    expected = {k: policy['original_artifact'][k] for k in ('bytes', 'sha256')}
    with fmt.StoredView(specs, expected['bytes'], deadline) as view:
        before = view.whole_hash(); require(before == expected, 'complete concatenated original bytes/SHA differ')
        result = fmt.inspect_original(view, policy, roots, budgets, deadline, verify=verify)
        after = view.whole_hash(); require(before == after, 'whole view changed during all-body read')
    require(result['members'] == policy['observed_original_denominator']['members']
            and result['expanded_bytes'] == policy['observed_original_denominator']['expanded_bytes']
            and len(result['selected']) == policy['observed_original_denominator']['selected_files']
            and result['selected_bytes'] == policy['observed_original_denominator']['selected_bytes'],
            'independently observed original population differs from sealed prior report')
    return {'whole_before': before, 'whole_after': after, 'index': result}

def observed_outputs(policy, roots, deadline):
    """Only after bound ECHILD. Preserve complete partial originals on failure."""
    rows, totals = [], {}
    for volume, root in roots.items():
        used = {key: 0 for key in ('container', 'selected', 'metadata', 'parent')}
        count = 0
        for path in sorted(root.rglob('*')):
            io.check_deadline(deadline); s = path.lstat()
            require(not stat.S_ISLNK(s.st_mode), 'observed output symlink refused')
            if stat.S_ISDIR(s.st_mode):
                require(s.st_uid == os.geteuid() and stat.S_IMODE(s.st_mode) == 0o700, 'output directory differs')
                continue
            require(stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid() and s.st_nlink == 1, 'output leaf is not owned regular')
            rel = path.relative_to(root)
            if rel.parts[0].startswith('part-') and path.name in ('official-part.original.zip', 'official-part.original.zip.partial'):
                category = 'container'
            elif rel.parts[0] == 'selected': category = 'selected'
            elif rel.parts[0] == 'readback' or path.name == 'DOWNLOAD.json': category = 'metadata'
            else: category = 'parent'
            actual = c.seal(path, policy['volumes'][volume]['limits'][category], deadline=deadline)
            used[category] += actual['bytes']; count += 1
            require(count <= 2048 and used[category] <= policy['volumes'][volume]['limits'][category], 'output count/category cap exceeded')
            rows.append({'volume': volume, 'category': category, 'relative_path': str(rel), **actual})
        totals[volume] = used
    return rows, totals
