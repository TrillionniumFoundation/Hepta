"""Read/copy only the already closed failed CLI experiment. Never load its DSO."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys

PLAN = Path('/tmp/hia-cli-json-c-runtime-lifetime-plan-r2b-20261112-e26e')
ACTUAL = Path('/tmp/hia-cli-json-c-runtime-lifetime-actual-r2b-20261112-e26e')
ROOT = Path('/workspace/scratch/e26ed3e2edcf/root')
OUT = Path('/tmp/hia-cli-json-c-runtime-lifetime-failure-r2b-20261112-e26e')
PARENT = '5f1c4f6bc7f8ebdf3b3e3c9c17f543a6281346d0'
sys.path.insert(0, str(PLAN / 'control'))
from common import identity, pin, read_file, wire
from original_current_compiler import json_original
from support import closed_owner, capture_closed, owner_paths, stage_command, environment
from verify import c_image

CHECKS = []
def check(name, condition):
    if not condition:
        raise ValueError(name)
    CHECKS.append(name)

def read(path, maximum=16 << 20):
    return read_file(Path(path), maximum)

def obj(path):
    raw, record = read(path)
    return json_original(raw), record, raw

def save(path, raw):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        pos = 0
        while pos < len(raw):
            n = os.write(fd, raw[pos:])
            if n <= 0:
                raise OSError('incomplete evidence write')
            pos += n
        os.fsync(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        back = b''
        while len(back) < len(raw):
            part = os.read(fd, min(65536, len(raw) - len(back)))
            if not part:
                raise OSError('incomplete evidence readback')
            back += part
        check('writeback:' + str(path.relative_to(OUT)), back == raw and not os.read(fd, 1))
    finally:
        os.close(fd)

def namespace(root):
    rows = []
    pending = [root]
    while pending:
        directory = pending.pop()
        info = directory.lstat()
        check('directory-type:' + str(directory), stat.S_ISDIR(info.st_mode))
        for path in sorted(directory.iterdir()):
            info = path.lstat()
            row = {'path': path.relative_to(root).as_posix(), 'identity': identity(info)}
            if stat.S_ISDIR(info.st_mode):
                row['kind'] = 'directory'
                pending.append(path)
            elif stat.S_ISREG(info.st_mode):
                row['kind'] = 'regular'
            else:
                row['kind'] = 'symlink' if stat.S_ISLNK(info.st_mode) else 'special'
            rows.append(row)
    return sorted(rows, key=lambda x: x['path'])

def elf_symbols(raw):
    header = struct.Struct('<16sHHIQQQIHHHHHH').unpack_from(raw)
    check('ELF64-little-endian', header[0][:7] == b'\x7fELF\x02\x01\x01')
    shoff, shsize, shcount = header[6], header[11], header[12]
    check('ELF-section-extents', shsize == 64 and shoff + shsize * shcount <= len(raw))
    sections = [struct.unpack_from('<IIQQQQIIQQ', raw, shoff + n * shsize) for n in range(shcount)]
    symbols = []
    for section in sections:
        if section[1] != 11:
            continue
        stringsec = sections[section[6]]
        strings = raw[stringsec[4]:stringsec[4] + stringsec[5]]
        check('ELF-dynsym-shape', section[9] == 24 and section[5] % 24 == 0)
        for at in range(section[4], section[4] + section[5], 24):
            name, info, other, index, value, extent = struct.unpack_from('<IBBHQQ', raw, at)
            end = strings.find(b'\0', name)
            check('ELF-dynsym-name-' + str(at), 0 <= name <= end < len(strings))
            name = strings[name:end].decode('ascii')
            if name:
                symbols.append({'name': name, 'type': info & 15, 'bind': info >> 4,
                                'visibility': other, 'section': index,
                                'value': value, 'bytes': extent})
    return symbols

def main():
    policy, policy_pin, _ = obj(PLAN / 'POLICY.json')
    request, request_pin, _ = obj(PLAN / 'REQUEST.json')
    check('frozen-policy-pin', policy_pin['sha256'] == '82380a6976d8618ef386f092b27fc8f76780236eeb7b1e02038b2697d2b2b766')
    check('frozen-request-pin', request_pin['sha256'] == '2e97663689dd224aab5717bb0c97a87f4f48e19e6079949e01d19b420cd76b74')
    spawn, _, _ = obj(ROOT / 'cli-c-runtime-lifetime-invocation-r2b/SPAWN.json')
    wrapper, _, _ = obj(ACTUAL / 'WRAPPER.json')
    life, life_pin, life_raw = obj(ACTUAL / 'owned/outer.lifecycle.json')
    _, outer_request_pin, outer_request_raw = obj(ACTUAL / 'owned/outer.lifecycle.json.request.json')
    command = [policy['python']['path'], '-I', '-S', '-B', str(PLAN / 'control/worker.py'),
               '--policy', str(PLAN / 'POLICY.json'), '--policy-sha256', policy_pin['sha256']]
    outer = closed_owner(wrapper, life_raw, outer_request_raw, command=command, cwd=PLAN,
                         env=environment(ACTUAL / 'work/temporary'),
                         paths=owner_paths(ACTUAL / 'owned', 'outer'), seconds=180, parent=spawn['pid'])
    events = ['qualification_started', 'owned_child_observed', 'qualification_exit_observed', 'owned_child_reaped']
    check('outer-natural-nonzero-closed', outer['returncode'] == 1 and wrapper['supervisor_returncode'] == 1
          and outer['timed_out'] is False and outer['exit_observed_before_deadline'] is True
          and outer.get('owner_error') is None and outer['interrupted_signals'] == []
          and outer['event_overflow'] is False and [x['kind'] for x in outer['events']] == events)
    # Only after independently bound actual ECHILD do we inspect any work outputs.
    original_namespace = namespace(ACTUAL)
    inventory, _, _ = obj(ACTUAL / 'CLOSED-ORIGINALS.json')
    recaptured = capture_closed(ACTUAL / 'work', 32 << 20)
    check('complete-work-inventory-exact', inventory == recaptured)
    check('complete-work-inventory-size', len(inventory['rows']) == 34
          and inventory['regular_bytes'] == 3906208 and inventory['errors'] == [])
    final, _, _ = obj(ACTUAL / 'FINAL.json')
    worker, _, _ = obj(ACTUAL / 'work/REPORT.json')
    check('original-terminal-HOLD', final['status'] == worker['status'] == 'HOLD'
          and final['closed_owner'] is True and final['source_preserved'] is True
          and final['natural_owner'] is False and final['complete_original_inventory'] is True)
    check('original-scope-not-upgraded', all(final[k] is False for k in
          ['body_driver_qualified', 'full_graph_qualified', 'fresh_cold', 'default_changed',
           'original17_executed', 'original46_executed']))
    check('actual-stages-complete', worker['expected_stages'] == ['c-compile','runtime','hia-compile','lifetime']
          and worker['attempted_stages'] == ['c-compile','runtime']
          and worker['completed_stages'] == ['c-compile']
          and set(worker['owners']) == {'c-compile','runtime'} and worker['inner_closure_confirmed'] is True)
    cjoin = c_image(policy, ACTUAL / 'work')
    prior_join, _, _ = obj(ACTUAL / 'work/C-BUILD-JOIN.json')
    check('independent-actual-C-ELF-and-dependency-join', cjoin == prior_join)
    inner = []
    for label, seconds, expected_rc in [('c-compile',20,0),('runtime',5,1)]:
        paths = owner_paths(ACTUAL / 'work/owners', label)
        row = worker['owners'][label]
        actual_wrapper, _, _ = obj(ACTUAL / ('work/owners/' + label + '.WRAPPER.json'))
        actual_life, lp, lr = obj(paths['receipt_path'])
        _, rp, rr = obj(paths['receipt_path'] + '.request.json')
        check(label + '-wrapper-bound-worker', actual_wrapper == row['wrapper'])
        checked = closed_owner(actual_wrapper, lr, rr,
            command=stage_command(policy, PLAN / 'POLICY.json', policy_pin['sha256'], label,
                                  dso=cjoin if label == 'runtime' else None),
            cwd=PLAN, env=environment(ACTUAL / 'work/temporary', compiler=label == 'c-compile'),
            paths=paths, seconds=seconds, parent=outer['qualification_pid'])
        check(label + '-natural-actual-returncode', checked['returncode'] == expected_rc
              and checked['timed_out'] is False and checked['exit_observed_before_deadline'] is True
              and checked.get('owner_error') is None and checked['interrupted_signals'] == []
              and checked['event_overflow'] is False and [x['kind'] for x in checked['events']] == events)
        stored_closed, _, _ = obj(ACTUAL / ('work/owners/' + label + '.CLOSED.json'))
        # run_step saves its CLOSED_PENDING record before in-memory natural classification.
        check(label + '-saved-closed-pending', stored_closed['status'] == 'CLOSED_PENDING_NATURAL_SUCCESS')
        check(label + '-saved-closed-originals', stored_closed['originals'] == row['originals'])
        for role, record in row['originals'].items():
            check(label + '-raw-' + role, pin(Path(record['path']), 4 << 20) == record)
        inner.append({'label':label,'qualification_seconds':seconds,'cleanup_seconds':3,
                      'returncode':expected_rc,'life':lp,'request':rp,
                      'elapsed_to_exit_ns':checked['events'][2]['monotonic_ns']-checked['events'][0]['monotonic_ns'],
                      'closed_ECHILD':True,'timed_out':False})
    runtime, runtime_pin, _ = obj(ACTUAL / 'work/runtime/REPORT.json')
    case, case_pin, _ = obj(ACTUAL / ('work/runtime/' + policy['runtime_ids'][0] + '.json'))
    check('runtime-denominators-and-load-failure', len(policy['runtime_ids']) == 8 and len(policy['lifetime_ids']) == 10
          and runtime['status'] == 'HOLD' and runtime['expected_ids'] == policy['runtime_ids']
          and runtime['loaded_ids'] == policy['runtime_ids'][:1] and runtime['executed_ids'] == []
          and runtime['outcomes'] == [case] and case['status'] == 'HOLD'
          and len(runtime['errors']) == 1 and 'undefined symbol: _PyErr_SetRaisedException' in runtime['errors'][0])
    check('no-HIA-or-pump-entry', runtime['hia_entry_calls'] == runtime['c_pump_calls'] == 0)
    check('remaining-stages-unexecuted', list((ACTUAL / 'work/hia-build').iterdir()) == []
          and list((ACTUAL / 'work/lifetime').iterdir()) == []
          and not any(p.name.startswith(('hia-compile.','lifetime.')) for p in (ACTUAL / 'work/owners').iterdir()))
    before, _, before_raw = obj(ACTUAL / 'INPUTS-BEFORE.json')
    for relative in ['INPUTS-AFTER.json','work/INPUTS-BEFORE.json','work/INPUTS-AFTER.json']:
        actual_snapshot, _, raw = obj(ACTUAL / relative)
        check('actual-input-full-byte-equality-' + relative, raw == before_raw and actual_snapshot == before)
    expected_snapshot, _, _ = obj(ROOT / 'cli-c-runtime-lifetime-review-r2b/FROZEN-INPUTS.original.json')
    check('actual-input-root-prefrozen-structure-equality', before == expected_snapshot)
    check('source-and-system-denominators', before['source_files'] == 182
          and len(policy['source_files']) == 182 and len(before['system']['files']) == 4555)
    source_records = {x['path']:x for x in before['files']}
    for row in policy['source_files']:
        path = PLAN / 'source' / row['path']
        actual_raw, actual_pin = read(path)
        check('source-pin:' + row['path'], actual_pin == source_records[str(path)]
              and len(actual_raw) == row['bytes'] and actual_pin['sha256'] == row['sha256']
              and hashlib.sha1(b'blob ' + str(len(actual_raw)).encode() + b'\0' + actual_raw).hexdigest() == row['git_blob'])
    dso, dso_pin = read(ACTUAL / 'work/c-build/cli-json.so')
    symbols = elf_symbols(dso)
    tls = [x for x in symbols if x['section'] == 0 and x['name'] == '_PyErr_SetRaisedException']
    check('actual-ELF-undefined-raised-setter', len(tls) == 1 and tls[0]['type'] == 0)
    check('actual-DSO-pin', dso_pin['sha256'] == '0d2a0d0085a851e77d463561025d7537915fa421298c058f92e0fc836023cf1d')
    root_readback, root_readback_pin, _ = obj(ROOT / 'cli-c-runtime-lifetime-invocation-r2b/READBACK.json')
    check('root-independent-readback-pin', root_readback_pin['sha256'] == '75a56b7d3d317a2361f2e3b4ca71421b6cfc27508e49441a402c8806aec90164')
    check('root-independent-outcome-agrees', root_readback['status'] == 'HOLD'
          and root_readback['C_image'] == dso_pin and root_readback['runtime_completed'] == 0
          and root_readback['HIA_compile_executed'] is False and root_readback['lifetime_executed'] == 0)

    raw_sources = []
    for prefix, base in [('actual', ACTUAL),
                         ('root-review', ROOT / 'cli-c-runtime-lifetime-review-r2b'),
                         ('root-invocation', ROOT / 'cli-c-runtime-lifetime-invocation-r2b')]:
        rows = namespace(base)
        check(prefix + '-no-special-originals', all(x['kind'] in ('regular','directory') for x in rows))
        for row in rows:
            if row['kind'] == 'regular':
                raw_sources.append((base / row['path'], prefix + '/' + row['path']))
    for name in ['review_cli_finite_r2b_inputs.py','invoke_cli_finite_r2b_once.py','audit_cli_finite_r2b_actual.py']:
        raw_sources.append((ROOT / name, 'root-readers/' + name))
    raw_sources.append((Path('/tmp/hia-cold-peer-reviews-20261112/cli-json-C-runtime-lifetime-30d2-static-review.json'),
                        'peer-review/cli-json-C-runtime-lifetime-30d2-static-review.json'))
    originals = []
    for source, relative in raw_sources:
        raw, source_pin = read(source)
        target = OUT / 'originals' / relative
        save(target, raw)
        copied, copied_pin = read(target)
        check('copied-original:' + relative, copied == raw)
        originals.append({'path': 'originals/' + relative, 'source': str(source),
                          'source_identity': source_pin['identity'] if 'identity' in source_pin else identity(source.lstat()),
                          'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                          'git_blob':hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
                          'source_pin':source_pin,'copy_pin':copied_pin})
    check('complete-actual-41-copied', sum(x['path'].startswith('originals/actual/') for x in originals) == 41)
    check('actual-originals-remained-identical', namespace(ACTUAL) == original_namespace)
    for row in originals:
        check('original-final-read:' + row['path'], pin(Path(row['source']), 16 << 20) == row['source_pin'])
    save(OUT / 'ORIGINALS.json', wire({'schema':'hia.cli-json.finite-r2b-failure-originals.v1',
         'qualification_status':'HOLD','parent_commit':PARENT,'rows':originals,
         'count':len(originals),'bytes':sum(x['bytes'] for x in originals),
         'all_regular_originals_byte_copied':True,'no_originals_modified':True}))
    result = {'schema':'hia.cli-json.finite-r2b-independent-failure-readback.v1',
       'audit_status':'READONLY_FAILURE_AUDIT_PASS','qualification_status':'HOLD',
       'parent_commit':PARENT,'request':request_pin,'policy':policy_pin,
       'outer':{'life':life_pin,'request':outer_request_pin,'returncode':1,'closed_ECHILD':True,
                'timed_out':False,'qualification_seconds':180,'cleanup_seconds':3,
                'elapsed_to_exit_ns':outer['events'][2]['monotonic_ns']-outer['events'][0]['monotonic_ns']},
       'inner_owners':inner,'C_image':dso_pin,'C_image_join_reparsed':True,
       'undefined_dynamic_symbols':[x for x in symbols if x['section']==0],
       'runtime_report':runtime_pin,'failed_case':case_pin,
       'runtime_expected_ids':policy['runtime_ids'],'runtime_loaded_ids':runtime['loaded_ids'],
       'runtime_executed_ids':[],'runtime_elapsed_ns':runtime['elapsed_ns'],
       'primary_actual_error':'undefined symbol: _PyErr_SetRaisedException',
       'HIA_compile_executed':False,'lifetime_expected_ids':policy['lifetime_ids'],
       'lifetime_executed_ids':[],'HIA_returns':0,'C_pump_calls':0,
       'four_actual_input_snapshots_byte_equal':True,'root_preexec_snapshot_structure_equal':True,
       'source_files_rehashed':182,'system_input_rows_bound':4555,
       'all_system_files_reread_by_this_auditor':False,
       'actual_work_namespace_rows':34,'actual_work_regular_bytes':3906208,
       'actual_regular_originals':41,'originals_count':len(originals),
       'originals_bytes':sum(x['bytes'] for x in originals),'check_count':len(CHECKS),'checks':CHECKS,
       'product_rerun':False,'C_compile_repeated':False,'native_loaded_by_auditor':False,
       'original_17_CLI_executed':False,'original_46_traces_executed':False,
       'body_activation_CALL_SEND_UNPACK_closed':False,'default_changed':False,
       'root_independent_readback':root_readback_pin}
    save(OUT / 'AUDIT.json', wire(result))
    print(json.dumps({k:result[k] for k in ['audit_status','qualification_status','check_count',
         'originals_count','originals_bytes','primary_actual_error','runtime_loaded_ids','runtime_executed_ids']}))

if __name__ == '__main__':
    main()
