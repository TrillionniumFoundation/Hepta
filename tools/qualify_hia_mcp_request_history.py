"""Real native process controls for the owner-scoped request_history ABI.

The observer supplies descriptors and inspects public results. Policy, private
metadata parsing, sorting, pagination and filesystem custody run in the HIA ELF.
These are component controls; public MCP and whole cold qualification are separate.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import struct

from tests.hia_request_audit_native_support import Audit, good, write_json

OWNER = 'a'*64
UNAVAILABLE = 'request history unavailable to this session or private metadata refused'
CURSOR = 'request history cursor expired or unavailable to this session'
SEMANTICS = 'native_request_dispatch_observation_not_side_effect_delivery_or_business_success'


def record(number, owner=OWNER, accepted=1, state='completed', elapsed=1):
    return dict(request_id=f'{number:064x}', owner=owner, tool_name='hia_describe',
                state=state, accepted_unix_ms=accepted, elapsed_ms=elapsed)


def seed(root, rows):
    hot = root/'request-audit'
    hot.mkdir(mode=0o700, exist_ok=True)
    for row in rows:
        write_json(hot/(row['request_id']+'.json'), row)


def snapshot(root):
    result = {}
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        if path.is_file() and not path.is_symlink():
            result[path.relative_to(root).as_posix()] = (
                info.st_dev, info.st_ino, info.st_mode, sha256(path.read_bytes()).hexdigest())
    return result


def page(reply):
    good(reply)
    value = reply['value']
    assert set(value) == {'requests', 'next_after_id', 'retention', 'status_semantics',
                          'session_scope', 'cross_session_resume', 'history_is_live',
                          'automatic_operation_retry'}
    assert value['retention'] == {'global':512, 'per_session':128}
    assert value['status_semantics'] == SEMANTICS
    assert value['session_scope'] == 'native_mcp_session_only'
    assert value['cross_session_resume'] is False
    assert value['history_is_live'] is True
    assert value['automatic_operation_retry'] is False
    assert len(value['requests']) <= 32
    for row in value['requests']:
        assert set(row) == {'request_id', 'tool_name', 'state', 'accepted_unix_ms', 'elapsed_ms'}
    assert reply['text'] == json.dumps(value, sort_keys=True, separators=(',', ':'))
    wire = {'content':[{'type':'text', 'text':reply['text']}], 'isError':False}
    assert len(json.dumps(wire, separators=(',', ':')).encode()) <= 65536
    return value


def refused(reply, text=UNAVAILABLE, reason=None):
    assert reply['status'] == 1 and reply['value'] is None, reply
    assert reply['text'] == text, reply
    if reason is not None:
        assert reply['reason'] == reason, reply
    return reply


def qualify(image, output):
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    checks = []

    def run(label, body):
        directory = output/label
        directory.mkdir(mode=0o700)
        with Audit(directory/'root', image, directory/'wire') as audit:
            good(audit.prepare())
            body(audit, directory)
        checks.append({'case':label, 'passed':True})
        print('NATIVE_HISTORY_PASS', label, flush=True)

    def empty(a, directory):
        a.lease(0)
        before = snapshot(a.root)
        assert page(a.history())['requests'] == []
        assert page(a.history())['requests'] == []
        assert snapshot(a.root) == before
        assert not list((a.root/'request-audit').glob('*.json'))
    run('empty-no-self-audit', empty)

    def ordered(a, directory):
        a.lease(0)
        rows = [record(9, accepted=7), record(3, accepted=7),
                record(4, owner='b'*64, accepted=1),
                record(7, accepted=8, state='failed', elapsed=17),
                record(6, accepted=0, state='unknown', elapsed=None)]
        seed(a.root, rows)
        before = snapshot(a.root)
        first = page(a.history(limit=2))
        assert [r['request_id'] for r in first['requests']] == [f'{6:064x}', f'{3:064x}']
        assert first['next_after_id'] == f'{3:064x}'
        second = page(a.history(limit=2, after_id=first['next_after_id']))
        assert [r['request_id'] for r in second['requests']] == [f'{9:064x}', f'{7:064x}']
        assert second['next_after_id'] is None
        assert page(a.history(after_id=f'{7:064x}'))['requests'] == []
        refused(a.history(after_id=f'{4:064x}'), CURSOR, 33)
        refused(a.history(after_id='f'*64), CURSOR, 33)
        assert [r['request_id'] for r in page(a.history(owner='b'*64))['requests']] == [f'{4:064x}']
        assert snapshot(a.root) == before
    run('owner-time-cursor-no-archive-write', ordered)

    def retention(a, directory):
        a.lease(0)
        seed(a.root, [record(index, owner='abcd'[index % 4]*64, accepted=index)
                      for index in range(512)])
        before = snapshot(a.root)
        seen, cursor = [], None
        for index in range(4):
            value = page(a.history(after_id=cursor))
            assert len(value['requests']) == 32
            seen += [r['request_id'] for r in value['requests']]
            cursor = value['next_after_id']
            assert (cursor is None) == (index == 3)
        assert seen == [f'{index:064x}' for index in range(0, 512, 4)]
        assert snapshot(a.root) == before
        assert len(list((a.root/'request-audit').glob('*.json'))) == 512
    run('global-512-owner-128-four-pages', retention)

    def live(a, directory):
        a.lease(0)
        begin = good(a.begin())
        values = {r['request_id']:r for r in page(a.history())['requests']}
        assert values[begin['id']]['state'] == 'accepted'
        assert values[begin['id']]['elapsed_ms'] is None
        good(a.finish(begin))
        values = {r['request_id']:r for r in page(a.history())['requests']}
        assert values[begin['id']]['state'] == 'completed'
        assert isinstance(values[begin['id']]['elapsed_ms'], int)
        target = record(99, state='unknown', elapsed=None)
        seed(a.root, [target])
        pin = good(a.begin(gen=2, tool='request_status', target=target['request_id']))
        values = {r['request_id']:r for r in page(a.history(gen=2))['requests']}
        assert values[target['request_id']]['state'] == 'unknown'
        assert values[pin['id']]['state'] == 'accepted'
        good(a.finish(pin, completion=2))
        values = {r['request_id']:r for r in page(a.history(gen=2))['requests']}
        assert values[pin['id']]['state'] == 'failed'
    run('live-ticket-read-pin-and-finish', live)

    def dead(a, directory):
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:
            try:
                os.close(read_fd)
                a.lease(0)
                row = good(a.begin())
                os.write(write_fd, json.dumps(row).encode()+b'\n')
                while True:
                    signal.pause()
            finally:
                os._exit(91)
        os.close(write_fd)
        try:
            with os.fdopen(read_fd, 'rb') as stream:
                row = json.loads(stream.readline())
            os.kill(child, signal.SIGKILL)
            status = os.waitpid(child, 0)[1]
            assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
            child = 0
            a.lease(0)
            values = page(a.history(gen=2))['requests']
            assert len(values) == 1 and values[0]['request_id'] == row['id']
            assert values[0]['state'] == 'unknown' and values[0]['elapsed_ms'] is None
        finally:
            if child:
                os.kill(child, signal.SIGKILL)
                os.waitpid(child, 0)
    run('dead-kernel-lease-reaped', dead)

    def malformed(a, directory):
        refused(a.history(), reason=29)
        a.lease(0)
        changes = [(8,2), (16,4), (24,513), (32,1), (40,1), (48,32),
                   (56,1), (64,0), (72,1), (88,0), (88,33), (96,63), (104,1)]
        for index, (offset, value) in enumerate(changes):
            raw = a.history_frame()
            struct.pack_into('<Q', raw, offset, value)
            refused(a.history_exchange('malformed-word-'+str(index), raw))
            assert page(a.history())['requests'] == []
        for label, offset, value in [('owner',128,65), ('cursor-padding',192,1),
                                     ('tail-padding',256,1), ('root-path',512,120)]:
            raw = a.history_frame()
            raw[offset] = value
            refused(a.history_exchange('malformed-'+label, raw))
            assert page(a.history())['requests'] == []
    run('strict-protocol-custody-and-recovery', malformed)

    def corruption(label, mutate):
        def check(a, directory):
            a.lease(0)
            row = record(1)
            seed(a.root, [row])
            mutate(a, directory, row)
            refused(a.history())
        run(label, check)

    def record_symlink(a, directory, row):
        path = a.root/'request-audit'/(row['request_id']+'.json')
        target = directory/'outside.json'
        path.rename(target)
        path.symlink_to(target)
    corruption('record-symlink-refused', record_symlink)
    corruption('record-mode-refused', lambda a,d,r: (a.root/'request-audit'/(r['request_id']+'.json')).chmod(0o644))

    def duplicate(a, directory, row):
        path = a.root/'request-audit'/(row['request_id']+'.json')
        path.write_text(path.read_text()[:-1]+',"owner":"'+OWNER+'"}')
    corruption('duplicate-record-field-refused', duplicate)

    def unknown(a, directory, row):
        path = a.root/'request-audit'/(row['request_id']+'.json')
        path.write_text(path.read_text()[:-1]+',"unknown":true}')
    corruption('unknown-record-field-refused', unknown)
    corruption('hot-mode-refused', lambda a,d,r: (a.root/'request-audit').chmod(0o755))

    def hot_symlink(a, directory, row):
        path = a.root/'request-audit'
        target = directory/'outside-hot'
        path.rename(target)
        path.symlink_to(target, target_is_directory=True)
    corruption('hot-symlink-refused', hot_symlink)

    def excess(a, directory, row):
        seed(a.root, [record(index, owner='abcd'[index % 4]*64)
                      for index in range(2, 514)])
    corruption('hot-513-refused', excess)

    def staging(a, directory, row):
        path = a.root/'request-audit'/('.'+'b'*64+'-'+'c'*64+'.tmp')
        write_json(path, {})
        path.chmod(0o644)
    corruption('unsafe-staging-refused', staging)

    def replaced(a, directory, row):
        a.root.rename(directory/'old-root')
        a.root.mkdir(mode=0o700)
    corruption('held-root-replacement-refused', replaced)

    def recover(a, directory):
        a.lease(0)
        hot = a.root/'request-audit'
        hot.mkdir(mode=0o700, exist_ok=True)
        stage = hot/('.'+'b'*64+'-'+'c'*64+'.tmp')
        write_json(stage, {})
        assert page(a.history())['requests'] == []
        assert not stage.exists()
        hot.rmdir()
        assert page(a.history())['requests'] == []
        assert hot.is_dir() and (hot.stat().st_mode & 0o7777) == 0o700
    run('verified-staging-cleanup-empty-hot-recreate', recover)

    report = {'schema':'hepta.hia.request-history-native-controls.v1',
              'scope':'actual native request-audit query process; public MCP and complete cold separately gated',
              'executable_sha256':sha256(image.read_bytes()).hexdigest(),
              'passed':len(checks), 'cases':checks, 'whole_cold_qualification_claimed':False}
    (output/'qualification.json').write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(qualify(args.image.resolve(), args.output.resolve()), sort_keys=True))


if __name__ == '__main__':
    main()
