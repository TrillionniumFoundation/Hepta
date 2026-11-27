"""Real process and kernel controls for native retained archive queries."""
from __future__ import annotations
import argparse
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import time

from tests.hia_request_audit_native_support import Audit, good, identity, write_json
from tools.qualify_hia_mcp_request_history import record, snapshot

UNAVAILABLE = 'archive index preparing or validation unavailable; repeat only this metadata query'
DEADLINE = 'archive metadata query total deadline exceeded; repeat only the metadata query'


class ArchiveAudit(Audit):
    def archive_frame(self, *, deadline_ns=None, **kwargs):
        raw = self.history_frame(**kwargs)
        raw[:8] = b'HIARQY01'
        struct.pack_into('<Q', raw, 16, 4)
        deadline = time.monotonic_ns()+3_000_000_000 if deadline_ns is None else deadline_ns
        struct.pack_into('<2Q', raw, 256, *divmod(deadline, 1_000_000_000))
        return raw

    def archive_exchange(self, label, frame):
        self.count += 1
        stem = f'{self.count:04d}-{label}'
        (self.evidence/(stem+'.input.bin')).write_bytes(frame)
        fcntl.lockf(self.fd, fcntl.LOCK_EX, 1, 1, os.SEEK_SET)
        try:
            assert self.client.send(frame) == len(frame)
            raw = self.client.recv(64+65536+1)
        finally:
            fcntl.lockf(self.fd, fcntl.LOCK_UN, 1, 1, os.SEEK_SET)
        (self.evidence/(stem+'.output.bin')).write_bytes(raw)
        assert 64 < len(raw) <= 64+65536 and raw[:8] == b'HIARQO01', (label, len(raw), self.proc.poll())
        version,size,status,reason,slot,generation,reserved = struct.unpack_from('<7Q', raw, 8)
        assert version == 1 and size == len(raw) and reserved == 0 and status in (0,1)
        assert (status == 0) == (reason == 0)
        text = raw[64:].decode()
        answer = dict(status=status, reason=reason, slot=slot, generation=generation,
                      text=text, value=json.loads(text) if status == 0 else None)
        (self.evidence/(stem+'.json')).write_text(json.dumps(answer, indent=2)+'\n')
        return answer

    def archive(self, **kwargs):
        return self.archive_exchange('archive', self.archive_frame(**kwargs))


def seed_archive(root, records, *, shard_after=None):
    root = Path(root)
    if shard_after is not None:
        shards = root/'request-archive-v12'
        shards.mkdir(mode=0o700)
        for index in range(256):
            (shards/f'{index:02x}').mkdir(mode=0o700)
        write_json(root/'.request-archive-v12-anchor.json', {
            'format':12, 'root':identity(root), 'legacy':identity(root/'request-archive-v11'),
            'archive':identity(shards), 'shards':[identity(shards/f'{i:02x}') for i in range(256)]})
    for index, row in enumerate(records):
        folder = root/'request-archive-v11'
        if shard_after is not None and index >= shard_after:
            folder = root/'request-archive-v12'/row['request_id'][:2]
        write_json(folder/(row['request_id']+'.json'), row)


def page(answer):
    good(answer)
    value = answer['value']
    assert set(value) == {'requests','next_after_id','total','archive_retention','history_is_live',
                          'coverage','contains_parameters_or_output','automatic_operation_retry'}
    assert value['archive_retention'] == 'no_automatic_metadata_eviction'
    assert value['coverage'] == 'metadata_retained_at_archive_introduction_and_subsequent_admitted_requests'
    assert value['history_is_live'] is True and value['contains_parameters_or_output'] is False
    assert value['automatic_operation_retry'] is False and len(value['requests']) <= 32
    assert answer['text'] == json.dumps(value, sort_keys=True, separators=(',', ':'))
    assert len(json.dumps({'content':[{'type':'text','text':answer['text']}],
                           'isError':False,'resultType':'complete'},separators=(',',':')).encode()) <= 65536
    return value


def refused(answer, *, deadline=False):
    assert answer['status'] == 1 and answer['value'] is None, answer
    assert answer['text'] == (DEADLINE if deadline else UNAVAILABLE), answer
    if deadline:
        assert answer['reason'] == 37, answer
    return answer


def qualify(image, output):
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    checks = []

    def run(label, operation):
        directory = output/label
        directory.mkdir(mode=0o700)
        with ArchiveAudit(directory/'root', image, directory/'wire') as audit:
            good(audit.prepare())
            audit.lease(0)
            operation(audit, directory)
        checks.append({'case':label,'passed':True})
        print('NATIVE_ARCHIVE_PASS', label, flush=True)

    def empty(a, d):
        before = snapshot(a.root)
        result = page(a.archive())
        assert result['requests'] == [] and result['total'] == 0 and result['next_after_id'] is None
        assert snapshot(a.root) == before
    run('empty-without-self-admission', empty)

    def retained(a, d):
        rows = [record(i, accepted=800-i, owner=('b' if i%4 == 0 else 'a')*64) for i in range(800)]
        seed_archive(a.root, rows)
        before = snapshot(a.root)
        ids, cursor = [], None
        while True:
            value = page(a.archive(after_id=cursor))
            assert value['total'] == 600
            ids.extend(row['request_id'] for row in value['requests'])
            cursor = value['next_after_id']
            if cursor is None:
                break
        assert ids == [row['request_id'] for row in sorted(rows,key=lambda row:(row['accepted_unix_ms'],row['request_id'])) if row['owner'] == 'a'*64]
        assert not list((a.root/'request-audit').glob('*.json'))
        assert snapshot(a.root) == before
    run('retained-beyond-hot-512-and-owner-128', retained)

    def mixed(a, d):
        rows = [record((i<<248)|1, accepted=255-i) for i in range(256)]
        seed_archive(a.root, rows, shard_after=17)
        before = snapshot(a.root)
        value = page(a.archive(limit=2))
        assert value['total'] == 256 and [r['request_id'] for r in value['requests']] == [rows[-1]['request_id'],rows[-2]['request_id']]
        after = page(a.archive(after_id=rows[1]['request_id']))
        assert [r['request_id'] for r in after['requests']] == [rows[0]['request_id']]
        assert snapshot(a.root) == before
    run('mixed-legacy-and-256-shards', mixed)

    def owners(a, d):
        rows = [record(3, accepted=7),record(2, accepted=7),record(1,owner='b'*64)]
        seed_archive(a.root, rows)
        value = page(a.archive(limit=1))
        assert value['requests'][0]['request_id'] == rows[1]['request_id'] and value['total'] == 2
        refused(a.archive(after_id=rows[2]['request_id']))
        refused(a.archive(after_id='f'*64))
        assert page(a.archive(owner='b'*64))['total'] == 1
    run('same-owner-order-and-independent-cursors', owners)

    def expired(a, d):
        (a.root/'request-audit').rmdir()
        before = snapshot(a.root)
        refused(a.archive(deadline_ns=time.monotonic_ns()-1), deadline=True)
        assert not (a.root/'request-audit').exists() and snapshot(a.root) == before
    run('expired-before-opening-hot-state', expired)

    def held_store(a, d):
        before = snapshot(a.root)
        fcntl.lockf(a.fd, fcntl.LOCK_EX, 1, 0, os.SEEK_SET)
        started = time.monotonic()
        try:
            refused(a.archive(deadline_ns=time.monotonic_ns()+150_000_000), deadline=True)
            assert 0.10 <= time.monotonic()-started < 1.0
            assert snapshot(a.root) == before
        finally:
            fcntl.lockf(a.fd, fcntl.LOCK_UN, 1, 0, os.SEEK_SET)
        assert page(a.archive())['total'] == 0
    run('absolute-deadline-while-store-lock-held', held_store)

    def wide_time(a, d):
        rows = [record(1, accepted=0), record(2, accepted=(1<<64)-1),
                record(3, accepted=1<<64), record(4, accepted=(1<<128)-1)]
        seed_archive(a.root, rows)
        assert [r['accepted_unix_ms'] for r in page(a.archive(limit=2))['requests']] == [0,(1<<64)-1]
        assert page(a.archive(after_id=rows[3]['request_id']))['requests'] == []
        refused(a.archive(after_id=rows[1]['request_id'],limit=1))
        refused(a.archive(limit=1))
        assert a.history(limit=1)['status'] == 1
        assert a.begin()['status'] != 0
    run('u128-order-selected-overflow-poisons-store', wide_time)

    def live(a, d):
        receipt = good(a.begin())
        value = page(a.archive())
        assert value['total'] == 1 and value['requests'][0]['state'] == 'accepted'
        good(a.finish(receipt))
        assert page(a.archive())['requests'][0]['state'] == 'completed'
    run('real-kernel-ticket-and-completion', live)

    for label, change in [
        ('bad-version',lambda f:struct.pack_into('<Q',f,8,2)),
        ('bad-operation',lambda f:struct.pack_into('<Q',f,16,3)),
        ('bad-limit',lambda f:struct.pack_into('<Q',f,88,33)),
        ('bad-owner',lambda f:f.__setitem__(slice(128,192),b'A'*64)),
        ('bad-root-binding',lambda f:struct.pack_into('<Q',f,32,999999)),
        ('bad-reserved',lambda f:f.__setitem__(300,1)),
        ('bad-time-nanoseconds',lambda f:struct.pack_into('<Q',f,264,1000000000)),
        ('future-budget-refused',lambda f:struct.pack_into('<Q',f,256,time.monotonic_ns()//1000000000+20)),
    ]:
        def invalid(a,d,change=change):
            before = snapshot(a.root)
            frame = a.archive_frame()
            change(frame)
            refused(a.archive_exchange(label,frame))
            assert snapshot(a.root) == before
        run(label,invalid)

    def bad_foreign(a,d):
        rows = [record(1),record(2,owner='b'*64)]
        seed_archive(a.root,rows)
        path = a.root/'request-archive-v11'/(rows[1]['request_id']+'.json')
        path.write_bytes(b'{"invalid":true}')
        refused(a.archive(limit=1))
    run('complete-original-validation-includes-foreign-owner',bad_foreign)

    def wrong_shard(a,d):
        row = record(1)
        seed_archive(a.root,[row],shard_after=0)
        path=a.root/'request-archive-v12'/'00'/(row['request_id']+'.json')
        path.rename(a.root/'request-archive-v12'/'01'/path.name)
        refused(a.archive())
    run('wrong-physical-shard-refused',wrong_shard)

    def duplicate(a,d):
        row=record(1)
        seed_archive(a.root,[row],shard_after=0)
        write_json(a.root/'request-archive-v11'/(row['request_id']+'.json'),row)
        refused(a.archive())
    run('duplicate-legacy-shard-identity-refused',duplicate)

    for label,mutate in [
        ('symlink-original',lambda p:(p.rename(p.with_suffix('.saved')),p.symlink_to(p.with_suffix('.saved')))),
        ('hardlinked-original',lambda p:os.link(p,p.parent/'extra-link')),
        ('insecure-original-mode',lambda p:p.chmod(0o644)),
    ]:
        def changed(a,d,mutate=mutate):
            row=record(1);seed_archive(a.root,[row]);p=a.root/'request-archive-v11'/(row['request_id']+'.json')
            mutate(p);refused(a.archive())
        run(label,changed)

    report={'schema':'hepta.hia.request-archive-native.component.v1','scope':'independent native daemon component',
            'passed':len(checks),'checks':checks,'audit_sha256':sha256(image.read_bytes()).hexdigest(),
            'whole_cold_qualified':False,'public_mcp_qualified':False,'query_budget_seconds':3}
    (output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--audit',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(qualify(args.audit.resolve(),args.output.resolve())))

if __name__=='__main__':
    main()
