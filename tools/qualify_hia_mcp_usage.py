"""Execute the native retained usage ABI against real files and kernel leases."""
from __future__ import annotations
import argparse
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import time

from tests.hia_request_audit_native_support import good, write_json
from tools.qualify_hia_mcp_request_archive import ArchiveAudit, seed_archive, refused
from tools.qualify_hia_mcp_request_history import record, snapshot


class UsageAudit(ArchiveAudit):
    def usage_frame(self, **kwargs):
        raw = self.archive_frame(limit=0, **kwargs)
        raw[:8] = b'HIAUSQ01'
        struct.pack_into('<Q', raw, 16, 5)
        return raw

    def usage_exchange(self, label, frame):
        self.count += 1
        stem = f'{self.count:04d}-{label}'
        (self.evidence/(stem+'.input.bin')).write_bytes(frame)
        fcntl.lockf(self.fd, fcntl.LOCK_EX, 1, 1, os.SEEK_SET)
        try:
            assert self.client.send(frame) == len(frame)
            raw = self.client.recv(65601)
        finally:
            fcntl.lockf(self.fd, fcntl.LOCK_UN, 1, 1, os.SEEK_SET)
        (self.evidence/(stem+'.output.bin')).write_bytes(raw)
        assert 64 < len(raw) <= 65600 and raw[:8] == b'HIAUSO01', (label, len(raw), self.proc.poll())
        version, size, status, reason, slot, generation, reserved = struct.unpack_from('<7Q', raw, 8)
        assert version == 1 and size == len(raw) and status in (0, 1) and reserved == 0
        assert (status == 0) == (reason == 0)
        text = raw[64:].decode()
        answer = dict(status=status, reason=reason, slot=slot, generation=generation,
                      text=text, value=json.loads(text) if status == 0 else None)
        (self.evidence/(stem+'.json')).write_text(json.dumps(answer, indent=2)+'\n')
        return answer

    def usage(self, **kwargs):
        return self.usage_exchange('usage', self.usage_frame(**kwargs))


def projected(answer):
    good(answer)
    value = answer['value']
    assert set(value) == {'active', 'completed', 'contains_parameters_or_output', 'coverage',
                         'failed', 'first_accepted_unix_ms', 'last_accepted_unix_ms', 'retention',
                         'schema', 'scope', 'semantics', 'tool_counts', 'total_requests', 'unknown'}
    assert value['schema'] == 'hepta-private-usage-v1'
    assert value['scope'] == 'same_verified_credential_or_native_session'
    assert value['retention'] == 'archive_metadata_not_evicted_with_hot_cache'
    assert value['contains_parameters_or_output'] is False
    assert value['total_requests'] == sum(value[k] for k in ('active', 'unknown', 'completed', 'failed'))
    assert value['total_requests'] == sum(value['tool_counts'].values())
    assert answer['text'] == json.dumps(value, sort_keys=True, separators=(',', ':'))
    return value


def qualify(image, output):
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    checks = []
    report = {'schema': 'hepta.hia.usage-native.component.v1', 'passed': False,
              'scope': 'independent native daemon component', 'checks': checks,
              'audit_sha256': sha256(image.read_bytes()).hexdigest(),
              'whole_cold_qualified': False, 'public_mcp_qualified': False,
              'query_budget_seconds': 3}

    def run(label, operation):
        directory = output/label
        directory.mkdir(mode=0o700)
        with UsageAudit(directory/'root', image, directory/'wire') as audit:
            good(audit.prepare())
            audit.lease(0)
            operation(audit, directory)
        checks.append({'case': label, 'passed': True})
        print('NATIVE_USAGE_PASS', label, flush=True)

    try:
        def empty(a, d):
            before = snapshot(a.root)
            value = projected(a.usage())
            assert value['total_requests'] == 0 and value['tool_counts'] == {}
            assert value['first_accepted_unix_ms'] is None and value['last_accepted_unix_ms'] is None
            assert snapshot(a.root) == before
        run('empty-without-self-admission', empty)

        def retained(a, d):
            rows = []
            for i in range(800):
                state = ('unknown', 'completed', 'failed')[i % 3]
                row = record(i, owner=('b' if i % 4 == 0 else 'a')*64, accepted=800-i,
                             state=state, elapsed=None if state == 'unknown' else 7)
                row['tool_name'] = ('host_list', 'file_info', 'hia_describe')[i % 3]
                rows.append(row)
            seed_archive(a.root, rows)
            before = snapshot(a.root)
            for owner in ('a', 'b', 'c'):
                selected = [r for r in rows if r['owner'] == owner*64]
                value = projected(a.usage(owner=owner*64))
                assert value['total_requests'] == len(selected) and value['active'] == 0
                for state in ('unknown', 'completed', 'failed'):
                    assert value[state] == sum(r['state'] == state for r in selected)
                assert value['first_accepted_unix_ms'] == (min(r['accepted_unix_ms'] for r in selected) if selected else None)
                assert value['last_accepted_unix_ms'] == (max(r['accepted_unix_ms'] for r in selected) if selected else None)
            assert snapshot(a.root) == before and not list((a.root/'request-audit').glob('*.json'))
        run('retained-beyond-hot-and-private-owner-counts', retained)

        def shards(a, d):
            rows = [record((i << 248) | 1, accepted=255-i) for i in range(256)]
            seed_archive(a.root, rows, shard_after=17)
            before = snapshot(a.root)
            value = projected(a.usage())
            assert value['total_requests'] == 256 and value['tool_counts'] == {'hia_describe': 256}
            assert (value['first_accepted_unix_ms'], value['last_accepted_unix_ms']) == (0, 255)
            assert snapshot(a.root) == before
        run('mixed-legacy-and-all-256-shards', shards)

        def live(a, d):
            receipt = good(a.begin())
            value = projected(a.usage())
            assert value['active'] == 1 and value['unknown'] == 0 and value['total_requests'] == 1
            good(a.finish(receipt))
            value = projected(a.usage())
            assert value['active'] == 0 and value['unknown'] == 0 and value['completed'] == 1
        run('actual-kernel-ticket-and-completion', live)

        def wide(a, d):
            rows = [record(1, accepted=0), record(2, accepted=(1 << 64)-1),
                    record(3, owner='b'*64, accepted=(1 << 128)-1)]
            seed_archive(a.root, rows)
            value = projected(a.usage())
            assert (value['first_accepted_unix_ms'], value['last_accepted_unix_ms']) == (0, (1 << 64)-1)
            refused(a.usage(owner='b'*64))
            refused(a.usage())
            assert a.history()['status'] == 1 and a.begin()['status'] != 0
        run('owner-u128-projection-and-store-wide-poison', wide)

        for size, count, allowed in ((64, 508, True), (64, 509, False), (3, 963, True), (3, 964, False)):
            def budget(a, d, size=size, count=count, allowed=allowed):
                rows = []
                for i in range(count):
                    row = record(i, accepted=i)
                    row['tool_name'] = 't'*(size-3)+''.join(chr(97+(i//(26**power)) % 26) for power in (2, 1, 0))
                    rows.append(row)
                assert len({r['tool_name'] for r in rows}) == count
                seed_archive(a.root, rows)
                before = snapshot(a.root)
                result = a.usage()
                if allowed:
                    value = projected(result)
                    assert len(value['tool_counts']) == count and value['total_requests'] == count
                else:
                    refused(result)
                assert projected(a.usage(owner='b'*64))['total_requests'] == 0
                assert snapshot(a.root) == before
            run(f'original-distinct-tool-budget-{size}-{count}', budget)

        def expired(a, d):
            (a.root/'request-audit').rmdir()
            before = snapshot(a.root)
            refused(a.usage(deadline_ns=time.monotonic_ns()-1), deadline=True)
            assert snapshot(a.root) == before and not (a.root/'request-audit').exists()
        run('expired-before-opening-hot-state', expired)

        def held(a, d):
            before = snapshot(a.root)
            fcntl.lockf(a.fd, fcntl.LOCK_EX, 1, 0, os.SEEK_SET)
            started = time.monotonic()
            try:
                refused(a.usage(deadline_ns=time.monotonic_ns()+150_000_000), deadline=True)
                assert 0.10 <= time.monotonic()-started < 1.0
                assert snapshot(a.root) == before
            finally:
                fcntl.lockf(a.fd, fcntl.LOCK_UN, 1, 0, os.SEEK_SET)
            projected(a.usage())
        run('absolute-deadline-while-store-lock-held', held)

        mutations = [
            ('version', 8, 2), ('operation', 16, 4), ('root-binding', 32, 999999),
            ('nonzero-limit', 88, 1), ('nonzero-cursor', 96, 64), ('reserved', 300, 1),
            ('invalid-nanoseconds', 264, 1000000000),
        ]
        for label, offset, value in mutations:
            def malformed(a, d, offset=offset, value=value):
                before = snapshot(a.root)
                frame = a.usage_frame()
                struct.pack_into('<Q', frame, offset, value)
                refused(a.usage_exchange(label, frame))
                assert snapshot(a.root) == before
            run('strict-usage-abi-'+label, malformed)

        def foreign(a, d):
            rows = [record(1), record(2, owner='b'*64)]
            seed_archive(a.root, rows)
            (a.root/'request-archive-v11'/(rows[1]['request_id']+'.json')).write_bytes(b'{"invalid":true}')
            refused(a.usage())
        run('foreign-original-validation-before-projection', foreign)
        report['passed'] = True
        report['passed_checks'] = len(checks)
        return report
    finally:
        (output/'qualification.json').write_text(json.dumps(report, indent=2)+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--audit', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(qualify(args.audit.resolve(), args.output.resolve())))


if __name__ == '__main__':
    main()
