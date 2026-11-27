"""Run bounded pending ownership policies as actual four-root native code.

This observer does not claim a disk index, background worker or public route.
It retains complete control inputs and outputs and exercises both simultaneous
8192-entry cohorts in the original 32 MiB process state without aliasing them.
"""
from __future__ import annotations
import argparse
import ctypes
import gzip
from hashlib import sha256
import json
from pathlib import Path
import runpy
import struct

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools.generate_hia_mcp_request_audit_common import authored, C
from tools.generate_hia_mcp_service import document
from tools.qualify_hia_mcp_request_history_seed import HistorySeeds

ENTRY = r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s) < 64 or length(o) < 544 or length(w) < STATE_BYTES:
        return 4294967295
    copy_input(s,w,0,INPUT,64)
    op = get(w,INPUT)
    result = 0
    size = 160
    if op == 0:
        index_init(w)
    elif op == 1:
        index_publication_before(w,get(w,INPUT+8),get(w,INPUT+16),get(w,INPUT+24))
    elif op == 2:
        if length(s) != 448:
            return 4294967295
        copy_input(s,w,64,TEMP_RECORD,384)
        result = choose(index_note(w,TEMP_RECORD,TEMP_RECORD+240),1,0)
    elif op == 3:
        index_publication_after(w,get(w,INPUT+8),get(w,INPUT+16),get(w,INPUT+24),get(w,INPUT+32),get(w,INPUT+40),get(w,INPUT+48),get(w,INPUT+56) != 0)
    elif op == 4:
        result = choose(index_claim(w,get(w,INPUT+8) != 0,get(w,INPUT+16),get(w,INPUT+24),get(w,INPUT+32)),1,0)
    elif op == 5:
        result = choose(index_complete_claim(w,get(w,INPUT+8) != 0,get(w,INPUT+16)),1,0)
    elif op == 6:
        result = choose(index_query_allowed(w,get(w,INPUT+8) != 0,get(w,INPUT+16),get(w,INPUT+24),get(w,INPUT+32)),1,0)
    elif op == 7:
        result = index_drain_action(w,get(w,INPUT+8),get(w,INPUT+16),get(w,INPUT+24))
    elif op == 8:
        if length(s) != 832:
            return 4294967295
        copy_input(s,w,64,RECORD,768)
        result = index_transition(w,RECORD,RECORD+384)
    elif op == 9:
        array = I_SORT
        count = get(w,I_BASE)
        if get(w,INPUT+8) != 0:
            array = I_CLAIM
            count = get(w,I_BASE+112)
        position = get(w,INPUT+16)
        if position >= count:
            return 4294967295
        at = index_slot(get(w,array+position*8))
        offset = 0
        while offset < 384:
            word_store(o,160+offset,get(w,at+offset))
            offset = offset+8
        size = 544
    elif op == 10:
        index_invalidate(w)
    else:
        return 4294967295
    word_store(o,0,result)
    offset = 0
    while offset < 152:
        word_store(o,8+offset,get(w,I_BASE+offset))
        offset = offset+8
    return size
'''


def entry(number, *, owner='a'*64, state=0, accepted=None, elapsed=None, tool='file_info', stamp=1):
    raw = bytearray(384)
    raw[:64] = f'{number:064x}'.encode()
    raw[64:128] = owner.encode()
    raw[128:128+len(tool)] = tool.encode()
    accepted = number if accepted is None else accepted
    struct.pack_into('<6Q', raw, 192, len(tool), state, accepted & ((1 << 64)-1),
                     accepted >> 64, int(elapsed is not None), elapsed or 0)
    struct.pack_into('<Q', raw, 240, stamp)
    return bytes(raw)


def qualify(root, bootstrap, author, output):
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    module = runpy.run_path(str(author))
    offsets = module['C']
    source = render_assembly(document(authored(ENTRY+module['SOURCE'], extra=offsets),
                                      'request_index_state_observer')).encode()
    (output/'index-state.hepta').write_bytes(source)
    seeds = HistorySeeds(root, bootstrap, output/'compiler')
    report = {'schema': 'hepta.hia.pending-index-state-native-controls.v1', 'passed': False,
              'author_sha256': sha256(author.read_bytes()).hexdigest(),
              'observer_sha256': sha256(Path(__file__).read_bytes()).hexdigest(),
              'state_bytes': C['STATE_BYTES'], 'maximum_pending': 8192,
              'maximum_claimed': 8192, 'checks': [], 'whole_cold_qualified': False,
              'whole_runtime_qualified': False, 'disk_index_qualified': False,
              'public_integration_qualified': False, 'original_rust_parity_claimed': False}
    observed = []
    try:
        flat = seeds.compile(source, 'div-word')
        (output/'index-state.flat').write_bytes(flat)
        report['native_source_sha256'] = sha256(source).hexdigest()
        report['native_image_sha256'] = sha256(flat).hexdigest()
        report['native_image_bytes'] = len(flat)
        image = NativeHiaJsonImage(flat, sha256(flat).hexdigest())
        workspace = ctypes.create_string_buffer(C['STATE_BYTES'] + 64)
        address = ctypes.addressof(workspace) + 32
        ctypes.memset(workspace, 0xa5, 32)
        ctypes.memset(address+C['STATE_BYTES'], 0xa5, 32)
        preserved_outputs = b'\xa3'*(8*65664)
        ctypes.memmove(address+C['B_OUTPUTS'], preserved_outputs, len(preserved_outputs))
        out = ctypes.create_string_buffer(544)

        def write(offset, value):
            ctypes.memmove(address+offsets['I_BASE']+offset, struct.pack('<Q', value), 8)

        def call(label, op, *args, data=b''):
            raw = struct.pack('<8Q', op, *(list(args)+[0]*(7-len(args))))+data
            src = ctypes.create_string_buffer(raw)
            ctypes.memset(out, 0xa7, 544)
            result = image._entry(src, len(raw), out, 544, address, C['STATE_BYTES'])
            assert result in (160, 544), (label, result)
            answer = bytes(out.raw[:result])
            assert out.raw[result:] == b'\xa7'*(544-result)
            assert src.raw[:len(raw)] == raw
            assert ctypes.string_at(address-32, 32) == ctypes.string_at(address+C['STATE_BYTES'], 32) == b'\xa5'*32
            words = struct.unpack('<20Q', answer[:160])
            observed.append({'case': label, 'input_hex': raw.hex(), 'returncode': result,
                             'output_hex': answer.hex()})
            return words, answer[160:]

        def check(label, condition):
            assert condition, label
            report['checks'].append({'case': label, 'passed': True})

        def ready(*, large=False, watched=True):
            call('initialize', 0)
            write(24, 1)
            write(56, int(large))
            write(72, int(watched))
            write(80, 7)
            write(88, 9)
            observed.append({'case': 'synthetic-original-state-fixture',
                             'state_header_hex': ctypes.string_at(address+offsets['I_BASE'], 152).hex()})

        ready()
        for n in range(8192):
            words, _ = call('fill-'+str(n), 2, data=entry(n))
            assert words[0] == 1 and words[1] == n+1
        check('8192-pending-entries-are-admitted', words[1] == 8192)
        replacement = entry(4096, state=1, elapsed=7)
        words, _ = call('update-at-capacity', 2, data=replacement)
        check('an-existing-id-can-update-at-8192', words[0] == 1 and words[1] == 8192)
        _, raw = call('read-updated-entry', 9, 0, 4096)
        check('complete-record-and-stamp-are-retained', raw == replacement)
        call('publish-generation', 3, 8192, 1, 7, 9, 10, 20, 1)
        words, _ = call('claim-complete-small-cohort', 4, 1, 1, 7, 9)
        check('busy-published-before-empty-small-queue', words[0] == 1 and words[1] == 0 and words[7] == 1 and words[15] == 8192)
        words, _ = call('query-while-claim-owned', 6, 1, 1, 7, 9)
        check('a-claimed-empty-queue-is-not-a-complete-view', words[0] == 0)
        for n in range(8192):
            words, _ = call('during-claim-'+str(n), 2, data=entry(100000+n))
            assert words[0] == 1 and words[1] == n+1
        check('two-independent-8192-cohorts-fit-original-state', words[1] == 8192 and words[14] == 16384 and words[15] == 8192)
        check('both-cohorts-preserve-complete-eight-metadata-output-buffers',
              ctypes.string_at(address+C['B_OUTPUTS'], len(preserved_outputs)) == preserved_outputs)
        _, raw = call('claimed-entry-after-second-fill', 9, 1, 4096)
        check('new-publications-do-not-alias-claimed-slots', raw == replacement)
        words, _ = call('capacity-new-id-refusal', 2, data=entry(999999))
        check('a-new-id-at-cap-invalidates-only-unclaimed-index-state', words[0] == 0 and words[1] == 0 and words[5] == 1 and words[15] == 8192)
        _, raw = call('claimed-entry-after-invalidation', 9, 1, 4096)
        check('invalidation-retains-in-flight-owner-data', raw == replacement)
        words, _ = call('finish-invalidated-claim', 5, 1, 16385)
        check('invalidated-write-cannot-publish-applied-generation', words[0] == 0 and words[7] == 0 and words[13] == 16384 and words[15] == 0)

        ready(large=True)
        for n in reversed(range(384)):
            words, _ = call('large-pending-'+str(n), 2, data=entry(n))
            assert words[0] == 1
        call('large-publication-generation', 3, 384, 1, 7, 9, 10, 20, 1)
        words, _ = call('claim-large-bounded-prefix', 4, 1, 1, 7, 9)
        check('large-claim-takes-256-and-leaves-128', words[0] == 1 and words[1] == 128 and words[15] == 256)
        for n in (0, 127, 255):
            _, raw = call('claimed-id-order-'+str(n), 9, 1, n)
            check('claimed-prefix-id-'+str(n), raw == entry(n))
        for n in (0, 127):
            _, raw = call('remaining-id-order-'+str(n), 9, 0, n)
            check('remaining-tail-id-'+str(n), raw == entry(n+256))
        call('finish-large-prefix', 5, 1, 16385)
        before = ctypes.string_at(address+offsets['I_BASE'], 152)
        words, _ = call('watched-readonly-tail', 6, 1, 1, 7, 9)
        check('watched-128-tail-is-readonly', words[0] == 1 and ctypes.string_at(address+offsets['I_BASE'], 152) == before)
        words, _ = call('ordinary-read-with-tail', 6, 0, 1, 7, 9)
        check('ordinary-complete-view-cannot-ignore-tail', words[0] == 0)
        words, _ = call('readonly-query-drain', 7, 1, 7, 9)
        check('query-requests-maintenance-without-taking-small-tail', words[0] == 2 and words[1] == 128 and words[9] == 1)
        call('129th-tail-entry', 2, data=entry(1001))
        words, _ = call('over-tail-view-refusal', 6, 1, 1, 7, 9)
        check('129-pending-entries-cannot-enter-readonly-tail', words[0] == 0)
        words, _ = call('large-backlog-drain', 7, 1, 7, 9)
        check('large-backlog-yields-for-bounded-writer', words[0] == 1 and words[1] == 129)
        before = ctypes.string_at(address+offsets['I_BASE'], 152)
        words, _ = call('changed-watch-claim-refusal', 4, 1, 1, 7, 10)
        check('changed-watch-does-not-take-a-cohort', words[0] == 0 and ctypes.string_at(address+offsets['I_BASE'], 152) == before)
        call('publication-before-changed-watch', 1, 1, 7, 10)
        words, _ = call('query-after-watch-change', 6, 1, 1, 7, 10)
        check('changed-writer-epoch-invalidates-cache', words[0] == 0 and words[1] == 0 and words[5] == 1)

        ready(large=True, watched=False)
        call('unwatched-tail-note', 2, data=entry(1))
        words, _ = call('unwatched-tail-query', 6, 1, 0, 0, 0)
        check('unwatched-tail-keeps-original-write-path', words[0] == 0)
        words, _ = call('unwatched-tail-drain', 7, 0, 0, 0)
        check('unwatched-small-tail-requires-catch-up', words[0] == 3 and words[1] == 1)
        ready()
        words, _ = call('claim-empty', 4, 1, 1, 7, 9)
        check('zero-entry-cohort-still-publishes-ownership', words[0] == 1 and words[7] == 1 and words[19] == 1)
        words, _ = call('second-empty-claim', 4, 1, 1, 7, 9)
        check('empty-cohort-cannot-be-double-owned', words[0] == 0)
        call('finish-empty-claim', 5, 1, 16384)
        write(8, (1 << 64)-1)
        words, _ = call('wrapping-generation', 3, 2, 1, 7, 9, 1, 0, 1)
        check('publication-generation-retains-u64-wrap', words[2] == 1)

        old = entry(7, state=1, accepted=(1 << 100)+9, elapsed=3)
        transitions = [('identical', old, 0),
                       ('older-unknown', entry(7, state=0, accepted=(1 << 100)+9), 0),
                       ('owner-change', entry(7, owner='b'*64, state=1, accepted=(1 << 100)+9, elapsed=3), 2),
                       ('tool-change', entry(7, tool='host_list', state=1, accepted=(1 << 100)+9, elapsed=3), 2),
                       ('accepted-u128-change', entry(7, state=1, accepted=(1 << 100)+10, elapsed=3), 2),
                       ('terminal-state-change', entry(7, state=2, accepted=(1 << 100)+9, elapsed=3), 3),
                       ('terminal-elapsed-change', entry(7, state=1, accepted=(1 << 100)+9, elapsed=4), 3),
                       ('stamp-only-change', entry(7, state=1, accepted=(1 << 100)+9, elapsed=3, stamp=2), 1)]
        for label, new, expected in transitions:
            words, _ = call('transition-'+label, 8, data=old+new)
            check('original-immutable-transition-'+label, words[0] == expected)
        words, _ = call('unknown-completes', 8, data=entry(7, accepted=(1 << 100)+9)+old)
        check('unknown-observation-can-complete', words[0] == 1)

        for label, slen, olen, wlen in [('short-input', 63, 544, C['STATE_BYTES']),
                                      ('short-output', 64, 543, C['STATE_BYTES']),
                                      ('short-workspace', 64, 544, C['STATE_BYTES']-1)]:
            src = ctypes.create_string_buffer(64)
            ctypes.memset(out, 0xa7, 544)
            before = ctypes.string_at(address+offsets['I_BASE'], 152)
            status = image._entry(src, slen, out, olen, address, wlen)
            check(label+'-refuses-without-visible-write', status == 4294967295 and out.raw == b'\xa7'*544 and ctypes.string_at(address+offsets['I_BASE'], 152) == before)
            observed.append({'case': label, 'lengths': [slen, olen, wlen], 'returncode': status, 'output_hex': out.raw.hex()})
        report.update(passed=True, passed_checks=len(report['checks']))
        return report
    finally:
        seeds.save()
        raw = b''.join((json.dumps(row, separators=(',', ':'))+'\n').encode() for row in observed)
        compressed = gzip.compress(raw, mtime=0)
        (output/'observations.jsonl.gz').write_bytes(compressed)
        report.update(observations=len(observed), raw_bytes=len(raw), raw_sha256=sha256(raw).hexdigest(),
                      compressed_bytes=len(compressed), compressed_sha256=sha256(compressed).hexdigest())
        (output/'qualification.json').write_text(json.dumps(report, indent=2)+'\n')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'bootstrap', 'author', 'output'):
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args()
    report = qualify(a.source.resolve(), a.bootstrap.resolve(), a.author.resolve(), a.output.resolve())
    print(json.dumps({key: report[key] for key in ('passed', 'passed_checks', 'observations', 'native_image_sha256')}))


if __name__ == '__main__':
    main()
