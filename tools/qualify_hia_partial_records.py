"""Finite, source-free partial-record qualification with three implementations.

The corpus is authored separately from the composite lowerer. Python executes
both the nominal input and its independently admitted primitive v7; an existing
independent Rust VM receives only that Core. Actual LLVM objects are linked to
an allocator observer. Fixed expected results, allocation events and release
order are calculated from the public scenario below, not copied from either VM.
This is finite execution evidence, not a whole-language refinement theorem.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.clang_capture import CaptureRejected, run_bounded
from hepta.hia_program import verify_core
from hepta.hia_program_llvm import compile_program_llvm, emit_program_llvm
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, HIAProgramTrap, execute_program
from hepta.hia_static_budget import (HIAStaticBudgetRejected, analyze_static_budget,
                                     qualify_vm_call_depth)
from hepta.hia_heap_bound import HIAHeapBoundRejected, qualify_live_heap_budget

SCHEMA = 'hepta.hia.partial-record-qualification.v1'
INPUT_SCHEMA = 'hepta.hia.composite.v3'
WRAPS = ['-Wl,--wrap=malloc', '-Wl,--wrap=calloc', '-Wl,--wrap=free']
PAIR = {'name': 'Pair', 'args': ['buffer', 'usize']}
RUST_EXECUTION_SCHEMA = 'hepta.hia.rust-byte-owner-execution.v1'
RUST_EXECUTION_PROFILE = 'bounded-cfg-byte-owner-bulk-v3'


def param(name, typ):
    return {'name': name, 'type': copy.deepcopy(typ)}


def partial(*fields):
    return {'partial': copy.deepcopy(PAIR), 'initialized': list(fields)}


def ins(op, args=(), out=(), **attrs):
    return {'op': op, 'args': list(args), 'out': [param(n, t) for n, t in out], 'attrs': attrs}


def const(name, typ, value):
    return ins('const', out=[(name, typ)], value=value)


def ret(*values):
    return {'op': 'ret', 'values': list(values)}


def branch(cond, yes, no):
    return {'op': 'branch', 'cond': cond,
            'then': {'target': yes[0], 'args': list(yes[1:])},
            'else': {'target': no[0], 'args': list(no[1:])}}


def block(name, params, ops, term):
    return {'id': name, 'params': [param(n, t) for n, t in params], 'ops': ops, 'term': term}


def function(name, params, returns, effects, blocks):
    return {'name': name, 'params': [param(n, t) for n, t in params],
            'returns': copy.deepcopy(returns), 'effects': effects,
            'entry': blocks[0]['id'], 'blocks': blocks}


def cleanup(name, initialized, *, reverse=True):
    """Explicit reverse resource-field cleanup, then consume the empty token."""
    live = list(initialized)
    source, ops = 'state', []
    for field in reversed(initialized) if reverse else initialized:
        live.remove(field)
        typ = 'usize' if field == 'tag' else 'buffer'
        value, rest = 'taken_' + field, 'after_' + field
        ops.append(ins('record.take', [source], [(value, typ), (rest, partial(*live))], field=field))
        if typ == 'buffer':
            ops.append(ins('owner.drop', [value]))
        source = rest
    ops.append(ins('record.abandon', [source]))
    return function(name, [('state', partial(*initialized))], [], ['alloc'],
                    [block('entry', [('state', partial(*initialized))], ops, ret())])


def program():
    """Build, carry, replace and observe a generic two-owner partial record.

    Failure results 100/200/300 identify the refused first/second/replacement
    allocation. Mode 1 cancels after the first field, returning 400. Successful
    records contain two buffers of size n and tag byte; their observed return
    is byte for n=0, otherwise 2*n + 2*byte + 17. A separate cooperative task
    carries only the initialized first/tag fields through cancel or completion.
    """
    empty = partial()
    left = partial('first', 'tag')
    right = partial('second', 'tag')
    full = partial('first', 'second', 'tag')
    types = [
        {'name': 'Pair', 'kind': 'record', 'params': ['T', 'U'],
         'fields': [param('first', 'T'), param('second', 'T'), param('tag', 'U')]},
        {'name': 'Step', 'kind': 'enum', 'params': [], 'variants': [
            {'name': 'pending', 'fields': [param('state', left)]},
            {'name': 'ready', 'fields': [param('result', 'usize')]}]},
        {'name': 'PartialTask', 'kind': 'task', 'params': [], 'state': left,
         'result': 'usize', 'poll': 'partial_poll', 'cancel': 'dispose_left'},
    ]
    dispose_left = cleanup('dispose_left', ['first', 'tag'])
    dispose_right = cleanup('dispose_right', ['second', 'tag'])
    dispose_full = cleanup('dispose_full', ['first', 'second', 'tag'])
    complete = function('complete', [('state', left), ('size', 'usize')], [full, 'bool'], ['alloc'], [
        block('entry', [('state', left), ('size', 'usize')], [
            ins('buffer.try_new', ['size'], [('second', 'buffer'), ('ok', 'bool')]),
            ins('record.insert', ['state', 'second'], [('completed', full)], field='second'),
        ], ret('completed', 'ok'))])
    observation = function('observe', [('pair', PAIR)], ['usize'], ['alloc', 'read', 'trap'], [
        block('entry', [('pair', PAIR)], [
            ins('record.unpack', ['pair'], [('a', 'buffer'), ('b', 'buffer'), ('tag', 'usize')]),
            ins('buffer.len', ['a'], [('na', 'usize')]), ins('buffer.len', ['b'], [('nb', 'usize')]),
            ins('int.add.checked', ['na', 'nb'], [('total', 'usize')]),
            ins('int.add.checked', ['total', 'tag'], [('base', 'usize')]),
            const('zero', 'usize', 0), ins('compare.eq', ['na', 'zero'], [('empty', 'bool')]),
        ], branch('empty', ('zero', 'a', 'b', 'base'), ('bytes', 'a', 'b', 'base'))),
        block('zero', [('za', 'buffer'), ('zb', 'buffer'), ('zbase', 'usize')], [
            ins('owner.drop', ['za']), ins('owner.drop', ['zb'])], ret('zbase')),
        block('bytes', [('ba', 'buffer'), ('bb', 'buffer'), ('bbase', 'usize')], [
            ins('borrow.read', ['ba'], [('ra', 'readbuf')]),
            ins('borrow.read', ['bb'], [('rb', 'readbuf')]), const('index', 'usize', 0),
            ins('buffer.load', ['ra', 'index'], [('va', 'u8')]),
            ins('buffer.load', ['rb', 'index'], [('vb', 'u8')]),
            ins('int.cast', ['va'], [('wide_a', 'usize')], mode='wrap'),
            ins('int.cast', ['vb'], [('wide_b', 'usize')], mode='wrap'),
            ins('int.add.checked', ['bbase', 'wide_a'], [('with_a', 'usize')]),
            ins('int.add.checked', ['with_a', 'wide_b'], [('answer', 'usize')]),
            ins('loan.end', ['ra']), ins('loan.end', ['rb']),
            ins('owner.drop', ['ba']), ins('owner.drop', ['bb']),
        ], ret('answer'))])
    signature = [('mode', 'u8'), ('size', 'usize'), ('byte', 'u8')]
    main = function('partial_case', signature, ['usize'], ['alloc', 'read', 'write', 'trap'], [
        block('entry', signature, [
            ins('record.begin', out=[('empty', empty)]),
            ins('buffer.try_new', ['size'], [('first', 'buffer'), ('ok_first', 'bool')]),
            ins('record.insert', ['empty', 'first'], [('has_first', partial('first'))], field='first'),
            ins('int.cast', ['byte'], [('tag', 'usize')], mode='wrap'),
            ins('record.insert', ['has_first', 'tag'], [('left', left)], field='tag'),
        ], branch('ok_first', ('choose', 'left', 'mode', 'size', 'byte'), ('failed_first', 'left'))),
        block('failed_first', [('f1_state', left)], [
            ins('call', ['f1_state'], function='dispose_left'), const('f1_answer', 'usize', 100),
        ], ret('f1_answer')),
        block('choose', [('c_state', left), ('c_mode', 'u8'), ('c_size', 'usize'), ('c_byte', 'u8')], [
            const('cancel_mode', 'u8', 1), ins('compare.eq', ['c_mode', 'cancel_mode'], [('cancel', 'bool')]),
        ], branch('cancel', ('cancelled', 'c_state'), ('build', 'c_state', 'c_size', 'c_byte'))),
        block('cancelled', [('cancel_state', left)], [
            ins('call', ['cancel_state'], function='dispose_left'), const('cancel_answer', 'usize', 400),
        ], ret('cancel_answer')),
        block('build', [('build_state', left), ('build_size', 'usize'), ('build_byte', 'u8')], [
            ins('call', ['build_state', 'build_size'], [('built', full), ('ok_second', 'bool')], function='complete'),
        ], branch('ok_second', ('replace', 'built', 'build_size', 'build_byte'), ('failed_second', 'built'))),
        block('failed_second', [('f2_state', full)], [
            ins('call', ['f2_state'], function='dispose_full'), const('f2_answer', 'usize', 200),
        ], ret('f2_answer')),
        block('replace', [('r_state', full), ('r_size', 'usize'), ('r_byte', 'u8')], [
            ins('record.finish', ['r_state'], [('pair', PAIR)]),
            ins('record.take', ['pair'], [('old', 'buffer'), ('without_first', right)], field='first'),
            ins('owner.drop', ['old']),
            ins('record.get', ['without_first'], [('retained_tag', 'usize')], field='tag'),
            ins('buffer.try_new', ['r_size'], [('replacement', 'buffer'), ('ok_replacement', 'bool')]),
        ], branch('ok_replacement', ('fill', 'without_first', 'replacement', 'r_byte'),
                  ('failed_replacement', 'without_first', 'replacement'))),
        block('failed_replacement', [('f3_state', right), ('f3_empty', 'buffer')], [
            ins('owner.drop', ['f3_empty']), ins('call', ['f3_state'], function='dispose_right'),
            const('f3_answer', 'usize', 300),
        ], ret('f3_answer')),
        block('fill', [('fill_state', right), ('fresh', 'buffer'), ('fill_byte', 'u8')], [
            ins('record.insert', ['fill_state', 'fresh'], [('filled', full)], field='first'),
            ins('record.borrow', ['filled'], [('first_writer', 'mutbuf')], field='first', mode='mut'),
            ins('buffer.fill', ['first_writer', 'fill_byte']), ins('loan.end', ['first_writer']),
            ins('record.borrow', ['filled'], [('second_writer', 'mutbuf')], field='second', mode='mut'),
            const('salt', 'u8', 17), ins('buffer.fill', ['second_writer', 'salt']), ins('loan.end', ['second_writer']),
            ins('record.finish', ['filled'], [('final_pair', PAIR)]),
            ins('call', ['final_pair'], [('result', 'usize')], function='observe'),
        ], ret('result'))])
    poll = function('partial_poll', [('state', left)], ['Step'], ['alloc'], [
        block('entry', [('state', left)], [
            ins('record.get', ['state'], [('tag', 'usize')], field='tag'),
            ins('call', ['state'], function='dispose_left'),
            ins('enum.make', ['tag'], [('result', 'Step')], variant='ready'),
        ], ret('result'))])
    task = function('partial_task', signature, ['usize'], ['alloc', 'trap'], [
        block('entry', signature, [
            ins('record.begin', out=[('empty', empty)]),
            ins('buffer.try_new', ['size'], [('first', 'buffer'), ('ok', 'bool')]),
            ins('record.insert', ['empty', 'first'], [('has_first', partial('first'))], field='first'),
            ins('int.cast', ['byte'], [('tag', 'usize')], mode='wrap'),
            ins('record.insert', ['has_first', 'tag'], [('state', left)], field='tag'),
            ins('task.create', ['state'], [('created', 'PartialTask')]),
            const('zero', 'u8', 0), ins('compare.eq', ['mode', 'zero'], [('pending', 'bool')]),
        ], branch('pending', ('pending_cancel', 'created'), ('start', 'created', 'mode'))),
        block('pending_cancel', [('pending_task', 'PartialTask')], [
            ins('task.cancel', ['pending_task'], [('cancelled', 'PartialTask')]),
            ins('task.state', ['cancelled'], [('status', 'u8')]), ins('task.close', ['cancelled']),
            ins('int.cast', ['status'], [('pending_result', 'usize')], mode='wrap'),
        ], ret('pending_result')),
        block('start', [('new_task', 'PartialTask'), ('start_mode', 'u8')], [
            ins('task.start', ['new_task'], [('running', 'PartialTask')]), const('one', 'u8', 1),
            ins('compare.eq', ['start_mode', 'one'], [('cancel_running', 'bool')]),
        ], branch('cancel_running', ('running_cancel', 'running'), ('finish', 'running'))),
        block('running_cancel', [('running_task', 'PartialTask')], [
            ins('task.cancel', ['running_task'], [('stopped', 'PartialTask')]),
            ins('task.state', ['stopped'], [('stopped_status', 'u8')]), ins('task.close', ['stopped']),
            ins('int.cast', ['stopped_status'], [('running_result', 'usize')], mode='wrap'),
        ], ret('running_result')),
        block('finish', [('poll_task', 'PartialTask')], [
            ins('task.poll', ['poll_task'], [('complete_task', 'PartialTask')]),
            ins('task.cancel', ['complete_task'], [('retained_task', 'PartialTask')]),
            ins('task.join', ['retained_task'], [('task_result', 'usize')]),
        ], ret('task_result'))])
    pair_types, pair_functions = two_payload_task()
    return {'schema': INPUT_SCHEMA, 'module': 'partial_record_qualification', 'types': types + pair_types,
            'functions': [dispose_left, dispose_right, dispose_full, complete, observation, main, poll, task]
                         + pair_functions}


def two_payload_task():
    """A task owns two distinguishable live payloads, released second then first.

    First/second allocation failures clean only the successfully acquired
    payloads. Pending and running cancellation invoke dispose_full; polling to
    ready invokes that same explicit cleanup before returning a scalar result.
    Cancelling an already cancelled/ready task must not call cleanup again.
    """
    empty, first, left, full = (partial(*fields) for fields in
                               [(), ('first',), ('first', 'tag'), ('first', 'second', 'tag')])
    types = [
        {'name': 'PairStep', 'kind': 'enum', 'params': [], 'variants': [
            {'name': 'pending', 'fields': [param('state', full)]},
            {'name': 'ready', 'fields': [param('result', 'usize')]}]},
        {'name': 'PairTask', 'kind': 'task', 'params': [], 'state': full,
         'result': 'usize', 'poll': 'pair_poll', 'cancel': 'dispose_full'},
    ]
    poll = function('pair_poll', [('state', full)], ['PairStep'], ['alloc', 'trap'], [
        block('entry', [('state', full)], [
            ins('record.borrow', ['state'], [('first_view', 'readbuf')], field='first', mode='read'),
            ins('buffer.len', ['first_view'], [('first_size', 'usize')]), ins('loan.end', ['first_view']),
            ins('record.borrow', ['state'], [('second_view', 'readbuf')], field='second', mode='read'),
            ins('buffer.len', ['second_view'], [('second_size', 'usize')]), ins('loan.end', ['second_view']),
            ins('record.get', ['state'], [('tag', 'usize')], field='tag'),
            ins('int.add.checked', ['first_size', 'second_size'], [('total', 'usize')]),
            ins('int.add.checked', ['total', 'tag'], [('answer', 'usize')]),
            ins('call', ['state'], function='dispose_full'),
            ins('enum.make', ['answer'], [('step', 'PairStep')], variant='ready'),
        ], ret('step'))])
    signature = [('mode', 'u8'), ('size', 'usize'), ('byte', 'u8')]
    task = function('partial_pair_task', signature, ['usize'], ['alloc', 'trap'], [
        block('entry', signature, [
            ins('record.begin', out=[('empty', empty)]),
            ins('buffer.try_new', ['size'], [('first', 'buffer'), ('first_ok', 'bool')]),
            ins('record.insert', ['empty', 'first'], [('first_state', first)], field='first'),
            ins('int.cast', ['byte'], [('tag', 'usize')], mode='wrap'),
            ins('record.insert', ['first_state', 'tag'], [('left_state', left)], field='tag'),
        ], branch('first_ok', ('second', 'left_state', 'size', 'mode'), ('first_failed', 'left_state'))),
        block('first_failed', [('first_failed_state', left)], [
            ins('call', ['first_failed_state'], function='dispose_left'), const('first_error', 'usize', 100),
        ], ret('first_error')),
        block('second', [('second_state', left), ('first_size', 'usize'), ('next_mode', 'u8')], [
            const('one', 'usize', 1), ins('int.add.checked', ['first_size', 'one'], [('next_size', 'usize')]),
            ins('buffer.try_new', ['next_size'], [('second', 'buffer'), ('second_ok', 'bool')]),
            ins('record.insert', ['second_state', 'second'], [('both', full)], field='second'),
        ], branch('second_ok', ('create', 'both', 'next_mode'), ('second_failed', 'both'))),
        block('second_failed', [('second_failed_state', full)], [
            ins('call', ['second_failed_state'], function='dispose_full'), const('second_error', 'usize', 200),
        ], ret('second_error')),
        block('create', [('state', full), ('create_mode', 'u8')], [
            ins('task.create', ['state'], [('created', 'PairTask')]), const('zero_mode', 'u8', 0),
            ins('compare.eq', ['create_mode', 'zero_mode'], [('cancel_pending', 'bool')]),
        ], branch('cancel_pending', ('pending_cancel', 'created'), ('start', 'created', 'create_mode'))),
        block('pending_cancel', [('pending_task', 'PairTask')], [
            ins('task.cancel', ['pending_task'], [('once_cancelled', 'PairTask')]),
            ins('task.cancel', ['once_cancelled'], [('cancelled', 'PairTask')]),
            ins('task.state', ['cancelled'], [('pending_status', 'u8')]), ins('task.close', ['cancelled']),
            ins('int.cast', ['pending_status'], [('pending_result', 'usize')], mode='wrap'),
        ], ret('pending_result')),
        block('start', [('new_task', 'PairTask'), ('start_mode', 'u8')], [
            ins('task.start', ['new_task'], [('running', 'PairTask')]), const('one_mode', 'u8', 1),
            ins('compare.eq', ['start_mode', 'one_mode'], [('cancel_running', 'bool')]),
        ], branch('cancel_running', ('running_cancel', 'running'), ('finish', 'running'))),
        block('running_cancel', [('running_task', 'PairTask')], [
            ins('task.cancel', ['running_task'], [('stopped', 'PairTask')]),
            ins('task.state', ['stopped'], [('running_status', 'u8')]), ins('task.close', ['stopped']),
            ins('int.cast', ['running_status'], [('running_result', 'usize')], mode='wrap'),
        ], ret('running_result')),
        block('finish', [('poll_task', 'PairTask')], [
            ins('task.poll', ['poll_task'], [('ready_task', 'PairTask')]),
            ins('task.cancel', ['ready_task'], [('retained_task', 'PairTask')]),
            ins('task.join', ['retained_task'], [('ready_result', 'usize')]),
        ], ret('ready_result')),
    ])
    return types, [poll, task]


def cases():
    rows = []
    for size in (0, 1, 7):
        for mode in (0, 1):
            for byte in (0, 73, 255):
                for fail in (0, 1, 2, 3):
                    rows.append({'function': 'partial_case', 'arguments': [mode, size, byte], 'fail_at': fail})
    for size in (1 << 63, (1 << 64) - 1):
        for mode in (0, 1):
            rows.append({'function': 'partial_case', 'arguments': [mode, size, 73], 'fail_at': 0})
    for size in (0, 1, 7):
        for mode in (0, 1, 2):
            for fail in (0, 1):
                rows.append({'function': 'partial_task', 'arguments': [mode, size, 73], 'fail_at': fail})
    for size in (0, 1, 7):
        for mode in (0, 1, 2):
            for fail in (0, 1, 2):
                rows.append({'function': 'partial_pair_task', 'arguments': [mode, size, 73], 'fail_at': fail})
    return rows


def independent_spec(row):
    """Observable scenario model; does not inspect HIA/LLVM or a VM result."""
    mode, size, byte = row['arguments']
    counts = dict(attempts=0, allocations=0, frees=0, live=0, live_bytes=0,
                  peak_bytes=0, refusals=0, invalid_frees=0, null_frees=0, free_order=[])
    active = {}

    def allocate(extent=size):
        if extent == 0:
            return 0, True
        if extent > (1 << 63) - 1:
            return 0, False
        counts['attempts'] += 1
        if counts['attempts'] == row['fail_at']:
            counts['refusals'] += 1
            return 0, False
        counts['allocations'] += 1
        ident = counts['allocations']
        active[ident] = extent
        counts['live'] += 1
        counts['live_bytes'] += extent
        counts['peak_bytes'] = max(counts['peak_bytes'], counts['live_bytes'])
        return ident, True

    def drop(ident):
        if ident:
            counts['live_bytes'] -= active.pop(ident)
            counts['live'] -= 1
            counts['frees'] += 1
            counts['free_order'].append(ident)

    first, ok = allocate()
    if row['function'] == 'partial_pair_task':
        if not ok:
            result, logical_owners = 100, 2
        else:
            second, ok = allocate(size + 1)
            drop(second)
            drop(first)
            result = 200 if not ok else 3 if mode in (0, 1) else 2 * size + 1 + byte
            # The ordinary task/enum layout preserves three empty state
            # owners after cancelling or becoming ready, plus its task token.
            logical_owners = 7 if ok else 3
    elif row['function'] == 'partial_task':
        drop(first)
        result = 3 if mode in (0, 1) else byte
        # The published task layout also owns three empty padding tokens.
        logical_owners = 5
    elif not ok:
        result = 100
        logical_owners = 2
    elif mode == 1:
        drop(first)
        result = 400
        logical_owners = 2
    else:
        second, ok = allocate()
        if not ok:
            drop(first)
            result = 200
            logical_owners = 3
        else:
            drop(first)
            replacement, ok = allocate()
            if not ok:
                drop(second)
                result = 300
            else:
                drop(replacement)
                drop(second)
                result = byte if size == 0 else 2 * size + 2 * byte + 17
            # Initial record token, first/second payload owners, the new
            # token on taking a full record, and the replacement owner.
            logical_owners = 5
    return {'result': result, 'logical_owners': logical_owners, **counts}


def native_spec(row):
    """Native allocation events do not expose zero-sized logical Owner tokens."""
    return {key: value for key, value in independent_spec(row).items() if key != 'logical_owners'}


def budget_cases():
    return ([{'max_steps': x, 'max_heap_bytes': 1024} for x in (1, 3, 8, 15, 25, 40, 60)]
            + [{'max_steps': 100000, 'max_heap_bytes': x} for x in (0, 6, 7, 13)])


OBSERVER = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/resource.h>
void *__real_malloc(size_t); void *__real_calloc(size_t,size_t); void __real_free(void *);
static void *addresses[64]; static size_t sizes[64], ids[64], release_order[64];
static size_t attempts, allocations, frees, live, live_bytes, peak_bytes, refusals, invalid_frees, null_frees, fail_at;
static void *remember(void *p,size_t n) {
  if(!p)return p;
  size_t i;for(i=0;i<64 && addresses[i];i++);if(i==64)exit(89);
  addresses[i]=p;sizes[i]=n;ids[i]=++allocations;live++;live_bytes+=n;
  if(live_bytes>peak_bytes)peak_bytes=live_bytes;return p;
}
void *__wrap_malloc(size_t n) {
  attempts++;if(attempts==fail_at){refusals++;return NULL;}
  return remember(__real_malloc(n),n);
}
void *__wrap_calloc(size_t n,size_t width) {
  attempts++;if(attempts==fail_at){refusals++;return NULL;}
  return remember(__real_calloc(n,width),n*width);
}
void __wrap_free(void *p) {
  if(!p){null_frees++;__real_free(p);return;}
  size_t i;for(i=0;i<64 && addresses[i]!=p;i++);
  if(i==64){invalid_frees++;return;}
  release_order[frees++]=ids[i];live--;live_bytes-=sizes[i];addresses[i]=NULL;__real_free(p);
}
extern size_t partial_case(uint8_t,size_t,uint8_t);
extern size_t partial_task(uint8_t,size_t,uint8_t);
extern size_t partial_pair_task(uint8_t,size_t,uint8_t);
struct input {unsigned kind;uint8_t mode;uint64_t size;uint8_t byte;size_t fail;};
static const struct input inputs[]={@CASES@};
int main(int argc,char **argv) {
  struct rlimit no_core={0,0};if(setrlimit(RLIMIT_CORE,&no_core))return 88;
  if(argc!=2)return 87;size_t index=(size_t)strtoull(argv[1],NULL,10);
  if(index>=sizeof(inputs)/sizeof(inputs[0]))return 86;
  struct input c=inputs[index];fail_at=c.fail;
  size_t value=c.kind==2 ? partial_pair_task(c.mode,(size_t)c.size,c.byte) :
               c.kind==1 ? partial_task(c.mode,(size_t)c.size,c.byte) : partial_case(c.mode,(size_t)c.size,c.byte);
  printf("{\"result\":%zu,\"attempts\":%zu,\"allocations\":%zu,\"frees\":%zu,\"live\":%zu,\"live_bytes\":%zu,\"peak_bytes\":%zu,\"refusals\":%zu,\"invalid_frees\":%zu,\"null_frees\":%zu,\"free_order\":[",value,attempts,allocations,frees,live,live_bytes,peak_bytes,refusals,invalid_frees,null_frees);
  for(size_t i=0;i<frees;i++)printf(i ? ",%zu" : "%zu",release_order[i]);
  puts("]}");return live || invalid_frees || null_frees ? 91 : 0;
}
'''


def observer_source():
    values = []
    for row in cases():
        mode, size, byte = row['arguments']
        kind = {'partial_case': 0, 'partial_task': 1, 'partial_pair_task': 2}[row['function']]
        values.append('{' + f"{kind},{mode},UINT64_C({size}),{byte},{row['fail_at']}" + '}')
    return OBSERVER.replace('@CASES@', ',\n'.join(values))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def rust_argv(executable, function, arguments, options):
    """The existing independent Machine accepts explicit scalar policy fields."""
    return [executable, '--owned-run', function, json.dumps(arguments),
            str(options['max_steps']), str(options['max_heap_bytes']),
            str(options['allocation_fail_at']) if options.get('allocation_fail_at') else 'none']


def analysis_receipts(program):
    """Reverify actual normalized Core; do not infer bounds from v3 metadata."""
    result = {'call_depth': qualify_vm_call_depth(program, max_call_depth=32)}
    for name, analyze, rejected in (
            ('static_budget', lambda: analyze_static_budget(program), HIAStaticBudgetRejected),
            ('live_heap', lambda: qualify_live_heap_budget(program, max_live_heap_bytes=16 * 1024 * 1024),
             HIAHeapBoundRejected)):
        try:
            result[name] = {'status': 'qualified', 'receipt': analyze()}
        except rejected as error:
            result[name] = {'status': 'unknown', 'code': error.code, 'message': str(error)}
    return result


def descriptor(path):
    path = Path(path)
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def write_json(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')


def source_identity():
    names = sorted({str(p.relative_to(ROOT)) for p in (ROOT / 'hepta').glob('*.py')} |
                   {str(Path(__file__).relative_to(ROOT))} |
                   {str(p.relative_to(ROOT)) for p in (ROOT / 'rust/hia-core-shadow').rglob('*.rs')})
    return {name: descriptor(ROOT / name)['sha256'] for name in names}


def retained_process(report, output, argv, *, input_text=None, expected=0,
                     timeout=60, stdout_limit=2_000_000, stderr_limit=1_000_000):
    """Keep each explicit invocation, including bounded failure stream prefixes.

    Production LLVM compilation has its own receipt and is not intercepted.
    Successful text captures have run_bounded's UTF-8/newline normalization;
    failed captures retain the original bytes and the total observed lengths.
    """
    start = time.monotonic()
    index = len(report['processes'])
    prefix = Path(output) / f'process-{index:04d}'
    entry = {'argv': [str(x) for x in argv], 'status': 'attempted'}
    report['processes'].append(entry)
    if input_text is not None:
        Path(str(prefix) + '.stdin').write_text(input_text, encoding='utf-8')
        entry['stdin'] = descriptor(str(prefix) + '.stdin')
    try:
        result = run_bounded(entry['argv'], cwd=ROOT, input_text=input_text, timeout=timeout,
                             stdout_limit=stdout_limit, stderr_limit=stderr_limit,
                             stdin_limit=8 * 1024 * 1024)
    except CaptureRejected as error:
        entry.update(status='capture_rejected', seconds=time.monotonic() - start,
                     capture_error={'code': error.code, 'message': str(error)},
                     capture_available=error.capture is not None)
        if error.capture_error is not None:
            entry['capture_retention_error'] = error.capture_error
        if error.capture is not None:
            capture = error.capture
            entry.update(returncode=capture.returncode, stream_encoding='raw_bytes')
            for name in ('stdout', 'stderr'):
                data = getattr(capture, name)
                path = Path(str(prefix) + '.' + name)
                path.write_bytes(data)
                entry[name] = descriptor(path)
                total = getattr(capture, name + '_total_bytes')
                entry[name + '_total_bytes'] = total
                entry[name + '_truncated'] = len(data) < total
        raise
    entry.update(status='completed', returncode=result.returncode, seconds=time.monotonic() - start,
                 stream_encoding='utf8_universal_newlines')
    for name in ('stdout', 'stderr'):
        path = Path(str(prefix) + '.' + name)
        path.write_text(getattr(result, name), encoding='utf-8')
        entry[name] = descriptor(path)
    require(result.returncode == expected,
            f'process {index} exited {result.returncode}, expected {expected}: {result.stderr[-2000:]}')
    return index, result.stdout


def qualify(output_directory, clang, rust_vm):
    output = Path(output_directory).absolute()
    output.mkdir(parents=True, exist_ok=False)
    clang, rust_vm = Path(clang).resolve(strict=True), Path(rust_vm).resolve(strict=True)
    before = source_identity()
    tools_before = {'clang': descriptor(clang), 'rust_vm': descriptor(rust_vm)}
    report = {'schema': SCHEMA, 'status': 'running', 'passed': False, 'processes': [],
              'source_before': before, 'tools_before': tools_before,
              'git_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'git_status': subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True),
              'claims': {'finite_partial_record_execution': False,
                         'whole_language_soundness_proved': False, 'llvm_refinement_proved': False,
                         'real_concurrency_qualified': False, 'gpu_or_physical_board_qualified': False,
                         'two_live_payload_cancel_order_qualified': False},
              'cases': cases(), 'differential': [], 'budgets': [], 'native': {}, 'negative_controls': []}
    write_json(output / 'plan.json', {'schema': 'hepta.hia.partial-record-plan.v1', 'cases': cases(),
               'expected': [independent_spec(row) for row in cases()], 'source': before,
               'tools': tools_before, 'max_steps': 100000, 'max_heap_bytes': 16 * 1024 * 1024,
               'budget_cases': budget_cases(),
               'budget_return_control': {'max_steps': 60, 'max_heap_bytes': 1024},
               'process_timeout_seconds': 60, 'explicit_process_attempts_retained': True,
               'production_compilation_evidence': 'success receipt or reported exception; internal streams not intercepted'})

    def run(argv, *, input_text=None, expected=0):
        return retained_process(report, output, argv, input_text=input_text, expected=expected)

    def python_run(core, row, options):
        try:
            return execute_program(core, row['function'], row['arguments'], max_call_depth=32, **options)
        except (HIAProgramTrap, HIAProgramBudgetExceeded) as error:
            return error.report

    try:
        document = program()
        write_json(output / 'input.json', document)
        nominal = verify_core(document)
        core = verify_core(nominal.canonical_bytes)
        (output / 'core.json').write_bytes(core.canonical_bytes)
        require(nominal.canonical_bytes == core.canonical_bytes, 'nominal/core bytes differ')
        report.update(input_sha256=nominal.input_sha256, core_sha256=core.sha256,
                      normalization_report=nominal.normalization_report,
                      analysis=analysis_receipts(nominal))
        for index, row in enumerate(cases()):
            options = {'max_steps': 100000, 'max_heap_bytes': 16 * 1024 * 1024}
            if row['fail_at']:
                options['allocation_fail_at'] = row['fail_at']
            py_nominal, py_core = (python_run(value, row, options) for value in (nominal, core))
            process, raw = run(rust_argv(rust_vm, row['function'], row['arguments'], options),
                               input_text=core.canonical_bytes.decode())
            rust = json.loads(raw)
            entry = {'index': index, 'case': row, 'options': options, 'python_nominal': py_nominal,
                     'python_core': py_core, 'rust_process': process, 'rust': rust,
                     'independent_expected': independent_spec(row)}
            report['differential'].append(entry)
            require(rust['schema'] == RUST_EXECUTION_SCHEMA and rust['profile'] == RUST_EXECUTION_PROFILE,
                    'unknown Rust execution schema or profile')
            for field in ('status', 'steps', 'resources', 'program_sha256', 'values'):
                require(canonical(py_nominal[field]) == canonical(py_core[field]) == canonical(rust[field]),
                        f'case {index}: nominal/Core/Rust {field} differs')
            expected = independent_spec(row)
            require(py_core['status'] == 'returned' and py_core['values'] == [expected['result']], 'external scalar result differs')
            ledger = py_core['resources']
            for observed, specified in [('allocation_attempts', 'attempts'), ('allocations', 'allocations'),
                                        ('frees', 'frees'), ('live_bytes', 'live_bytes'), ('peak_bytes', 'peak_bytes')]:
                require(ledger[observed] == expected[specified], f'case {index}: independent allocator {observed} differs')
            require(ledger['live_owners'] == ledger['live_local_loans'] == ledger['live_chains'] == 0,
                    'returned program retains resources')
            require(ledger['owners_created'] == ledger['owners_dropped'] == expected['logical_owners'],
                    f'case {index}: independently specified logical Owner count differs')

        budget_case = {'function': 'partial_case', 'arguments': [0, 7, 73], 'fail_at': 0}
        for options in budget_cases():
            py = python_run(core, budget_case, options)
            process, raw = run(rust_argv(rust_vm, 'partial_case', [0, 7, 73], options),
                               input_text=core.canonical_bytes.decode())
            rust = json.loads(raw)
            report['budgets'].append({'options': options, 'python': py, 'rust': rust, 'rust_process': process})
            require(rust['schema'] == RUST_EXECUTION_SCHEMA and rust['profile'] == RUST_EXECUTION_PROFILE,
                    'unknown Rust budget execution schema or profile')
            for field in ('status', 'steps', 'resources', 'program_sha256'):
                require(canonical(py[field]) == canonical(rust[field]), f'budget {field} differs')
            if options == {'max_steps': 60, 'max_heap_bytes': 1024}:
                require(py['status'] == 'returned' and py['values'] == rust['values'] == [177],
                        'upper-budget return control differs')
            else:
                require(py['status'] == 'budget_exceeded' and py['error']['code'] == rust['error']['code'],
                        'expected budget stop absent')

        observer = output / 'observer.c'
        observer.write_text(observer_source())
        for name, value in [('nominal', nominal), ('core', core)]:
            ir = emit_program_llvm(value)
            (output / (name + '.ll')).write_text(ir.text)
            artifact = output / (name + '.o')
            compilation = compile_program_llvm(ir, program=value, output=artifact, clang=str(clang), kind='object')
            executable = output / name
            linked, _ = run([clang, '-std=c11', '-O2', '-Werror=implicit-function-declaration', observer, artifact, *WRAPS, '-o', executable])
            group = {'compilation': compilation, 'link_process': linked, 'executable': descriptor(executable), 'cases': []}
            report['native'][name] = group
            for index, row in enumerate(cases()):
                executed, raw = run([executable, str(index)])
                observed = json.loads(raw)
                group['cases'].append({'index': index, 'process': executed, 'observed': observed})
                require(canonical(observed) == canonical(native_spec(row)), f'{name} native case {index} differs')

        selected = next(index for index, row in enumerate(cases()) if row == {
            'function': 'partial_case', 'arguments': [0, 7, 73], 'fail_at': 0})
        original_ir = (output / 'nominal.ll').read_text()
        missing = '\n'.join(line for line in original_ir.splitlines() if 'call void @free(' not in line) + '\n'
        require(missing != original_ir, 'missing-free control made no mutation')
        missing_path = output / 'missing-free.ll'
        missing_path.write_text(missing)
        bad_executable = output / 'missing-free'
        linked, _ = run([clang, '-x', 'ir', '-O3', '-c', missing_path, '-o', output / 'missing-free.o'])
        linked_observer, _ = run([clang, '-std=c11', '-O2', observer, output / 'missing-free.o', *WRAPS, '-o', bad_executable])
        executed, raw = run([bad_executable, str(selected)], expected=91)
        bad = json.loads(raw)
        expected = independent_spec(cases()[selected])
        require(bad['result'] == expected['result'] and bad['allocations'] == 3 and bad['frees'] == 0
                and bad['live_bytes'] == 21, 'missing-free control did not expose correct-result resource defect')
        report['negative_controls'].append({'name': 'missing_free', 'qualified_hia_artifact': False,
               'compile_process': linked, 'link_process': linked_observer, 'run_process': executed, 'observed': bad,
               'detected': True, 'reason': 'correct scalar result; three unreleased payloads'})

        wrong_document = copy.deepcopy(document)
        changed = 0
        for fn in wrong_document['functions']:
            for body in fn['blocks']:
                for operation in body['ops']:
                    if operation['op'] == 'const' and operation['out'][0]['name'] == 'salt':
                        operation['attrs']['value'] = 18
                        changed += 1
        require(changed == 1, 'wrong-byte control must change exactly one constant')
        write_json(output / 'wrong-byte-input.json', wrong_document)
        wrong_core = verify_core(wrong_document)
        (output / 'wrong-byte-core.json').write_bytes(wrong_core.canonical_bytes)
        wrong_ir = emit_program_llvm(wrong_core)
        (output / 'wrong-byte.ll').write_text(wrong_ir.text)
        wrong_object, wrong_executable = output / 'wrong-byte.o', output / 'wrong-byte'
        wrong_build = compile_program_llvm(wrong_ir, program=wrong_core, output=wrong_object, clang=str(clang), kind='object')
        wrong_link, _ = run([clang, '-std=c11', '-O2', observer, wrong_object, *WRAPS, '-o', wrong_executable])
        wrong_run, raw = run([wrong_executable, str(selected)])
        observed = json.loads(raw)
        require(observed['result'] == expected['result'] + 1 and observed['live'] == 0,
                'wrong-byte control did not expose clean-resource behavioral mismatch')
        report['negative_controls'].append({'name': 'wrong_byte', 'compilation': wrong_build,
               'link_process': wrong_link, 'run_process': wrong_run, 'observed': observed,
               'detected': True, 'equivalent_to_original': False, 'reason': 'result disagrees with fixed scenario specification'})

        order_case = next(index for index, row in enumerate(cases()) if row == {
            'function': 'partial_pair_task', 'arguments': [0, 7, 73], 'fail_at': 0})
        wrong_order_document = copy.deepcopy(document)
        cleanup_index = next(index for index, fn in enumerate(wrong_order_document['functions'])
                             if fn['name'] == 'dispose_full')
        wrong_order_document['functions'][cleanup_index] = cleanup(
            'dispose_full', ['first', 'second', 'tag'], reverse=False)
        write_json(output / 'wrong-cleanup-order-input.json', wrong_order_document)
        wrong_order_core = verify_core(wrong_order_document)
        (output / 'wrong-cleanup-order-core.json').write_bytes(wrong_order_core.canonical_bytes)
        wrong_order_ir = emit_program_llvm(wrong_order_core)
        (output / 'wrong-cleanup-order.ll').write_text(wrong_order_ir.text)
        wrong_order_object, wrong_order_executable = output / 'wrong-cleanup-order.o', output / 'wrong-cleanup-order'
        wrong_order_build = compile_program_llvm(wrong_order_ir, program=wrong_order_core,
                                                output=wrong_order_object, clang=str(clang), kind='object')
        wrong_order_link, _ = run([clang, '-std=c11', '-O2', observer, wrong_order_object, *WRAPS,
                                  '-o', wrong_order_executable])
        wrong_order_run, raw = run([wrong_order_executable, str(order_case)])
        order_observed, order_expected = json.loads(raw), native_spec(cases()[order_case])
        require(order_expected['free_order'] == [2, 1], 'two-live-payload cancellation specification is absent')
        require(canonical(order_observed) == canonical({**order_expected, 'free_order': [1, 2]}),
                'wrong cleanup order did not isolate a correct-result, fully-freed order defect')
        report['negative_controls'].append({'name': 'wrong_cleanup_order', 'compilation': wrong_order_build,
               'case_index': order_case, 'link_process': wrong_order_link, 'run_process': wrong_order_run,
               'observed': order_observed, 'expected': order_expected, 'detected': True,
               'equivalent_to_original': False,
               'reason': 'correct scalar and allocator totals; initialized fields released in the wrong order'})
        report['source_after'] = source_identity()
        report['tools_after'] = {'clang': descriptor(clang), 'rust_vm': descriptor(rust_vm)}
        require(before == report['source_after'], 'qualification source changed during execution')
        require(tools_before == report['tools_after'], 'qualification tool changed during execution')
        report['claims']['finite_partial_record_execution'] = True
        report['claims']['two_live_payload_cancel_order_qualified'] = True
        report['status'], report['passed'] = 'passed', True
    except BaseException as error:
        report['status'], report['error'] = 'failed', {'type': type(error).__name__, 'message': str(error)}
        raise
    finally:
        write_json(output / 'report.json', report)
        files = [descriptor(path) for path in sorted(output.iterdir()) if path.is_file()]
        write_json(output / 'manifest.json', {'schema': 'hepta.hia.partial-record-manifest.v1', 'files': files})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-directory', required=True)
    parser.add_argument('--clang', required=True)
    parser.add_argument('--rust-vm', required=True)
    args = parser.parse_args()
    report = qualify(args.output_directory, args.clang, args.rust_vm)
    print(json.dumps({'status': report['status'], 'differential_cases': len(report['differential']),
                      'budget_cases': len(report['budgets']),
                      'native_case_executions': sum(len(value['cases']) for value in report['native'].values()),
                      'native_negative_controls': len(report['negative_controls'])}, sort_keys=True))


if __name__ == '__main__':
    main()
