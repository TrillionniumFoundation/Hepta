"""Independent v2 receipt and prewrite controls; no original finite input changes.

Policy corruption follows an actual policy entry. Raw guard inputs are explicitly
synthetic mechanical projections and never stand in for policy/original equality.
Native policy/raw groups use actual kernel entries. Callback controls use
an explicitly fake parent kernel and an actual nested child MEMFD.
"""
from __future__ import annotations

import argparse
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys
import traceback
import types

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / 'tests/fixtures/executable_capture_receipt_controls_v2.json'
INPUT_SHA256 = 'de826a9088681f446853ba137d6646402e2f1d0ea4b49c286e5c264bb087f092'
PREFIX = 'capture.receipt.v2.'
MASK = (1 << 64) - 1


class ControlError(Exception):
    pass


class FirstWriteReached(Exception):
    pass


def inputs():
    raw = INPUT.read_bytes()
    if sha256(raw).hexdigest() != INPUT_SHA256:
        raise ValueError('receipt control input identity differs')
    value = json.loads(raw)
    rows = value['ordered_controls']
    if (value['count'] != 72 or len(rows) != 72
            or value['ordered_ids'] != [row['id'] for row in rows]
            or len(set(value['ordered_ids'])) != 72):
        raise ValueError('receipt control complete order differs')
    return raw, value


def _owner(base, policy, effects, host):
    return types.SimpleNamespace(policy=types.SimpleNamespace(_entry=policy),
        effects=types.SimpleNamespace(_entry=effects), host_abi=host,
        check=base.check, retained_admitted_owner=base)


def _fake_base(entry, case=None):
    from tests.hia_executable_capture_originals import World
    from tests.test_hia_executable_capture import FakeKernelEntry
    world = World({'id': 'receipt-control', 'raw_hex': '616263', **(case or {})})
    def error(_class):
        world.raise_errno(ctypes.get_errno())
    owner = types.SimpleNamespace(policy=types.SimpleNamespace(_entry=entry),
        effects=types.SimpleNamespace(_entry=FakeKernelEntry(world)),
        host_abi=(None, world.audit, world.signals, error), check=lambda: None)
    return owner, world


def _unknown(operation, cls):
    try:
        operation()
    except cls as error:
        return error
    raise AssertionError('the declared invalid transport was accepted')


def _sticky(frame, counts):
    from hepta.hia_executable_capture import ExecutableCaptureUnknown
    before = tuple(counts())
    _unknown(frame.finish, ExecutableCaptureUnknown)
    if tuple(counts()) != before or frame.record.loss is None or frame.record.terminal:
        raise AssertionError('lost workspace was replayed or made terminal')


def _policy_trigger(label, q, r):
    if label.startswith('stale-active.after-'):
        prior = {'memfd': 1, 'write': 2, 'audit': 8, 'close': 7}[label.rsplit('-', 1)[1]]
        return q[2] == 1 and q[4] == prior
    if label.startswith('initial.'):
        return q[2] == 0
    if label in ('terminal.sequence-changed', 'kind.reply-success-state-error'):
        return r[2] == 2
    if label == 'terminal.error-identity-not-current':
        return r[2] == 3
    if label == 'event-two.error-handle-not-bound':
        return q[2] == 2
    if label == 'kind.reply-terminal-state-active':
        return q[2] == 1 and q[4] == 1
    if label == 'kind.reply-active-state-terminal':
        return r[2] == 2
    return q[2] == 1 and q[4] == 1


def policy_case(base, logical_id, *, actual_kernel):
    from hepta.hia_executable_capture import (
        _CaptureFrame, ExecutableCaptureUnknown, _sum_words)
    label = logical_id.removeprefix(PREFIX + 'policy.')
    counts = {'policy': [], 'raw': [], 'injected': 0, 'at_fault': None}
    previous = []
    frame_box = []
    audit_error = ControlError('actual-audit-error-for-close-receipt')
    needs_close = label in ('stale-active.after-close',
                            'event-two.error-handle-not-bound',
                            'terminal.error-identity-not-current')
    saved_policy, saved_raw = base.policy._entry, base.effects._entry
    def raw_entry(*args):
        q = struct.unpack('<12Q', ctypes.string_at(args[0], 96))
        status = saved_raw(*args)
        counts['raw'].append({'action': q[2], 'status': status,
            'state': list(struct.unpack('<12Q', ctypes.string_at(args[4], 96)))})
        return status
    saved_audit = base.host_abi[1]
    def audit(*args):
        answer = saved_audit(*args)
        if needs_close and args[0] == 'os.chmod':
            raise audit_error
        return answer
    def entry(*args):
        q = struct.unpack('<16Q', ctypes.string_at(args[0], 128))
        status = saved_policy(*args)
        if status != 128:
            raise AssertionError('control prerequisite policy entry was refused')
        current_receipt = ctypes.string_at(args[2], 128)
        current_state = ctypes.string_at(args[4], args[5])
        r = list(struct.unpack('<16Q', current_receipt))
        w = list(struct.unpack('<32Q', current_state[:256]))
        counts['policy'].append({'event': q[2], 'sequence': q[3], 'action': q[4],
                                 'kind': r[2], 'returned_sequence': r[3]})
        if counts['injected'] or not _policy_trigger(label, q, r):
            previous[:] = [(current_receipt, current_state)]
            return status
        counts['injected'] += 1
        counts['at_fault'] = (len(counts['policy']), len(counts['raw']))
        if label.startswith('stale-active.'):
            if len(previous) != 1:
                raise AssertionError('stale receipt prerequisite is missing')
            old_r, old_w = previous[0]
            ctypes.memmove(args[2], old_r, len(old_r))
            ctypes.memmove(args[4], old_w, len(old_w))
            return status
        if label == 'request.changed-during-entry':
            ctypes.memmove(ctypes.addressof(args[0]) + 128, b'X', 1)
            return status
        if label == 'output.canary-changed':
            ctypes.memmove(ctypes.addressof(args[2]) + 128, b'X', 1)
            return status
        if label == 'workspace.canary-changed':
            ctypes.memmove(ctypes.addressof(args[4]) + args[5], b'X', 1)
            return status
        if label == 'return.incomplete-status':
            return 127
        if label == 'terminal.error-identity-not-current':
            frame_box[0]._errors[r[9]] = ControlError('different-nonactive-error')
            return status
        if label == 'active.sequence-not-advanced':
            r[3] = w[5] = q[3]
        elif label == 'active.sequence-skips':
            r[3] = w[5] = q[3] + 2
        elif label == 'terminal.sequence-changed':
            r[3] = w[5] = q[3] + 1
        elif label == 'initial.kind-not-active':
            r[2] = r[12] = w[4] = 2
            r[4] = w[6] = 0
            r[5] = w[7] = 73
            r[6:9] = [0, 0, 0]
        elif label == 'initial.action-not-memfd':
            r[4] = w[6] = 2
            r[5] = w[7] = 73
            r[6:9] = [0, 3, 0]
        elif label == 'initial.sequence-not-one':
            r[3] = w[5] = 2
        elif label == 'kind.reply-active-state-terminal':
            r[2] = 1
        elif label == 'kind.reply-terminal-state-active':
            r[2] = 2
        elif label == 'kind.reply-success-state-error':
            r[12] = w[4] = 3
        elif label == 'event-two.error-handle-not-bound':
            r[9] = w[11] = q[6] - 1
        elif label == 'continuation.nonce-mismatch':
            r[10] = w[2] = r[10] ^ 1
        elif label == 'workspace.input-length-mismatch':
            w[9] += 1
        elif label == 'workspace.offset-out-of-range':
            w[8] = w[9] + 1
        elif label not in ('receipt.checksum-invalid', 'workspace.checksum-invalid'):
            raise AssertionError('unimplemented receipt control: ' + label)
        w[16] = _sum_words(struct.pack('<16Q', *w[:16]))
        r[13] = _sum_words(struct.pack('<13Q', *r[:13]))
        if label == 'receipt.checksum-invalid':
            r[13] ^= 1
        if label == 'workspace.checksum-invalid':
            w[16] ^= 1
        struct.pack_into('<16Q', args[2], 0, *r)
        struct.pack_into('<32Q', args[4], 0, *w)
        return status
    owner = _owner(base, entry, raw_entry,
                   (base.host_abi[0], audit, *base.host_abi[2:]))
    frame = _CaptureFrame(owner, b'abc')
    frame_box.append(frame)
    failure = _unknown(frame.finish, ExecutableCaptureUnknown)
    if (counts['injected'] != 1
            or counts['at_fault'] != (len(counts['policy']), len(counts['raw']))
            or frame.record.loss is None or frame.record.terminal
            or frame._last_child.loss is None or frame._last_child.terminal):
        raise AssertionError('corrupt actual policy receipt was confirmed or dispatched')
    _sticky(frame, lambda: (len(counts['policy']), len(counts['raw'])))
    if label == 'stale-active.after-close' and sum(r['action'] == 7 for r in counts['raw']) != 1:
        raise AssertionError('close must complete exactly once before withheld policy ACK')
    return {'id': logical_id, 'actual_policy_entry': True,
            'actual_kernel': actual_kernel, 'counts': counts,
            'error_type': type(failure).__name__, 'message': str(failure),
            'policy_child_unconfirmed': True, 'whole_unconfirmed': True,
            'same_workspace_refused': True, 'remaining_fds_owned_until_process_exit': actual_kernel}


def _synthetic_action(base, action, raw=b'abc'):
    from hepta.hia_executable_capture import (
        _CaptureFrame, STATE_MAGIC, RECEIPT_MAGIC, _sum_words)
    frame = _CaptureFrame(base, raw)
    n = len(raw)
    fd = MASK if action == 1 else 73
    w = [STATE_MAGIC, 1, *frame.nonce, 1, 1, action, fd, 0, n,
         0, 1 if action == 7 else 0, 0, 1 if action == 7 else 0, 0, 0, 0, *([0] * 15)]
    offset, count, arg = 0, 0, 0
    if action == 1:
        arg = 3
    elif action == 2:
        count = n
    elif action == 3:
        arg = 320
    elif action == 4:
        arg = 15
    elif action == 6:
        count = n + 1
    r = [RECEIPT_MAGIC, 1, 1, 1, action, fd, offset, count, arg,
         w[11], *frame.nonce, 1, 0, 0, 0]
    w[16] = _sum_words(struct.pack('<16Q', *w[:16]))
    r[13] = _sum_words(struct.pack('<13Q', *r[:13]))
    struct.pack_into('<32Q', frame.state, 0, *w)
    frame._accepted_policy, frame._accepted_state = tuple(r), tuple(w)
    return frame, r, w


def prewrite_case(base, logical_id):
    from hepta.hia_executable_capture import ExecutableCaptureUnknown, _sum_words
    label = logical_id.removeprefix(PREFIX)
    if label.startswith('raw-capacity.'):
        action = 6 if label.endswith(('workspace', 'policy-readback')) else 2
    else:
        part = label.split('.')[1]
        action = {'action-domain': 1, 'memfd': 1, 'nonmemfd': 2, 'write': 2,
                  'chmod': 3, 'add-seals': 4, 'get-seals': 5, 'pread': 6, 'close': 7}[part]
    raw_calls = []
    def never(*args):
        raw_calls.append(True)
        raise AssertionError('invalid raw guard reached a primitive')
    owner = _owner(base, base.policy._entry, never, base.host_abi)
    frame, r, w = _synthetic_action(owner, action)
    key = label.removeprefix('raw-operand.')
    if label.startswith('raw-capacity.'):
        attribute, size = {
            'raw-capacity.request': ('raw_request', 96 + 3 + 15),
            'raw-capacity.output': ('raw_output', 96 + 15),
            'raw-capacity.workspace': ('raw_state', 96 + 4 + 15),
            'raw-capacity.policy-readback': ('state', 257 + 3 + 15),
        }[label]
        setattr(frame, attribute, ctypes.create_string_buffer(size))
    elif key == 'action-domain':
        r[4] = w[6] = 8
        r[5] = w[7] = 73
        r[8] = w[15] = 3
    elif key == 'memfd.fd':
        r[5] = w[7] = 73
    elif key in ('memfd.offset', 'chmod.offset', 'add-seals.offset', 'get-seals.offset',
                 'pread.offset', 'close.offset'):
        r[6] = 1
    elif key in ('memfd.count', 'chmod.count', 'add-seals.count', 'get-seals.count', 'close.count'):
        r[7] = 1
    elif key == 'memfd.flags':
        r[8] = 1
    elif key == 'nonmemfd.fd':
        r[5] = w[7] = 2147483648
    elif key == 'write.offset':
        r[6] = 1
    elif key == 'write.count':
        r[7] = 4
    elif key == 'write.payload-length':
        # Same claimed action with a newly shorter immutable source object.
        # The actual raw length is rechecked before any write; no forged slice.
        frame.raw = b'ab'
    elif key in ('write.argument', 'get-seals.argument', 'pread.argument', 'close.argument'):
        r[8] = 1
    elif key == 'chmod.mode':
        r[8] = 511
    elif key == 'add-seals.argument':
        r[8] = 0
    elif key == 'pread.count-zero':
        r[7] = 0
    elif key == 'pread.count-over-capacity':
        r[7] = MASK
    elif key == 'pread.count-not-input-plus-one':
        r[7] = 3
    else:
        raise AssertionError('unimplemented raw guard: ' + label)
    w[16] = _sum_words(struct.pack('<16Q', *w[:16]))
    r[13] = _sum_words(struct.pack('<13Q', *r[:13]))
    # This is explicitly synthetic guard state, not an invented native ACK.
    if label != 'raw-capacity.policy-readback':
        struct.pack_into('<32Q', frame.state, 0, *w)
    frame._accepted_policy, frame._accepted_state = tuple(r), tuple(w)
    buffers = (frame.raw_request, frame.raw_output, frame.raw_state, frame.state)
    before = tuple(bytes(buffer) for buffer in buffers)
    writes = []
    saved = struct.pack_into, ctypes.memmove, ctypes.memset
    def guard(*args, **kwargs):
        writes.append(True)
        raise AssertionError('malformed raw parameters reached a buffer write')
    try:
        struct.pack_into = ctypes.memmove = ctypes.memset = guard
        failure = _unknown(lambda: frame._raw_effect(frame._accepted_policy), ExecutableCaptureUnknown)
    finally:
        struct.pack_into, ctypes.memmove, ctypes.memset = saved
    if writes or raw_calls or tuple(bytes(buffer) for buffer in buffers) != before:
        raise AssertionError('raw prewrite refusal changed storage or entered native')
    if frame.record.loss is not None or frame._started:
        raise AssertionError('safe synthetic preparation invented an effect or delivery loss')
    frame.record.retire()
    return {'id': logical_id, 'synthetic_projection': True, 'buffer_writes': 0,
            'raw_entries': 0, 'before_after_bytes_equal': True,
            'error_type': type(failure).__name__, 'message': str(failure),
            'not_policy_or_original_equivalence': True}


def valid_prewrite_boundaries(base):
    rows = []
    for n in (0, 1, 1 << 20):
        frame, _, _ = _synthetic_action(base, 6, b'x' * n)
        writes = []
        saved = struct.pack_into, ctypes.memmove, ctypes.memset
        def first(*args, **kwargs):
            writes.append(True)
            raise FirstWriteReached('valid prewrite admission reached its first write')
        try:
            struct.pack_into = ctypes.memmove = ctypes.memset = first
            try:
                frame._raw_effect(frame._accepted_policy)
            except FirstWriteReached:
                pass
            else:
                raise AssertionError('valid guard did not reach the first-write boundary')
        finally:
            struct.pack_into, ctypes.memmove, ctypes.memset = saved
        if len(writes) != 1 or frame._started or frame.record.loss is not None:
            raise AssertionError('valid prewrite control performed an effect')
        frame.record.retire()
        rows.append({'input_bytes': n, 'pread_count': n + 1,
                     'first_write_reached': True, 'raw_executed': False})
    return rows


def raw_loss_case(base, logical_id):
    from hepta.hia_executable_capture import _CaptureFrame, ExecutableCaptureUnknown
    label = logical_id.removeprefix(PREFIX + 'raw-loss.')
    name, loss_kind = label.split('.')
    target = {'memfd': 1, 'write': 2, 'chmod': 3, 'add-seals': 4,
              'get-seals': 5, 'pread': 6, 'close': 7}[name]
    injected = MemoryError('actual-raw-return-withheld-' + name)
    counts = {'policy': [], 'raw': [], 'injected': 0, 'at_fault': None}
    saved_policy, saved_raw = base.policy._entry, base.effects._entry
    def policy(*args):
        status = saved_policy(*args)
        counts['policy'].append(status)
        return status
    def raw_entry(*args):
        q = struct.unpack('<12Q', ctypes.string_at(args[0], 96))
        status = saved_raw(*args)
        r = struct.unpack('<12Q', ctypes.string_at(args[2], 96))
        w = struct.unpack('<12Q', ctypes.string_at(args[4], 96))
        counts['raw'].append({'action': q[2], 'request': list(q),
                              'status': status, 'receipt': list(r), 'state': list(w)})
        if q[2] == target and counts['injected'] == 0:
            if status != 96 or w[0] != 2 or r[3] != 2:
                raise AssertionError('actual raw return prerequisite was not complete')
            counts['injected'] = 1
            counts['at_fault'] = (len(counts['policy']), len(counts['raw']))
            if loss_kind == 'withheld':
                raise injected
            # Only the returned transport is corrupted, after the actual
            # syscall and its complete raw receipt have both been recorded.
            struct.pack_into('<Q', args[2], 40, r[5] ^ 1)
        return status
    saved_audit = base.host_abi[1]
    def audit(*args):
        answer = saved_audit(*args)
        if target == 7 and args[0] == 'os.chmod':
            raise ControlError('actual-audit-error-to-reach-one-close')
        return answer
    owner = _owner(base, policy, raw_entry,
                   (base.host_abi[0], audit, *base.host_abi[2:]))
    frame = _CaptureFrame(owner, b'abc')
    try:
        frame.finish()
    except BaseException as failure:
        caught = failure
    else:
        raise AssertionError('actual raw delivery loss was accepted')
    if loss_kind == 'withheld':
        if caught is not injected:
            raise AssertionError('the original injected MemoryError identity was replaced')
    elif not isinstance(caught, ExecutableCaptureUnknown):
        raise AssertionError('an inconsistent actual raw receipt was not UNKNOWN')
    if (counts['injected'] != 1
            or counts['at_fault'] != (len(counts['policy']), len(counts['raw']))
            or frame.record.loss is None or frame.record.terminal
            or frame._last_child.loss is None or frame._last_child.terminal):
        raise AssertionError('an unconfirmed actual raw effect continued or became terminal')
    if loss_kind == 'withheld' and frame.record.loss.error is not injected:
        raise AssertionError('actual child loss origin identity differs')
    _sticky(frame, lambda: (len(counts['policy']), len(counts['raw'])))
    if target == 7 and sum(row['action'] == 7 for row in counts['raw']) != 1:
        raise AssertionError('unknown close was retried')
    return {'id': logical_id, 'actual_policy_entry': True, 'actual_kernel': True,
            'counts': counts, 'error_type': type(caught).__name__, 'message': str(caught),
            'withheld_error_identity': loss_kind == 'withheld',
            'whole_unconfirmed': True, 'same_workspace_refused': True,
            'remaining_fds_owned_until_process_exit': True}


def negative_case(base, logical_id):
    from hepta.hia_executable_capture import _CaptureFrame
    counts = {'raw': [], 'fault_closes': 0, 'policy': []}
    saved_policy, saved_raw = base.policy._entry, base.effects._entry
    def policy(*args):
        status = saved_policy(*args)
        counts['policy'].append(status)
        return status
    def raw_entry(*args):
        q = struct.unpack('<12Q', ctypes.string_at(args[0], 96))
        if q[2] == 5 and counts['fault_closes'] == 0:
            # Explicit external fault: close this exact fd before the actual
            # GET_SEALS. The primitive must report real kernel -EBADF.
            os.close(q[3])
            counts['fault_closes'] += 1
        status = saved_raw(*args)
        r = struct.unpack('<12Q', ctypes.string_at(args[2], 96))
        w = struct.unpack('<12Q', ctypes.string_at(args[4], 96))
        counts['raw'].append({'action': q[2], 'status': status,
                              'receipt': list(r), 'state': list(w)})
        return status
    owner = _owner(base, policy, raw_entry, base.host_abi)
    frame = _CaptureFrame(owner, b'abc')
    try:
        frame.finish()
    except OSError as failure:
        caught = failure
    else:
        raise AssertionError('real negative syscall result did not raise its ordinary error')
    negative = [row for row in counts['raw'] if row['action'] in (5, 7)]
    if (counts['fault_closes'] != 1 or [r['action'] for r in negative] != [5, 7]
            or any(row['status'] != 96 or row['receipt'][4] != MASK - 8
                   or row['state'][0] != 2 or row['state'][2] != MASK - 8 for row in negative)
            or caught.errno != 9 or not isinstance(caught.__context__, OSError)
            or caught.__context__.errno != 9 or frame._known_error is not caught
            or frame.record.loss is not None or not frame.record.terminal
            or not frame.record.retired):
        raise AssertionError('complete negative receipt was not a confirmed ordinary error')
    before = (len(counts['policy']), len(counts['raw']))
    from hepta.hia_executable_capture import ExecutableCaptureUnknown
    _unknown(frame.finish, ExecutableCaptureUnknown)
    if before != (len(counts['policy']), len(counts['raw'])):
        raise AssertionError('a completed single-use frame was entered again')
    return {'id': logical_id, 'actual_policy_entry': True, 'actual_kernel': True,
            'explicit_external_fd_close': True, 'counts': counts,
            'error_type': type(caught).__name__, 'errno': caught.errno,
            'context_errno': caught.__context__.errno, 'original_error_identity': True,
            'ordinary_terminal_confirmed': True, 'loss_absent': True}


def callback_case(base, logical_id):
    from hepta.hia_executable_capture import _CaptureFrame, ExecutableCaptureUnknown
    signal = logical_id.endswith('signal.child-loss-replaced')
    fake_case = ({'kernel_fault': {'operation': 'WRITE', 'occurrence': 1, 'errno': 4}}
                 if signal else None)
    fake, world = _fake_base(base.policy._entry, fake_case)
    injected = MemoryError('actual-nested-memfd-delivery-withheld')
    replacement = ControlError('callback-replaced-the-actual-child-error')
    counts = {'parent_policy': [], 'parent_fake_raw': [], 'child_policy': [],
              'child_actual_raw': [], 'callbacks': 0, 'after_child_loss': None}
    children = []
    def parent_policy(*args):
        result = base.policy._entry(*args)
        counts['parent_policy'].append(result)
        return result
    def parent_raw(*args):
        q = struct.unpack('<12Q', ctypes.string_at(args[0], 96))
        result = fake.effects._entry(*args)
        counts['parent_fake_raw'].append(q[2])
        return result
    def child_policy(*args):
        result = base.policy._entry(*args)
        counts['child_policy'].append(result)
        return result
    def child_raw(*args):
        q = struct.unpack('<12Q', ctypes.string_at(args[0], 96))
        result = base.effects._entry(*args)
        w = struct.unpack('<12Q', ctypes.string_at(args[4], 96))
        counts['child_actual_raw'].append({'action': q[2], 'status': result, 'state': list(w)})
        if q[2] != 1 or result != 96 or w[0] != 2:
            raise AssertionError('nested actual MEMFD prerequisite differs')
        raise injected
    def nested():
        counts['callbacks'] += 1
        child = _CaptureFrame(_owner(base, child_policy, child_raw, base.host_abi), b'child')
        children.append(child)
        try:
            child.finish()
        except MemoryError as error:
            if error is not injected:
                raise AssertionError('nested original error identity changed')
        else:
            raise AssertionError('nested child delivery was not lost')
        counts['after_child_loss'] = (
            len(counts['parent_policy']), len(counts['parent_fake_raw']),
            len(counts['child_policy']), len(counts['child_actual_raw']))
        if signal:
            raise replacement
    def audit(*args):
        result = world.audit(*args)
        if not signal and args[0] == 'os.chmod':
            nested()  # Deliberately swallowed by the provider.
        return result
    def signals():
        result = world.signals()
        nested()  # Deliberately replaced by a different ordinary provider error.
        return result
    owner = _owner(base, parent_policy, parent_raw,
                   (fake.host_abi[0], audit, signals, fake.host_abi[3]))
    frame = _CaptureFrame(owner, b'abc')
    try:
        frame.finish()
    except BaseException as failure:
        caught = failure
    else:
        raise AssertionError('callback child loss became an ordinary returned outcome')
    actual_counts = lambda: (
        len(counts['parent_policy']), len(counts['parent_fake_raw']),
        len(counts['child_policy']), len(counts['child_actual_raw']))
    if (counts['callbacks'] != 1 or len(children) != 1
            or counts['after_child_loss'] != actual_counts()
            or frame.record.loss is None or frame.record.loss.error is not injected
            or frame.record.terminal or children[0].record.loss is not frame.record.loss
            or children[0].record.terminal):
        raise AssertionError('actual child loss did not remain causal and unconfirmed')
    if signal:
        if caught is not replacement:
            raise AssertionError('ordinary replacement identity changed')
    elif not isinstance(caught, ExecutableCaptureUnknown):
        raise AssertionError('swallowed child loss did not refuse the parent continuation')
    _sticky(frame, actual_counts)
    _sticky(children[0], actual_counts)
    world.verify_faults()
    return {'id': logical_id, 'actual_parent_policy_entry': True,
            'parent_kernel_is_explicit_fake': True, 'actual_child_kernel': True,
            'counts': counts, 'error_type': type(caught).__name__,
            'message': str(caught), 'actual_child_loss_origin_identity': True,
            'ordinary_replacement_identity': signal,
            'whole_unconfirmed': True, 'same_workspace_refused': True,
            'remaining_child_fd_owned_until_process_exit': True}


def _pin(path, raw):
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def _capture_sources():
    from hepta.hia_executable_capture import SOURCE_INPUTS
    names = tuple(dict.fromkeys((*SOURCE_INPUTS,
        'tests/hia_executable_capture_receipt_controls.py',
        'tests/test_hia_executable_capture_receipt.py',
        'tests/fixtures/executable_capture_receipt_controls_v2.json')))
    captured = []
    for name in names:
        path = ROOT / name
        raw = path.read_bytes()
        captured.append((path, raw))
    return captured


def _select_rows(table, group):
    kind = {'policy': 'policy_receipt', 'prewrite': 'mechanical_prewrite_guard',
            'raw': 'actual_raw_completion_then_withheld_receipt',
            'callbacks': 'actual_causal_resource_loss'}
    if group == 'raw':
        return [row for row in table['ordered_controls']
                if row['kind'] in (kind[group], 'actual_raw_completion_then_inconsistent_receipt',
                                   'complete_negative_receipt')]
    return [row for row in table['ordered_controls'] if row['kind'] == kind[group]]


def run(args):
    raw_input, table = inputs()
    sources = _capture_sources()
    rows = _select_rows(table, args.group)
    expected_count = {'policy': 24, 'prewrite': 31, 'raw': 15, 'callbacks': 2}[args.group]
    if len(rows) != expected_count or (args.mode == 'vm' and args.group not in ('policy', 'prewrite')):
        raise ValueError('new complete control group differs')
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    plan = {'schema': 'hepta.executable-capture.receipt-control-plan.v2',
            'mode': args.mode, 'group': args.group, 'ordered_ids': [row['id'] for row in rows],
            'input': _pin(INPUT, raw_input), 'count': expected_count,
            'source_pins': [_pin(path, raw) for path, raw in sources],
            'whole_native_closed': False, 'ordinary_route_changed': False,
            'legacy_removal_authorized': False}
    (output / 'planned.json').write_text(json.dumps(plan, indent=2, sort_keys=True) + '\n')
    if args.mode == 'vm':
        from tests.test_hia_executable_capture import VMEntry
        entry = VMEntry()
        base, _ = _fake_base(entry)
    else:
        from hepta.hia_executable_capture import load_executable_capture
        base = load_executable_capture(args.manifest, args.manifest_sha256,
                                       allow_development=args.development == '1')
    started, stopped, results, failures = [], [], [], []
    for row in rows:
        logical_id = row['id']
        started.append(logical_id)
        try:
            if args.group == 'policy':
                if args.mode == 'vm':
                    local, _ = _fake_base(entry)
                else:
                    local = base
                result = policy_case(local, logical_id, actual_kernel=args.mode == 'native')
            elif args.group == 'prewrite':
                result = prewrite_case(base, logical_id)
            elif row['kind'] in ('actual_raw_completion_then_withheld_receipt',
                                  'actual_raw_completion_then_inconsistent_receipt'):
                result = raw_loss_case(base, logical_id)
            elif row['kind'] == 'complete_negative_receipt':
                result = negative_case(base, logical_id)
            else:
                result = callback_case(base, logical_id)
        except BaseException as error:
            result = {'id': logical_id, 'status': 'FAIL',
                      'error_type': type(error).__name__, 'message': str(error),
                      'traceback': ''.join(traceback.format_exception(error))}
            failures.append(logical_id)
        else:
            result['status'] = 'PASS'
        stopped.append(logical_id)
        results.append(result)
        # Each real result is flushed independently. A killed child has only
        # its honest prefix, never a fabricated complete report.
        (output / (sha256(logical_id.encode()).hexdigest() + '.json')).write_text(
            json.dumps(result, indent=2, sort_keys=True) + '\n')
    boundaries = []
    if args.group == 'prewrite':
        boundaries = valid_prewrite_boundaries(base)
    drift = [str(path) for path, raw in sources if path.read_bytes() != raw]
    if INPUT.read_bytes() != raw_input:
        drift.append(str(INPUT))
    report = {'schema': 'hepta.executable-capture.receipt-control-report.v2',
              'status': 'PASS' if not failures and not drift else 'FAIL',
              'mode': args.mode, 'group': args.group, 'planned': plan['ordered_ids'],
              'started': started, 'stopped': stopped, 'count': expected_count,
              'results': results, 'failures': failures, 'source_drift': drift,
              'valid_prewrite_boundaries': boundaries, 'input': plan['input'],
              'source_pins': plan['source_pins'], 'actual_pid': os.getpid(),
              'actual_pgid': os.getpgrp(), 'actual_runtime': sys.version,
              'whole_native_closed': False, 'ordinary_route_changed': False,
              'legacy_removal_authorized': False}
    (output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'status': report['status'], 'count': expected_count,
                      'failures': failures, 'source_drift': drift}, sort_keys=True))
    return 0 if report['status'] == 'PASS' else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', required=True, choices=('vm', 'native'))
    parser.add_argument('--group', required=True, choices=('policy', 'prewrite', 'raw', 'callbacks'))
    parser.add_argument('--output', required=True)
    parser.add_argument('--manifest')
    parser.add_argument('--manifest-sha256')
    parser.add_argument('--development', choices=('0', '1'), default='0')
    args = parser.parse_args()
    if args.mode == 'native' and (args.manifest is None or args.manifest_sha256 is None):
        parser.error('native controls require the exact explicit manifest and expected SHA')
    return run(args)


if __name__ == '__main__':
    raise SystemExit(main())
