#!/usr/bin/env python3
"""Contain one Linux command tree in a dedicated child-subreaper process."""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time


SCHEMA = 'hepta.hia.process-tree-cleanup.v1'
TERM_GRACE_SECONDS = 0.25
KILL_GRACE_SECONDS = 4.0
POLL_SECONDS = 0.005
STOP_SIGNAL = None


def set_child_subreaper():
    if sys.platform != 'linux':
        raise OSError('Linux child-subreaper support is required')
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def process_stat(pid):
    text = (Path('/proc') / str(pid) / 'stat').read_text()
    fields = text.rsplit(')', 1)[1].split()
    return {'pid': pid, 'state': fields[0], 'ppid': int(fields[1]),
            'pgid': int(fields[2]), 'session': int(fields[3]),
            'start_ticks': int(fields[19])}


def direct_children(parent_pid):
    children = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            row = process_stat(int(entry.name))
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        if row['ppid'] == parent_pid:
            children.append(row)
    return sorted(children, key=lambda row: row['pid'])


def live_group_members(group):
    members = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            row = process_stat(int(entry.name))
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        if row['pgid'] == group and row['state'] not in ('Z', 'X'):
            if row['session'] != group:
                raise ValueError('target process group changed its session identity')
            members.append(row)
    return sorted(members, key=lambda row: row['pid'])


def reap_children(supervisor_pid, target):
    for row in direct_children(supervisor_pid):
        if target is not None and row['pid'] == target.pid:
            target.poll()
            continue
        try:
            os.waitpid(row['pid'], os.WNOHANG)
        except ChildProcessError:
            pass


def live_children(supervisor_pid, target):
    reap_children(supervisor_pid, target)
    return [row for row in direct_children(supervisor_pid) if row['state'] not in ('Z', 'X')]


def record_error(errors, phase, error):
    errors.append({'phase': phase, 'type': type(error).__name__, 'message': str(error)})


def signal_child(supervisor_pid, row, sig, signals, errors):
    try:
        current = process_stat(row['pid'])
    except (FileNotFoundError, ProcessLookupError):
        return
    except OSError as error:
        record_error(errors, 'verify-child-before-signal', error)
        return
    if (current['ppid'] != supervisor_pid or current['start_ticks'] != row['start_ticks']
            or current['state'] in ('Z', 'X')):
        return
    try:
        os.kill(row['pid'], sig)
        item = {'scope': 'adopted-child', 'pid': row['pid'], 'signal': sig.name}
        if item not in signals:
            signals.append(item)
    except ProcessLookupError:
        pass
    except OSError as error:
        record_error(errors, 'signal-adopted-child', error)


def signal_group(group, sig, signals, errors):
    try:
        os.killpg(group, sig)
        item = {'scope': 'target-process-group', 'group': group, 'signal': sig.name}
        if item not in signals:
            signals.append(item)
    except ProcessLookupError:
        pass
    except OSError as error:
        record_error(errors, 'signal-target-process-group', error)


def terminate_tree(supervisor_pid, target):
    started = time.monotonic_ns()
    signals = []
    errors = []
    before = live_children(supervisor_pid, target)
    if target is not None:
        signal_group(target.pid, signal.SIGTERM, signals, errors)
    term_deadline = time.monotonic() + TERM_GRACE_SECONDS
    while True:
        children = live_children(supervisor_pid, target)
        if not children:
            break
        for row in children:
            if target is None or row['pid'] != target.pid:
                signal_child(supervisor_pid, row, signal.SIGTERM, signals, errors)
        if time.monotonic() >= term_deadline:
            break
        time.sleep(POLL_SECONDS)
    kill_deadline = time.monotonic() + KILL_GRACE_SECONDS
    while True:
        children = live_children(supervisor_pid, target)
        group_members = live_group_members(target.pid) if target is not None else []
        if not children and not group_members:
            break
        if target is not None:
            signal_group(target.pid, signal.SIGKILL, signals, errors)
        for row in children:
            if target is None or row['pid'] != target.pid:
                signal_child(supervisor_pid, row, signal.SIGKILL, signals, errors)
        if time.monotonic() >= kill_deadline:
            break
        time.sleep(POLL_SECONDS)
    after = live_children(supervisor_pid, target)
    group_after = live_group_members(target.pid) if target is not None else []
    drained = not after and not group_after
    if not drained:
        errors.append({'phase': 'final-observation', 'type': 'LiveDescendantsRemain',
                       'message': json.dumps({'children': after, 'target_group': group_after},
                                             sort_keys=True, separators=(',', ':'))})
    return {'adopted_children_before_cleanup': before,
            'adopted_children_after_cleanup': after,
            'target_group_members_after': group_after, 'signals': signals,
            'errors': errors, 'drained': drained,
            'elapsed_ns': time.monotonic_ns() - started}


def request_stop(signum, frame):
    global STOP_SIGNAL
    if STOP_SIGNAL is None:
        STOP_SIGNAL = signum


def write_result(path, value):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, separators=(',', ':'), allow_nan=False)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def main():
    if len(sys.argv) < 5 or sys.argv[3] != '--' or not sys.argv[4:]:
        return 125
    result_path, cwd, argv = sys.argv[1], sys.argv[2], sys.argv[4:]
    supervisor_pid = os.getpid()
    before_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    target = None
    started = time.monotonic_ns()
    errors = []
    group_before = []
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, request_stop)
    try:
        set_child_subreaper()
        if STOP_SIGNAL is not None:
            raise RuntimeError('supervisor interrupted before target spawn')
        target = subprocess.Popen(argv, cwd=cwd, start_new_session=True)
        while target.poll() is None and STOP_SIGNAL is None:
            time.sleep(POLL_SECONDS)
        if STOP_SIGNAL is not None or target.poll() is None:
            cleanup = terminate_tree(supervisor_pid, target)
        else:
            children_before = live_children(supervisor_pid, target)
            group_before = live_group_members(target.pid)
            if children_before or group_before:
                cleanup = terminate_tree(supervisor_pid, target)
            else:
                cleanup = {'adopted_children_before_cleanup': [],
                           'adopted_children_after_cleanup': [],
                           'target_group_members_after': [], 'signals': [],
                           'errors': [], 'drained': True, 'elapsed_ns': 0}
        target_exit_code = target.poll() if target.poll() is not None else None
        incomplete = (STOP_SIGNAL is not None or bool(cleanup['adopted_children_before_cleanup'])
                      or bool(group_before) or not cleanup['drained'])
        after_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        receipt = {
            'schema': SCHEMA, 'supervisor_pid': supervisor_pid,
            'target_pid': target.pid, 'target_process_group': target.pid,
            'target_exit_code': target_exit_code, 'interrupted_signal': STOP_SIGNAL,
            'incomplete_process_tree': bool(incomplete),
            'adopted_children_before_cleanup': cleanup['adopted_children_before_cleanup'],
            'adopted_children_after_cleanup': cleanup['adopted_children_after_cleanup'],
            'target_group_members_after': cleanup['target_group_members_after'],
            'signals': cleanup['signals'], 'errors': errors + cleanup['errors'],
            'drained': cleanup['drained'], 'elapsed_ns': time.monotonic_ns() - started,
            'child_user_seconds': max(0.0, after_usage.ru_utime - before_usage.ru_utime),
            'child_system_seconds': max(0.0, after_usage.ru_stime - before_usage.ru_stime),
        }
    except BaseException as error:
        record_error(errors, 'supervisor', error)
        if target is not None:
            cleanup = terminate_tree(supervisor_pid, target)
            after_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
            receipt = {
                'schema': SCHEMA, 'supervisor_pid': supervisor_pid,
                'target_pid': target.pid, 'target_process_group': target.pid,
                'target_exit_code': target.poll() if target.poll() is not None else None,
                'interrupted_signal': STOP_SIGNAL, 'incomplete_process_tree': True,
                'adopted_children_before_cleanup': cleanup['adopted_children_before_cleanup'],
                'adopted_children_after_cleanup': cleanup['adopted_children_after_cleanup'],
                'target_group_members_after': cleanup['target_group_members_after'],
                'signals': cleanup['signals'], 'errors': errors + cleanup['errors'],
                'drained': cleanup['drained'], 'elapsed_ns': time.monotonic_ns() - started,
                'child_user_seconds': max(0.0, after_usage.ru_utime - before_usage.ru_utime),
                'child_system_seconds': max(0.0, after_usage.ru_stime - before_usage.ru_stime),
            }
        else:
            after_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
            receipt = {
                'schema': SCHEMA, 'supervisor_pid': supervisor_pid,
                'target_pid': None, 'target_process_group': None, 'target_exit_code': 127,
                'interrupted_signal': STOP_SIGNAL, 'incomplete_process_tree': True,
                'adopted_children_before_cleanup': [], 'adopted_children_after_cleanup': [],
                'target_group_members_after': [], 'signals': [], 'errors': errors,
                'drained': False, 'elapsed_ns': time.monotonic_ns() - started,
                'child_user_seconds': max(0.0, after_usage.ru_utime - before_usage.ru_utime),
                'child_system_seconds': max(0.0, after_usage.ru_stime - before_usage.ru_stime),
            }
    try:
        write_result(result_path, receipt)
    except OSError:
        return 125
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
