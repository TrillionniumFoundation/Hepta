"""Bound external test-workflow steps without altering any product qualification gate.

This supervisor observes only its POSIX process group. It does not replace the
Selfhost-Core owner's 180-second deadline or its stronger subreaper/ECHILD proof.
"""
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def run_workflow_step(command, *, cwd, env, stdout_path, stderr_path,
                      receipt_path, seconds):
    assert 0 < seconds <= 7200
    stdout_path, stderr_path, receipt_path = map(Path, (stdout_path, stderr_path, receipt_path))
    assert not any(p.exists() for p in (stdout_path, stderr_path, receipt_path))
    started = time.monotonic()
    timed_out = False
    cleanup_errors = []
    signalled = []
    with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            returncode = process.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            returncode = None
        try:
            os.killpg(process.pid, 0)
            group_alive = True
        except ProcessLookupError:
            group_alive = False
        if group_alive:
            for sig, grace in ((signal.SIGTERM, 1), (signal.SIGKILL, 2)):
                try:
                    os.killpg(process.pid, sig)
                    signalled.append(sig.name)
                except ProcessLookupError:
                    break
                deadline = time.monotonic() + grace
                while time.monotonic() < deadline:
                    process.poll()
                    try:
                        os.killpg(process.pid, 0)
                    except ProcessLookupError:
                        break
                    time.sleep(0.01)
                else:
                    continue
                break
        try:
            returncode = process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            cleanup_errors.append('workflow leader could not be reaped')
        try:
            os.killpg(process.pid, 0)
            group_gone = False
        except ProcessLookupError:
            group_gone = True
    completed = returncode == 0 and not timed_out and not group_alive and group_gone and not cleanup_errors
    report = {'schema':'hepta.hia.external-workflow-process.v1',
              'status':'WORKFLOW_STEP_COMPLETED' if completed else 'WORKFLOW_STEP_HOLD',
              'command':list(command), 'cwd':str(cwd), 'returncode':returncode,
              'timed_out':timed_out,'seconds':time.monotonic()-started,
              'workflow_seconds':seconds,
              'cleanup':{'scope':'started POSIX process group only','complete':group_gone,
                         'full_process_tree_claimed':False,'signalled':signalled,'errors':cleanup_errors},
              'selfhost_qualification_gate_modified':False,
              'logs':{str(p):sha256(p.read_bytes()).hexdigest() for p in (stdout_path,stderr_path)}}
    receipt_path.write_text(json.dumps(report,indent=2)+'\n')
    return report
