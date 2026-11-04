"""Bounded Linux capture for the frozen seven-certificate acceptance protocol.

Only the original process group is contained. In particular, this does not claim
containment of descendants which deliberately create a different session/group.
No Popen poll/wait/communicate is used: the leader stays unreaped until SIGKILL.
"""
from __future__ import annotations

import codecs
import errno
import hashlib
import os
import selectors
import signal
import stat
import subprocess
import time

PROCESS_NS = 60_000_000_000
CLEANUP_NS = 2_000_000_000
RAW_STAGE = 507_392
RAW_GLOBAL = 825_336


def unspawned_process():
    """The closed, explicitly unobserved process record."""
    return dict(spawned=False, returncode=None, timed_out=False,
                incomplete=False, output_truncated=False, leader_reaped=False,
                stdout_eof=False, stderr_eof=False, original_group_empty=False,
                elapsed_ns=0, cleanup_ns=0, leader_pid=None, original_pgid=None,
                leader_start_ticks=None, terminal_observation="not_observed",
                pre_reap_group_signal="not_attempted", leader_reap_observed=False,
                post_reap_group_probe="not_observed")


def _leader_identity(pid):
    # /proc stat comm can contain spaces and ')'; all subsequent fields cannot.
    with open(f"/proc/{pid}/stat", "rb", buffering=0) as stream:
        raw = stream.read(4097)
    if len(raw) > 4096 or not raw.startswith(str(pid).encode() + b" ("):
        raise ValueError("process identity")
    fields = raw[raw.rindex(b")") + 2:].split()
    if int(fields[2]) != pid or int(fields[3]) != pid:
        raise ValueError("session identity")
    ticks = int(fields[19])
    if not 0 <= ticks <= 18_446_744_073_709_551_615:
        raise ValueError("start ticks")
    return ticks


def capture(argv, *, cwd, env, stdout_path, stderr_path, raw_remaining,
            launch_deadline_ns):
    """Return {process, logs, error_code}; never turn incomplete output into success.

    Callers supply the remaining aggregate allowance, never a larger budget.
    Deadlines are absolute monotonic nanoseconds. Limits have no runtime knobs.
    Log files must not already exist. Parent validation owns ancestor identity.
    """
    p = unspawned_process()
    result = dict(process=p, logs=None, error_code=None)
    if (type(raw_remaining) is not int or not 0 <= raw_remaining <= RAW_GLOBAL
            or type(launch_deadline_ns) is not int or launch_deadline_ns < 0):
        result["error_code"] = "capture_incomplete"
        return result
    outputs = {}
    paths = {"stdout": stdout_path, "stderr": stderr_path}
    try:
        for name, path in paths.items():
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            outputs[name] = fd
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise OSError(errno.EINVAL, "capture file")
    except (OSError, ValueError, TypeError):
        for name, fd in outputs.items():
            # Unlink only the same exclusively created inode, never a replacement.
            try:
                opened = os.fstat(fd)
                named = os.lstat(paths[name])
                if (opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino):
                    os.unlink(paths[name])
            except OSError:
                pass
            finally:
                os.close(fd)
        result["error_code"] = "filesystem_invalid"
        return result
    hashes = {name: hashlib.sha256() for name in outputs}
    counts = {name: 0 for name in outputs}
    decoders = {name: codecs.getincrementaldecoder("utf-8")("strict") for name in outputs}
    used = 0
    child = None
    selector = None
    killed_at = None
    started = None
    broken_capture = False

    def fail(code):
        if result["error_code"] is None:
            result["error_code"] = code

    def kill_original_group():
        nonlocal killed_at
        if child is None or killed_at is not None:
            return
        # Establish the cleanup deadline before the one and only nonzero signal.
        # No operation in this module reaps the child before this function.
        killed_at = time.monotonic_ns()
        p["elapsed_ns"] = killed_at - started
        if p["elapsed_ns"] >= PROCESS_NS:
            p["timed_out"] = True
            fail("process_timeout")
        try:
            os.killpg(child.pid, signal.SIGKILL)
            p["pre_reap_group_signal"] = "sigkill_sent"
        except ProcessLookupError:
            p["pre_reap_group_signal"] = "sigkill_no_signalable_group"
        except OSError:
            p["pre_reap_group_signal"] = "failed"
            fail("cleanup_failed")

    def within_window():
        """Check between bounded I/O operations; a blocking syscall cannot be preempted.

        On return from such a syscall, kill immediately if the process deadline
        elapsed, or reject cleanup if its fixed window expired. Never hide an
        overrun by clipping the serialized duration into an accepting record.
        """
        if child is None:
            return True
        now = time.monotonic_ns()
        if killed_at is None and now >= started + PROCESS_NS:
            p["timed_out"] = True
            fail("process_timeout")
            kill_original_group()
            now = time.monotonic_ns()
        if killed_at is not None and now >= killed_at + CLEANUP_NS:
            p["incomplete"] = True
            result["error_code"] = "cleanup_failed"
            return False
        return True

    def consume(name, data):
        nonlocal used, broken_capture
        if broken_capture or not within_window():
            return
        allowance = min(RAW_STAGE - used, raw_remaining - used)
        if len(data) > allowance:
            p["output_truncated"] = True
            fail("output_limit")
            kill_original_group()
            data = data[:allowance]
        if not data:
            return
        # Reserve both counters before any write. Actual retained counts/hashes
        # are updated per successful write, including a partial write on failure.
        used += len(data)
        try:
            decoders[name].decode(data, final=False)
        except UnicodeError:
            fail("capture_incomplete")
            p["incomplete"] = True
            kill_original_group()
        try:
            view = memoryview(data)
            while view:
                if not within_window():
                    return
                written = os.write(outputs[name], view)
                if written <= 0:
                    raise OSError(errno.EIO, "short capture write")
                hashes[name].update(view[:written])
                counts[name] += written
                view = view[written:]
                if not within_window():
                    return
        except OSError:
            fail("filesystem_invalid")
            p["incomplete"] = True
            broken_capture = True
            kill_original_group()

    def drain(timeout):
        for key, _ in selector.select(timeout):
            if not within_window():
                return
            name = key.data
            try:
                data = os.read(key.fd, 65536 if p["output_truncated"] else
                               min(65536, max(1, min(RAW_STAGE, raw_remaining) - used + 1)))
            except BlockingIOError:
                continue
            if not within_window():
                return
            if data:
                consume(name, data)
            else:
                selector.unregister(key.fileobj)
                p[name + "_eof"] = True
                try:
                    decoders[name].decode(b"", final=True)
                except UnicodeError:
                    fail("capture_incomplete")
                    p["incomplete"] = True
                    kill_original_group()

    try:
        selector = selectors.DefaultSelector()
        # Last clock check immediately adjacent to spawn, after log preparation.
        started = time.monotonic_ns()
        if started >= launch_deadline_ns:
            fail("launch_deadline")
        else:
            child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     start_new_session=True, close_fds=True, bufsize=0)
            p.update(spawned=True, leader_pid=child.pid, original_pgid=child.pid)
            # Popen includes process setup and may itself block. A pre-call
            # clock check alone cannot prove that the child was established
            # before the launch cutoff. Reject uncertainty without treating an
            # already-created child as an unspawned prelaunch failure.
            if time.monotonic_ns() >= launch_deadline_ns:
                p["incomplete"] = True
                fail("capture_incomplete")
                kill_original_group()
            else:
                p["leader_start_ticks"] = _leader_identity(child.pid)
                for name in ("stdout", "stderr"):
                    stream = getattr(child, name)
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, name)
                deadline = started + PROCESS_NS
                while killed_at is None:
                    now = time.monotonic_ns()
                    if now >= deadline:
                        p["timed_out"] = True
                        fail("process_timeout")
                        kill_original_group()
                        break
                    observed = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    if observed is not None:
                        p["terminal_observation"] = "waitid_wnowait"
                        kill_original_group()
                        break
                    drain(min(0.01, (deadline - now) / 1_000_000_000))
    except (Exception, KeyboardInterrupt):
        fail("capture_incomplete" if child is not None else "process_failed")
        p["incomplete"] = child is not None
        kill_original_group()
    finally:
        if child is not None:
            kill_original_group()
            cleanup_deadline = killed_at + CLEANUP_NS
            # Setup itself can fail after spawn; retain/observe each available pipe.
            for name in ("stdout", "stderr"):
                stream = getattr(child, name)
                try:
                    if not p[name + "_eof"] and stream not in selector.get_map():
                        os.set_blocking(stream.fileno(), False)
                        selector.register(stream, selectors.EVENT_READ, name)
                except (OSError, KeyError, ValueError):
                    p["incomplete"] = True
                    fail("capture_incomplete")
            while time.monotonic_ns() < cleanup_deadline:
                try:
                    if not p["leader_reaped"]:
                        pid, status = os.waitpid(child.pid, os.WNOHANG)
                        if pid == child.pid:
                            p["returncode"] = os.waitstatus_to_exitcode(status)
                            child.returncode = p["returncode"]
                            p["leader_reaped"] = True
                            p["leader_reap_observed"] = True
                    if p["leader_reaped"]:
                        # Emptiness is the latest observation, not a latched
                        # historical ESRCH (the numeric pgid may be reused).
                        p["original_group_empty"] = False
                        try:
                            os.killpg(child.pid, 0)
                            p["post_reap_group_probe"] = "group_exists"
                        except ProcessLookupError:
                            p["post_reap_group_probe"] = "esrch"
                            p["original_group_empty"] = True
                        except OSError:
                            p["post_reap_group_probe"] = "unknown_or_permission_error"
                            break
                    if (p["leader_reaped"] and p["stdout_eof"] and p["stderr_eof"]
                            and p["original_group_empty"]
                            and p["post_reap_group_probe"] == "esrch"):
                        break
                    remaining = cleanup_deadline - time.monotonic_ns()
                    if remaining <= 0:
                        break
                    drain(min(0.01, remaining / 1_000_000_000))
                except (Exception, KeyboardInterrupt):
                    p["incomplete"] = True
                    fail("capture_incomplete")
                    # A failed read must not skip a still-possible bounded reap.
                    remaining = cleanup_deadline - time.monotonic_ns()
                    if remaining > 0:
                        time.sleep(min(0.01, remaining / 1_000_000_000))
            cleanup_elapsed = time.monotonic_ns() - killed_at
            p["cleanup_ns"] = min(CLEANUP_NS, cleanup_elapsed)
            if cleanup_elapsed >= CLEANUP_NS or not (p["leader_reaped"] and p["stdout_eof"] and p["stderr_eof"]
                    and p["original_group_empty"]
                    and p["post_reap_group_probe"] == "esrch"
                    and p["pre_reap_group_signal"] in
                    ("sigkill_sent", "sigkill_no_signalable_group")):
                p["incomplete"] = True
                result["error_code"] = "cleanup_failed"
            elif p["returncode"] != 0:
                fail("process_failed")
            for name in ("stdout", "stderr"):
                stream = getattr(child, name)
                if stream is not None:
                    stream.close()
        if selector is not None:
            selector.close()
        for name, fd in outputs.items():
            try:
                os.fsync(fd)
                info = os.fstat(fd)
                named = os.lstat(paths[name])
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or info.st_size != counts[name]
                        or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
                    raise OSError(errno.EINVAL, "capture changed")
            except OSError:
                fail("filesystem_invalid")
                p["incomplete"] = bool(child)
            finally:
                os.close(fd)
        if killed_at is not None:
            # File persistence is not extra compiler computation time. Still
            # fail conservatively if it pushes capture past the cleanup window.
            cleanup_elapsed = time.monotonic_ns() - killed_at
            p["cleanup_ns"] = min(CLEANUP_NS, cleanup_elapsed)
            if cleanup_elapsed >= CLEANUP_NS:
                p["incomplete"] = True
                result["error_code"] = "cleanup_failed"
        result["logs"] = {name: {"sha256": hashes[name].hexdigest(), "bytes": counts[name]}
                          for name in ("stdout", "stderr")}
    return result
