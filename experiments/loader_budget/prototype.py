"""Isolated bounded regular-file reader, not wired into any production loader.

Bounds byte materialization, not filesystem latency, parser work or native code.
"""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import threading


class Rejected(ValueError):
    pass


@dataclass(frozen=True)
class Limits:
    per_file: int = 1_000_000
    total_bytes: int = 16_000_000
    reads: int = 256
    chunk_bytes: int = 64 * 1024

    def __post_init__(self):
        for value in (self.per_file, self.total_bytes, self.reads, self.chunk_bytes):
            if type(value) is not int or value <= 0:
                raise ValueError('limits must be positive integers')


class Reader:
    """One request, including repeated reads; no cached-byte authorization.

    checkpoint is a cooperative deadline hook. Every attempted read consumes one
    invocation; bytes actually returned by the OS are charged, including the one
    overflow sentinel. Rejection makes this object terminal.
    """
    def __init__(self, limits=Limits(), checkpoint=lambda: None, *, on_failure=None):
        self.limits = limits
        self.on_failure = on_failure
        self.checkpoint = checkpoint
        self.bytes_read = 0
        self.reads = 0
        self.closed = False
        self._active = threading.Lock()

    def _reject(self, message, **provenance):
        if self.on_failure is not None:
            self.on_failure(phase='read', **provenance)
        raise Rejected(message)

    def _check(self):
        if self.closed:
            self._reject('reader is terminal', category='terminal')
        self.checkpoint()

    def _chunks(self, path, max_bytes=None):
        if not self._active.acquire(blocking=False):
            self.closed = True
            self._reject('overlapping reader operations are not admitted', category='reentrancy')
        fd = None
        try:
            self._check()
            if max_bytes is not None and (type(max_bytes) is not int or max_bytes <= 0):
                self._reject('invalid per-read byte quota', category='schema')
            if self.reads >= self.limits.reads:
                self._reject('read invocation quota exceeded', category='budget', dimension='reads', limit=self.limits.reads, admitted=self.reads, attempted=self.reads + 1)
            self.reads += 1
            # Nonblocking open prevents a FIFO substituted after path checks from
            # hanging before fstat. fstat checks the opened object, not its name.
            fd = os.open(Path(path), os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                self._reject('only regular files are admitted', category='schema')
            remaining = self.limits.total_bytes - self.bytes_read
            cap = min(self.limits.per_file, remaining,
                      self.limits.per_file if max_bytes is None else max_bytes)
            aggregate = remaining <= min(self.limits.per_file, self.limits.per_file if max_bytes is None else max_bytes)
            dimension = 'total_bytes' if aggregate else 'per_file'
            limit = self.limits.total_bytes if aggregate else cap
            admitted = self.bytes_read if aggregate else 0
            if info.st_size > cap:
                self._reject('file or aggregate byte quota exceeded', category='budget', dimension=dimension, limit=limit, admitted=admitted, attempted=admitted + info.st_size)
            consumed = 0
            while True:
                self._check()
                block = os.read(fd, min(self.limits.chunk_bytes, cap - consumed + 1))
                self.bytes_read += len(block)
                consumed += len(block)
                if consumed > cap:
                    self._reject('file grew beyond byte quota', category='budget', dimension=dimension, limit=limit, admitted=admitted + consumed - len(block), attempted=admitted + consumed)
                if not block:
                    break
                yield block
        except BaseException as error:
            if self.on_failure is not None:
                self.on_failure(error=error, phase='read')
            self.closed = True
            raise
        finally:
            try:
                if fd is not None:
                    os.close(fd)
            except BaseException as error:
                if self.on_failure is not None:
                    self.on_failure(error=error, phase='close')
                self.closed = True
                raise
            finally:
                self._active.release()

    def read(self, path, *, max_bytes=None):
        return b''.join(self._chunks(path, max_bytes))

    def digest(self, path, *, max_bytes=None):
        result = hashlib.sha256()
        for chunk in self._chunks(path, max_bytes):
            result.update(chunk)
        return result.hexdigest()
