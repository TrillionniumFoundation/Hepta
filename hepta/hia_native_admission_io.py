"""Private hosted POSIX I/O for executable/source admission.

These operations inspect executable inputs, not a user's capture provider.
The business stable_read/capture_path expressions still use their original
namespace's os/Path/stream objects. Every admission performs fresh I/O; this
module neither caches file contents nor suppresses admission syscalls.

The resolver adapts CPython's PSF-licensed posixpath realpath and pathlib
predicate/loop conventions. The complete PSF license is retained at the end of this source.
Changes: explicit captured builtin capability table, only bool strict modes,
and separate 3.12 / 3.13+ resolver paths. No user path policy is added.
"""
from __future__ import annotations

from errno import EBADF, EISDIR, ELOOP, ENOENT, ENOTDIR
from pathlib import Path
import stat
import sys
import types

try:
    import posix as _posix
except ImportError:
    _posix = None

_NAMES = ('fspath', 'getcwd', 'getcwdb', 'lstat', 'readlink', 'stat',
          'open', 'read', 'fstat', 'close', 'strerror')
_FSPATH, _GETCWD, _GETCWDB, _LSTAT, _READLINK, _STAT = range(6)
_OPEN, _READ, _FSTAT, _CLOSE, _STRERROR = range(6, 11)
_VERSION = sys.version_info[:2]
_IS_LINK, _IS_DIR, _IS_REG = stat.S_ISLNK, stat.S_ISDIR, stat.S_ISREG
_IGNORED_ERRNOS = (ENOENT, ENOTDIR, EBADF, ELOOP)
_IGNORED_WINERRORS = (21, 123, 1921)


def _builtin_capabilities():
    if _posix is None:
        return None
    captured = tuple(getattr(_posix, name) for name in _NAMES)
    for name, operation in zip(_NAMES, captured):
        if (type(operation) is not types.BuiltinFunctionType
                or operation.__module__ != 'posix'
                or operation.__name__ != name or operation.__self__ is not _posix):
            raise RuntimeError('native admission requires original POSIX builtin capabilities')
    return captured


_CAPABILITIES = _builtin_capabilities()
_OPEN_FLAGS = (0 if _posix is None else
               _posix.O_RDONLY | _posix.O_CLOEXEC | _posix.O_NOFOLLOW | _posix.O_NONBLOCK)


def _join(path, tail, sep):
    if tail.startswith(sep) or not path:
        return tail
    return path + tail if path.endswith(sep) else path + sep + tail


def _split(path, sep):
    index = path.rfind(sep) + 1
    head, tail = path[:index], path[index:]
    if head and head != sep * len(head):
        head = head.rstrip(sep)
    return head, tail


def _normpath(path, sep, dot, dotdot):
    if not path:
        return dot
    initial = path.startswith(sep)
    if initial and path.startswith(sep * 2) and not path.startswith(sep * 3):
        initial = 2
    parts = []
    for part in path.split(sep):
        if not part or part == dot:
            continue
        if (part != dotdot or (not initial and not parts)
                or (parts and parts[-1] == dotdot)):
            parts.append(part)
        elif parts:
            parts.pop()
    return sep * initial + sep.join(parts) or dot


class _AdmissionIO:
    """One explicit capability owner; alternate tables are test-only fixtures.

    A successful open transfers its returned descriptor into one finally
    close. close is attempted once. A close that raises is propagated and is
    never retried: this code does not claim the descriptor was closed after
    an unknown close result, asynchronous interruption, or process loss.
    """
    __slots__ = ('_ops',)

    def __init__(self, operations):
        if type(operations) is not tuple or len(operations) != len(_NAMES):
            raise TypeError('native admission needs the complete capability tuple')
        self._ops = operations

    def _legacy_joinrealpath(self, path, rest, strict, seen):
        """CPython 3.12 traversal, including its relative error filenames."""
        binary = isinstance(path, bytes)
        sep, dot, dotdot = (b'/', b'.', b'..') if binary else ('/', '.', '..')
        ignored_error = () if strict else OSError
        if rest.startswith(sep):
            rest, path = rest[1:], sep
        while rest:
            name, _, rest = rest.partition(sep)
            if not name or name == dot:
                continue
            if name == dotdot:
                if path:
                    path, name = _split(path, sep)
                    if name == dotdot:
                        path = _join(_join(path, dotdot, sep), dotdot, sep)
                else:
                    path = dotdot
                continue
            newpath = _join(path, name, sep)
            try:
                status = self._ops[_LSTAT](newpath)
            except ignored_error:
                linked = False
            else:
                linked = _IS_LINK(status.st_mode)
            if not linked:
                path = newpath
                continue
            if newpath in seen:
                path = seen[newpath]
                if path is not None:
                    continue
                if strict:
                    self._ops[_STAT](newpath)
                else:
                    return _join(newpath, rest, sep), False
            seen[newpath] = None
            path, complete = self._legacy_joinrealpath(
                path, self._ops[_READLINK](newpath), strict, seen)
            if not complete:
                return _join(path, rest, sep), False
            seen[newpath] = path
        return path, True

    def _realpath(self, filename, strict):
        filename = self._ops[_FSPATH](filename)
        binary = isinstance(filename, bytes)
        sep, dot, dotdot = (b'/', b'.', b'..') if binary else ('/', '.', '..')
        getcwd = self._ops[_GETCWDB if binary else _GETCWD]
        if _VERSION < (3, 13):
            path, _ = self._legacy_joinrealpath(filename[:0], filename, strict, {})
            if not path.startswith(sep):
                path = _join(getcwd(), path, sep)
            return _normpath(path, sep, dot, dotdot)

        # This is the complete 3.13/3.14 bool-strict traversal. In 3.14
        # ELOOP is constructed directly; 3.13 obtains it from a real stat.
        ignored_error = () if strict else OSError
        rest = filename.split(sep)[::-1]
        part_count = len(rest)
        path = sep if filename.startswith(sep) else getcwd()
        seen = {}
        while part_count:
            name = rest.pop()
            if name is None:
                seen[rest.pop()] = path
                continue
            part_count -= 1
            if not name or name == dot:
                continue
            if name == dotdot:
                path = path[:path.rindex(sep)] or sep
                continue
            newpath = path + name if path == sep else path + sep + name
            try:
                mode = self._ops[_LSTAT](newpath).st_mode
                if not _IS_LINK(mode):
                    if strict and part_count and not _IS_DIR(mode):
                        raise OSError(ENOTDIR, self._ops[_STRERROR](ENOTDIR), newpath)
                    path = newpath
                    continue
                if newpath in seen:
                    path = seen[newpath]
                    if path is not None:
                        continue
                    if strict:
                        if _VERSION < (3, 14):
                            self._ops[_STAT](newpath)
                        else:
                            raise OSError(ELOOP, self._ops[_STRERROR](ELOOP), newpath)
                    path = newpath
                    continue
                target = self._ops[_READLINK](newpath)
            except ignored_error:
                pass
            else:
                if target.startswith(sep):
                    path = sep
                seen[newpath] = None
                rest.append(newpath)
                rest.append(None)
                target_parts = target.split(sep)[::-1]
                rest.extend(target_parts)
                part_count += len(target_parts)
                continue
            path = newpath
        return path

    def resolve_path(self, value, *, strict=True):
        # Call sites use the same concrete Path construction as before.
        # No Path.resolve/os.path.realpath lookup occurs in this capsule.
        path = Path(value)
        if type(strict) is not bool:
            raise TypeError('native admission resolver strict mode must be bool')
        if _VERSION >= (3, 13):
            return Path(self._realpath(path, strict))
        try:
            resolved = self._realpath(path, strict)
        except OSError as error:
            if error.errno == ELOOP or getattr(error, 'winerror', 0) == 1921:
                raise RuntimeError('Symlink loop from %r' % error.filename)
            raise
        result = Path(resolved)
        if not strict:
            try:
                self._ops[_STAT](result)
            except OSError as error:
                if error.errno == ELOOP or getattr(error, 'winerror', 0) == 1921:
                    raise RuntimeError('Symlink loop from %r' % error.filename)
        return result

    def is_file(self, path):
        # pathlib <=3.13 propagates some OSError families; 3.14's
        # os.path.isfile returns False for every OSError and ValueError.
        try:
            return _IS_REG(self._ops[_STAT](path).st_mode)
        except OSError as error:
            if (_VERSION < (3, 14)
                    and getattr(error, 'errno', None) not in _IGNORED_ERRNOS
                    and getattr(error, 'winerror', None) not in _IGNORED_WINERRORS):
                raise
            return False
        except ValueError:
            return False

    def source_resource_path(self, anchor, name):
        root = self.resolve_path(anchor, strict=False).parent.parent
        resources = root if self.is_file(root / 'pyproject.toml') else root / 'hepta' / '_data'
        return resources / name

    def regular_bytes(self, path, limit):
        descriptor = self._ops[_OPEN](path, _OPEN_FLAGS)
        try:
            before = self._ops[_FSTAT](descriptor)
            mode = before.st_mode
            if _IS_DIR(mode):
                # fdopen rejects directories before the original bounded-file check.
                raise IsADirectoryError(EISDIR, self._ops[_STRERROR](EISDIR), descriptor)
            if not _IS_REG(mode) or not 0 < before.st_size <= limit:
                raise ValueError('store-lifecycle input must be a bounded ordinary file')
            remaining = limit + 1
            parts = []
            while remaining:
                part = self._ops[_READ](descriptor, remaining)
                if not part:
                    break
                parts.append(part)
                remaining -= len(part)
            raw = b''.join(parts)
            after = self._ops[_FSTAT](descriptor)
        finally:
            self._ops[_CLOSE](descriptor)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in fields):
            raise ValueError('store-lifecycle input changed while being read')
        return raw


_ADMISSION = None if _CAPABILITIES is None else _AdmissionIO(_CAPABILITIES)


def source_resource_path(anchor, name):
    """Retain the exact source-module anchor and checkout/installed predicate."""
    if _ADMISSION is None:
        # The existing unselected source lookup remains usable on non-POSIX
        # hosts; the executable Capture contract is still Linux-only.
        root = Path(anchor).resolve().parent.parent
        resources = root if (root / 'pyproject.toml').is_file() else root / 'hepta' / '_data'
        return resources / name
    return _ADMISSION.source_resource_path(anchor, name)


def resolve_path(path, *, strict=True):
    if _ADMISSION is None:
        raise RuntimeError('native Capture admission requires POSIX capabilities')
    return _ADMISSION.resolve_path(path, strict=strict)


def regular_bytes(path, limit):
    if _ADMISSION is None:
        raise RuntimeError('native Capture admission requires POSIX capabilities')
    return _ADMISSION.regular_bytes(path, limit)

# Copyright (c) 2001 Python Software Foundation; All Rights Reserved.
# Adaptation notice: capability-bound traversal; see the module docstring.
# PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2
# --------------------------------------------
#
# 1. This LICENSE AGREEMENT is between the Python Software Foundation
# ("PSF"), and the Individual or Organization ("Licensee") accessing and
# otherwise using this software ("Python") in source or binary form and
# its associated documentation.
#
# 2. Subject to the terms and conditions of this License Agreement, PSF hereby
# grants Licensee a nonexclusive, royalty-free, world-wide license to reproduce,
# analyze, test, perform and/or display publicly, prepare derivative works,
# distribute, and otherwise use Python alone or in any derivative version,
# provided, however, that PSF's License Agreement and PSF's notice of copyright,
# i.e., "Copyright (c) 2001 Python Software Foundation; All Rights Reserved"
# are retained in Python alone or in any derivative version prepared by Licensee.
#
# 3. In the event Licensee prepares a derivative work that is based on
# or incorporates Python or any part thereof, and wants to make
# the derivative work available to others as provided herein, then
# Licensee hereby agrees to include in any such work a brief summary of
# the changes made to Python.
#
# 4. PSF is making Python available to Licensee on an "AS IS"
# basis.  PSF MAKES NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR
# IMPLIED.  BY WAY OF EXAMPLE, BUT NOT LIMITATION, PSF MAKES NO AND
# DISCLAIMS ANY REPRESENTATION OR WARRANTY OF MERCHANTABILITY OR FITNESS
# FOR ANY PARTICULAR PURPOSE OR THAT THE USE OF PYTHON WILL NOT
# INFRINGE ANY THIRD PARTY RIGHTS.
#
# 5. PSF SHALL NOT BE LIABLE TO LICENSEE OR ANY OTHER USERS OF PYTHON
# FOR ANY INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES OR LOSS AS
# A RESULT OF MODIFYING, DISTRIBUTING, OR OTHERWISE USING PYTHON,
# OR ANY DERIVATIVE THEREOF, EVEN IF ADVISED OF THE POSSIBILITY THEREOF.
#
# 6. This License Agreement will automatically terminate upon a material
# breach of its terms and conditions.
#
# 7. Nothing in this License Agreement shall be deemed to create any
# relationship of agency, partnership, or joint venture between PSF and
# Licensee.  This License Agreement does not grant permission to use PSF
# trademarks or trade name in a trademark sense to endorse or promote
# products or services of Licensee, or any third party.
#
# 8. By copying, installing or otherwise using Python, Licensee
# agrees to be bound by the terms and conditions of this License
# Agreement.
