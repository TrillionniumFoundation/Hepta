"""Bounded transport for the pinned, same-instance scalar C frontend."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import shutil
import subprocess
import time

LIMIT = 32_000_000
TIMEOUT = 30

class FrontendError(ValueError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)

def _capture(args):
    """Bound both pipes while running; never buffer unbounded subprocess output."""
    try:
        # A failed or completed driver must not leave compiler grandchildren
        # holding pipe FDs (or burning resources) after the direct child exits.
        with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              start_new_session=(os.name == 'posix')) as proc:
            chunks = {proc.stdout: bytearray(), proc.stderr: bytearray()}
            try:
                with selectors.DefaultSelector() as selector:
                    for stream in chunks:
                        selector.register(stream, selectors.EVENT_READ)
                    deadline = time.monotonic() + TIMEOUT
                    while selector.get_map():
                        left = deadline - time.monotonic()
                        if left <= 0:
                            raise FrontendError('E_C_FRONTEND_TIMEOUT', 'C frontend timed out')
                        for key, _ in selector.select(min(left, 0.1)):
                            block = os.read(key.fileobj.fileno(), 65536)
                            if not block:
                                selector.unregister(key.fileobj)
                                continue
                            chunks[key.fileobj].extend(block)
                            if sum(map(len, chunks.values())) > LIMIT:
                                raise FrontendError('E_C_FRONTEND_SIZE', 'C frontend output exceeds limit')
                    try:
                        status = proc.wait(timeout=max(0.001, deadline-time.monotonic()))
                    except subprocess.TimeoutExpired as exc:
                        raise FrontendError('E_C_FRONTEND_TIMEOUT', 'C frontend timed out') from exc
                if status:
                    raise FrontendError('E_CLANG_REJECT', chunks[proc.stderr][-5000:].decode('utf-8', errors='replace'))
                return bytes(chunks[proc.stdout]).decode('utf-8')
            finally:
                if os.name == 'posix':
                    # Kill the isolated process group even if its leader exited:
                    # inherited stdout/stderr FDs can otherwise keep us hung.
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                elif proc.poll() is None:
                    proc.kill()
                proc.wait()
    except (OSError, UnicodeError) as exc:
        raise FrontendError('E_C_FRONTEND_ENV', str(exc)) from exc

def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate envelope key')
        result[key] = value
    return result

def scalar_frontend(src: Path, source: bytes, clang: str):
    helper = os.environ.get('HEPTA_C_FRONTEND') or shutil.which('hepta-c-frontend')
    if not helper or not Path(helper).is_file():
        raise FrontendError('E_C_FRONTEND_ENV', 'Build pinned tools/c_frontend.cpp and set HEPTA_C_FRONTEND; no AST-only fallback')
    # These establish the driver configuration only. The authoritative model
    # below comes from the same CompilerInstance as the AST and macro callbacks.
    version = _capture([clang, '--version']).splitlines()
    if not version or version[0] != 'Debian clang version 19.1.7 (3+b1)':
        raise FrontendError('E_C_FRONTEND_ENV', 'Requires matching pinned Debian Clang 19.1.7 (3+b1)')
    resource = _capture([clang, '-print-resource-dir']).strip()
    target = _capture([clang, '-dumpmachine']).strip()
    if not resource or not target or '\n' in resource or '\n' in target:
        raise FrontendError('E_C_FRONTEND_ENV', 'Invalid Clang driver configuration')
    raw = _capture([helper, shutil.which(clang) or clang, resource, target, str(src)])
    try:
        data = json.loads(raw, object_pairs_hook=_unique_pairs)
        if not isinstance(data, dict) or type(data.get('schema')) is not int or data['schema'] != 1:
            raise ValueError('wrong envelope schema')
        if data.get('compiler') != 'Debian clang version 19.1.7 (3+b1)':
            raise ValueError('unqualified frontend compiler build')
        if data.get('target') != target or data.get('source_sha256') != hashlib.sha256(source).hexdigest() or data.get('source_size') != len(source):
            raise ValueError('source or target binding mismatch')
        for key in ('int_bits', 'long_bits', 'long_long_bits', 'pointer_bits'):
            if type(data.get(key)) is not int or data[key] not in (32, 64):
                raise ValueError('unsupported data model')
        if data['int_bits'] != 32 or data['long_long_bits'] != 64:
            raise ValueError('requires 32-bit int and 64-bit long long')
        events = data['main_macro_expansions']
        if not isinstance(events, list) or len(events) > 4096:
            raise ValueError('invalid macro event inventory')
        for event in events:
            if not isinstance(event, dict) or not isinstance(event.get('name'), str) or not event['name'] or type(event.get('offset')) is not int or not 0 <= event['offset'] < len(source):
                raise ValueError('invalid main macro location')
        # Preserve the original JSONNodeDumper key order for #18 filename elision.
        if not isinstance(data.get('ast_json'), str):
            raise ValueError('missing ordered AST')
        root = json.loads(data['ast_json'])
        if not isinstance(root, dict) or root.get('kind') != 'TranslationUnitDecl':
            raise ValueError('invalid translation unit')
    except (ValueError, KeyError, TypeError, RecursionError) as exc:
        raise FrontendError('E_C_FRONTEND_PROTOCOL', str(exc)) from exc
    if events:
        raise FrontendError('E_C_MACRO', 'Active main-file macro expansion is unsupported: ' + events[0]['name'])
    model = {'sizeof_int': data['int_bits']//8, 'sizeof_long': data['long_bits']//8,
             'sizeof_long_long': data['long_long_bits']//8, 'sizeof_pointer': data['pointer_bits']//8,
             'target': data['target'], 'clang_version': data['compiler']}
    return root, model
