"""Transport an admitted Agent dependency query to the pinned native Core CLI."""
from __future__ import annotations

import subprocess

from .hia_agent_store import wire
from .hia_agent_store_native import _sealed_image
from .hia_edit_query import MAX_QUERY_BYTES

EXECUTABLE = ('hia-prepare-edit-query', 4 << 20)


class NativeAgentEditQuery:
    """The worker binding owns the executable's bytes and release custody."""

    def __init__(self, captured):
        self._code = captured.raw

    def prepare(self, program, selector):
        site = {**selector, "fields": ["op", "args", "attrs"]}
        request = b'[' + program.canonical_bytes + b',' + wire(site) + b']'
        flags = ['--agent-compact']
        if program.structured_bytes is not None:
            flags.append(program.input_sha256)
        with _sealed_image(self._code) as fd:
            try:
                result = subprocess.run([f'/proc/self/fd/{fd}', *flags], input=request,
                                        capture_output=True, env={'PATH': ''},
                                        pass_fds=(fd,), timeout=20, check=False)
            except subprocess.TimeoutExpired as exc:
                raise OSError('native Agent dependency query did not finish') from exc
        if result.returncode in (2, 3) and not result.stdout and not result.stderr:
            return None
        if (result.returncode != 0 or result.stderr
                or not 0 < len(result.stdout) <= MAX_QUERY_BYTES):
            raise ValueError('invalid native Agent dependency reply')
        return result.stdout
