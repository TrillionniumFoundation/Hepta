"""Transport an admitted Agent dependency query to the pinned native Core CLI."""
from __future__ import annotations

import subprocess

from .hia_agent_store import decode_data, wire
from .hia_agent_store_native import _sealed_image
from .hia_edit_query import MAX_QUERY_BYTES
from .hia_program_tools import HIAEditRejected

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
                result = subprocess.run(['hia-prepare-agent-edit-query', *flags],
                                        executable=f'/proc/self/fd/{fd}', input=request,
                                        capture_output=True, env={'PATH': ''},
                                        pass_fds=(fd,), timeout=20, check=False)
            except subprocess.TimeoutExpired as exc:
                raise OSError('native Agent dependency query did not finish') from exc
        if result.returncode in (2, 3) and not result.stdout and not result.stderr:
            return None
        if result.returncode == 2 and not result.stderr and 0 < len(result.stdout) <= 512:
            report = decode_data(result.stdout)
            diagnostics = report.get('diagnostics') if type(report) is dict else None
            if (type(diagnostics) is list and len(diagnostics) == 1
                    and type(diagnostics[0]) is dict):
                message = diagnostics[0].get('message')
                if (report.get('ok') is False and report.get('status') == 'error'
                        and diagnostics[0].get('code') == 'E_DRIVER'
                        and diagnostics[0].get('phase') == 'driver' and type(message) is str
                        and message.startswith('E_HIA_QUERY: ')):
                    raise HIAEditRejected(message)
        if (result.returncode != 0 or result.stderr
                or not 0 < len(result.stdout) <= MAX_QUERY_BYTES):
            raise ValueError('invalid native Agent dependency reply')
        return result.stdout
