"""Trusted qualification worker; this file is never in a provider capsule.

The normal workspace frontend has no JSON fault-injection capability. This
separate worker uses the production Python test hook at its two existing
durable-write checkpoints, emits an observation, and dies with os._exit(71).
It contains no hidden task inputs, provider credentials, or source evaluator.
"""
from __future__ import annotations

import json
import os
import sys

from hepta import workspace
from workspace_frontend import STORE, current_record, main as normal_main, snapshot

EXIT_CODE = 71
CHECKPOINTS = ('prepared', 'published')


def metadata(value):
    return {key: item for key, item in value.items() if key != 'files'}


def main():
    message = json.loads(sys.stdin.read())
    if message.get('operation') == 'observe':
        if set(message) != {'operation', 'old_version'}:
            raise ValueError('E_CRASH_SCHEMA: malformed historical pin observation')
        print(json.dumps({'ok': True, 'api': 'pin', 'operation': 'observe',
                          'current_snapshot': snapshot(workspace.pin(STORE)),
                          'old_pinned_snapshot': snapshot(workspace.pin(STORE, message['old_version'])),
                          'publication': current_record()}))
        return
    if (set(message) != {'operation', 'rustc', 'patch', 'qualification_checkpoint'}
            or message['operation'] != 'commit' or message['qualification_checkpoint'] not in CHECKPOINTS):
        raise ValueError('E_CRASH_SCHEMA: require a trusted commit and exact checkpoint')
    point = message.pop('qualification_checkpoint')
    patch = message['patch']

    def crash(at):
        if at != point:
            return
        marker = {'schema': 'hepta.workspace_crash_marker.v1', 'checkpoint': at,
                  'exit_code': EXIT_CODE, 'mechanism': 'os._exit',
                  'patch_sha256': workspace.digest(workspace.canonical(patch)),
                  'current_snapshot': metadata(snapshot(workspace.pin(STORE))),
                  'old_pinned_snapshot': metadata(snapshot(workspace.pin(STORE, patch['expected_version']))),
                  'publication': current_record()}
        # flush is essential: os._exit intentionally skips Python cleanup.
        print(json.dumps(marker), flush=True)
        os._exit(EXIT_CODE)

    # The same checked/native production path used by normal prepare/commit.
    # If the checkpoint is not reached this returns normally; the parent must
    # reject the result as a missing crash, never label it successful injection.
    normal_main(message, _checkpoint=crash)


if __name__ == '__main__':
    try:
        main()
    except (workspace.WorkspaceError, ValueError, KeyError, TypeError, OSError) as exc:
        print(json.dumps({'ok': False, 'operation': 'crash_rpc_error', 'diagnostics': str(exc)}))
