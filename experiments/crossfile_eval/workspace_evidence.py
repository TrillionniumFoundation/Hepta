"""Check recorded production traces, not a self-declared capability label."""
from __future__ import annotations

import re


def validate_workspace_record(report, *, require_committed=False):
    session = report.get('session')
    if (not isinstance(session, dict) or session.get('backend') != 'hepta.workspace/hepta.patch.v4'
            or session.get('initialized') is not True or session.get('final_pinned') is not True):
        raise ValueError('production workspace initialization and final pin evidence required')
    events = session.get('events')
    if not isinstance(events, list) or not events or events[0].get('operation') != 'initialize':
        raise ValueError('production workspace trace is missing initialization')
    if events[-1].get('operation') != 'pin':
        raise ValueError('submitted candidate must come from the final production pin')
    if report.get('run_kind') in {'provider_adapter_run', 'trusted_namespace_workspace_fixture'}:
        if session.get('namespace_required') is not True or any(e.get('namespace_required') is not True for e in events):
            raise ValueError('provider and strict workspace runs require namespace isolation on every RPC')
    profile = session.get('profile')
    compiler = report['compiler']
    if (not isinstance(profile, dict) or profile.get('compiler_sha256') != compiler['hepta_compiler_sha256']
            or profile.get('rustc_sha256') != compiler['rustc']['executable_sha256']):
        raise ValueError('production workspace profile differs from frozen compiler')
    for event in events:
        for key in ('snapshot', 'current_snapshot'):
            if key not in event: continue
            snap = event[key]
            validation = snap.get('validation', {})
            if (snap.get('profile') != profile or snap.get('compiler_sha256') != profile['compiler_sha256']
                    or validation.get('ok') is not True or validation.get('backend_ok') is not True
                    or validation.get('rustc_sha256') != profile['rustc_sha256']
                    or validation.get('backend_flags') != profile['native_flags']
                    or validation.get('backend_target') != profile['native_target']):
                raise ValueError('production snapshot lacks its frozen complete native validation')
    final = events[-1]
    pinned = final.get('current_snapshot', {})
    if (final.get('api') != 'pin' or final.get('ok') is not True
            or final.get('process_status') != 'exited' or final.get('process_returncode') != 0
            or pinned.get('version') != report.get('submitted_version')
            or pinned.get('version') != session.get('workspace_version')
            or pinned.get('source_sha256') != report.get('submitted_sha256')
            or pinned.get('source_sha256') != session.get('source_sha256')
            or final.get('publication', {}).get('current', {}).get('version') != pinned.get('version')):
        raise ValueError('final production CURRENT, pin and submitted source identities differ')
    journal = final.get('publication', {}).get('journal')
    if journal is not None and (journal.get('state') != 'committed' or journal.get('after') != pinned.get('version')):
        raise ValueError('final production journal is unresolved or differs from CURRENT')
    commits = [e for e in events if e.get('operation') == 'commit' and e.get('ok') is True and e.get('applied') is True]
    for commit in commits:
        position = events.index(commit)
        prepares = [e for e in events[:position] if e.get('operation') == 'prepare' and e.get('ok') is True]
        if not prepares: raise ValueError('production commit has no validated preparation')
        prepared = prepares[-1]
        if (prepared.get('applied') is not False or prepared.get('after') != commit.get('after')
                or prepared.get('before') != commit.get('before')
                or prepared.get('patch_sha256') != commit.get('patch_sha256')
                or not re.fullmatch('[0-9a-f]{64}', prepared.get('patch_sha256', ''))
                or prepared.get('patch_preconditions') != commit.get('patch_preconditions')
                or prepared.get('current_snapshot', {}).get('version') != prepared.get('before')
                or commit.get('current_snapshot', {}).get('version') != commit.get('after')):
            raise ValueError('production preparation and commit must bind the same request and checked version')
    exercised = bool(commits) and session.get('inspected') is True and session.get('recovered') is True
    if exercised:
        last = commits[-1]
        recovered = [e for e in events[events.index(last) + 1:] if e.get('operation') == 'recover' and e.get('ok') is True]
        if (not recovered or recovered[-1].get('current_snapshot', {}).get('version') != last.get('after')
                or last.get('after') != pinned.get('version')
                or session.get('committed_workspace_version') != last.get('after')
                or session.get('prepared_workspace_version') != last.get('after')):
            raise ValueError('committed workspace recovery and final pin disagree')
    if (session.get('production_workspace_v4_exercised') is not exercised
            or report.get('claims', {}).get('production_workspace_v4_exercised') is not exercised):
        raise ValueError('production workspace capability label differs from its actual trace')
    if require_committed and not exercised:
        raise ValueError('successful protocol-arm outcome requires actual production prepare, commit and recovery')
    return exercised
