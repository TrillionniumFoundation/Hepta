"""One bounded RPC into the actual production workspace implementation.

The store persists across separate processes. This helper contains no private
cases, answers, provider credentials, or arbitrary Python evaluation endpoint.
"""
import json
from pathlib import Path
import sys

from hepta.ast import HeptaError
from hepta import workspace

STORE = Path('store').resolve()


def snapshot(snapshot):
    manifest = snapshot['manifest']
    root = Path(snapshot['root'])
    files = {name: (root / name).read_bytes().decode('utf-8') for name in manifest['files']}
    source_id = workspace.digest(workspace.canonical({name: workspace.digest(source.encode())
                                                    for name, source in sorted(files.items())}))
    validation = manifest['validation']
    backend = validation['backend']
    return {'version': snapshot['version'], 'files': files, 'source_sha256': source_id,
            'entry': manifest['entry'], 'file_sha256': manifest['files'],
            'interface_sha256': manifest['interface_sha256'], 'compiler_sha256': manifest['compiler_sha256'],
            'profile': manifest['profile'], 'validated_sources': manifest['validated_sources'],
            'validation': {'ok': validation['ok'], 'status': validation['status'],
                           'checks': validation['checks'], 'backend_ok': backend['ok'],
                           'backend_status': backend['status'], 'backend_target': backend['target'],
                           'backend_flags': backend['flags'],
                           'rustc_sha256': backend['toolchain']['executable_sha256'],
                           'report_sha256': workspace.digest(workspace.canonical(validation))}}


def current_record():
    head = (STORE / 'CURRENT').read_bytes()
    journal = (STORE / 'JOURNAL').read_bytes() if (STORE / 'JOURNAL').exists() else None
    return {'current': json.loads(head), 'current_sha256': workspace.digest(head),
            'journal': json.loads(journal) if journal else None,
            'journal_sha256': workspace.digest(journal) if journal else None}


def main():
    message = json.loads(sys.stdin.read())
    operation = message['operation']
    if operation == 'initialize':
        result = workspace.initialize(STORE, Path('bundle'), message['entry'], rustc=message['rustc'])
        api = 'initialize'
    elif operation == 'inspect':
        result = workspace.inspect_workspace(STORE)
        api = 'inspect_workspace'
    elif operation in {'prepare', 'commit'}:
        result = workspace.apply_workspace_patch(STORE, message['patch'], apply=operation == 'commit', rustc=message['rustc'])
        api = 'apply_workspace_patch'
    elif operation == 'recover':
        result = workspace.recover(STORE)
        api = 'recover'
    elif operation == 'pin':
        result = {'schema': workspace.SCHEMA, 'ok': True, 'snapshot': workspace.pin(STORE)}
        api = 'pin'
    else:
        raise ValueError('E_WORKSPACE_RPC: unsupported operation')
    # Preserve all transaction outcome flags, especially applied=true/unknown
    # after a publication error. Never translate an uncertain commit to rollback.
    out = {key: result[key] for key in ('schema', 'ok', 'applied', 'status', 'before', 'after',
            'changes', 'interface_changed', 'recovery', 'candidate_version', 'diagnostics') if key in result}
    out.update(api=api, operation=operation, workspace_schema=workspace.SCHEMA, patch_schema=workspace.PATCH_SCHEMA)
    if 'validation' in result and not result.get('ok'):
        out['validation'] = result['validation']
    if 'snapshot' in result:
        out['snapshot'] = snapshot(result['snapshot'])
    if (STORE / 'CURRENT').exists():
        out['current_snapshot'] = snapshot(workspace.pin(STORE))
        out['publication'] = current_record()
    if operation == 'inspect' and result.get('ok'):
        files = out['snapshot']['files']
        indexed = {}
        for path, values in result['nodes'].items():
            selected = []
            for node in values:
                kind = node['kind']
                if kind not in {'function', 'body', 'struct', 'enum'}: continue
                common = {**node, 'native_kind': kind, 'language': 'hepta',
                          'declaration_kind': 'function' if kind in {'function', 'body'} else kind,
                          'text': files[path][node['start']:node['end']]}
                if kind in {'function', 'body'}: selected.append(common)
                if kind != 'body': selected.append({**common, 'kind': 'declaration'})
            indexed[path] = sorted(selected, key=lambda n: (n['start'], n['end'], n['kind']))
        out['nodes'] = indexed
    print(json.dumps(out))


try:
    main()
except (workspace.WorkspaceError, HeptaError, ValueError, KeyError, TypeError, OSError, RecursionError) as exc:
    print(json.dumps({'ok': False, 'operation': 'rpc_error', 'diagnostics': str(exc),
                      'publication_state': 'unverified', 'error_type': type(exc).__name__}))
