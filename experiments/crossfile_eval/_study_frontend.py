"""Narrow child for study indexing/materialization, with no private task inputs.

Only the compiler, bounded public study helpers, and current public snapshot are
copied into this capsule. Provider execution uses the same namespace gate as
native compilation; no source parser runs in the provider parent process.
"""
import json
from pathlib import Path
import sys

from hepta.ast import HeptaError
from hepta.parser import parse
from hepta.pipeline import interface
from study_support.semantic import nodes, replace_nodes, rust_tokens
from study_support.tasks import canonical, digest, validate_files


def main():
    message = json.loads(sys.stdin.read())
    request = message['request']
    files = {name: (Path('candidate') / name).read_bytes().decode('utf-8') for name in request['files']}
    validate_files(request, files)
    if message['operation'] == 'replace_nodes':
        files = replace_nodes(request, files, message['edits'])
    indexed = {name: nodes(request['language'], files[name], name) for name in request['editable']}
    if message.get('contracts') and request['task_id'] == 'api_migration':
        if any(n['symbol'] == 'subtotal' for values in indexed.values() for n in values):
            raise ValueError('E_API_CONTRACT: obsolete subtotal declaration remains')
    if request['language'] == 'hepta':
        # Reuse the production interface representation, including return_mode.
        signature = {name: interface(parse(source, name)) for name, source in files.items() if name.endswith('.hepta')}
    else:
        # Rust's bounded profile has no full AST. Retain complete signature/type
        # tokens and attributes; ignore only function bodies/comments/spacing.
        # Equivalent but textually different signatures can conservatively be
        # classified as migrations rather than silently treated as unchanged.
        signature = {}
        for name, source in files.items():
            if not name.endswith('.rs'): continue
            all_nodes = nodes('rust', source, name)
            records = []
            for declaration in all_nodes:
                if declaration['kind'] != 'declaration': continue
                body = next((n for n in all_nodes if n['kind'] == 'body' and n['symbol'] == declaration['symbol']), None)
                end = body['start'] if body is not None else declaration['end']
                tokens, _ = rust_tokens(source[declaration['start']:end])
                records.append((declaration['symbol'], declaration['declaration_kind'], [t.text for t in tokens]))
            signature[name] = sorted(records)
    answer = {'ok': True, 'interface_sha256': digest(canonical(signature)),
              'interface_basis': 'production_hepta_interface' if request['language'] == 'hepta' else 'bounded_rust_signature_tokens',
              'source_profile': 'hepta_parser' if request['language'] == 'hepta' else 'bounded_rust_tokens_not_full_ast'}
    if message['operation'] == 'query_nodes': answer['nodes'] = indexed
    if message['operation'] == 'replace_nodes': answer['files'] = files
    print(json.dumps(answer))


try:
    main()
except (HeptaError, ValueError, KeyError, TypeError, OSError, RecursionError) as exc:
    print(json.dumps({'ok': False, 'diagnostics': str(exc)}))
