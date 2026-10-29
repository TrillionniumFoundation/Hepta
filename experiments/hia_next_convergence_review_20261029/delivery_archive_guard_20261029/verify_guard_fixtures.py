#!/usr/bin/env python3
"""Exercise only packer guards on tiny synthetic temporary files; never pack."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from urllib.parse import quote, urlencode

HERE = Path(__file__).parent
SOURCE = HERE / 'GUARDED_BUILD_DELIVERY_ARCHIVE.py'
ROWS = []
SENTINEL = 'synthetic-value-must-not-be-printed'


def expect(name, operation, category=None):
    try:
        operation()
    except ValueError as error:
        message = str(error)
        assert category and '[' + category + ']' in message, (name, type(error).__name__)
        assert SENTINEL not in message and 'https://' not in message
        ROWS.append({'name': name, 'expected': 'rejected', 'observed_category': category, 'passed': True, 'matching_values_disclosed': False})
    else:
        assert category is None, name
        ROWS.append({'name': name, 'expected': 'accepted', 'passed': True})


def main():
    source_bytes = SOURCE.read_bytes()
    module_spec = importlib.util.spec_from_file_location('reviewed_delivery_guard', SOURCE)
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    # An accidental call to the ZIP constructor is a fixture failure.
    zip_calls = []
    def no_zip(*args, **kwargs):
        zip_calls.append(1)
        raise AssertionError('ZIP constructor is forbidden in this fixture run')
    module.zipfile.ZipFile = no_zip
    with tempfile.TemporaryDirectory(prefix='hepta-delivery-guard-fixture-') as temp:
        root = Path(temp)
        def write(name, data=b'{}'):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            return path
        def text_check(name, value):
            return module.candidate_text_guard(root / name, value)
        plain = write('plain/record.json')
        expect('plain_evidence_directory', lambda: list(module.evidence_files(plain.parent)))
        for name, is_dir in [('git_file', False), ('git_dir', True), ('nested_git_file/child', False), ('nested_git_dir/child', True)]:
            path = root / name
            path.mkdir(parents=True)
            marker = path / '.git'
            marker.mkdir() if is_dir else marker.write_text('synthetic worktree marker')
            selected = path if not name.startswith('nested') else path.parent
            expect(name, lambda p=selected: list(module.evidence_files(p)), 'live-checkout-root')
        root_link = root / 'root_link'
        root_link.symlink_to(plain.parent, target_is_directory=True)
        expect('root_directory_symlink', lambda: list(module.evidence_files(root_link)), 'symlink-path-component')
        leaf_link = plain.parent / 'leaf_link.json'
        leaf_link.symlink_to(plain)
        expect('file_symlink', lambda: module.add_candidate({}, leaf_link, 'leaf.json'), 'symlink-path-component')
        leaf_link.unlink()
        nested = root / 'nested_link'
        nested.mkdir()
        (nested / 'child').symlink_to(plain.parent, target_is_directory=True)
        expect('descendant_directory_symlink', lambda: list(module.evidence_files(nested)), 'symlink-path-component')
        expect('ancestor_directory_symlink', lambda: module.add_candidate({}, root_link / 'record.json', 'record.json'), 'symlink-path-component')
        for name in ['weights.gguf', 'weights.gguf.partial', 'weights.gguf.download.json', 'weights.safetensors']:
            path = write(name)
            expect(name, lambda p=path: module.add_candidate({}, p, p.name), 'model-weight-filename')
        disguised = write('disguised.json', b'GGUFsynthetic only')
        expect('GGUF_magic_under_other_extension', lambda: module.read_candidate(disguised), 'GGUF-payload-magic')
        protected = root / 'configured_model_root'
        protected.mkdir()
        original_model_root = module.PROTECTED_MODEL_ROOT
        module.PROTECTED_MODEL_ROOT = protected
        expect('explicit_protected_model_directory', lambda: list(module.evidence_files(protected)), 'protected-model-directory')
        module.PROTECTED_MODEL_ROOT = original_model_root
        oversized = write('budget_record.json', b'x' * 33)
        previous_cap = module.MAX_MEMBER_BYTES
        module.MAX_MEMBER_BYTES = 32
        expect('bounded_member_read', lambda: module.read_candidate(oversized), 'member-exceeds-preflight-budget')
        module.MAX_MEMBER_BYTES = previous_cap
        fifo = root / 'fifo.json'
        os.mkfifo(fifo)
        expect('FIFO_rejected_without_blocking', lambda: module.read_candidate(fifo), 'non-regular-file')
        named_request = write('model-download-request.json')
        expect('downloader_request_filename', lambda: module.add_candidate({}, named_request, named_request.name), 'downloader-request-json-filename')
        public = 'https://' + 'example.invalid/immutable-public-model?download=true'
        expect('downloader_request_structure', lambda: text_check('misc.json', json.dumps({'url': public, 'destination': 'synthetic'}).encode()), 'downloader-request-json-structure')
        expect('request_name_and_URL', lambda: text_check('request.json', json.dumps({'url': public}).encode()), 'downloader-request-json-structure')
        signed = 'https://' + 'example.invalid/file?' + urlencode({'X-Amz-Signature': SENTINEL})
        expect('signed_URL_JSON', lambda: text_check('record.json', json.dumps({'origin': signed}).encode()), 'signed-or-bearer-download-url')
        escaped = json.dumps({'origin': signed}).replace('https:', 'https\\u003a').encode()
        expect('signed_URL_JSON_escaped', lambda: text_check('record.json', escaped), 'signed-or-bearer-download-url')
        expect('signed_URL_percent_encoded', lambda: text_check('record.log', quote(signed, safe='').encode()), 'signed-or-bearer-download-url')
        html_url = 'https://' + 'example.invalid/file?download=true&amp;' + urlencode({'X-Goog-Signature': SENTINEL})
        expect('signed_URL_HTML_escaped', lambda: text_check('record.log', html_url.encode()), 'signed-or-bearer-download-url')
        bearer = 'https://' + 'example.invalid/file?' + urlencode({'sig': SENTINEL})
        expect('bearer_query_variant', lambda: text_check('record.txt', bearer.encode()), 'signed-or-bearer-download-url')
        userinfo = 'https://' + 'synthetic-user:' + SENTINEL + '@example.invalid/file'
        expect('URL_userinfo_credential', lambda: text_check('record.log', userinfo.encode()), 'url-userinfo-credential')
        expect('public_acquisition_outcome_preserved', lambda: text_check('acquisition.json', json.dumps({'url': public, 'passed': True, 'bytes': 17, 'sha256': 'synthetic'}).encode()))
        expect('model_transport_request_preserved', lambda: text_check('transport-001.request.json', json.dumps({'messages': [{'role': 'user', 'content': 'synthetic source edit'}], 'payload': {'prompt': [1, 2, 3]}, 'rendered_prompt': 'synthetic'}).encode()))
        expect('malformed_failure_evidence_preserved', lambda: text_check('failed.json', b'{"error":"unfinished'))
        for version in ['v7', 'v8', 'v9', 'v10']:
            name = 'hepta-next-agent-' + version + '-result.json'
            assert module.phase_allows_name(name, module.BEFORE_V8) is False
            assert module.phase_allows_name(name, 'after-v9') is True
            assert module.phase_allows_path('/tmp/' + name, module.BEFORE_V8) is False
            assert module.phase_allows_path('/tmp/hepta-next-agent-' + version + '-raw/RESULT.json', module.BEFORE_V8) is False
            ROWS.append({'name': 'old_phase_excludes_' + version, 'passed': True, 'old_phase_included': False, 'new_phase_included': True})
        safe = write('safe.json', b'{"status":"synthetic"}')
        bad = write('bad.log', signed.encode())
        expect('all_candidate_preflight_refuses_signed_text', lambda: module.preflight({'a': safe, 'b': bad}), 'signed-or-bearer-download-url')
        bound = module.preflight({'safe': safe})
        safe.write_text('{"status":"synthetic changed"}')
        _, _, after = module.read_candidate(safe)
        expect('post_preflight_change_rejected', lambda: module.require_preflight_identity(safe, after, bound['safe']), 'candidate-changed-after-preflight')
        expect('packer_source_itself_is_text_admissible', lambda: module.candidate_text_guard(SOURCE, source_bytes))
        assert not list(root.rglob('*.zip'))
    tree = ast.parse(source_bytes)
    main_node = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
    preflight_lines = [node.lineno for node in ast.walk(main_node) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'preflight']
    zip_lines = [node.lineno for node in ast.walk(main_node) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'ZipFile']
    assert len(preflight_lines) == 1 and zip_lines and preflight_lines[0] < min(zip_lines)
    assert zip_calls == []
    report = {'schema': 'hepta.delivery-archive.guard-synthetic-checks.v1',
              'source_sha256': hashlib.sha256(source_bytes).hexdigest(), 'source_bytes': len(source_bytes),
              'fixtures': ROWS, 'fixture_count': len(ROWS), 'passed': True,
              'packer_main_executed': False, 'actual_evidence_directories_scanned': 0,
              'model_weight_bytes_read': 0, 'native_model_tokenizer_compiler_executions': 0,
              'archive_constructor_calls': len(zip_calls), 'archives_created': 0, 'uploads': 0,
              'AST_preflight_precedes_first_ZIP_constructor': True,
              'old_archive_or_producer_evidence_modified': False,
              'limits': ['Only tiny synthetic temporary fixtures exercise the guards.',
                         'No end-to-end archive was generated or newly approved for transfer.',
                         'Candidate text URL classification is a conservative preflight, not a proof about arbitrary opaque binary content.',
                         'Opaque nested archives/bundles retain their separately required content review.']}
    (HERE / 'FIXTURE_CHECKS.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ['fixture_count', 'passed', 'archives_created', 'uploads', 'packer_main_executed']}, indent=2))


if __name__ == '__main__':
    main()
