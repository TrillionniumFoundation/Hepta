"""Inert deterministic source derivation; never launches the authored controls."""
from pathlib import Path
import ast
import hashlib
import json

ROOT = Path(__file__).resolve().parent
PREFIX = 'experiments/hia_full32_r4_failed_custody_20261112/gzip-ranges-r1'
BRANCH = 'codex/hia-full32-r4-gzip-originals-run-r1-20261112-e26e'
WORK = 'hia-full32-r4-gzip-originals-r1'
PUBLIC = 'hia-full32-r4-gzip-originals-public-r1'
SCHEMA = 'hia.actions.failed-full32-gzip-parts-policy.v1'


def replace_functions(source, replacements):
    rows = source.splitlines(keepends=True)
    tree = ast.parse(source)
    found = {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    for name in sorted(replacements, key=lambda key: found[key].lineno, reverse=True):
        node = found[name]
        rows[node.lineno - 1:node.end_lineno] = [replacements[name].rstrip() + '\n']
    return ''.join(rows)


def functions(source):
    lines = source.splitlines(keepends=True)
    return {n.name: ''.join(lines[n.lineno - 1:n.end_lineno]) for n in ast.parse(source).body
            if isinstance(n, ast.FunctionDef)}


def save(name, text):
    path = ROOT / 'control' / name
    with path.open('x') as out:
        out.write(text)
    ast.parse(text, filename=name) if name.endswith('.py') else None


base_worker = (ROOT / 'reference/worker.py').read_text()
base_controller = (ROOT / 'reference/controller.py').read_text()
delta = functions((ROOT / 'controller_delta.py').read_text())
limits_extra = """'minimum_free_bytes': 8 << 30, 'minimum_free_inodes': 100000,
                'compressed_part_bytes': 313 << 20,
                'small_original_bytes': 160 << 20, 'small_derived_bytes': 32 << 20,
                'small_public_bytes': 224 << 20,
                'inner_stream_bytes': 16 << 30, 'outer_stream_bytes': 4 << 30}"""


def common_changes(source):
    source = source.replace('hia.actions.v88-full-original-parts-policy.v1', SCHEMA)
    source = source.replace("'name': 'part-%02d.bin' % ordinal", "'name': 'part-%02d.bin.gz' % ordinal")
    source = source.replace("'minimum_free_bytes': 8 << 30, 'minimum_free_inodes': 100000}", limits_extra)
    source = source.replace("'process_owner_impl.py', 'original_receiver.py'}", "'process_owner_impl.py', 'original_receiver.py', 'gzip_evidence.py'}")
    source = source.replace('fixed five custody controls differ', 'fixed six custody controls differ')
    return source


worker = common_changes(base_worker)
worker = replace_functions(worker, {'split_original': '''def split_original(path, pin, policy, root, helper, deadline):
    module = load_gzip_helper(root / 'control', policy)
    return module.split_original(path, pin, expected_parts(policy), root, deadline)
'''})
worker = worker.replace('def expected_parts(policy):', delta['load_gzip_helper'] + '\n\n\ndef expected_parts(policy):', 1)
worker = worker.replace("'original_ZIP_members_decompressed': False,", "'all_available_original_bodies_read': False,")
worker = worker.replace("        stage = 'MULTIPLE_CONTIGUOUS_PARTS'", """        stage = 'ORIGINAL_TYPED_BYTES_AND_SMALL_DIAGNOSTICS'
        evidence = load_gzip_helper(control, policy)
        try:
            report['inspection'] = evidence.inspect_original(path, pin, root, deadline, helper.catalog)
        except BaseException as error:
            report['inspection'] = {'status': 'HOLD', 'error_type': type(error).__name__,
                                    'errno': getattr(error, 'errno', None)}
        report['all_available_original_bodies_read'] = (
            report['inspection'].get('all_available_original_bodies_independently_read') is True)
        helper.checkpoint(report)
        stage = 'MULTIPLE_CONTIGUOUS_GZIP_RANGES'""")
worker = worker.replace("        report.update(status='SEALED_PARTS_PENDING_NATURAL_GUARDIAN',", """        require(report.get('inspection', {}).get('diagnostic_channel_complete') is True,
                'full original inspection or whole small diagnostic channel is HOLD')
        report.update(status='SEALED_PARTS_PENDING_NATURAL_GUARDIAN',""")
save('worker.py', worker)

controller = common_changes(base_controller)
controller = controller.replace('import argparse\n', 'import argparse\nimport importlib.util\n', 1)
controller = controller.replace("CHUNK = 1 << 20\n", "CHUNK = 1 << 20\nGZIP_HELPER = None\n", 1)
controller = replace_functions(controller, {key: delta[key] for key in ('concat_parts', 'closed_storage_observation')})
controller = controller.replace('def expected_parts(policy):', delta['load_gzip_helper'] + '\n\n\ndef expected_parts(policy):', 1)
controller = controller.replace('def finalize(args):', delta['capture_small'] + '\n\n\ndef finalize(args):', 1)
controller = controller.replace("report.get('original_ZIP_members_decompressed') is False", "report.get('all_available_original_bodies_read') is True")
controller = controller.replace("actual = file_record(root / 'parts' / expected['name'], expected['bytes'])\n        require(actual['bytes'] == expected['bytes'] and stat.S_IMODE(actual['identity'][2]) == 0o400,", "actual = file_record(root / 'parts' / expected['name'], 313 << 20)\n        require(actual['bytes'] > 0 and stat.S_IMODE(actual['identity'][2]) == 0o400,")
controller = controller.replace("        same_original_record(produced.get('original'), actual)\n        records.append(actual)", """        same_original_record(produced.get('original'), actual)
        restored = GZIP_HELPER.decode_range(actual['path'], expected, actual)
        require(produced.get('compression') == 'gzip' and produced.get('compresslevel') == 1
                and produced.get('mtime') == 0 and produced.get('raw_bytes') == expected['bytes']
                and produced.get('raw_sha256') == restored['sha256']
                and produced.get('restoration') == restored, 'actual gzip range restoration differs')
        records.append(actual)""")
controller = controller.replace("source.suffix == '.bin'", "source.name.endswith('.bin.gz')")
controller = controller.replace("target.name in ('slice.bin', 'unverified-range.bin')", "target.name in ('slice.bin.gz', 'unverified-range.bin.gz')")
controller = controller.replace("    _, policy, _, root, public, context = policy_and_context(args)\n    pin = fixed_policy(policy)", "    control, policy, _, root, public, context = policy_and_context(args)\n    global GZIP_HELPER\n    GZIP_HELPER = load_gzip_helper(control, policy)\n    pin = fixed_policy(policy)")
controller = controller.replace("    public.mkdir(mode=0o700)\n    for item in parts:", "    public.mkdir(mode=0o700)\n    (public / 'small').mkdir(mode=0o700)\n    for item in parts:")
controller = controller.replace("'historical_results_reclassified': False, 'original_ZIP_members_decompressed': False,", "'historical_results_reclassified': False, 'all_available_original_bodies_read': False,")
controller = controller.replace("    storage_observed = False\n    copied = []", "    storage_observed = False\n    small_complete = False\n    report = None\n    copied = []")
controller = controller.replace(" / 'slice.bin'", " / 'slice.bin.gz'")
controller = controller.replace("'kind': 'SEALED_ORIGINAL_RANGE'", "'kind': 'SEALED_SINGLE_GZIP_OF_ORIGINAL_RANGE'")
controller = controller.replace("    if closed:\n        original_name", """    if closed:
        try:
            result['small_diagnostics'] = capture_small(root, public, policy,
                report.get('inspection') if type(report) is dict else None)
            small_complete = result['small_diagnostics']['complete']
            result['all_available_original_bodies_read'] = small_complete
        except BaseException as exc:
            error('SMALL_DIAGNOSTIC_CUSTODY', exc)
        original_name""")
controller = controller.replace("actual = file_record(destination, item['bytes'])", "actual = file_record(destination, 313 << 20)")
controller = controller.replace("source_record = file_record(source, item['bytes'])\n                        actual = relocate_slice(source, directory / 'unverified-range.bin', source_record)", "source_record = file_record(source, 313 << 20)\n                        actual = relocate_slice(source, directory / 'unverified-range.bin.gz', source_record)")
controller = controller.replace(" / 'unverified-range.bin'):", " / 'unverified-range.bin',\n                                  public / ('part-%02d' % item['ordinal']) / 'unverified-range.bin.gz'):")
controller = controller.replace("                diagnostic_bytes += actual['bytes']", "                destinations.append(copy_original(path, public / 'small' / ('current--' + name.replace('/', '--')), actual))\n                diagnostic_bytes += actual['bytes']")
controller = controller.replace("complete = (closed and natural and accepted and captures_complete and storage_observed", "complete = (closed and natural and accepted and captures_complete and storage_observed and small_complete")
controller = controller.replace("    sync_dir(public)\n    print(json.dumps", """    create(public / 'small' / 'FINAL.json', final_raw)
    require(read(public / 'small' / 'FINAL.json', 2 << 20) == final_raw,
            'small-channel FINAL readback differs')
    small_files = []
    for path in sorted((public / 'small').iterdir()):
        small_files.append(file_record(path, 64 << 20))
    require(len(small_files) <= 4128 and sum(x['bytes'] for x in small_files) <= 224 << 20,
            'complete small diagnostic artifact exceeds fixed count/byte bound')
    sync_dir(public / 'small')
    sync_dir(public)
    print(json.dumps""")
save('controller.py', controller)

# These byte-exact bodies are deliberate invariant checks, not execution evidence.
worker_functions = functions(worker)
controller_functions = functions(controller)
original_worker_functions, original_controller_functions = functions(base_worker), functions(base_controller)
unchanged_worker = [name for name in original_worker_functions if original_worker_functions[name] == worker_functions.get(name)]
unchanged_controller = [name for name in original_controller_functions if original_controller_functions[name] == controller_functions.get(name)]
required_worker = ('NoRedirect',)  # class is checked separately below.
for name in ('new_client', 'deadline_check', 'api_request', 'bounded_response', 'metadata', 'official_location', 'storage_download', 'load_helper'):
    assert name in unchanged_worker, name
for name in ('closed_guardian', 'natural_guardian', 'check_setup', 'run', 'copy_original', 'copy_unverified_range'):
    assert name in unchanged_controller, name
for source in (worker, controller):
    ast.parse(source)
report = {'schema': 'hia.failed-full32-gzip.source-derivation.v1',
          'unchanged_worker_function_bodies': unchanged_worker,
          'unchanged_controller_function_bodies': unchanged_controller,
          'worker_AST_passed': True, 'controller_AST_passed': True,
          'network_executed': False, 'owner_executed': False, 'product_executed': False}
(ROOT / 'evidence/STATIC-DERIVATION.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
print(json.dumps(report, sort_keys=True))
