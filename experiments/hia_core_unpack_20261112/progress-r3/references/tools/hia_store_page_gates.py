"""Read complete cold-bound Store/page evidence; never synthesize a product pass."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

LEGACY_V8_GATES = (
    'source_bound_prerequisites_admitted', 'prerequisites_preserved',
    'json_preflight_complete_module', 'agent_journal_source_and_native',
    'composite_types_helpers_and_complete_nominal_lowering', 'journal_selected_ordinary_callers',
    'json_wire_complete_module', 'ordinary_json_wire_entry_complete_module',
    'worker_report_complete_module', 'machine_plan_complete_module',
    'linked_observer_complete_module', 'machine_plan_selected_ordinary_callers',
    'json_wire_selected_ordinary_callers', 'json_wire_cache_complete_module',
    'cli_complete_module_and_retained_cold_bundle',
    'machine_encoding_complete_component_and_original_callers',
    'original_selected_caller_denominators_preserved',
)
NEW_GATES = (
    'agent_store_authority_complete_module', 'agent_store_authority_selected_ordinary_callers',
    'artifact_read_complete_module', 'artifact_read_selected_ordinary_callers',
)
SUCCESSOR_GATES = LEGACY_V8_GATES + NEW_GATES
CALLER_MODULES = (
    'tests.test_hia_agent_native_tools', 'tests.test_hia_agent_native_proof_contract',
    'tests.test_hia_agent_native_lease_snapshot', 'tests.test_hia_agent_native_machine_choices',
    'tests.test_hia_agent_native_campaign',
)
OWNERS = {
    'authority': {
        'module': 'tests.test_hia_agent_store_authority_native', 'component_tests': 15,
        'prefix': 'HEPTA_HIA_AGENT_STORE_AUTHORITY', 'fixture_build': 'qualified',
        'caller_driver': 'tools.qualify_hia_agent_store_authority_callers',
        'caller_schema': 'hepta.hia.agent-store-authority-selected-callers.v1', 'caller_build': 'authority',
        'source': 'examples/hia_bootstrap/agent_store_authority.hiaasm',
        'manifest_schema': 'hepta.hia.agent-store-authority-native.v2',
        'build_schema': 'hepta.hia.agent-store-authority-build.v1',
        'caller_sources': ('hepta/hia_agent_store.py', 'hepta/hia_agent_store_authority_native.py',
            'hepta/hia_worker_report_native.py', 'hepta/hia_json_wire_native.py',
            'tools/generate_hia_agent_store_authority.py', 'tools/generate_hia_worker_report.py',
            'examples/hia_bootstrap/agent_store_authority.hiaasm', 'tools/qualify_hia_agent_store_authority_callers.py'),
    },
    'page': {
        'module': 'tests.test_hia_artifact_read_native', 'component_tests': 11,
        'prefix': 'HEPTA_HIA_ARTIFACT_PAGE', 'fixture_build': 'bundle',
        'caller_driver': 'tools.qualify_hia_artifact_read_callers',
        'caller_schema': 'hepta.hia.artifact-read-selected-callers.v1', 'caller_build': 'page',
        'source': 'examples/hia_bootstrap/artifact_page.hiaasm',
        'manifest_schema': 'hepta.hia.artifact-page-native.v2',
        'build_schema': 'hepta.hia.artifact-page-build.v1',
        'caller_sources': ('hepta/hia_agent_service.py', 'hepta/hia_artifact_page_native.py',
            'tools/generate_hia_artifact_page.py', 'tools/build_hia_artifact_page.py',
            'examples/hia_bootstrap/artifact_page.hiaasm', 'examples/hia_bootstrap/json_wire.hiaasm',
            'hepta/hia_json_wire_native.py', 'tools/qualify_hia_artifact_read_callers.py'),
    },
}
ANOMALIES = ('errors', 'failures', 'skipped', 'expected_failures', 'unexpected_successes')
TOOLS = ('hia_describe', 'hia_artifact', 'hia_read', 'hia_context', 'hia_inspect',
         'hia_candidate', 'hia_verify', 'hia_emit', 'hia_evaluate', 'hia_adopt', 'hia_rollback')


def require(value, message):
    if not value:
        raise ValueError(message)


def json_file(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate receipt field')
            result[key] = value
        return result
    return json.loads(Path(path).read_bytes(), object_pairs_hook=unique)


def file_record(path):
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def child_path(parent, name):
    require(type(name) is str and name and not Path(name).is_absolute()
            and '..' not in Path(name).parts, 'build child must be a relative retained file')
    path = (parent / name).resolve(strict=True)
    require(path.is_relative_to(parent.resolve(strict=True)), 'build child escaped retained directory')
    return path


def cold_inputs(path):
    """Use the original cold admission and bind its actual nested report/B3."""
    from tools.build_hia_json_preflight import admit_cold_build
    path = Path(path).resolve(strict=True); raw = path.read_bytes(); outer = json_file(path)
    nested_path = Path(outer['nested_report']).resolve(strict=True)
    nested_raw = nested_path.read_bytes(); nested = json_file(nested_path)
    require(sha256(nested_raw).hexdigest() == outer.get('nested_report_sha256'), 'cold nested report identity differs')
    compiler = Path(nested['generations'][-1]['produced_image']).resolve(strict=True)
    compiler_raw = compiler.read_bytes(); sources = admit_cold_build(compiler_raw, raw)
    require(nested.get('source_manifest') == sources, 'cold nested source identity differs')
    require([v.get('produced_sha256') for v in nested['generations']] == outer['generation_sha256'],
            'cold nested generations differ')
    return {'source_manifest': sources, 'cold_sha256': sha256(raw).hexdigest(),
            'compiler_sha256': sha256(compiler_raw).hexdigest(),
            'identities': [file_record(p) for p in (path, nested_path, compiler)]}


def manifest_image(path, schema, source, context):
    path = Path(path); manifest = json_file(path)
    require(manifest.get('schema') == schema, 'native manifest schema differs')
    require(manifest.get('source_sha256') == context['source_manifest'].get(source), 'native source differs')
    require(manifest.get('compiler_sha256') == context['compiler_sha256'], 'native compiler differs')
    image = child_path(path.parent, manifest.get('image_path'))
    require(file_record(image)['sha256'] == manifest.get('image_sha256'), 'actual native image differs')
    return manifest, image


def compile_receipt(receipt, manifest, image, context):
    require(type(receipt) is dict and receipt.get('status') == 'returned' and receipt.get('abi_status') == 0,
            'native compile did not return successfully')
    require(receipt.get('source_sha256') == manifest['source_sha256']
            and receipt.get('input_sha256') == manifest['source_sha256']
            and receipt.get('produced_sha256') == manifest['image_sha256']
            and receipt.get('image_sha256') == context['compiler_sha256']
            and receipt.get('artifact_sha256') == context['compiler_sha256'], 'compile identities differ')
    require(receipt.get('source_unchanged') is True and receipt.get('forbidden_compiler_modules_loaded') == [],
            'compile source/authoring boundary differs')
    require(receipt.get('produced_bytes') == image.stat().st_size and image.stat().st_size > 0,
            'compile output extent differs')
    require(receipt.get('limits') == {'address_bytes': 268435456, 'core_dumpable': False, 'cpu_seconds': 10,
            'output_capacity': 1048576, 'stack_bytes': 8388608, 'workspace_bytes': 1048576},
            'original native compile limits differ')


def build_context(build, context):
    require(build.get('scope') == 'MATCHING_SOURCE_COLD_BUILD', 'development build cannot qualify')
    require(build.get('source_manifest') == context['source_manifest'], 'build source closure differs')
    require(build.get('cold_report_sha256') == context['cold_sha256'], 'build cold identity differs')
    require(build.get('production_activated') is False, 'build activation claim differs')


def inspect_build(owner, folder, context):
    """Verify actual retained bytes for a source-bound single or two-image build."""
    config = OWNERS[owner]; folder = Path(folder)
    build = json_file(folder / 'build.json'); build_context(build, context)
    require(build.get('schema') == config['build_schema'], 'build schema differs')
    require(build.get('compiler_sha256') == context['compiler_sha256'], 'build compiler differs')
    files = [folder / 'build.json', folder / 'manifest.json']
    if owner == 'authority':
        manifest, image = manifest_image(folder / 'manifest.json', config['manifest_schema'], config['source'], context)
        require(build.get('manifest') == manifest, 'build manifest differs')
        compile_receipt(build.get('native_compile_receipt'), manifest, image, context)
        files.append(image); manifests = {'authority': manifest}
    else:
        bundle = json_file(folder / 'manifest.json')
        require(bundle.get('schema') == 'hepta.hia.artifact-page-bundle.v2' and build.get('bundle') == bundle,
                'page bundle differs')
        manifests = {}
        for name, schema, source in (
                ('policy', config['manifest_schema'], config['source']),
                ('wire', 'hepta.hia.json-wire-native.v1', 'examples/hia_bootstrap/json_wire.hiaasm')):
            path = child_path(folder, bundle.get(name + '_manifest'))
            require(file_record(path)['sha256'] == bundle.get(name + '_manifest_sha256'), 'bundle child manifest differs')
            manifest, image = manifest_image(path, schema, source, context)
            manifests[name] = manifest; files.extend((path, image))
            if name == 'policy':
                require(build.get('policy_manifest') == manifest, 'page policy manifest differs')
                receipt = build.get('policy_compile_receipt')
            else:
                wire = json_file(path.parent / 'build.json'); build_context(wire, context)
                require(wire.get('schema') == 'hepta.hia.json-wire-build.v1'
                        and wire.get('manifest') == manifest and build.get('wire_build') == wire,
                        'retained wire build differs')
                receipt = wire.get('native_compile_receipt'); files.append(path.parent / 'build.json')
            compile_receipt(receipt, manifest, image, context)
    return {'owner': owner, 'files': [file_record(p) for p in files], 'manifests': manifests,
            'bundle': bundle if owner == 'page' else None}


def inspect_component_observations(owner, fixture, binding, context):
    """Bind the complete method assertions to their retained runtime objects."""
    fixture = Path(fixture); observed = json_file(fixture / 'observations.json')
    if owner == 'authority':
        require(observed.get('schema') == 'hepta.hia.agent-store-authority-observations.v1'
                and observed.get('scope') == 'MATCHING_SOURCE_COLD_BUILD'
                and observed.get('source_unchanged') is True and observed.get('manifest_unchanged') is True,
                'Store runtime observations differ')
        require(observed.get('source_sha256') == context['source_manifest'][OWNERS[owner]['source']]
                and observed.get('manifest_sha256') == binding['files'][1]['sha256'], 'Store observation identities differ')
        modes = observed.get('actual_native_modes', {})
        require(set(modes) == set(map(str, range(6))) and all(type(v) is int and v > 0 for v in modes.values()),
                'Store component did not exercise all six modes')
        comparisons = observed.get('comparisons')
        require(type(comparisons) is list and comparisons and all(v.get('equal') is True for v in comparisons),
                'Store component lacks exact comparison observations')
    else:
        require(observed.get('scope') == 'MATCHING_SOURCE_COLD_NATIVE_TESTS'
                and observed.get('policy_image') == binding['manifests']['policy']['image_sha256']
                and observed.get('wire_image') == binding['manifests']['wire']['image_sha256'],
                'page runtime identities differ')
        before = observed.get('source_before')
        require(type(before) is dict and before and before == observed.get('source_after')
                and all(context['source_manifest'].get(k) == v for k, v in before.items()), 'page observation source differs')
        boundary = observed.get('observations', {}).get('full_boundaries', {})
        cases = boundary.get('observations', [])
        require(boundary.get('status') == 'DEVELOPMENT_BOUNDARIES_PASS' and boundary.get('expected_case_count') == 42
                and boundary.get('failures') == [] and boundary.get('source_preserved') is True
                and len(cases) == 42 and len({v.get('case') for v in cases}) == 42
                and all(v.get('status') == 'PASS' for v in cases), 'complete fresh 42-page boundary observations missing')
        require(boundary.get('policy_image') == binding['manifests']['policy']['image_sha256']
                and boundary.get('wire_image') == binding['manifests']['wire']['image_sha256'], 'page boundary images differ')
        for name in ('max-artifact-ascii', 'max-artifact-invalid-last', 'max-artifact-utf8-four'):
            found = [v for v in cases if v.get('case') == name]
            require(len(found) == 1 and found[0].get('source_bytes') == 64 << 20
                    and found[0].get('full_input_observation_bytes') == 64 << 20, 'original 64 MiB page boundary not observed')
    installed = fixture / 'installed'; child = json_file(installed / 'child.stdout')
    require(child.get('status') == 'PASS' and (installed / 'child.stderr').read_bytes() == b'', 'installed child did not pass cleanly')
    site = installed / 'site'; resource = site / 'hepta/_data' / OWNERS[owner]['source']
    require(Path(child['source']).resolve(strict=True) == resource.resolve(strict=True)
            and file_record(resource)['sha256'] == context['source_manifest'][OWNERS[owner]['source']],
            'installed selected source differs')
    for name, expected in context['source_manifest'].items():
        if name.startswith('hepta/') and name.endswith('.py'):
            require(file_record(site / name)['sha256'] == expected, 'installed Python byte identity differs: ' + name)
    if owner == 'page':
        require(child.get('calls', 0) > 1
                and child == observed.get('observations', {}).get('installed'), 'installed page observations differ')
        require(file_record(site / 'hepta/_data/examples/hia_bootstrap/json_wire.hiaasm')['sha256']
                == context['source_manifest']['examples/hia_bootstrap/json_wire.hiaasm'], 'installed page wire source differs')
    return {'observations': file_record(fixture / 'observations.json'),
            'installed_stdout': file_record(installed / 'child.stdout'),
            'installed_stderr': file_record(installed / 'child.stderr')}


def complete_ids(report, expected, count):
    require(type(expected) is list and len(expected) == count and len(set(expected)) == count,
            'expected test denominator differs')
    require(report.get('loaded_test_ids') == expected and report.get('chosen_test_ids') == expected
            and report.get('executed_test_ids') == expected, 'test IDs are incomplete or reordered')
    require(all(type(report.get(k)) is int and report[k] == count for k in ('tests_loaded', 'tests_chosen', 'tests_run')),
            'test counts differ')
    require(all(report.get(k) == [] for k in ANOMALIES), 'unittest anomalies are not empty')


def validate_component(owner, report, expected, binding, context, runtime_observations):
    config = OWNERS[owner]
    require(report.get('schema') == 'hepta.hia.store-page-component.v1' and report.get('owner') == owner,
            'component report schema/owner differs')
    require(report.get('status') == 'PASS' and report.get('scope') == 'MATCHING_SOURCE_COLD_COMPONENT',
            'component lacks matching cold execution')
    complete_ids(report, expected, config['component_tests'])
    require(report.get('modules') == [config['module']] and report.get('loader_errors') == [],
            'component selection differs')
    require(report.get('unittest_successful') is True, 'unittest did not report success')
    require(report.get('source_before') == context['source_manifest'] == report.get('source_after')
            and report.get('source_preserved') is True and report.get('cold_inputs_preserved') is True,
            'component source/cold inputs changed')
    require(report.get('build_binding') == binding and report.get('cold_inputs') == context['identities'],
            'component actual build binding differs')
    require(type(runtime_observations) is dict and runtime_observations
            and report.get('runtime_observations') == runtime_observations,
            'retained component runtime observations differ from actual readback')
    return True


def validate_callers(owner, report, expected, binding, context):
    config = OWNERS[owner]
    require(report.get('schema') == config['caller_schema'] and report.get('status') == 'PASS'
            and report.get('scope') == 'MATCHING_SOURCE_COLD_SELECTED_CALLERS', 'caller scope/status differs')
    complete_ids(report, expected, 67)
    require(report.get('modules') == list(CALLER_MODULES) and report.get('explicit_development_exclusions') == {},
            'original caller selection differs')
    require(report.get('retained_owner_forbidden') is True and report.get('retained_owner_entries') == [],
            'retained semantic owner entered')
    require(report.get('all_eleven_agent_tools_exercised') is True
            and report.get('source_manifest') == context['source_manifest']
            and report.get('matching_cold_source_closure_stable') is True, 'caller source/tool evidence differs')
    source = report.get('source_sha256')
    require(type(source) is dict and set(source) == set(config['caller_sources']) and report.get('source_after_sha256') == source
            and all(context['source_manifest'].get(k) == v for k, v in source.items()), 'caller source pins differ')
    require(report.get('evidence_dir_retained') is True, 'caller build was not retained')
    require(Path(report.get('manifest_path', '')).resolve() == Path(binding['files'][1]['path'])
            and (Path(report.get('evidence_dir', '')) / config['caller_build'] / 'manifest.json').resolve()
            == Path(binding['files'][1]['path']), 'caller manifest is not its retained build')
    suffix = 'store' if owner == 'authority' else 'page'
    with_owner = report.get('agent_tools_with_native_' + suffix, {})
    without_owner = report.get('agent_tools_without_native_' + suffix, {})
    require(all(type(v) is int and v > 0 for m in (with_owner, without_owner) for v in m.values())
            and set(TOOLS) <= set(with_owner) | set(without_owner), 'actual eleven-tool counters are incomplete')
    if owner == 'authority':
        methods = ('ref', 'get', 'resolve_uri', 'profile', 'check_profile', 'put')
        modes = report.get('actual_native_modes', {})
        require(report.get('all_six_store_modes_entered_native') is True and set(modes) == set(methods)
                and all(type(modes[k]) is int and modes[k] > 0 for k in methods), 'six Store modes were not observed')
        uri = report.get('independent_uri_control', {})
        require(uri.get('status') == 'PASS' and uri.get('part_of_original_loaded_ids') is False
                and uri.get('failure') is None and type(uri.get('reference')) is dict and uri['reference']
                and uri['reference'] == uri.get('native'), 'independent URI control differs')
        manifest = binding['manifests']['authority']
        require(report.get('source_manifest_image_stable') is True and report.get('manifest') == manifest
                and report.get('image_sha256') == manifest['image_sha256'], 'caller Store image differs')
    else:
        counts = [report.get('actual_native_entries', {}).get('read'),
                  report.get('agent_tools_with_native_page', {}).get('hia_read'),
                  report.get('actual_native_step_returns', {}).get('2')]
        require(report.get('ordinary_hia_read_entered_native') is True
                and all(type(v) is int and v > 0 for v in counts),
                'ordinary page execution was not observed')
        require(report.get('source_manifest_images_stable') is True
                and report.get('policy_image_sha256') == binding['manifests']['policy']['image_sha256']
                and report.get('wire_image_sha256') == binding['manifests']['wire']['image_sha256'],
                'caller page bundle images differ')
        files = {v['path']: {'size': v['bytes'], 'sha256': v['sha256']}
                 for v in binding['files'] if Path(v['path']).name != 'build.json'}
        require(report.get('bundle_manifest') == binding['bundle']
                and report.get('bundle_files_before') == files == report.get('bundle_files_after'),
                'actual caller page bundle files differ')
    return True


def require_successor_gates(gates):
    """v9 integration may call this; a v8-only PASS cannot satisfy new owners."""
    require(type(gates) is dict and set(gates) == set(SUCCESSOR_GATES)
            and all(gates[k] is True for k in SUCCESSOR_GATES), 'all 21 successor gates must independently pass')
    return True
