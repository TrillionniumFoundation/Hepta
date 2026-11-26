"""Author the source-bound, matching Future family as native release stage 13.

HIASTD01 is retained data consumed by the HIA release owner. Source capture,
compilation, kit construction, packing, identity checks and publication execute
without this development author or a hosted semantic implementation.
"""
from hashlib import sha256
from pathlib import Path
import json
from tools.generate_hia_native_controller_release import ControllerRecipe, BOOT, FILTER_POLICY

ROOT = Path(__file__).resolve().parents[1]
RECIPE = BOOT + 'release_stage_future.hiastd'
RECEIPT = 'docs/HIA_NATIVE_FUTURE_RELEASE_BUILD.json'
VALUE_ROLES = ('result_value_owner', 'result_value_core', 'result_value_import',
               'result_value_export', 'background_optimizer_json_capture',
               'agent_binary64_format', 'result_value_binary64')
RECORD_VALUE_ROLES = VALUE_ROLES + ('result_value_dict_iterator', 'result_value_classes',
                                  'native_class_mro', 'result_value_records')
PUBLIC_ROLES = ('background_optimizer_future_public_owner',
                'background_optimizer_future_public_carrier',
                'background_optimizer_future_public_timeout',
                'background_optimizer_future_public_log',
                'multiversion_background_future_cell', 'multiversion_future')
ADAPTER = 'background_optimizer_future_release_packer'
CANCELLATION_ROLES = ('publication_cancellation_public', 'multiversion_runtime_handles',
                      'publication_cancellation_effects', 'multiversion_future')


def equal_digest(r, value, expected):
    r.node(8, (r.digest(value), r.literal(bytes.fromhex(expected))))


def build_recipe():
    receipt_bytes = (ROOT / RECEIPT).read_bytes()
    receipt = json.loads(receipt_bytes)
    assert receipt['schema'] == 'hepta.hia.future-native-release-build.v1'
    assert receipt['status'] == 'PASS'
    assert not any(receipt[name] for name in ('whole_public_future_closed',
        'whole_background_optimizer_closed', 'final_unified_dispatcher_qualified', 'production_activated'))
    protocol = receipt.get('value_protocol', 'HIABVP01')
    assert protocol in ('HIABVP01', 'HIABVP04')
    if protocol == 'HIABVP04':
        assert receipt['inherited_behavior_requalified'] is True
        assert receipt['value_class_queries_qualified'] is True
        assert receipt['future_kind_qualification']['path'] in receipt['source_files']
        assert receipt['value_roles'] == list(RECORD_VALUE_ROLES)
        assert receipt['value_packer'] == 'result_value_records_packer'
        assert receipt['value_qualification']['path'] in receipt['source_files']
        value_roles, value_packer = RECORD_VALUE_ROLES, 'result_value_records_packer'
    else:
        value_roles, value_packer = VALUE_ROLES, 'result_value_packer'
    r = ControllerRecipe()
    paths = sorted(row['source_path'] for row in receipt['modules'])
    assert len(paths) == len(set(paths)) and BOOT + FILTER_POLICY in paths
    assert BOOT + 'native_filter_packer.hepta' in paths and BOOT + 'selfhost.hepta' in paths
    r.compile_exact(paths)
    compiler = r.import_product('hia-source-build')
    equal_digest(r, compiler, receipt['compiler']['sha256'])
    r.node(8, (r.length(compiler), r.q(receipt['compiler']['bytes'])))
    for path, expected in sorted(receipt['source_files'].items()):
        equal_digest(r, r.source(path), expected)
    for row in receipt['modules']:
        path = row['source_path']
        assert row['double_compile_identical'] is True
        equal_digest(r, r.source_views[path], row['source_sha256'])
        equal_digest(r, r.compiled[path], row['flat_sha256'])
        r.node(8, (r.length(r.source_views[path]), r.q(row['source_bytes'])))
        r.node(8, (r.length(r.compiled[path]), r.q(row['flat_bytes'])))
    r.small_builder = r.checked_kit('native_filter_packer.hepta')
    # The builder is reconstructed in this invocation from the three captured
    # HIA sources. This also binds it to the qualification's actual native kit.
    equal_digest(r, r.small_builder, receipt['native_filter_kit']['dag_frame_sha256'])
    r.node(8, (r.length(r.small_builder), r.q(receipt['native_filter_kit']['dag_frame_bytes'])))
    packers = {}
    for name in (value_packer, 'background_optimizer_future_public_packer', ADAPTER,
                 'publication_cancellation_packer'):
        image = r.native_filter(r.compiled[BOOT + name + '.hepta'], wide=False)
        expected = receipt['wrappers'][name]
        equal_digest(r, image, expected['sha256'])
        r.node(8, (r.length(image), r.q(expected['bytes'])))
        packers[name] = image

    def flat(name):
        return r.compiled[BOOT + name + '.hepta']

    def publish(name, value):
        expected = receipt['products'][name]
        equal_digest(r, value, expected['sha256'])
        r.node(8, (r.length(value), r.q(expected['bytes'])))
        r.publish(name, value, expected['sha256'])
        return value

    parts = [flat(name) for name in value_roles]
    wire = r.concat(r.literal(protocol.encode('ascii')), r.q(len(value_roles)),
                    *(r.length(p) for p in parts), r.q(1), *parts)
    value = publish('hia-result-value.core.bin', r.run(packers[value_packer], wire, 0))
    policy = flat('background_optimizer_future_public_observers_notify')
    wire = r.concat(r.literal(b'HIABFNPK'), r.length(policy), r.q(0, 0), policy)
    notify = publish('hia-future-notify.core.bin', r.run(packers[ADAPTER], wire, 0))
    parts = [flat(name) for name in PUBLIC_ROLES] + [value, notify]
    wire = r.concat(r.literal(b'HIABFPP2'), r.q(8), *(r.length(p) for p in parts), r.q(1), *parts)
    publish('hia-future-public.core.bin', r.run(packers['background_optimizer_future_public_packer'], wire, 0))
    parts = [flat('background_optimizer_future_public_observers'),
             flat('background_optimizer_future_public_observers_math')]
    wire = r.concat(r.literal(b'HIABFOPK'), *(r.length(p) for p in parts), r.q(0), *parts)
    observers = publish('hia-future-observers.core.bin', r.run(packers[ADAPTER], wire, 0))
    parts = [flat('background_optimizer_future_public_observers_iterable'), observers]
    wire = r.concat(r.literal(b'HIABFAPK'), *(r.length(p) for p in parts), r.q(0), *parts)
    publish('hia-future-iterable.core.bin', r.run(packers[ADAPTER], wire, 0))
    parts = [flat(name) for name in CANCELLATION_ROLES]
    wire = r.concat(r.literal(b'HIAPCPK1'), r.q(4), *(r.length(p) for p in parts), r.q(0, 0), *parts)
    publish('hia-publication-cancellation.core.bin', r.run(packers['publication_cancellation_packer'], wire, 0))
    frozen = r.source(RECEIPT)
    pin = sha256(receipt_bytes).hexdigest()
    equal_digest(r, frozen, pin)
    r.publish('hia-future-build.json', frozen, pin)
    assert len(r.nodes) <= 8192 and r.next_handle <= 2049 and len(r.binary()) <= 1048576
    resources = sorted((set(receipt['source_files']) - set(paths)) | {RECEIPT})
    return r, paths, resources


def register_stage(paths, resources, published):
    table = ROOT / BOOT / 'release_stage_sources.tsv'
    lines = table.read_text('ascii').splitlines()
    header = lines[0].split('\t')
    assert header[0] == 'stage' and 12 <= int(header[1]) <= 16
    records = [line for line in lines[1:] if line.split('\t')[1] != '13']
    before = [line for line in records if int(line.split('\t')[1]) < 13]
    after = [line for line in records if int(line.split('\t')[1]) > 13]
    rows = ['stage\t13\tnative-matching-future-family',
            'need\t13\t0\thia-source-build', 'need\t13\t0\tselfhost.image.bin']
    for index, path in enumerate(paths):
        rows.append('compile\t13\tfuture-' + str(index // 96) + '\t' + Path(path).name
                    + '\t' + path.removeprefix(BOOT))
    rows.append('kit\t13\t' + FILTER_POLICY + '\tnative_filter_packer.hepta')
    rows.extend('resource\t13\t' + path for path in resources)
    rows.extend('output\t13\t' + name for name in published)
    rows.append('framing\t13\t0\tHIABFPP2\tsource-bound-matching-inherited-future-family')
    output_count = sum(line.startswith('output\t') for line in records) + len(published)
    final = ['stage\t' + str(max(int(header[1]), 13)) + '\t' + str(output_count)] + before + rows + after
    encoded = ('\n'.join(final) + '\n').encode('ascii')
    assert len(encoded) <= 262144 and output_count <= 128
    assert sum(line.startswith('compile\t') for line in final) <= 1024
    table.write_bytes(encoded)


def main():
    recipe, paths, resources = build_recipe()
    (ROOT / RECIPE).write_bytes(recipe.binary())
    register_stage(paths, resources, recipe.published)
    print(json.dumps({'recipe': RECIPE, 'nodes': len(recipe.nodes), 'handles': recipe.next_handle - 1,
                      'bytes': len(recipe.binary()), 'sources': len(paths), 'resources': resources,
                      'published': recipe.published}, indent=2))


if __name__ == '__main__':
    main()
