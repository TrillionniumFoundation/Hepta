"""Author source-bound public runtime publication DAGs.

Only checked-in HIA and HIASTD01 data execute in production. This development
author records the native construction, source custody and publication checks.
"""
from pathlib import Path
import json

from tools.generate_hia_native_controller_release import ControllerRecipe, BOOT, FILTER_POLICY

ROOT = Path(__file__).resolve().parents[1]
RECIPE_PATH = BOOT + 'release_stage_runtime.hiastd'
NDU_RECIPE = 'docs/HIA_NATIVE_NDU_EVALUATOR_RECIPE.json'
NDU_RECEIPT = 'docs/HIA_NATIVE_NDU_EVALUATOR_BUILD.json'


def equal_digest(r, value, expected):
    r.node(8, (r.digest(value), r.literal(bytes.fromhex(expected))))


def build_recipe():
    description = json.loads((ROOT / NDU_RECIPE).read_text())
    receipt_bytes = (ROOT / NDU_RECEIPT).read_bytes()
    receipt = json.loads(receipt_bytes)
    assert description['schema'] == 'hepta.hia.ndu-native-recipe.v1'
    assert receipt['schema'] == 'hepta.hia.ndu-native-build.v1'
    assert description['publish']['require_exact_output_sha256'] == receipt['binary_sha256']
    assert description['pack']['magic'] == 'HIANDP01'
    assert description['pack']['reserved_zero_at'] == 40
    assert description['pack']['tail_roles'] == ['transport', 'evaluator', 'number', 'debug']
    r = ControllerRecipe()
    modules = description['compile']['roles']
    paths = sorted({BOOT + FILTER_POLICY, BOOT + 'native_filter_packer.hepta',
                    *(row['source_path'] for row in modules)})
    r.compile_exact(paths)
    # The source compiler is this invocation's previously published and sealed
    # product, not a path supplied by a leaf request or a receipt.
    compiler = r.import_product('hia-source-build')
    equal_digest(r, compiler, receipt['build_inputs']['compiler']['sha256'])
    r.node(8, (r.length(compiler), r.q(receipt['build_inputs']['compiler']['bytes'])))
    for path, digest in sorted(receipt['source_files'].items()):
        equal_digest(r, r.source(path), digest)
    for row in modules:
        source, flat = r.source_views[row['source_path']], r.compiled[row['source_path']]
        equal_digest(r, source, row['source_sha256'])
        equal_digest(r, flat, row['flat_sha256'])
        r.node(8, (r.length(source), r.q(row['source_bytes'])))
        r.node(8, (r.length(flat), r.q(row['flat_bytes'])))
    r.small_builder = r.checked_kit('native_filter_packer.hepta')
    packer_row = next(row for row in modules if row['role'] == 'packer')
    packer = r.native_filter(r.compiled[packer_row['source_path']], wide=False)
    equal_digest(r, packer, receipt['build_inputs']['packer_wrapper_sha256'])
    by_role = {row['role']: r.compiled[row['source_path']] for row in modules}
    parts = [by_role[name] for name in description['pack']['tail_roles']]
    packet = r.concat(r.literal(b'HIANDP01'), *(r.length(p) for p in parts), r.q(0), *parts)
    image = r.run(packer, packet, 0)
    equal_digest(r, image, receipt['binary_sha256'])
    r.node(8, (r.length(image), r.q(receipt['binary_bytes'])))
    r.publish('hia-ndu-evaluator', image, receipt['binary_sha256'])
    # This is the frozen source/output qualification binding. Its original
    # filter-root provenance is not relabelled as this DAG's executing tool.
    # Its own recipe explicitly authorizes publication after the checks above.
    from hashlib import sha256
    frozen_receipt = r.source(NDU_RECEIPT)
    receipt_pin = sha256(receipt_bytes).hexdigest()
    equal_digest(r, frozen_receipt, receipt_pin)
    r.publish('hia-ndu-evaluator-build.json', frozen_receipt, receipt_pin)
    assert len(r.nodes) <= 8192 and r.next_handle <= 2049
    assert len(r.binary()) <= 1048576
    resources = sorted(set(receipt['source_files']) - set(paths) | {NDU_RECEIPT})
    return r, paths, resources


def register_stage(paths, resources, published):
    table = ROOT / BOOT / 'release_stage_sources.tsv'
    lines = table.read_text('ascii').splitlines()
    header = lines[0].split('\t')
    assert header[0] == 'stage' and 11 <= int(header[1]) <= 16, header
    records = [line for line in lines[1:] if line.split('\t')[1] != '12']
    before = [line for line in records if int(line.split('\t')[1]) < 12]
    after = [line for line in records if int(line.split('\t')[1]) > 12]
    rows = ['stage\t12\tnative-public-runtime',
            'need\t12\t0\thia-source-build',
            'need\t12\t0\tselfhost.image.bin']
    for index, path in enumerate(paths):
        rows.append('compile\t12\truntime-' + str(index // 96) + '\t'
                    + Path(path).name + '\t' + path.removeprefix(BOOT))
    rows.append('kit\t12\t' + FILTER_POLICY + '\tnative_filter_packer.hepta')
    rows.extend('resource\t12\t' + path for path in resources)
    rows.extend('output\t12\t' + name for name in published)
    rows.append('framing\t12\t0\tHIANDP01\tqualified-source-module-wrapper-output-binding')
    stage_count = max(int(header[1]), 12)
    output_count = sum(line.startswith('output\t') for line in records) + len(published)
    final = ['stage\t' + str(stage_count) + '\t' + str(output_count)] + before + rows + after
    encoded = ('\n'.join(final) + '\n').encode('ascii')
    assert len(encoded) <= 262144 and output_count <= 128
    assert sum(line.startswith('compile\t') for line in final) <= 1024
    table.write_bytes(encoded)


def main():
    r, paths, resources = build_recipe()
    (ROOT / RECIPE_PATH).write_bytes(r.binary())
    register_stage(paths, resources, r.published)
    print(json.dumps({'recipe': RECIPE_PATH, 'nodes': len(r.nodes),
                      'handles': r.next_handle - 1, 'bytes': len(r.binary()),
                      'compile_sources': paths, 'resources': resources,
                      'published': r.published}, indent=2))


if __name__ == '__main__':
    main()
