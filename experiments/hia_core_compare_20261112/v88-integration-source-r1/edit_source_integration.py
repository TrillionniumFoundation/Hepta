"""Apply the first narrow integration changes to the exact partial c7aa source.

This script edits source only. It never imports Hepta or invokes a generator.
Every edited input is retained separately before its first mutation.
"""
from pathlib import Path
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE / 'source'
BEFORE = HERE / 'integration-before'


def change(name, replacements):
    path = ROOT / name
    original = path.read_text()
    updated = original
    for old, new, count in replacements:
        if updated.count(old) != count:
            raise ValueError((name, old[:100], updated.count(old), count))
        updated = updated.replace(old, new)
    saved = BEFORE / name
    saved.parent.mkdir(parents=True, exist_ok=True)
    with saved.open('x') as stream:
        stream.write(original)
    path.write_text(updated)


change('hepta/hia_agent_contract.py', [(
    'NATIVE_SOURCE_FILES = (\n',
    "NATIVE_SOURCE_FILES = (\n    'hepta/hia_core_compare_abi.json',\n"
    "    'examples/hia_bootstrap/core_compare.hiaasm',\n", 1)])
change('MANIFEST.in', [(
    'include examples/hia_bootstrap/core_unpack.hiaasm\n',
    'include examples/hia_bootstrap/core_unpack.hiaasm\n'
    'include hepta/hia_core_compare_abi.json\n'
    'include examples/hia_bootstrap/core_compare.hiaasm\n', 1)])
change('tests/test_hia_agent_installed_resources.py', [(
    "BUNDLED_SOURCE_BINDINGS={\n",
    "BUNDLED_SOURCE_BINDINGS={\n    'core_compare':('hepta.hia_core_compare_selection','control'),\n", 1), (
    "NATIVE_METADATA_RESOURCE_FILES=('hepta/hia_bounded_read_abi.json','hepta/hia_core_unpack_abi.json')",
    "NATIVE_METADATA_RESOURCE_FILES=('hepta/hia_bounded_read_abi.json','hepta/hia_core_unpack_abi.json',"
    "'hepta/hia_core_compare_abi.json')", 1)])
change('tools/generate_hia_core_compare.py', [(
    "    parser.add_argument('--output', type=Path, required=True)\n"
    "    args = parser.parse_args()\n"
    "    with args.output.open('x') as stream:\n"
    "        stream.write(render_assembly(document()))\n"
    "    print(args.output.name, args.output.stat().st_size)",
    "    parser.add_argument('--output', type=Path)\n"
    "    args = parser.parse_args()\n"
    "    output = args.output\n"
    "    mode = 'x'\n"
    "    if output is None:\n"
    "        output = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/core_compare.hiaasm'\n"
    "        mode = 'w'\n"
    "    with output.open(mode) as stream:\n"
    "        stream.write(render_assembly(document()))\n"
    "    print(output.name, output.stat().st_size)", 1)])
change('tests/test_hia_core_compare_source.py', [(
    'import sys\n', 'import sys\nimport tempfile\n', 1), (
    "BASE = Path(os.environ['HEPTA_COMPARE_BASE_ROOT'])\n"
    "EVIDENCE = Path(os.environ['HEPTA_COMPARE_CONTROL_EVIDENCE'])",
    "BASE = Path(os.environ.get('HEPTA_COMPARE_BASE_ROOT', str(ROOT)))\n"
    "_EXPLICIT_EVIDENCE = os.environ.get('HEPTA_COMPARE_CONTROL_EVIDENCE')\n"
    "EVIDENCE = Path(_EXPLICIT_EVIDENCE) if _EXPLICIT_EVIDENCE else None", 1), (
    "    def setUpClass(cls):\n        EVIDENCE.mkdir(mode=0o700)",
    "    def setUpClass(cls):\n"
    "        global EVIDENCE\n"
    "        if _EXPLICIT_EVIDENCE is None:\n"
    "            # A fresh, retained fixture makes ordinary unittest discovery\n"
    "            # portable without deleting diagnostics from a failing run.\n"
    "            EVIDENCE = Path(tempfile.mkdtemp(prefix='hia-core-compare-source-')) / 'evidence'\n"
    "        cls.evidence_directory = EVIDENCE\n"
    "        EVIDENCE.mkdir(mode=0o700)", 1)])
change('.github/workflows/hia-core.yml', [(
    'machine_elf core_lowering bounded_read core_unpack; do',
    'machine_elf core_lowering bounded_read core_unpack core_compare; do', 1), (
    "              'tests.test_hia_core_unpack_native.UnpackCompositionSourceTests',\n",
    "              'tests.test_hia_core_unpack_native.UnpackCompositionSourceTests',\n"
    "              'tests.test_hia_core_compare_source.ExactNumericComparisonSourceTests',\n"
    "              'tests.test_hia_core_compare_integration.NumericComparisonIntegrationSourceTests',\n", 1)])
change('tools/hia_compiler_owner_gates.py', [(
    "SOURCE_GENERATORS = LEGACY_SOURCE_GENERATORS + ('bounded_read', 'core_unpack')",
    "SOURCE_GENERATORS = LEGACY_SOURCE_GENERATORS + ('bounded_read', 'core_unpack', 'core_compare')", 1)])
change('tests/test_hia_compiler_owner_gates.py', [(
    "['bounded_read', 'core_unpack']", "['bounded_read', 'core_unpack', 'core_compare']", 2), (
    "ledger['generator_count'], 61", "ledger['generator_count'], 62", 1), (
    'len(actual), 61', 'len(actual), 62', 1), (
    'len(set(actual)), 61', 'len(set(actual)), 62', 1)])
change('tests/test_hia_store_page_gates.py', [(
    "generators[59:], ['bounded_read', 'core_unpack']",
    "generators[59:], ['bounded_read', 'core_unpack', 'core_compare']", 1)])
change('tests/test_hia_core_unpack_gates.py', [(
    "value['source_generator_count'], 61", "value['source_generator_count'], 62", 1)])
change('docs/HIA_COMPILER_OWNER_QUALIFICATION_GATES.json', [(
    '"generator_count": 61', '"generator_count": 62', 1), (
    '    "core_unpack"\n', '    "core_unpack",\n    "core_compare"\n', 1)])
change('docs/HIA_CORE_UNPACK_QUALIFICATION_GATES.json', [(
    '"source_generator_count": 61', '"source_generator_count": 62', 1), (
    '    "core_unpack"\n', '    "core_unpack",\n    "core_compare"\n', 1), (
    '"61 generator order unchanged"',
    '"original 61 generator prefix preserved; core_compare appended as number 62"', 1)])

print(json.dumps({'status': 'SOURCE_EDITS_ONLY', 'executed_product': False,
                  'backup_root': str(BEFORE)}, sort_keys=True))
