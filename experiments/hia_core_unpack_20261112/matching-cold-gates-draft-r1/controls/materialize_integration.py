"""Create proposed snapshots only below this independent draft's inputs directory."""
from pathlib import Path
import json

BASE=Path('/tmp/hia-core-unpack-v83-20261112-r1/source')
DRAFT=Path(__file__).resolve().parents[1]
OUT=DRAFT/'inputs'

def write(name,raw):
    path=OUT/name
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(raw)

workflow=(BASE/'.github/workflows/hia-core.yml').read_text()
anchor='      - name: Preserve actual cold failure and stage evidence\n'
steps='''      - name: Matching-cold UNPACK with the original complete Core116
        run: |
          set -eu
          python -B tools/qualify_hia_core_unpack_ci.py owned-callers \\
            --cold-report "$RUNNER_TEMP/hia-cold.json" \\
            --evidence-dir "$RUNNER_TEMP/hia-core-unpack-evidence" \\
            --output "$RUNNER_TEMP/hia-core-unpack-callers-admission.json"
      - name: Complete 18 UNPACK controls and independent two-gate conjunction
        run: |
          set -eu
          python -B tools/qualify_hia_core_unpack_ci.py owned-component \\
            --cold-report "$RUNNER_TEMP/hia-cold.json" \\
            --evidence-dir "$RUNNER_TEMP/hia-core-unpack-evidence" \\
            --output "$RUNNER_TEMP/hia-core-unpack-gates.json"
'''
assert workflow.count(anchor)==1
workflow=workflow.replace(anchor,steps+anchor)
source_anchor="              'tests.test_hia_core_unpack_native.UnpackCompositionSourceTests',\n"
assert workflow.count(source_anchor)==1
workflow=workflow.replace(source_anchor,source_anchor+"              'tests.test_hia_core_unpack_gates',\n")
artifact_anchor='            ${{ runner.temp }}/hia-core-lowering-gate.json\n'
assert workflow.count(artifact_anchor)==1
workflow=workflow.replace(artifact_anchor,artifact_anchor+'''            ${{ runner.temp }}/hia-core-unpack-evidence/
            ${{ runner.temp }}/hia-core-unpack-callers-admission.json
            ${{ runner.temp }}/hia-core-unpack-gates.json
''')
write('.github/workflows/hia-core.yml',workflow)
(DRAFT/'controls/added-ci-steps.yml.txt').write_text(steps)

path='experiments/hia_native_successor_runner_20261111/run_hia_qualification_v9.py'
runner=(BASE/path).read_text()
runner=runner.replace('harness_revision v9 records', 'harness_revision v10 records')
anchor='from tools import hia_compiler_owner_gates as compiler_owner_gates\n'
assert runner.count(anchor)==1
runner=runner.replace(anchor,anchor+'from tools import hia_core_unpack_gates as core_unpack_gates\n')
anchor="                 'compiler_owner_gates': Path(compiler_owner_gates.__file__).resolve()}"
assert runner.count(anchor)==1
runner=runner.replace(anchor,"                 'compiler_owner_gates': Path(compiler_owner_gates.__file__).resolve(),\n                 'core_unpack_gates': Path(core_unpack_gates.__file__).resolve(),\n                 'core_unpack_ci': root / 'tools/qualify_hia_core_unpack_ci.py'}")
anchor="elf_component_outcome = {'completed': False, 'passed': False, 'executed': False}\n"
assert runner.count(anchor)==1
runner=runner.replace(anchor,anchor+"core_unpack_outcome = {'completed': False, 'passed': False, 'executed': False}\n"+
    "discarded_unpack_selector = environment.pop('HEPTA_HIA_CORE_UNPACK_MANIFEST', None) is not None\n")
# Only the full retained suite receives this evidence *path*, never an ambient native selector.
anchor="    step_environment['HEPTA_HIA_CORE_MODULE_GRAPH_OBSERVATIONS'] = str(out / (name + '-module-projects'))\n"
assert runner.count(anchor)==1
runner=runner.replace(anchor,"    if name == 'full-retained-regression':\n"+
    "        step_environment['HEPTA_HIA_CORE_UNPACK_COLD_REPORT'] = str(cold)\n"+
    "        step_environment['HEPTA_HIA_CORE_UNPACK_MATCHING_CALLER_EVIDENCE'] = str(out / 'core-unpack-evidence')\n"+anchor)
func='''

def complete_core_unpack():
    """Conjoin the two original 180/3 phases; do not split or replace Core116."""
    from tools.qualify_hia_core_unpack_ci import qualify_all, write_new
    outcome = {'completed': False, 'passed': False, 'executed': True,
               'gates': {name: False for name in core_unpack_gates.NEW_GATES},
               'separate_original_180_second_owners': 2,
               'original116_split': False, 'whole_native_delivery_qualified': False}
    started = time.monotonic()
    context = None
    try:
        context = core_unpack_gates.cold_inputs(cold)
        inspection = qualify_all(cold, out / 'core-unpack-evidence')
        outcome['completed'] = True
        actual = core_unpack_gates.inspect_all(out / 'core-unpack-evidence', cold, context)
        core_unpack_gates.require(actual == inspection, 'UNPACK full-harness independent readback changed')
        outcome['inspection'] = actual
        outcome['gates'] = actual['gates']
        outcome['passed'] = True
    except BaseException as error:
        outcome['passed'] = False
        outcome['error'] = repr(error)
    finally:
        if context is not None:
            try:
                core_unpack_gates.require(core_unpack_gates.cold_inputs(cold) == context,
                                          'UNPACK final matching-cold identity changed')
                core_unpack_gates.source_now(context)
            except BaseException as error:
                outcome['passed'] = False
                outcome['final_identity_error'] = repr(error)
        outcome['seconds'] = time.monotonic() - started
        write_new(out / 'core-unpack-conjunction.json', outcome)
    return outcome
'''
anchor='\ndef suite(name, names=None, discover=False):\n'
assert runner.count(anchor)==1
runner=runner.replace(anchor,func+anchor)
anchor="    if a.full:\n        ok = suite('full-retained-regression', discover=True) and ok\n"
assert runner.count(anchor)==1
runner=runner.replace(anchor,"    core_unpack_outcome = complete_core_unpack()\n"+
    "    ok = core_unpack_outcome['passed'] and ok\n"+anchor)
anchor='mandatory_v9_gates = {**mandatory_store_page_gates, **compiler_gates}\n'
assert runner.count(anchor)==1
runner=runner.replace(anchor,anchor+"mandatory_v10_gates = {**mandatory_v9_gates, **{name:\n"+
    "    core_unpack_outcome.get('passed') is True and core_unpack_outcome.get('gates', {}).get(name) is True\n"+
    "    for name in core_unpack_gates.NEW_GATES}}\n")
anchor='    compiler_owner_gates.require_successor_gates(mandatory_v9_gates)\n'
assert runner.count(anchor)==1
runner=runner.replace(anchor,anchor+'    core_unpack_gates.require_successor_gates(mandatory_v10_gates)\n')
runner=runner.replace("'harness_revision': 'v9'", "'harness_revision': 'v10'")
anchor="          'mandatory_v9_gates': mandatory_v9_gates,\n"
assert runner.count(anchor)==1
runner=runner.replace(anchor,anchor+"          'mandatory_v10_gates': mandatory_v10_gates,\n"+
    "          'core_unpack_conjunction': core_unpack_outcome,\n"+
    "          'discarded_unpack_selector': discarded_unpack_selector,\n")
write('experiments/hia_native_successor_runner_20261111/run_hia_qualification_v10.py',runner)

# The retained full-suite mode admits the exact prior conjunction; it does not
# silently skip native methods and does not activate a global Core selector.
path='tests/test_hia_core_unpack_native.py'
raw=(BASE/path).read_text()
anchor="        if not core_path or not unpack_path:\n            raise unittest.SkipTest('requires explicit paired Core and UNPACK manifests')\n"
replacement="""        cold = os.environ.get('HEPTA_HIA_CORE_UNPACK_COLD_REPORT')
        matched = os.environ.get('HEPTA_HIA_CORE_UNPACK_MATCHING_CALLER_EVIDENCE')
        if not core_path and not unpack_path and (cold or matched):
            if not cold or not matched:
                raise AssertionError('complete retained UNPACK needs both matching-cold evidence inputs')
            from tools import hia_core_unpack_gates as gates
            context = gates.cold_inputs(Path(cold))
            actual = gates.inspect_all(Path(matched), Path(cold), context)
            binding = gates.component_binding(actual['callers'])
            core_path = binding['Core39']['bundle_files'][0]['path']
            unpack_path = binding['UNPACK']['files'][0]['path']
        if not core_path or not unpack_path:
            raise unittest.SkipTest('requires explicit paired Core and UNPACK manifests')
"""
assert raw.count(anchor)==1
raw=raw.replace(anchor,replacement)
anchor='        cls.owner = core.installed_core_lowering(cls.core_manifest, vars(backend))\n'
replacement="        with patch.dict(os.environ, {selection.SELECTOR: str(cls.unpack_manifest)}):\n"+ \
    '            cls.owner = core.installed_core_lowering(cls.core_manifest, vars(backend))\n'
assert raw.count(anchor)==1
raw=raw.replace(anchor,replacement)
write(path,raw)
(DRAFT/'controls/retained-suite-setup-replacements.json').write_text(json.dumps([
["        if not core_path or not unpack_path:\n            raise unittest.SkipTest('requires explicit paired Core and UNPACK manifests')\n",replacement if False else """        cold = os.environ.get('HEPTA_HIA_CORE_UNPACK_COLD_REPORT')
        matched = os.environ.get('HEPTA_HIA_CORE_UNPACK_MATCHING_CALLER_EVIDENCE')
        if not core_path and not unpack_path and (cold or matched):
            if not cold or not matched:
                raise AssertionError('complete retained UNPACK needs both matching-cold evidence inputs')
            from tools import hia_core_unpack_gates as gates
            context = gates.cold_inputs(Path(cold))
            actual = gates.inspect_all(Path(matched), Path(cold), context)
            binding = gates.component_binding(actual['callers'])
            core_path = binding['Core39']['bundle_files'][0]['path']
            unpack_path = binding['UNPACK']['files'][0]['path']
        if not core_path or not unpack_path:
            raise unittest.SkipTest('requires explicit paired Core and UNPACK manifests')
"""],
[anchor,replacement]],indent=2)+'\n')

path='tools/hia_selfhost_contract.py'
raw=(BASE/path).read_text()
anchor="    'tools/qualify_hia_core_unpack_callers.py',\n"
addition="""    'tools/hia_core_unpack_gates.py',
    'tools/qualify_hia_core_unpack_ci.py',
    'tools/hia_core_unpack_controls/finite_controls.py',
    'tools/hia_core_unpack_controls/finite_launcher.py',
    'tests/test_hia_core_unpack_gates.py',
    'docs/HIA_CORE_UNPACK_QUALIFICATION_GATES.json',
    'experiments/hia_native_successor_runner_20261111/run_hia_qualification_v10.py',
"""
assert raw.count(anchor)==1
raw=raw.replace(anchor,anchor+addition)
anchor="        'explicit_core_unpack_companion': {\n"
section="""        'matching_cold_core_unpack_qualification_requirements': {
            'reader': 'tools/hia_core_unpack_gates.py',
            'ci_adapter': 'tools/qualify_hia_core_unpack_ci.py',
            'full_runner': 'experiments/hia_native_successor_runner_20261111/run_hia_qualification_v10.py',
            'old_mandatory_gates_preserved': 30,
            'additional_mandatory_gates': 2,
            'complete_component_groups': [4, 6, 8],
            'complete_component_methods': 18,
            'finite_control_source_preserved_exactly': True,
            'composition_source_methods': 2,
            'composition_native_methods': 6,
            'original_complete_caller_groups': [15, 51, 50],
            'same_cold_B3_Core39_and_UNPACK_required': True,
            'both_gates_require_complete116_and_composition': True,
            'phase_qualification_seconds': 180,
            'phase_cleanup_seconds': 3,
            'separate_product_owners': 2,
            'runtime_version': '3.14.4',
            'development_capsule_accepted': False,
            'CPython_object_runtime_still_hosted': True,
            'current_source_matching_cold_pass_claimed': False,
        },
"""
assert raw.count(anchor)==1
raw=raw.replace(anchor,section+anchor)
write(path,raw)
