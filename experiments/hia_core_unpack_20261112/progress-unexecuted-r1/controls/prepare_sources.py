"""Materialize this isolated source proposal; do not import or run products."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = Path('/tmp/hia-core-unpack-v83-20261112-r1/source')
DRAFT = Path('/tmp/hia-core-unpack-matching-gates-draft-r1/inputs')

def change(name, source, replacements):
    old = (source / name).read_text()
    new = old
    for before, after in replacements:
        if new.count(before) != 1:
            raise ValueError('nonunique patch anchor: ' + name + ': ' + repr(before[:80]))
        new = new.replace(before, after)
    target = ROOT / 'inputs' / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(new)
    reference = ROOT / 'references' / name
    reference.parent.mkdir(parents=True, exist_ok=True)
    reference.write_text(old)

change('tools/qualify_hia_core_unpack_callers.py', BASE, [
    ('    from tools import qualify_hia_core_lowering_callers as original\n',
     '    from tools import qualify_hia_core_lowering_callers as original\n'
     '    from tools.hia_core_unpack_progress import ProgressRecorder\n'),
    ('    companion_before, files = [], []\n',
     '    companion_before, files = [], []\n    progress = None\n'),
    ("        report['original_qualifier_argv'] = argv\n",
     "        report['original_qualifier_argv'] = argv\n"
     "        progress_groups = [dict(label=label, modules=list(modules), ids=list(ids))\n"
     "            for label, modules, ids in (\n"
     "                ('component', original.COMPONENT_MODULES, original.COMPONENT_IDS),\n"
     "                ('original-machine', original.ORIGINAL_MODULES, original.ORIGINAL_IDS),\n"
     "                ('original-core', original.CORE_MODULES, original.CORE_IDS))]\n"
     "        progress = ProgressRecorder(directory, progress_groups, lambda: sum(returns.values()))\n"),
    ("            stack.enter_context(patch.object(unittest.TextTestResult, 'startTest', start))\n",
     "            stack.enter_context(patch.object(unittest.TextTestResult, 'startTest', start))\n"
     "            stack.enter_context(progress.observe())\n"),
    ("        report['seconds'] = time.monotonic() - started\n",
     "        try:\n"
     "            if progress is None:\n"
     "                raise ValueError('UNPACK qualification progress was never admitted')\n"
     "            report['progress'] = progress.finish(complete=report['status'] == 'PASS',\n"
     "                original_report=report.get('original_report'))\n"
     "            if report['status'] == 'PASS' and report['progress']['complete'] is not True:\n"
     "                raise ValueError('complete UNPACK progress receipt is required')\n"
     "        except BaseException:\n"
     "            report['status'] = 'FAIL'\n"
     "            report['progress_error'] = traceback.format_exc()\n"
     "        report['seconds'] = time.monotonic() - started\n")])

change('tools/hia_core_unpack_gates.py', DRAFT, [
    ('from tools import hia_compiler_owner_gates as previous\n',
     'from tools import hia_compiler_owner_gates as previous\n'
     'from tools import hia_core_unpack_progress as progress\n'),
    ("ERROR_FIELDS = ('error', 'preservation_error', 'final_identity_error')\n",
     "ERROR_FIELDS = ('error', 'preservation_error', 'final_identity_error', 'progress_error')\n"),
    ("    'tools/hia_core_unpack_gates.py', 'tools/qualify_hia_core_unpack_ci.py',\n",
     "    'tools/hia_core_unpack_gates.py', 'tools/qualify_hia_core_unpack_ci.py',\n"
     "    'tools/hia_core_unpack_progress.py', 'tests/test_hia_core_unpack_progress.py',\n"),
    ("            'UNPACK original Core116 report pin differs')\n",
     "            'UNPACK original Core116 report pin differs')\n"
     "    progress_binding = progress.inspect_progress(evidence, groups, report['original_report'])\n"
     "    require(report.get('progress') == progress_binding\n"
     "            and progress_binding['native_step_returns'] == sum(\n"
     "                row['count'] for row in report['actual_UNPACK_step_returns']),\n"
     "            'UNPACK complete progress bytes or actual return count differs')\n"),
    ("            'ledger': ledger, 'installed': installed}\n",
     "            'ledger': ledger, 'installed': installed, 'progress': progress_binding}\n")])

change('tools/hia_selfhost_contract.py', DRAFT, [
    ("    'tools/hia_core_unpack_gates.py',\n",
     "    'tools/hia_core_unpack_gates.py',\n"
     "    'tools/hia_core_unpack_progress.py',\n"
     "    'tests/test_hia_core_unpack_progress.py',\n"),
    ("            'reader': 'tools/hia_core_unpack_gates.py',\n",
     "            'reader': 'tools/hia_core_unpack_gates.py',\n"
     "            'progress_reader': 'tools/hia_core_unpack_progress.py',\n"
     "            'complete_progress_and_original_report_both_required': True,\n"
     "            'progress_is_method_pass': False,\n"
     "            'progress_only_in_UNPACK_wrapper_within_original_180_seconds': True,\n"
     "            'progress_max_bytes': 524288,\n"
     "            'progress_max_event_bytes': 1024,\n"
     "            'progress_max_events': 4096,\n"
     "            'progress_max_receipt_bytes': 131072,\n")])

change('.github/workflows/hia-core.yml', DRAFT, [
    ("              'tests.test_hia_core_unpack_gates',\n",
     "              'tests.test_hia_core_unpack_gates',\n"
     "              'tests.test_hia_core_unpack_progress.UnpackQualificationProgressTests',\n")])

# Read-only references for the independent mechanical check, never imported.
for name, source in (
    ('tools/qualify_hia_core_lowering_callers.py', BASE),
    ('tools/hia_compiler_owner_gates.py', DRAFT),
):
    target = ROOT / 'references' / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((source / name).read_bytes())
