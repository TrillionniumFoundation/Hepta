"""Admit retained Agent callers through three fixed, reversible source pairs.

The historical source is retained as complete original bytes. The current test
module keeps the main branch's five Linux constant fallbacks. Its execution is
reported under its actual identity; it is never labelled byte-identical to the
historical module. Namespace canonical resources and the renamed continuation
fixture each have their own complete retained and executed byte identities.
This is not a general AST-equivalence or hash allowlist.
"""
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = 'tests/test_hia_agent_native_tools.py'
RETAINED_SOURCE = 'tests/fixtures/hia_original_agent_callers_v1/test_hia_agent_native_tools.py.txt'
ORIGINAL_BYTES = 42664
ORIGINAL_SHA256 = 'fe9f54d7132432bc7514ee58451111897ac06907f44e724c502f51028da5d901'
COMPATIBILITY_BYTES = 42759
COMPATIBILITY_SHA256 = '5e6e26c4adb9100f6c25cb2bdbdfbd4c9752c15017e851dee3723b7451ae28ee'
_ORIGINAL_HUNK = b"""            required = fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL
            self.assertEqual(fcntl.fcntl(fd,fcntl.F_GET_SEALS)&required,required)
"""
_COMPATIBILITY_HUNK = b"""            required = (getattr(fcntl,'F_SEAL_WRITE',8)|getattr(fcntl,'F_SEAL_GROW',4)
                        |getattr(fcntl,'F_SEAL_SHRINK',2)|getattr(fcntl,'F_SEAL_SEAL',1))
            self.assertEqual(fcntl.fcntl(fd,getattr(fcntl,'F_GET_SEALS',1034))&required,required)
"""


def admit_source(root, name, expected):
    if name in _FIXED_PROJECTIONS:
        return _admit_fixed_projection(root, name, expected)
    raw = (Path(root) / name).read_bytes()
    observed = {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
    identity = {'path': name, 'retained': {'bytes': expected['bytes'], 'sha256': expected['sha256']},
                'executed': observed, 'mode': 'EXACT_RETAINED_BYTES', 'byte_identical': True}
    if name != TARGET:
        if observed != identity['retained']:
            raise ValueError('original Agent test bytes differ: ' + name)
        return identity
    original = (ROOT / RETAINED_SOURCE).read_bytes()
    if (len(original) != ORIGINAL_BYTES or sha256(original).hexdigest() != ORIGINAL_SHA256
            or identity['retained'] != {'bytes': ORIGINAL_BYTES, 'sha256': ORIGINAL_SHA256}
            or original.count(_ORIGINAL_HUNK) != 1):
        raise ValueError('retained original Agent test bytes differ: ' + name)
    identity['retained_source'] = RETAINED_SOURCE
    if raw == original:
        return identity
    if (observed != {'bytes': COMPATIBILITY_BYTES, 'sha256': COMPATIBILITY_SHA256}
            or raw.count(_COMPATIBILITY_HUNK) != 1
            or raw.replace(_COMPATIBILITY_HUNK, _ORIGINAL_HUNK, 1) != original
            or original.replace(_ORIGINAL_HUNK, _COMPATIBILITY_HUNK, 1) != raw):
        raise ValueError('original Agent test bytes differ: ' + name)
    identity.update(mode='EXACT_FCNTL_CONSTANT_COMPATIBILITY_BYTES', byte_identical=False,
                    retained_bytes_recovered_exactly=True,
                    compatibility_scope='Five existing fcntl attributes use the main Linux numeric fallbacks; '
                                        'all other original source bytes, methods, assertions and budgets are unchanged.')
    return identity


# These two complete source pairs are fixed inputs, not an extensible AST whitelist.
_FIXED_PROJECTIONS = {'tests/test_hia_artifact_namespace_native.py': {'executed_path': 'tests/test_hia_artifact_namespace_native.py',
                                                 'retained_source': 'tests/fixtures/hia_original_agent_callers_v1/test_hia_artifact_namespace_native.py.txt',
                                                 'retained': {'bytes': 59174,
                                                              'sha256': '1873ab3d845230813effa1b3db38f729f1bbdcaa713ac0669d3d3730797f17fa'},
                                                 'executed': {'bytes': 59531, 'sha256': 'ee49fdc193f9bfb3875075228715e51f4d67e9871c9d2a78b4c8acab113ba32e'},
                                                 'mode': 'EXACT_NAMESPACE_CANONICAL_AND_RESOURCE_FIXTURE',
                                                 'hunks': ((b'                compiler = Path(development)'
                                                            b"; mode = 'DEVELOPMENT_REUSED_COMPILER'\n     "
                                                            b'       else:\n                seed, _ = build'
                                                            b'_seed(cls.folder)\n                source = ('
                                                            b"ROOT / 'examples/hia_bootstrap/selfhost.hiaa"
                                                            b"sm').read_bytes()\n                first, _ ="
                                                            b" compile_stage(cls.folder, 'B1', seed, sourc"
                                                            b"e, image_format='seed-shared')\n             "
                                                            b"   compiler, _ = compile_stage(cls.folder, '"
                                                            b"B2', first, source)\n                assert f"
                                                            b'irst.read_bytes() == compiler.read_bytes()\n',
                                                            b'                compiler = Path(development)'
                                                            b"; mode = 'DEVELOPMENT_REUSED_COMPILER'\n     "
                                                            b'       else:\n                seed, _ = build'
                                                            b'_seed(cls.folder)\n                source = ('
                                                            b"ROOT / 'examples/hia_bootstrap/selfhost.hept"
                                                            b"a').read_bytes()\n                first, _ = "
                                                            b"compile_stage(cls.folder, 'B1', seed, source"
                                                            b", image_format='seed-shared')\n              "
                                                            b"  compiler, _ = compile_stage(cls.folder, 'B"
                                                            b"2', first, source)\n                assert fi"
                                                            b'rst.read_bytes() == compiler.read_bytes()\n'),
                                                           (b"                ('namespace', 'artifact_name"
                                                            b"space', SCHEMA, 'manifest'),\n               "
                                                            b" ('request', 'request_journal', 'hepta.hia.r"
                                                            b"equest-journal-native.v1', 'request_manifest"
                                                            b"'),\n                ('budget', 'execution_bu"
                                                            b"dget', 'hepta.hia.execution-budget-native.v1"
                                                            b"', 'budget_manifest')):\n                sour"
                                                            b"ce = (ROOT / 'examples/hia_bootstrap' / (sou"
                                                            b"rce_name + '.hiaasm')).read_bytes()\n        "
                                                            b'        image, receipt = compile_stage(cls.f'
                                                            b'older, label, compiler, source)\n            '
                                                            b"    manifest = {'schema': schema, 'source_sh"
                                                            b"a256': sha256(source).hexdigest(),\n         "
                                                            b"           'image_path': image.name, 'image_"
                                                            b"sha256': sha256(image.read_bytes()).hexdiges"
                                                            b't(),\n',
                                                            b"                ('namespace', 'artifact_name"
                                                            b"space', SCHEMA, 'manifest'),\n               "
                                                            b" ('request', 'request_journal', 'hepta.hia.r"
                                                            b"equest-journal-native.v1', 'request_manifest"
                                                            b"'),\n                ('budget', 'execution_bu"
                                                            b"dget', 'hepta.hia.execution-budget-native.v1"
                                                            b"', 'budget_manifest')):\n                sour"
                                                            b"ce = (ROOT / 'examples/hia_bootstrap' / (sou"
                                                            b"rce_name + '.hepta')).read_bytes()\n         "
                                                            b'       image, receipt = compile_stage(cls.fo'
                                                            b'lder, label, compiler, source)\n             '
                                                            b"   manifest = {'schema': schema, 'source_sha"
                                                            b"256': sha256(source).hexdigest(),\n          "
                                                            b"          'image_path': image.name, 'image_s"
                                                            b"ha256': sha256(image.read_bytes()).hexdigest"
                                                            b'(),\n'),
                                                           (b'\n    def test_actual_installed_wheel_namespa'
                                                            b'ce_request_atomicity_and_restart_without_aut'
                                                            b'horing(self):\n        import shutil\n        '
                                                            b'from hepta.hia_agent_contract import DISCOVE'
                                                            b'RY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_'
                                                            b'FILES, COMPILER_BUILD_FILES, PUBLICATION_BUI'
                                                            b"LD_FILES\n        source = self.case / 'sourc"
                                                            b"e'; source.mkdir()\n        shutil.copytree(R"
                                                            b"OOT / 'hepta', source / 'hepta', ignore=shut"
                                                            b"il.ignore_patterns('__pycache__'))\n        r"
                                                            b"esources = tuple('docs/' + name for name in "
                                                            b'DISCOVERY_FILES) + NATIVE_SOURCE_FILES + SOU'
                                                            b'RCE_BUILD_FILES + COMPILER_BUILD_FILES + PUB'
                                                            b'LICATION_BUILD_FILES\n        for name in (*r'
                                                            b"esources, 'setup.py', 'pyproject.toml', 'MAN"
                                                            b"IFEST.in'):\n            target = source / na"
                                                            b'me; target.parent.mkdir(parents=True, exist_'
                                                            b'ok=True)\n            shutil.copyfile(ROOT / '
                                                            b'name, target)\n',
                                                            b"\n    def test_actual_installed_wheel_namespace_request_atomicity_and_restart_without_authoring(self):\n        import shutil\n        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES, ENTRY_BUILD_FILES\n        source = self.case / 'source'; source.mkdir()\n        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))\n        resources = tuple('docs/' + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES + BACKEND_BUILD_FILES + EMITTER_BUILD_FILES + BYTE_WRAPPER_BUILD_FILES + MACHINE_OBJECT_BUILD_FILES + EXECUTION_OBSERVATION_BUILD_FILES + CONTINUATION_BUILD_FILES + ENTRY_BUILD_FILES\n        for name in (*resources, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):\n            target = source / name; target.parent.mkdir(parents=True, exist_ok=True)\n            shutil.copyfile(ROOT / name, target)\n"))},
 'tests/test_hia_slot_ledger_native.py': {'executed_path': 'tests/test_hia_slot_ledger_continuation_native.py',
                                          'retained_source': 'tests/fixtures/hia_original_agent_callers_v1/test_hia_slot_ledger_native.py.txt',
                                          'retained': {'bytes': 77450,
                                                       'sha256': '59a8d0b712fe61f2a84b2ea11edea99c0e0a6201612452b3ee4683e9dea2485f'},
                                          'executed': {'bytes': 78294, 'sha256': '11adc48cde3df2b31716dfeee07f76801cd531e21be06f6f3e5168e77338dfc8'},
                                          'mode': 'EXACT_SLOT_CONTINUATION_MODULE_AND_RESOURCE_FIXTURE',
                                          'hunks': ((b'import unittest\nfrom unittest.mock import patch\n'
                                                     b'\nfrom hepta.hia_slot_ledger_native import (SOURCE, S'
                                                     b'CHEMA, SELECTOR, REQUEST_MAGIC,\n    RESULT_MAGIC, Na'
                                                     b'tiveSlotLedgerImage, SlotLedgerUnknown, LedgerState)'
                                                     b'\n\nROOT = Path(__file__).resolve().parents[1]\n',
                                                     b'import unittest\nfrom unittest.mock import patch\n'
                                                     b'\nfrom hepta.hia_slot_ledger_continuation_native impo'
                                                     b'rt (SOURCE, SCHEMA, SELECTOR, REQUEST_MAGIC,\n    RES'
                                                     b'ULT_MAGIC, NativeSlotLedgerImage, SlotLedgerUnknown,'
                                                     b' LedgerState)\n\nROOT = Path(__file__).resolve().paren'
                                                     b'ts[1]\n'),
                                                    (b'\n    def test_generated_source_and_bootstrap_bounds('
                                                     b'self):\n        from hepta.hia_agent_assembly import '
                                                     b'render_assembly\n        from tools.generate_hia_slot'
                                                     b'_ledger import document\n        program = document()'
                                                     b'\n        self.assertEqual(SOURCE.read_text(), render'
                                                     b'_assembly(program))\n        self.assertLessEqual(len'
                                                     b"(program['functions']), 128)\n",
                                                     b'\n    def test_generated_source_and_bootstrap_bounds('
                                                     b'self):\n        from hepta.hia_agent_assembly import '
                                                     b'render_assembly\n        from tools.generate_hia_slot'
                                                     b'_ledger_continuation import document\n        program'
                                                     b' = document()\n        self.assertEqual(SOURCE.read_t'
                                                     b'ext(), render_assembly(program))\n        self.assert'
                                                     b"LessEqual(len(program['functions']), 128)\n"),
                                                    (b"            b'lease-000102030405460788090a0b0c0d0e0f"
                                                     b"')\n\n    def test_cold_builder_refuses_before_output_"
                                                     b'or_compilation(self):\n        from tools.build_hia_s'
                                                     b'lot_ledger import build\n        with tempfile.Tempor'
                                                     b'aryDirectory() as directory:\n            path = Path'
                                                     b"(directory); (path / 'compiler').write_bytes(b'not a"
                                                     b" compiler')\n            (path / 'cold').write_text('"
                                                     b"{}')\n",
                                                     b"            b'lease-000102030405460788090a0b0c0d0e0f"
                                                     b"')\n\n    def test_cold_builder_refuses_before_output_"
                                                     b'or_compilation(self):\n        from tools.build_hia_s'
                                                     b'lot_ledger_continuation import build\n        with te'
                                                     b'mpfile.TemporaryDirectory() as directory:\n          '
                                                     b"  path = Path(directory); (path / 'compiler').write_"
                                                     b"bytes(b'not a compiler')\n            (path / 'cold')"
                                                     b".write_text('{}')\n"),
                                                    (b'\n    def test_selected_missing_native_dependency_ref'
                                                     b'uses_before_filesystem_creation(self):\n        from '
                                                     b'hepta.hia_agent_store import AgentStore\n        with'
                                                     b' tempfile.TemporaryDirectory() as directory, patch.d'
                                                     b"ict(os.environ, {\n            SELECTOR: 'explicit', "
                                                     b"'HEPTA_HIA_ARTIFACT_NAMESPACE_MANIFEST': '',\n       "
                                                     b"     'HEPTA_HIA_REQUEST_JOURNAL_MANIFEST': '', 'HEPT"
                                                     b"A_HIA_EXECUTION_BUDGET_MANIFEST': ''}), \\\n          "
                                                     b"      patch('hepta.hia_slot_ledger_native._installed"
                                                     b"_json_image', return_value=object()):\n            ro"
                                                     b"ot = Path(directory) / 'state'\n            with self"
                                                     b".assertRaisesRegex(SlotLedgerUnknown, 'requires admi"
                                                     b"tted native'):\n                AgentStore(root)\n",
                                                     b'\n    def test_selected_missing_native_dependency_ref'
                                                     b'uses_before_filesystem_creation(self):\n        from '
                                                     b'hepta.hia_agent_store import AgentStore\n        depe'
                                                     b"ndencies = ('HEPTA_HIA_ARTIFACT_NAMESPACE_MANIFEST',"
                                                     b"\n                        'HEPTA_HIA_REQUEST_JOURNAL_"
                                                     b"MANIFEST',\n                        'HEPTA_HIA_EXECUT"
                                                     b"ION_BUDGET_MANIFEST')\n        env = {key: value for "
                                                     b'key, value in os.environ.items()\n               if k'
                                                     b"ey not in dependencies}\n        env[SELECTOR] = 'exp"
                                                     b"licit'\n        with tempfile.TemporaryDirectory() as"
                                                     b' directory, patch.dict(os.environ, env, clear=True),'
                                                     b" \\\n                patch('hepta.hia_slot_ledger_cont"
                                                     b"inuation_native._installed_json_image', return_value"
                                                     b"=object()):\n            root = Path(directory) / 'st"
                                                     b"ate'\n            with self.assertRaisesRegex(SlotLed"
                                                     b"gerUnknown, 'requires admitted native'):\n           "
                                                     b'     AgentStore(root)\n'),
                                                    (b'    def test_explicit_cold_and_development_configura'
                                                     b'tion_never_mix(self):\n        with tempfile.Temporar'
                                                     b'yDirectory() as directory:\n            path = Path(d'
                                                     b"irectory) / 'cold'; path.write_text('{}')\n          "
                                                     b"  with patch.dict(os.environ, {'HEPTA_HIA_SLOT_LEDGE"
                                                     b"R_COLD_REPORT': str(path),\n                'HEPTA_HI"
                                                     b"A_SLOT_LEDGER_DEVELOPMENT_COMPILER': ''}), \\\n       "
                                                     b"             patch('tools.qualify_hia_selfhost.build"
                                                     b"_seed', side_effect=AssertionError('seed entered')):"
                                                     b'\n                with self.assertRaisesRegex(ValueEr'
                                                     b"ror, 'cold report lacks a compiler'):\n              "
                                                     b'      SlotLedgerNativeTests.setUpClass()\n           '
                                                     b" with patch.dict(os.environ, {'HEPTA_HIA_SLOT_LEDGER"
                                                     b"_COLD_REPORT': str(path),\n                'HEPTA_HIA"
                                                     b"_SLOT_LEDGER_DEVELOPMENT_COMPILER': 'explicit'}):\n  "
                                                     b'              with self.assertRaisesRegex(ValueError'
                                                     b", 'development compiler cannot be combined'):\n      "
                                                     b'              SlotLedgerNativeTests.setUpClass()\n\n',
                                                     b'    def test_explicit_cold_and_development_configura'
                                                     b'tion_never_mix(self):\n        with tempfile.Temporar'
                                                     b'yDirectory() as directory:\n            path = Path(d'
                                                     b"irectory) / 'cold'; path.write_text('{}')\n          "
                                                     b"  with patch.dict(os.environ, {'HEPTA_HIA_SLOT_LEDGE"
                                                     b"R_CONTINUATION_COLD_REPORT': str(path),\n            "
                                                     b"    'HEPTA_HIA_SLOT_LEDGER_CONTINUATION_DEVELOPMENT_"
                                                     b"COMPILER': ''}), \\\n                    patch('tools."
                                                     b"qualify_hia_selfhost.build_seed', side_effect=Assert"
                                                     b"ionError('seed entered')):\n                with self"
                                                     b".assertRaisesRegex(ValueError, 'cold report lacks a "
                                                     b"compiler'):\n                    SlotLedgerNativeTest"
                                                     b's.setUpClass()\n            with patch.dict(os.enviro'
                                                     b"n, {'HEPTA_HIA_SLOT_LEDGER_CONTINUATION_COLD_REPORT'"
                                                     b": str(path),\n                'HEPTA_HIA_SLOT_LEDGER_"
                                                     b"CONTINUATION_DEVELOPMENT_COMPILER': 'explicit'}):\n  "
                                                     b'              with self.assertRaisesRegex(ValueError'
                                                     b", 'development compiler cannot be combined'):\n      "
                                                     b'              SlotLedgerNativeTests.setUpClass()\n\n'),
                                                    (b'        from tests.test_hia_artifact_namespace_nativ'
                                                     b'e import ArtifactNamespaceNativeTests\n        from t'
                                                     b'ools.build_hia_json_preflight import current_sources'
                                                     b'\n        from tools.qualify_hia_selfhost import comp'
                                                     b"ile_stage\n        cold = os.environ.get('HEPTA_HIA_S"
                                                     b"LOT_LEDGER_COLD_REPORT')\n        development = os.en"
                                                     b"viron.get('HEPTA_HIA_SLOT_LEDGER_DEVELOPMENT_COMPILE"
                                                     b"R')\n        if cold and development:\n            rai"
                                                     b"se ValueError('development compiler cannot be combin"
                                                     b"ed with a ledger cold report')\n        if cold:\n",
                                                     b'        from tests.test_hia_artifact_namespace_nativ'
                                                     b'e import ArtifactNamespaceNativeTests\n        from t'
                                                     b'ools.build_hia_json_preflight import current_sources'
                                                     b'\n        from tools.qualify_hia_selfhost import comp'
                                                     b"ile_stage\n        cold = os.environ.get('HEPTA_HIA_S"
                                                     b"LOT_LEDGER_CONTINUATION_COLD_REPORT')\n        develo"
                                                     b"pment = os.environ.get('HEPTA_HIA_SLOT_LEDGER_CONTIN"
                                                     b"UATION_DEVELOPMENT_COMPILER')\n        if cold and de"
                                                     b"velopment:\n            raise ValueError('development"
                                                     b' compiler cannot be combined with a ledger cold repo'
                                                     b"rt')\n        if cold:\n"),
                                                    (b"                compiler = Path(nested['generations'"
                                                     b"][-1]['produced_image'])\n            except (KeyErro"
                                                     b'r, IndexError, TypeError) as error:\n                '
                                                     b"raise ValueError('ledger cold report lacks a compile"
                                                     b"r') from error\n        evidence = os.environ.get('HE"
                                                     b"PTA_HIA_SLOT_LEDGER_EVIDENCE', '')\n        with patc"
                                                     b"h.dict(os.environ, {\n            'HEPTA_HIA_ARTIFACT"
                                                     b"_NAMESPACE_COLD_REPORT': cold or '',\n            'HE"
                                                     b"PTA_HIA_ARTIFACT_NAMESPACE_DEVELOPMENT_COMPILER': de"
                                                     b"velopment or '',\n",
                                                     b"                compiler = Path(nested['generations'"
                                                     b"][-1]['produced_image'])\n            except (KeyErro"
                                                     b'r, IndexError, TypeError) as error:\n                '
                                                     b"raise ValueError('ledger cold report lacks a compile"
                                                     b"r') from error\n        evidence = os.environ.get('HE"
                                                     b"PTA_HIA_SLOT_LEDGER_CONTINUATION_EVIDENCE', '')\n    "
                                                     b"    with patch.dict(os.environ, {\n            'HEPTA"
                                                     b"_HIA_ARTIFACT_NAMESPACE_COLD_REPORT': cold or '',\n  "
                                                     b"          'HEPTA_HIA_ARTIFACT_NAMESPACE_DEVELOPMENT_"
                                                     b"COMPILER': development or '',\n"),
                                                    (b'        cls.dependencies = _DependencyBuild\n        '
                                                     b'cls.folder, cls.serial = _DependencyBuild.folder, 0\n'
                                                     b'        if cold:\n            from tools.build_hia_sl'
                                                     b'ot_ledger import build\n            cls.manifest = bu'
                                                     b"ild(cls.folder / 'slot-ledger', compiler, Path(cold)"
                                                     b")\n            mode = 'MATCHING_CURRENT_SOURCE_COLD_B"
                                                     b"UILD'\n        else:\n",
                                                     b'        cls.dependencies = _DependencyBuild\n        '
                                                     b'cls.folder, cls.serial = _DependencyBuild.folder, 0\n'
                                                     b'        if cold:\n            from tools.build_hia_sl'
                                                     b'ot_ledger_continuation import build\n            cls.'
                                                     b"manifest = build(cls.folder / 'slot-ledger', compile"
                                                     b"r, Path(cold))\n            mode = 'MATCHING_CURRENT_"
                                                     b"SOURCE_COLD_BUILD'\n        else:\n"),
                                                    (b'        from tests.test_hia_artifact_namespace_nativ'
                                                     b'e import interrupt_opcode\n        import gc\n        '
                                                     b'import weakref\n        from hepta.hia_slot_ledger_na'
                                                     b'tive import NativeSlotLedgerStore\n        calls = []'
                                                     b'\n        class Compared:\n            def __ne__(self'
                                                     b', other):\n',
                                                     b'        from tests.test_hia_artifact_namespace_nativ'
                                                     b'e import interrupt_opcode\n        import gc\n        '
                                                     b'import weakref\n        from hepta.hia_slot_ledger_co'
                                                     b'ntinuation_native import NativeSlotLedgerStore\n     '
                                                     b'   calls = []\n        class Compared:\n            de'
                                                     b'f __ne__(self, other):\n'),
                                                    (b'\n    def test_actual_direct_consumption_return_loss_'
                                                     b'never_replays(self):\n        from tests.test_hia_art'
                                                     b'ifact_namespace_native import interrupt_opcode\n     '
                                                     b'   from hepta.hia_slot_ledger_native import DirectLe'
                                                     b'dgerState\n        calls = []\n        class Compared:'
                                                     b'\n            def __ne__(self, other): calls.append(o'
                                                     b'ther); return False\n',
                                                     b'\n    def test_actual_direct_consumption_return_loss_'
                                                     b'never_replays(self):\n        from tests.test_hia_art'
                                                     b'ifact_namespace_native import interrupt_opcode\n     '
                                                     b'   from hepta.hia_slot_ledger_continuation_native im'
                                                     b'port DirectLedgerState\n        calls = []\n        cl'
                                                     b'ass Compared:\n            def __ne__(self, other): c'
                                                     b'alls.append(other); return False\n'),
                                                    (b'\n    def test_actual_installed_wheel_ledger_and_sour'
                                                     b'ce_custody_without_authoring(self):\n        import s'
                                                     b'hutil\n        from hepta.hia_agent_contract import D'
                                                     b'ISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FI'
                                                     b'LES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES\n '
                                                     b"       source = self.case / 'wheel-source'; source.m"
                                                     b"kdir()\n        shutil.copytree(ROOT / 'hepta', sourc"
                                                     b"e / 'hepta', ignore=shutil.ignore_patterns('__pycach"
                                                     b"e__'))\n        resources = tuple('docs/' + name for "
                                                     b'name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + SOU'
                                                     b'RCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION'
                                                     b"_BUILD_FILES\n        for name in (*resources, 'setup"
                                                     b".py', 'pyproject.toml', 'MANIFEST.in'):\n            "
                                                     b'target = source / name; target.parent.mkdir(parents='
                                                     b'True, exist_ok=True)\n            shutil.copyfile(ROO'
                                                     b'T / name, target)\n',
                                                     b"\n    def test_actual_installed_wheel_ledger_and_source_custody_without_authoring(self):\n        import shutil\n        from hepta.hia_agent_contract import (DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES,\n            COMPILER_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES,\n            BYTE_WRAPPER_BUILD_FILES, CONTINUATION_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES,\n            MACHINE_OBJECT_BUILD_FILES, PUBLICATION_BUILD_FILES, ENTRY_BUILD_FILES)\n        source = self.case / 'wheel-source'; source.mkdir()\n        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))\n        resources = tuple(dict.fromkeys(\n            tuple('docs/' + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES +\n            SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + BACKEND_BUILD_FILES +\n            EMITTER_BUILD_FILES + BYTE_WRAPPER_BUILD_FILES + CONTINUATION_BUILD_FILES +\n            EXECUTION_OBSERVATION_BUILD_FILES + MACHINE_OBJECT_BUILD_FILES +\n            PUBLICATION_BUILD_FILES + ENTRY_BUILD_FILES))\n        for name in (*resources, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):\n            target = source / name; target.parent.mkdir(parents=True, exist_ok=True)\n            shutil.copyfile(ROOT / name, target)\n"),
                                                    (b'sys.meta_path.insert(0,NoAuthoring())\nfrom hepta.hia'
                                                     b'_agent_service import HIAAgentService\nfrom hepta.hia'
                                                     b'_agent_store import AgentStore,AgentRejected,wire\nfr'
                                                     b'om hepta.hia_slot_ledger_native import SOURCE,SELECT'
                                                     b'OR,admitted_slot_ledger\nfrom hepta import hia_execut'
                                                     b'ion_budget as budget\nassert Path(sys.argv[1]) in SOU'
                                                     b'RCE.parents,SOURCE\ndef forbidden(*args,**kwargs):rai'
                                                     b"se AssertionError('installed owner entered original "
                                                     b"policy')\n",
                                                     b'sys.meta_path.insert(0,NoAuthoring())\nfrom hepta.hia'
                                                     b'_agent_service import HIAAgentService\nfrom hepta.hia'
                                                     b'_agent_store import AgentStore,AgentRejected,wire\nfr'
                                                     b'om hepta.hia_slot_ledger_continuation_native import '
                                                     b'SOURCE,SELECTOR,admitted_slot_ledger\nfrom hepta impo'
                                                     b'rt hia_execution_budget as budget\nassert Path(sys.ar'
                                                     b'gv[1]) in SOURCE.parents,SOURCE\ndef forbidden(*args,'
                                                     b"**kwargs):raise AssertionError('installed owner ente"
                                                     b"red original policy')\n"))}}


def _admit_fixed_projection(root, name, expected):
    rule = _FIXED_PROJECTIONS[name]
    original = (ROOT / rule['retained_source']).read_bytes()
    raw = (Path(root) / rule['executed_path']).read_bytes()
    retained = {'bytes': len(original), 'sha256': sha256(original).hexdigest()}
    observed = {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
    if (retained != rule['retained']
            or {'bytes': expected['bytes'], 'sha256': expected['sha256']} != retained):
        raise ValueError('retained original Agent test bytes differ: ' + name)
    if observed != rule['executed']:
        raise ValueError('original Agent test bytes differ: ' + name)
    forward, backward = original, raw
    for before, after in rule['hunks']:
        if forward.count(before) != 1:
            raise ValueError('retained original Agent source hunk differs: ' + name)
        forward = forward.replace(before, after, 1)
    for before, after in reversed(rule['hunks']):
        if backward.count(after) != 1:
            raise ValueError('original Agent test compatibility hunk differs: ' + name)
        backward = backward.replace(after, before, 1)
    if forward != raw or backward != original:
        raise ValueError('original Agent test bytes differ: ' + name)
    return {'path': name, 'executed_path': rule['executed_path'],
            'retained_source': rule['retained_source'], 'retained': retained,
            'executed': observed, 'mode': rule['mode'], 'byte_identical': False,
            'retained_bytes_recovered_exactly': True}


def execution_id(original):
    old = 'tests.test_hia_slot_ledger_native'
    if original == old or original.startswith(old + '.'):
        return 'tests.test_hia_slot_ledger_continuation_native' + original[len(old):]
    return original
