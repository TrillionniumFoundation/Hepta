"""Native campaign receipt-integrity gates; unit fixtures do not establish value."""
from copy import deepcopy
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_macro_policy import digest, wire
from tools.qualify_hia_macro_campaign import (CampaignRejected, Evidence, Journal,
    _native_result_correct, _read_regular, run_campaign, verify_campaign)


def rewrite_object(root, original, value):
    """Rehash a malicious edit and every referring JSON, retaining old objects.

    A checksum-only verifier would accept this. The contract verifier must still
    catch mismatching event/ledger values or fabricated fixture provenance.
    """
    manifest = json.loads((root / 'campaign.json').read_bytes())
    raw_objects = {item['sha256']: (root / 'objects' / item['sha256']).read_bytes()
                   for item in manifest['objects']}
    rebuilt = {}
    additions = {}
    def visit(identity):
        if identity in rebuilt:
            return rebuilt[identity]
        if identity == original:
            content = deepcopy(value)
        else:
            try:
                content = json.loads(raw_objects[identity])
            except (ValueError, UnicodeError):
                rebuilt[identity] = identity
                return identity
        before = deepcopy(content)
        content = transform(content)
        if identity != original and content == before:
            rebuilt[identity] = identity
            return identity
        new = digest(content)
        additions[new] = wire(content)
        rebuilt[identity] = new
        return new
    def transform(item):
        if type(item) is str and item in raw_objects:
            return visit(item)
        if type(item) is list:
            return [transform(x) for x in item]
        if type(item) is dict:
            return {k: transform(v) for k, v in item.items()}
        return item
    # Inventory entries describe raw objects, so only transform references in
    # the actual manifest, then rebuild the complete original-byte inventory.
    manifest.pop('objects')
    manifest = transform(manifest)
    raw_objects.update(additions)
    for identity, raw in raw_objects.items():
        path = root / 'objects' / identity
        if not path.exists():
            path.write_bytes(raw)
            path.chmod(0o600)
    manifest['objects'] = sorted([{'sha256': identity, 'byte_size': len(raw)}
                                 for identity, raw in raw_objects.items()], key=lambda x:x['sha256'])
    (root / 'campaign.json').write_bytes(wire(manifest))
    return rebuilt



class JournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'evidence'
        self.evidence = Evidence(self.root)

    def test_disjoint_intervals_include_between_operation_overhead(self):
        ticks = iter([100, 120, 150, 190, 210, 270, 280])
        journal = Journal(self.evidence, 'fixed', 'task', {'wall_ns': 1000}, clock=lambda: next(ticks))
        journal.run('search', 'proposal', lambda: {'candidate': 'one'})
        journal.run('search', 'refusal', lambda: {'status': 'rejected'}, expected_status='rejected')
        journal.close()
        self.assertEqual([entry['wall_ns'] for entry in journal.entries], [50, 60, 70])
        self.assertEqual(sum(entry['wall_ns'] for entry in journal.entries), journal.cursor - journal.origin)
        self.assertEqual(journal.entries[1]['status'], 'rejected')
        with self.assertRaises(CampaignRejected):
            journal.run('search', 'too late', lambda: None)

    def test_exception_retains_failed_interval_and_actual_error(self):
        ticks = iter([10, 20, 80])
        journal = Journal(self.evidence, 'fixed', 'task', {'wall_ns': 1000}, clock=lambda: next(ticks))
        with self.assertRaisesRegex(CampaignRejected, 'RuntimeError'):
            journal.run('search', 'bad candidate', lambda: (_ for _ in ()).throw(RuntimeError('rejected')))
        event = json.loads((self.root / 'objects' / journal.entries[0]['receipt_sha256']).read_bytes())
        self.assertEqual(event['failure']['type'], 'RuntimeError')
        self.assertEqual(journal.entries[0]['status'], 'failed')
        self.assertEqual(journal.entries[0]['wall_ns'], 70)

    def test_exhausted_budget_does_not_call_operation_and_records_attempt(self):
        ticks = iter([10, 20, 30])
        journal = Journal(self.evidence, 'fixed', 'task', {'wall_ns': 1}, clock=lambda: next(ticks))
        called = []
        with self.assertRaisesRegex(CampaignRejected, 'exhausted'):
            journal.run('search', 'late attempt', lambda: called.append(True))
        self.assertEqual(called, [])
        self.assertEqual(journal.entries[0]['status'], 'failed')

    def test_private_exclusive_original_object_and_bounded_read(self):
        identity = self.evidence.put({'real': 'bytes'})
        path = self.root / 'objects' / identity
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(self.evidence.put({'real': 'bytes'}), identity)
        self.assertEqual(_read_regular(path), wire({'real': 'bytes'}))
        with self.assertRaises(CampaignRejected):
            _read_regular(path, maximum=2)
        with self.assertRaises(FileExistsError):
            Evidence(self.root)


class NativeObservationTests(unittest.TestCase):
    def test_complete_flag_cannot_replace_matching_each_expected_value(self):
        task = {"workload": {"cases": [{"expected": {"status": "returned", "values": [8]}},
                                        {"expected": {"status": "returned", "values": [9]}}]}}
        report = {"schema": "hepta.hia.agent.native-observation.v1", "artifact_sha256": "a"*64,
            "complete": True, "planned_cases": 2, "completed_cases": 2, "repetitions": 1,
            "warmup": 0, "measured_calls": 2, "observations": [
                {"status": "returned", "values": [8], "mismatch": False},
                {"status": "returned", "values": [9], "mismatch": False}]}
        use = {"status": "returned", "termination_confirmed": True, "started": True,
               "returncode": 0, "report": report}
        self.assertTrue(_native_result_correct(use, task, "a"*64))
        report["observations"][1]["values"] = [10]
        self.assertFalse(_native_result_correct(use, task, "a"*64))
        report["observations"][1]["values"] = [9]
        report["observations"].pop()
        self.assertFalse(_native_result_correct(use, task, "a"*64))

    def test_cleanup_uncertainty_does_not_become_success(self):
        task = {"workload": {"cases": []}}
        use = {"status": "returned", "termination_confirmed": False, "report": {}}
        self.assertFalse(_native_result_correct(use, task, "a"*64))


class WorkerSourceInventoryTests(unittest.TestCase):
    def test_actual_worker_inventory_matches_current_installation_identity(self):
        from tools import qualify_hia_macro_campaign as campaign
        from hepta import hia_agent_contract as contract
        with tempfile.TemporaryDirectory() as directory:
            evidence = Evidence(Path(directory) / 'worker-sources')
            observed = campaign._worker_sources(evidence)
            self.assertEqual(digest(observed), contract.installation_manifest()['worker_sha256'])
            assets = (tuple('docs/' + name for name in contract.DISCOVERY_FILES)
                + contract.NATIVE_SOURCE_FILES + contract.SOURCE_BUILD_FILES
                + contract.COMPILER_BUILD_FILES + contract.PUBLICATION_BUILD_FILES
                + contract.BACKEND_BUILD_FILES + contract.EMITTER_BUILD_FILES + contract.BYTE_WRAPPER_BUILD_FILES + contract.MACHINE_OBJECT_BUILD_FILES + contract.EXECUTION_OBSERVATION_BUILD_FILES + contract.CONTINUATION_BUILD_FILES)
            self.assertLessEqual(set(assets), set(observed))
            for name in assets:
                self.assertEqual((evidence.root / 'objects' / observed[name]).read_bytes(),
                                 (campaign.ROOT / name).read_bytes())

    def test_each_asset_group_is_fresh_and_missing_resource_refuses(self):
        from tools import qualify_hia_macro_campaign as campaign
        from hepta import hia_agent_contract as contract
        from hashlib import sha256
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            source = directory / 'source'
            assets = (tuple('docs/' + name for name in contract.DISCOVERY_FILES)
                + contract.NATIVE_SOURCE_FILES + contract.SOURCE_BUILD_FILES
                + contract.COMPILER_BUILD_FILES + contract.PUBLICATION_BUILD_FILES
                + contract.BACKEND_BUILD_FILES + contract.EMITTER_BUILD_FILES + contract.BYTE_WRAPPER_BUILD_FILES + contract.MACHINE_OBJECT_BUILD_FILES + contract.EXECUTION_OBSERVATION_BUILD_FILES + contract.CONTINUATION_BUILD_FILES)
            for name in assets:
                destination = source / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(campaign.ROOT / name, destination)
            shadow = source / 'hepta/_data/ignored_module.py'
            shadow.parent.mkdir(parents=True)
            shadow.write_bytes(b'SOURCE_RESOURCE_IS_NOT_AN_IMPORTED_MODULE = True\n')
            with patch.object(campaign, 'ROOT', source):
                baseline = campaign._worker_sources(Evidence(directory / 'baseline'))
                self.assertEqual(set(baseline), set(assets))
                groups = (contract.NATIVE_SOURCE_FILES, contract.SOURCE_BUILD_FILES,
                          contract.COMPILER_BUILD_FILES, contract.PUBLICATION_BUILD_FILES,
                          contract.BACKEND_BUILD_FILES, contract.EMITTER_BUILD_FILES, contract.BYTE_WRAPPER_BUILD_FILES, contract.MACHINE_OBJECT_BUILD_FILES, contract.EXECUTION_OBSERVATION_BUILD_FILES, contract.CONTINUATION_BUILD_FILES)
                for index, group in enumerate(groups):
                    name = group[0]
                    path = source / name
                    original = path.read_bytes()
                    path.write_bytes(original + b'\n')
                    changed = campaign._worker_sources(Evidence(directory / ('changed-' + str(index))))
                    self.assertNotEqual(changed[name], baseline[name])
                    self.assertEqual(changed[name], sha256(original + b'\n').hexdigest())
                    path.unlink()
                    try:
                        with self.assertRaises(FileNotFoundError):
                            campaign._worker_sources(Evidence(directory / ('missing-' + str(index))))
                    finally:
                        path.write_bytes(original)


    def test_dual_module_resource_observations_cannot_silently_overwrite(self):
        from tools import qualify_hia_macro_campaign as campaign
        from hepta import hia_agent_contract as contract
        from hashlib import sha256
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            source = directory / 'source'
            assets = (tuple('docs/' + name for name in contract.DISCOVERY_FILES)
                + contract.NATIVE_SOURCE_FILES + contract.SOURCE_BUILD_FILES
                + contract.COMPILER_BUILD_FILES + contract.PUBLICATION_BUILD_FILES
                + contract.BACKEND_BUILD_FILES + contract.EMITTER_BUILD_FILES + contract.BYTE_WRAPPER_BUILD_FILES + contract.MACHINE_OBJECT_BUILD_FILES + contract.EXECUTION_OBSERVATION_BUILD_FILES + contract.CONTINUATION_BUILD_FILES)
            for name in assets:
                destination = source / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(campaign.ROOT / name, destination)
            target = source / 'hepta/hia_program_normalization_notes.py'
            original = target.read_bytes()
            read = campaign._read_regular
            observations = []
            def drift_after_first_read(path, *args, **kwargs):
                raw = read(path, *args, **kwargs)
                if path == target:
                    observations.append(sha256(raw).hexdigest())
                    if len(observations) == 1:
                        target.write_bytes(raw + b'\n')
                return raw
            try:
                with patch.object(campaign, 'ROOT', source), patch.object(
                        campaign, '_read_regular', side_effect=drift_after_first_read):
                    with self.assertRaisesRegex(CampaignRejected, 'worker module and source resource differ'):
                        campaign._worker_sources(Evidence(directory / 'evidence'))
            finally:
                target.write_bytes(original)
            self.assertEqual(len(observations), 2)
            self.assertNotEqual(observations[0], observations[1])


class CampaignIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_tmp = tempfile.TemporaryDirectory()
        cls.original = Path(cls.original_tmp.name) / 'campaign'
        # Every planned row is intentionally over its budget before work starts.
        # This exercises failure denominators quickly, never a fake native pass.
        with contextlib.redirect_stdout(io.StringIO()):
            cls.verdict = run_campaign(cls.original, wall_ns=1)

    @classmethod
    def tearDownClass(cls):
        cls.original_tmp.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'copy'
        shutil.copytree(self.original, self.root)
        self.manifest = json.loads((self.root / 'campaign.json').read_bytes())
        self.comparison = json.loads((self.root / 'objects' / self.manifest['comparison_sha256']).read_bytes())
        self.row = self.comparison['arms'][0]['observations'][0]

    def test_every_failed_planned_task_is_retained_and_stays_hold(self):
        result = verify_campaign(self.root)
        self.assertEqual(result['planned_task_arms'], 32)
        self.assertEqual(result['correct_native_task_arms'], 0)
        self.assertEqual(result['native_ndu_evaluations'], 0)
        self.assertEqual(result['p1_acceptance'], 'HOLD')
        self.assertFalse(result['economic_benefit_established'])
        self.assertEqual(result['failed_or_rejected_attempts_retained'], 32)
        self.assertFalse(result['original_receipts_authenticated'])

    def test_modified_original_bytes_are_rejected(self):
        identity = self.row['ledger'][0]['receipt_sha256']
        (self.root / 'objects' / identity).write_bytes(b'{}')
        with self.assertRaisesRegex(CampaignRejected, 'digest and length'):
            verify_campaign(self.root)

    def test_missing_receipt_is_rejected(self):
        (self.root / 'objects' / self.row['result_receipt_sha256']).unlink()
        with self.assertRaises(FileNotFoundError):
            verify_campaign(self.root)

    def test_symlinked_original_object_is_rejected(self):
        path = self.root / 'objects' / self.row['result_receipt_sha256']
        target = self.root / 'external'
        path.rename(target)
        path.symlink_to(target)
        with self.assertRaises(OSError):
            verify_campaign(self.root)

    def test_hardlinked_original_object_is_rejected(self):
        path = self.root / 'objects' / self.row['result_receipt_sha256']
        os.link(path, self.root / 'alias')
        with self.assertRaisesRegex(CampaignRejected, 'single-link'):
            verify_campaign(self.root)

    def test_bundle_total_byte_budget_is_bounded(self):
        with patch("tools.qualify_hia_macro_campaign.MAX_BUNDLE_BYTES", 1):
            with self.assertRaisesRegex(CampaignRejected, 'bundle byte bound'):
                verify_campaign(self.root)

    def test_unknown_external_provider_cost_cannot_be_replaced_with_zero(self):
        self.manifest['external_cost_scope']['real_agent_provider_cost'] = 0
        self.manifest['external_cost_scope']['complete_real_agent_economics'] = True
        (self.root / 'campaign.json').write_bytes(wire(self.manifest))
        with self.assertRaisesRegex(CampaignRejected, 'unknown external costs'):
            verify_campaign(self.root)

    def test_frozen_registration_cannot_change(self):
        value = json.loads((self.root / 'registration.json').read_bytes())
        value['budget']['wall_ns'] += 1
        (self.root / 'registration.json').write_bytes(wire(value))
        with self.assertRaisesRegex(CampaignRejected, 'registration drift'):
            verify_campaign(self.root)

    def test_rehashed_event_cannot_change_charged_wall_cost(self):
        identity = self.row['ledger'][0]['receipt_sha256']
        event = json.loads((self.root / 'objects' / identity).read_bytes())
        event['wall_ns'] += 1
        rewrite_object(self.root, identity, event)
        with self.assertRaisesRegex(CampaignRejected, 'event cost binding'):
            verify_campaign(self.root)

    def test_rehashed_event_cannot_overlap_predecessor(self):
        identity = self.row['ledger'][0]['receipt_sha256']
        event = json.loads((self.root / 'objects' / identity).read_bytes())
        event['start_offset_ns'] += 1
        rewrite_object(self.root, identity, event)
        with self.assertRaisesRegex(CampaignRejected, 'gap, overlap'):
            verify_campaign(self.root)

    def test_result_cannot_invent_provider_receipt_even_after_rehash(self):
        identity = self.row['result_receipt_sha256']
        result = json.loads((self.root / 'objects' / identity).read_bytes())
        result['provider_receipt'] = {'tokens': 100, 'source': 'invented'}
        rewrite_object(self.root, identity, result)
        with self.assertRaisesRegex(CampaignRejected, 'model cost provenance'):
            verify_campaign(self.root)

    def test_fixture_cannot_report_economic_acceptance(self):
        self.manifest['economic_benefit_established'] = True
        (self.root / 'campaign.json').write_bytes(wire(self.manifest))
        with self.assertRaisesRegex(CampaignRejected, 'fixture cannot claim'):
            verify_campaign(self.root)

    def test_execution_order_is_frozen(self):
        self.manifest['execution_order'][0], self.manifest['execution_order'][1] = self.manifest['execution_order'][1], self.manifest['execution_order'][0]
        (self.root / 'campaign.json').write_bytes(wire(self.manifest))
        with self.assertRaisesRegex(CampaignRejected, 'execution order'):
            verify_campaign(self.root)


if __name__ == '__main__':
    unittest.main()
