"""Adversarial admission controls; synthetic records are never qualification evidence."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from tools.hia_native_cold_admission import admit_native_report, read_json


ROOT = Path(__file__).resolve().parents[1]


class NativeColdAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.compiler = b"synthetic-component-admission-control"
        self.observer = bytes(1107)
        self.sources = {"control.hepta": sha256(b"control").hexdigest()}
        metadata = json.loads((ROOT / "docs/HIA_NATIVE_SELFHOST_METADATA.json").read_bytes())
        self.contract = {"profile": metadata["profile"],
                         "native_cold_qualification": metadata["native_cold_qualification"]}
        native = self.contract["native_cold_qualification"]
        self.report = {"schema": "hepta.hia.selfhost-cold-replay.v2",
            "status": "NATIVE_COLD_SELFHOST_REPLAY_PASS", "returncode": 0,
            "profile": self.contract["profile"], "source_manifest": self.sources,
            "checks": {name: True for name in native["checks"]},
            "qualification_wall_limit_seconds": 180, "cleanup_wall_limit_seconds": 3,
            "nested_wall_elapsed_ns": 1, "cleanup_wall_elapsed_ns": 0,
            "generation_sha256": [sha256(self.compiler).hexdigest()] * 3,
            "modified_generation_sha256": ["1" * 64, "2" * 64, "2" * 64],
            "seed_sha256": "3" * 64, "native_flat_observer_hex": self.observer.hex(),
            "scheduler": {**native["scheduler"], "peak_phase_workers": 2,
                "peak_archive_workers": 1, "peak_pending_archives": 2, "peak_unsealed_phases": 4},
            "qualification_families": {row["family"]: {"original": True, "modified": True}
                for row in native["phase_plan_catalog"] if row["kind"] == "qualification"},
            "phases": [{**row, "returncode": 0, "nodes_retained": row["node_count"],
                "cleanup_complete": True, "sealed": True,
                "journal_sha256": "4" * 64, "archive_sha256": "5" * 64}
                for row in native["phase_plan_catalog"]]}

    def admit(self, value):
        return admit_native_report(self.compiler, json.dumps(value).encode(),
            contract=self.contract, sources=self.sources, observer_bytes=self.observer)

    def test_exact_native_contract_accepts_control_record(self):
        self.assertEqual(self.admit(self.report), self.sources)

    def test_legacy_and_lookalike_conclusions_are_rejected(self):
        for field, value in (("schema", "hepta.hia.selfhost-cold-replay.v1"),
                ("status", "COLD_SELFHOST_REPLAY_PASS"), ("returncode", False),
                ("profile", "foreign"), ("source_manifest", {}), ("seed_sha256", "0" * 63),
                ("generation_sha256", ["1" * 64] * 3),
                ("modified_generation_sha256", ["2" * 64] * 3),
                ("native_flat_observer_hex", "00")):
            with self.subTest(field=field):
                changed = deepcopy(self.report)
                changed[field] = value
                with self.assertRaises(ValueError):
                    self.admit(changed)

    def test_time_and_scheduler_bounds_are_exact_integer_controls(self):
        for field, value in (("qualification_wall_limit_seconds", 181),
                ("cleanup_wall_limit_seconds", 4), ("nested_wall_elapsed_ns", 180_000_000_001),
                ("nested_wall_elapsed_ns", True), ("cleanup_wall_elapsed_ns", 3_000_000_001),
                ("cleanup_wall_elapsed_ns", -1)):
            with self.subTest(field=field, value=value):
                changed = deepcopy(self.report)
                changed[field] = value
                with self.assertRaises(ValueError):
                    self.admit(changed)
        for field, value in (("phase_workers", 3), ("archive_workers", True),
                ("peak_phase_workers", 3), ("peak_archive_workers", 0),
                ("peak_pending_archives", 3), ("peak_unsealed_phases", 5), ("foreign", 1)):
            with self.subTest(field=field):
                changed = deepcopy(self.report)
                changed["scheduler"][field] = value
                with self.assertRaises(ValueError):
                    self.admit(changed)

    def test_missing_fields_false_checks_and_partial_families_are_rejected(self):
        for field in self.report:
            with self.subTest(missing=field):
                changed = deepcopy(self.report)
                del changed[field]
                with self.assertRaises(ValueError):
                    self.admit(changed)
        for value in (False, 1, "true"):
            changed = deepcopy(self.report)
            changed["checks"][next(iter(changed["checks"]))] = value
            with self.assertRaises(ValueError):
                self.admit(changed)
        changed = deepcopy(self.report)
        changed["checks"]["isolated_python_without_site"] = True
        with self.assertRaises(ValueError):
            self.admit(changed)
        for value in (False, 1):
            changed = deepcopy(self.report)
            changed["qualification_families"]["capacity"]["modified"] = value
            with self.assertRaises(ValueError):
                self.admit(changed)

    def test_phase_omission_duplicates_node_loss_and_order_are_rejected(self):
        mutations = []
        changed = deepcopy(self.report)
        changed["phases"].pop()
        mutations.append(changed)
        changed = deepcopy(self.report)
        changed["phases"][-1] = deepcopy(changed["phases"][-2])
        mutations.append(changed)
        changed = deepcopy(self.report)
        changed["phases"].reverse()
        mutations.append(changed)
        for field, value in (("nodes_retained", 0), ("returncode", False),
                ("sealed", 1), ("cleanup_complete", False), ("journal_sha256", "bad"),
                ("plan_sha256", "0" * 64), ("family", "foreign")):
            changed = deepcopy(self.report)
            changed["phases"][0][field] = value
            mutations.append(changed)
        for index, changed in enumerate(mutations):
            with self.subTest(mutation=index), self.assertRaises(ValueError):
                self.admit(changed)

    def test_duplicate_keys_and_non_json_numbers_are_rejected(self):
        for raw in (b'{"returncode":1,"returncode":0}', b'{"x":NaN}', b'{"x":Infinity}',
                    b'{"phases":[{"sealed":false,"sealed":true}]}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                read_json(raw)

    def test_zero_native_identities_are_rejected_at_every_receipt_position(self):
        mutations = []
        changed = deepcopy(self.report)
        changed['seed_sha256'] = '0' * 64
        mutations.append(('seed', changed))
        changed = deepcopy(self.report)
        changed['modified_generation_sha256'][0] = '0' * 64
        mutations.append(('modified-initial', changed))
        changed = deepcopy(self.report)
        changed['modified_generation_sha256'][1:] = ['0' * 64] * 2
        mutations.append(('modified-fixed-point', changed))
        for index, row in enumerate(self.report['phases']):
            for field in ('journal_sha256', 'archive_sha256'):
                changed = deepcopy(self.report)
                changed['phases'][index][field] = '0' * 64
                mutations.append((row['id'] + ':' + field, changed))
        for position, changed in mutations:
            with self.subTest(position=position), self.assertRaises(ValueError):
                self.admit(changed)

    def hosted_report(self):
        checks = (
            'export_manifest_matches_qualification', 'isolated_python_without_site',
            'nested_full_qualification_pass', 'nested_process_exit_zero',
            'no_ancestor_git_identity', 'no_bytecode_cache_created',
            'no_inherited_home_or_python_cache', 'no_inherited_seed_or_successor_images',
            'origin_hashes_preserved', 'owned_process_tree_cleanup_confirmed',
            'source_export_hashes_preserved',
        )
        return {'schema': 'hepta.hia.selfhost-cold-replay.v1',
                'status': 'COLD_SELFHOST_REPLAY_PASS', 'returncode': 0,
                'profile': self.contract['profile'], 'source_manifest': self.sources,
                'generation_sha256': self.report['generation_sha256'],
                'checks': {name: True for name in checks}}

    def builder_admit(self, report, roles):
        from tools import build_hia_json_preflight as builder
        contract = {**self.contract, 'source_identity': {'roles': roles}}
        with (patch('tools.hia_release_contract.validate_release_contract', return_value=contract),
              patch.object(builder, 'current_sources', return_value=self.sources),
              patch('tools.generate_hia_native_observer.reference_image', return_value=self.observer)):
            return builder.admit_cold_build(self.compiler, json.dumps(report).encode())

    def test_native_source_domain_cannot_use_hosted_report_checks(self):
        from tools.hia_release_contract import NATIVE_AUTHORITY
        roles = {'authoring_authority': NATIVE_AUTHORITY}
        with self.assertRaises(ValueError):
            self.builder_admit(self.hosted_report(), roles)
        self.assertEqual(self.builder_admit(self.report, roles), self.sources)

    def test_hosted_source_domain_cannot_select_native_report(self):
        from tools.hia_release_contract import HOSTED_SEED
        roles = {'seed_entry': HOSTED_SEED}
        with self.assertRaises(ValueError):
            self.builder_admit(self.report, roles)
        self.assertEqual(self.builder_admit(self.hosted_report(), roles), self.sources)
        incomplete = self.hosted_report()
        incomplete['checks'].pop('isolated_python_without_site')
        with self.assertRaises(ValueError):
            self.builder_admit(incomplete, roles)

    def test_unknown_source_domain_cannot_enter_either_report_gate(self):
        for report in (self.report, self.hosted_report()):
            for roles in ({}, {'authoring_authority': 'foreign.json'}):
                with self.subTest(schema=report['schema'], roles=roles), self.assertRaises(ValueError):
                    self.builder_admit(report, roles)

    def admit_integer_token(self, path, token, *, extension=False):
        changed = deepcopy(self.report)
        if extension:
            changed['extension'] = {'integer': None}
        owner = changed
        for key in path[:-1]:
            owner = owner[key]
        owner[path[-1]] = '__native_integer_token__'
        raw = json.dumps(changed).encode()
        marker = b'"__native_integer_token__"'
        self.assertEqual(raw.count(marker), 1)
        return admit_native_report(self.compiler, raw.replace(marker, token),
            contract=self.contract, sources=self.sources, observer_bytes=self.observer)

    def test_negative_zero_is_rejected_in_native_unsigned_integer_fields(self):
        paths = [('cleanup_wall_elapsed_ns',), ('scheduler', 'peak_pending_archives')]
        paths.extend(('phases', index, 'returncode')
                     for index in range(len(self.report['phases'])))
        for path in paths:
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.admit_integer_token(path, b'-0')

    def test_native_top_level_exit_retains_hia_zero_integer_compatibility(self):
        for token in (b'0', b'-0'):
            with self.subTest(token=token):
                self.assertEqual(self.admit_integer_token(('returncode',), token), self.sources)
        for token in (b'0.0', b'-0.0', b'0e0', b'false', b'null', b'"-0"'):
            with self.subTest(token=token), self.assertRaises(ValueError):
                self.admit_integer_token(('returncode',), token)

    def test_unused_native_extensions_keep_json_number_compatibility(self):
        for token in (b'-0', b'-1', b'0.0', b'0e0'):
            with self.subTest(token=token):
                self.assertEqual(self.admit_integer_token(('extension', 'integer'), token,
                                                         extension=True), self.sources)

    def test_default_json_reader_keeps_hosted_negative_zero_compatibility(self):
        self.assertEqual(read_json(b'{"returncode":-0,"cleanup_wall_elapsed_ns":-0}'),
                         {'returncode': 0, 'cleanup_wall_elapsed_ns': 0})


if __name__ == "__main__":
    unittest.main()
