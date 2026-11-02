"""Descriptive CFG versions cannot be confused with scalar CFG authority."""
from __future__ import annotations

import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from hepta.cfg import CFGSnapshot, lower_checked_cfg as scalar_cfg
from hepta.cfg_analysis import CFGAnalysisRejected, analyze_cfg
from hepta.checker import check
from hepta.flow_ir import (FlowLowerError, import_legacy_descriptive_cfg,
                           lower_checked_cfg)
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_routes import RouteRejected, admit_route, route_inventory
from hepta.parser import parse
from hepta.ssa import SSARejected, lower_cfg_scalar_ssa


SOURCE = "fn identity(n: i32) -> i32 effects {} { return n; }"
PATH = "cfg-version.hepta"


def checked(source=SOURCE, path=PATH):
    program = parse(source, path)
    result = check(program)
    if not result.ok:
        raise AssertionError([item.to_dict() for item in result.diagnostics])
    return program, result


def reseal(payload):
    payload = copy.deepcopy(payload)
    payload.pop("sha256", None)
    wire = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                      allow_nan=False, separators=(",", ":")).encode()
    payload["sha256"] = hashlib.sha256(wire).hexdigest()
    return payload


def legacy(source=SOURCE, path=PATH, project_sha256=None):
    program, result = checked(source, path)
    payload = lower_checked_cfg(program, result, project_sha256=project_sha256)
    payload["schema"] = "hepta.cfg.v0"
    return reseal(payload)


class CFGWireVersionTests(unittest.TestCase):
    def test_active_producers_have_distinct_unambiguous_schema_names(self):
        program, result = checked()
        descriptive = lower_checked_cfg(program, result)
        structural = scalar_cfg(program, result)
        self.assertNotEqual(descriptive["schema"], structural.schema)
        self.assertEqual(descriptive["schema"], "hepta.cfg.descriptive.v1")
        self.assertEqual(structural.schema, "hepta.cfg.v0")
        self.assertTrue(analyze_cfg(structural))
        self.assertTrue(lower_cfg_scalar_ssa(structural))
        # Even a digest-consistent Python carrier cannot grant scalar authority.
        content = {k: v for k, v in descriptive.items() if k != "sha256"}
        wire = json.dumps(content, sort_keys=True, ensure_ascii=False,
                          allow_nan=False, separators=(",", ":"))
        disguised = CFGSnapshot(structural.schema, wire,
                                hashlib.sha256(wire.encode()).hexdigest())
        with self.assertRaises(CFGAnalysisRejected):
            analyze_cfg(disguised)

    def test_legacy_import_replays_the_same_descriptive_producer(self):
        source = ("fn choose(n: i32) -> i32 effects {} { "
                  "if n > 0 { return n; } else { return 0; } }")
        # This field was historically metadata; it is never a project proof.
        project = "caller-project-label"
        old = legacy(source, project_sha256=project)
        for document in (old, json.dumps(old), json.dumps(old).encode()):
            with self.subTest(kind=type(document).__name__):
                current, report = import_legacy_descriptive_cfg(
                    document, source=source, path=PATH, project_sha256=project)
                self.assertEqual(current, lower_checked_cfg(
                    *checked(source), project_sha256=project))
                expected = dict(old, schema=current["schema"])
                self.assertEqual(current, reseal(expected))
                self.assertNotEqual(current["sha256"], old["sha256"])
                self.assertEqual(report["source_cfg_sha256"], old["sha256"])
                self.assertEqual(report["target_cfg_sha256"], current["sha256"])
                self.assertTrue(report["claims"]["fresh_source_check_and_descriptive_replay"])
                self.assertTrue(report["claims"]["payload_unchanged_excluding_schema_and_digest"])
                for claim in ("project_identity_authenticated", "independent_execution_authorized",
                              "source_to_core_refinement_proved", "whole_language_soundness_proved"):
                    self.assertIs(report["claims"][claim], False)
        self.assertEqual(old, legacy(source, project_sha256=project))

    def test_source_path_and_explicit_project_identity_must_all_replay(self):
        old = legacy(project_sha256="project-a")
        cases = [dict(source=SOURCE + "\n", path=PATH, project_sha256="project-a"),
                 dict(source=SOURCE, path="different.hepta", project_sha256="project-a"),
                 dict(source=SOURCE, path=PATH, project_sha256="project-b"),
                 dict(source=SOURCE, path=PATH)]
        for arguments in cases:
            with self.subTest(arguments=arguments):
                with self.assertRaises(FlowLowerError):
                    import_legacy_descriptive_cfg(old, **arguments)

    def test_schema_profile_claims_and_unknown_envelope_fields_cannot_be_guessed(self):
        old = legacy()
        mutations = {
            "unknown_schema": lambda x: x.update(schema="hepta.cfg.future.v1"),
            "new_schema_is_not_legacy": lambda x: x.update(schema="hepta.cfg.descriptive.v1"),
            "missing_profile": lambda x: x.pop("profile"),
            "wrong_profile": lambda x: x.update(profile="structural_cfg_only_not_proved"),
            "ambiguous_old_envelope": lambda x: x.update(status="structural_cfg_only_not_proved"),
            "extra_authority": lambda x: x.update(verified=True),
            "elevated_claim": lambda x: x["claims"].update(machine_lowering_verified=True),
            "missing_claim": lambda x: x["claims"].pop("ssa"),
            "unknown_claim": lambda x: x["claims"].update(new_proof=False),
            "integer_false_claim": lambda x: x["claims"].update(ssa=0),
        }
        for name, mutate in mutations.items():
            with self.subTest(case=name):
                changed = copy.deepcopy(old)
                mutate(changed)
                with self.assertRaises(FlowLowerError):
                    import_legacy_descriptive_cfg(reseal(changed), source=SOURCE, path=PATH)
        # Actual structural output is also refused by the descriptive adapter.
        with self.assertRaises(FlowLowerError):
            import_legacy_descriptive_cfg(scalar_cfg(*checked()).as_dict(),
                                         source=SOURCE, path=PATH)

    def test_checksum_and_resealed_nested_semantic_changes_are_refused(self):
        old = legacy()
        broken = copy.deepcopy(old)
        broken["functions"][0]["signature"]["returns"] = "u32"
        with self.assertRaisesRegex(FlowLowerError, "checksum"):
            import_legacy_descriptive_cfg(broken, source=SOURCE, path=PATH)

        def float_column(payload):
            span = payload["functions"][0]["graph"]["blocks"][0]["terminator"]["span"]
            span["column"] = float(span["column"])

        mutations = {
            "changed_return_type": lambda x: x["functions"][0]["signature"].update(returns="u32"),
            "unknown_function_field": lambda x: x["functions"][0].update(provenance_proved=True),
            "omitted_function": lambda x: x.update(functions=[]),
            "hidden_effect": lambda x: x["functions"][0]["effects"].append("unsafe"),
            "omitted_volatile_inventory": lambda x: x.pop("volatile_accesses"),
            "integer_false_external": lambda x: x["functions"][0].update(external=0),
            "float_span_column": float_column,
            "unknown_nested_operation": lambda x: x["functions"][0]["graph"]["blocks"][0]["terminator"].update(drop_all=True),
        }
        for name, mutate in mutations.items():
            with self.subTest(case=name):
                changed = copy.deepcopy(old)
                mutate(changed)
                with self.assertRaises(FlowLowerError):
                    import_legacy_descriptive_cfg(reseal(changed), source=SOURCE, path=PATH)

    def test_duplicate_nonfinite_cyclic_and_bounded_inputs_reject_before_replay(self):
        old = legacy()
        duplicate = json.dumps(old)[:-1] + ', "schema": "hepta.cfg.v0"}'
        cyclic = copy.deepcopy(old)
        cyclic["functions"].append(cyclic)
        for document in (duplicate, '{"schema": NaN}', cyclic, b"\xff", [], None):
            with self.subTest(kind=type(document).__name__):
                with patch("hepta.parser.parse", side_effect=AssertionError("must refuse before replay")):
                    with self.assertRaises(FlowLowerError):
                        import_legacy_descriptive_cfg(document, source=SOURCE, path=PATH)
        # Exercise limits using small patched bounds, without allocating huge inputs.
        with patch("hepta.hia_program_tools.MAX_INPUT_BYTES", 64):
            with patch("hepta.parser.parse", side_effect=AssertionError("must refuse before replay")):
                with self.assertRaises(FlowLowerError):
                    import_legacy_descriptive_cfg(old, source=SOURCE, path=PATH)
        for field in ("source", "path", "project_sha256"):
            arguments = dict(source=SOURCE, path=PATH, project_sha256=None)
            arguments[field] = object()
            with self.subTest(field=field):
                with self.assertRaises(FlowLowerError):
                    import_legacy_descriptive_cfg(old, **arguments)
        with self.assertRaises(FlowLowerError):
            import_legacy_descriptive_cfg(old, source=SOURCE, path="x" * 4097)

    def test_longer_target_schema_refuses_with_the_adapter_error_at_wire_limit(self):
        old = legacy()
        limit = len(json.dumps(old, sort_keys=True, ensure_ascii=False,
                               allow_nan=False, separators=(",", ":")).encode())
        # Old wire fits exactly; the explicit target schema requires more bytes.
        with patch("hepta.hia_program_tools.MAX_INPUT_BYTES", limit):
            with self.assertRaisesRegex(FlowLowerError, "fresh source replay refused"):
                import_legacy_descriptive_cfg(old, source=SOURCE, path=PATH)

    def test_source_replay_rechecks_and_rejects_unresolved_project_or_invalid_source(self):
        for source in ("import missing; " + SOURCE,
                       "fn bad() -> i32 effects {} { return false; }", "fn {"):
            old = legacy()
            old["source_sha256"] = hashlib.sha256(source.encode()).hexdigest()
            with self.subTest(source=source):
                with self.assertRaises(FlowLowerError):
                    import_legacy_descriptive_cfg(reseal(old), source=source, path=PATH)

    def test_all_descriptive_versions_stay_outside_scalar_and_hia_admission(self):
        current, report = import_legacy_descriptive_cfg(legacy(), source=SOURCE, path=PATH)
        for document in (legacy(), current, report):
            with self.subTest(schema=document["schema"]):
                with self.assertRaises(HIAProgramRejected):
                    verify_program(document)
                with self.assertRaises(HIAProgramRejected):
                    admit_route("standalone-hia", document)
                content = {k: v for k, v in document.items() if k != "sha256"}
                wire = json.dumps(content, sort_keys=True, separators=(",", ":"))
                for carrier_schema in (document["schema"], "hepta.cfg.v0"):
                    disguised = CFGSnapshot(carrier_schema, wire,
                                            hashlib.sha256(wire.encode()).hexdigest())
                    with self.assertRaises(CFGAnalysisRejected):
                        analyze_cfg(disguised)
                    with self.assertRaises(SSARejected):
                        lower_cfg_scalar_ssa(disguised)
        inventory = route_inventory()
        descriptions = [row for row in inventory["historical_ir"]
                        if row["input"] == current["schema"]]
        self.assertEqual(len(descriptions), 1)
        self.assertIs(descriptions[0]["independent_execution"], False)
        with patch("hepta.hia_routes.verify_program", side_effect=AssertionError("must reject route")):
            with self.assertRaises(RouteRejected):
                admit_route("descriptive-cfg", current)


if __name__ == "__main__":
    unittest.main()
