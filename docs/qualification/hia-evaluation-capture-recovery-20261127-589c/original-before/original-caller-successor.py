def test_evaluation_candidate_uses_exact_build_bound_native_observation(self):
        # Exercise the real public caller, not a replacement evaluator.
        # Claim and receipt checks retain their own full revalidation.
        workload = {"schema": "hepta.hia.agent.workload.v1", "cases": [
            {"function": "transform", "arguments": [250]}],
            "warmup_iterations": 0, "repetitions": 1}
        _base, _candidate, baseline, build, receipts = self.build_pair(workload=workload)
        native = self.service._native
        calls = []

        def observe(ref, context=None):
            calls.append((sys._getframe(1).f_code.co_name, ref))
            return native(ref, context)

        with patch.object(self.service, "_native", new=observe):
            evaluation = self.session.evaluate(baseline, build, receipts=receipts)
        self.assertIn(evaluation["outcome"], {"improved", "unchanged", "regressed"})
        self.assertTrue(evaluation["termination_confirmed"])
        self.assertTrue(evaluation["planned_workload_complete"])
        direct = [ref for owner, ref in calls if owner in ("_hia_evaluate_reference", "_hia_evaluate_with_components")]
        self.assertEqual(direct, [baseline["native_artifact"]])
        self.assertIn(("_build_inputs_with_components", build["native_artifact"]), calls)
