"""Seven complete VerifiedProgram representation/report policies; foreign providers remain explicit."""

def sha256(self):
        return payload_sha256(self.canonical_bytes).hex()

def canonical_json(self):
        return self.canonical_bytes.decode("utf-8")

def input_sha256(self):
        return payload_sha256(self.structured_bytes if self.structured_bytes is not None
                              else self.canonical_bytes).hex()

def scalar_entrypoints(self):
        # A nominal aggregate erased into scalar slots is still not a scalar
        # public signature.  Generated protocol helpers are internal too.
        document = self.as_dict()
        if "exports" in document:
            return frozenset(document["exports"])
        return frozenset(fn["name"] for fn in document["functions"]
                         if all(type(p["type"]) is str and p["type"] in SCALARS for p in fn["params"])
                         and all(type(t) is str and t in SCALARS for t in fn["returns"]))

def normalization_report(self):
        checked = verify_program(self)
        core = checked.as_dict()
        original = (decode_internal_canonical(checked.structured_bytes, max_nodes=MAX_NODES, max_depth=MAX_DEPTH)
                    if checked.structured_bytes is not None else core)
        return {"input_sha256": checked.input_sha256,
                "core_sha256": checked.sha256,
                "input_schema": original["schema"],
                "input_profile": profile_for_schema(original["schema"]),
                "core_schema": core["schema"],
                "core_profile": profile_for_schema(core["schema"]),
                "structured_elaboration_rechecked": checked.structured_bytes is not None,
                "primitive_core_rechecked": True,
                "source_ast_required": False,
                "public_scalar_entrypoints": sorted(checked.scalar_entrypoints)}

def as_dict(self):
        return decode_internal_canonical(self.canonical_bytes, max_nodes=MAX_NODES, max_depth=MAX_DEPTH)

def report(self):
        # This public constructor is intentionally not an authority. Even a
        # report rechecks the immutable bytes instead of trusting its class.
        checked = verify_program(self)
        data = checked.as_dict()
        profile = profile_for_schema(data["schema"])
        return {"schema": "hepta.hia.program-verification.v1", "ok": True,
                "profile": profile, "program_sha256": checked.sha256,
                "input_sha256": checked.input_sha256,
                "normalization": checked.normalization_report,
                "word_bits": WORD_BITS, "functions_checked": len(data["functions"]),
                "blocks_checked": sum(len(f["blocks"]) for f in data["functions"]),
                "source_required": False,
                "claims": {"typed_closed_ssa_checked": True,
                           "linear_resources_and_loan_provenance_checked": True,
                           "whole_language_soundness_proved": False,
                           "backend_refinement_proved": False,
                           "foreign_code_supported": False,
                           "escaping_loans_supported": False,
                           "parameter_bound_loan_returns_supported": supports_feature(data["schema"], "parameter_loan_returns"),
                           "concurrency_supported": False,
                           "nominal_products_and_enums_checked": checked.structured_bytes is not None,
                           "local_stored_loan_identity_checked": checked.structured_bytes is not None,
                           "record_field_borrow_provenance_checked": checked.structured_bytes is not None,
                           "cooperative_task_protocol_checked": checked.structured_bytes is not None,
                           "background_tasks_supported": False,
                           "recursive_heap_adts_supported": False,
                           "recursive_buffer_chains_supported": supports_feature(data["schema"], "recursive_chain"),
                           "preemptive_or_async_cancellation_supported": False}}
