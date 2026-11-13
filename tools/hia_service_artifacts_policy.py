"""Exact six original artifact-input policies; authoring input only."""

class HIAAgentService:
    def _profile(self, ref, name, *, _connection=None):
        return self.store.check_profile(ref, self.profiles[name], **_connection_arguments(_connection))

    def _program(self, ref, *, _connection=None):
        data, _ = self.store.get(ref, **_connection_arguments(_connection))
        return verify_program(decode_json(data))

    def _signature_values(self, program, foreign_buffer_exports=()):
        owner = getattr(self, '_native_emission', None)
        arguments = {'callee': _signatures if owner is None else owner.signatures,
                     'program': program, 'foreign_buffer_exports': foreign_buffer_exports}
        del self, owner, program, foreign_buffer_exports
        return arguments.pop('callee')(arguments.pop('program'), arguments.pop('foreign_buffer_exports'))

    def _native(self, ref, context=None, *, _connection=None):
        data, metadata = self.store.get(ref, kind="native", **_connection_arguments(_connection))
        if metadata["installation"] != self.identities or context is not None and metadata["context"] != context:
            reject("E_HIA_RECEIPT_BINDING", "native artifact belongs to a different context or implementation")
        program = self._program(metadata["candidate"], **_connection_arguments(_connection))
        retained_context = self._context(metadata["context"], **_connection_arguments(_connection))
        exports = tuple(map(tuple, retained_context.get("foreign_buffer_exports", [])))
        if (metadata["core_sha256"] != program.sha256 or self._signature_values(program, exports) != metadata["signatures"]
                or metadata.get("foreign_buffer_exports", []) != [list(pair) for pair in exports]):
            reject("E_HIA_RECEIPT_BINDING", "native artifact's admitted Core identity differs")
        return data, metadata, program

    def _build_receipt(self, ref, context, artifact, *, _connection=None):
        return self._build_inputs(ref, context, artifact, **_connection_arguments(_connection))[0]

    def _build_inputs(self, ref, context, artifact, *, _connection=None):
        """Capture and validate one immutable Core/object/final build observation."""
        record, _ = self.store.get_json(ref, kind="build-receipt", **_connection_arguments(_connection))
        if (record["context"] != context or record["native_artifact"] != artifact or record["installation"] != self.identities
                or record.get("target_profile") != self.profiles["target"]
                or record.get("backend_profile") != self.profiles["backend"]):
            reject("E_HIA_RECEIPT_BINDING", "build receipt belongs to a different native subject")
        data, metadata, program = self._native(artifact, context, **_connection_arguments(_connection))
        if any(record.get(name) != value for name, value in metadata.items()):
            reject("E_HIA_RECEIPT_BINDING", "build record differs from retained native metadata")
        built = record.get("native_build")
        if (type(built) is not dict or type(record.get("object_artifact")) is not dict
                or record["object_artifact"] != built.get("object_artifact")
                or record.get("object_sha256") != built.get("object_sha256")
                or built.get("core_sha256") != program.sha256
                or built.get("input_sha256") != program.input_sha256
                or built.get("implementation_sha256") != self.identities["backend_sha256"]
                or built.get("kind") != record["output_kind"]
                or built.get("foreign_buffer_exports") != record.get("foreign_buffer_exports", [])
                or built.get("artifact_sha256") != sha256(data).hexdigest()):
            reject("E_HIA_RECEIPT_BINDING", "build record differs from actual artifact bytes")
        object_bytes, object_metadata = self.store.get(record["object_artifact"], kind="build-object", **_connection_arguments(_connection))
        expected_metadata = {"schema": "hepta.hia.agent.build-object.v1", "core_sha256": program.sha256,
            "machine_plan_sha256": built.get("machine_plan_sha256"), "installation": self.identities}
        if (object_metadata != expected_metadata or sha256(object_bytes).hexdigest() != record["object_sha256"]
                or record["object_artifact"]["sha256"] != record["object_sha256"]
                or record["output_kind"] == "object" and object_bytes != data):
            reject("E_HIA_RECEIPT_BINDING", "retained object differs from its exact build binding")
        return record, data, object_bytes, program
