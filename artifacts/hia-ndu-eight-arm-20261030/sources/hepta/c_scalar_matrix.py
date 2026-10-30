"""Complete declared scalar C build variants into independent HIA objects.

This uses the existing C project AST/statement/expression translator. It does
not infer pointer contracts or add another C syntax implementation. Resource
migration remains the separate, explicitly contracted C-project workflow.
"""
from __future__ import annotations

from .c_allocation import allocation_names
from .c_migrate import MigrationRejected
from .c_project_matrix import capture_project_matrix, verify_project_matrix
from .c_translation import CTranslator, INTEGER
from .hia_program import verify_program
from .hia_program_source import lower_source


class _StandaloneScalarTranslator(CTranslator):
    def signature(self, node, key, unit, model):
        # C99/C11/C17 inline is a linkage rule, not just an optimization
        # hint. A non-static inline body need not define an external symbol.
        # The shared collector calls this hook for EVERY declaration before
        # folding prototypes into a body, so an inline specifier on an earlier
        # or later redeclaration cannot disappear from the admission decision.
        # This deliberately narrow policy belongs only to standalone scalar
        # migration; it does not alter the historical C/bridge translator.
        if node.get("inline") and node.get("storageClass") != "static":
            raise MigrationRejected(
                "E_C_MATRIX_INLINE",
                "Standalone C matrix requires explicitly static inline declarations; "
                "external inline linkage and redeclarations need separate qualification",
            )
        return super().signature(node, key, unit, model)

    def collect(self):
        super().collect()
        if self.record_nodes:
            raise MigrationRejected("E_C_MATRIX_PROFILE", "Record layouts are outside standalone scalar matrix migration")
        names = {"c_bool_to_int"}
        for fn in self.functions.values():
            if (fn["return"] not in INTEGER | {"bool", "Unit"}
                    or any(param["pointer"] or param["type"] not in INTEGER | {"bool"}
                           for param in fn["params"])
                    or allocation_names(fn["body"])):
                raise MigrationRejected("E_C_MATRIX_PROFILE", "C matrix profile requires scalar, nonallocating implementations")
            # Calls use fn['hepta_name'] from this shared table. Changing the
            # emitted name preserves C scalar exports without a foreign shim.
            generated = fn["name"] if fn["external_symbol"] else "internal_" + fn["key"]
            if generated in names:
                raise MigrationRejected("E_C_MATRIX_PROFILE", "Standalone C matrix symbol collision")
            names.add(generated)
            fn["hepta_name"] = generated

    def bridge(self):
        return ""


def lower_c_project_matrix(manifest, *, clang="clang"):
    captured = capture_project_matrix(manifest, clang=clang, language="c")
    variants = []
    for variant in captured["variants"]:
        translator = _StandaloneScalarTranslator(variant["capture"])
        source, _, functions = translator.emit()
        for function in functions:
            if not function["external_symbol"]:
                source = source.replace("pub fn " + function["hepta_name"] + "(",
                                        "fn " + function["hepta_name"] + "(", 1)
        source = source.replace("module c_project_migrated;", "module c_matrix_migrated;", 1)
        source = source.replace("// Safe Hepta core. C ABI bridges carry separate caller obligations.",
                                "// Captured scalar C implementation bodies; direct HIA without foreign calls.", 1)
        program = lower_source(source, path="<captured-c-scalar-build-variant>")
        # Legacy source lowering exposes all scalar helper functions by
        # default. Bind this ABI-facing adapter to the captured external C
        # declaration set and independently recheck the resulting export list.
        program = verify_program({**program.as_dict(),
                                  "exports": sorted(fn["hepta_name"] for fn in functions
                                                    if fn["external_symbol"])})
        if not translator.inventory_complete or any(row["status"].endswith("pending") for row in translator.inventory):
            raise MigrationRejected("E_C_MATRIX_INVENTORY", "Unresolved C matrix declaration inventory")
        variants.append({"name": variant["name"], "command_indices": variant["command_indices"],
                         "capture": variant["capture"], "program": program, "source": source,
                         "functions": functions, "declarations": translator.inventory,
                         "active_project_declarations": sum(row["status"] != "system_or_compiler_declaration"
                                                            for row in translator.inventory)})
    verify_project_matrix(captured)
    return {"schema": "hepta.c-project-matrix-migration.v1", "ok": True,
            "status": "all_declared_scalar_c_variants_verified_not_native_qualified",
            "matrix_capture": captured, "variants": variants,
            "claims": {"every_listed_command_assigned_exactly_once": True,
                       "same_c_translation_authority": True,
                       "separate_standalone_hia_per_variant": True,
                       "original_c_implementation_in_target": False,
                       "resource_contracts_inferred_or_qualified": False,
                       "unlisted_configurations_qualified": False,
                       "source_equivalence_proved": False}}
