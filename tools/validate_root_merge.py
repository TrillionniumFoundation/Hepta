"""Pure AST checks for the exact combined authoring revision; no product imports."""
import ast
import copy

def dump(node):
    return ast.dump(node, annotate_fields=True, include_attributes=False)

def nodes(text):
    return ast.parse(text).body

def named(text, name):
    found = [n for n in nodes(text) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.name == name]
    if len(found) != 1:
        raise AssertionError("expected one top-level definition: " + name)
    return found[0]

def assignments(text):
    result = {}
    for node in nodes(text):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    result[target.id] = node.value
    return result

def methods(text):
    result = {}
    for cls in nodes(text):
        if isinstance(cls, ast.ClassDef):
            for method in cls.body:
                if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) and method.name.startswith("test_"):
                    key = cls.name + "." + method.name
                    if key in result:
                        raise AssertionError("duplicate test method " + key)
                    result[key] = method
    return result

def same(left, right, label):
    if dump(left) != dump(right):
        raise AssertionError("complete AST differs: " + label)

class OriginalFunctionProjection(ast.NodeTransformer):
    def visit_Attribute(self, node):
        node = self.generic_visit(node)
        if node.attr == "_reference_main_function":
            node.attr = "_reference_function"
        return node
    def visit_Constant(self, node):
        if isinstance(node.value, str):
            node.value = node.value.replace("def _reference_main_function(", "def _reference_function(")
            node.value = node.value.replace("'_reference_function','_reference_main_function','_reference_helper_cache',", "'_reference_function',")
        return node

def validate(final_sources, originals):
    report = {"scope": "PURE_AST_ONLY", "checks": [], "product_imports": 0, "product_test_methods_executed": 0}
    regression_paths = (
        "tests/test_hia_composite_constructor_integration.py",
        "tests/test_hia_composite_outer_integration.py",
        "tests/test_hia_task_helpers_native.py",
        "tests/test_hia_composite_functions_native.py",
        "tests/test_hia_composite_types_native.py",
        "tests/test_hia_standalone_builder_source_binding.py",
        "tests/test_hia_original_select_fragments.py",
    )
    original_count = merged_count = additional_count = 0
    for path in regression_paths:
        old = methods(originals["main"][path])
        other = methods(originals["a733"][path])
        final = methods(final_sources[path])
        if not set(old) <= set(final) or not set(other) <= set(final):
            raise AssertionError("original method IDs missing: " + path)
        for key, method in old.items():
            current = copy.deepcopy(final[key])
            if path.endswith("test_hia_composite_functions_native.py") and key.rsplit(".", 1)[-1] in (
                "test_original_body_and_indivisible_bundle",
                "test_real_sdist_to_installed_wheel_and_each_source_or_image_custody_refusal",
            ):
                current = OriginalFunctionProjection().visit(current)
            same(method, current, path + ":" + key)
        additions = set(other) - set(old)
        for key in additions:
            same(other[key], final[key], path + ":added:" + key)
        if set(final) != set(old) | set(other):
            raise AssertionError("unrecorded test method change: " + path)
        original_count += len(old)
        merged_count += len(final)
        additional_count += len(additions)
        report["checks"].append({"path": path, "main_methods": len(old), "a733_methods": len(other),
                                 "merged_methods": len(final), "main_method_AST_preserved": True,
                                 "explicit_added_methods": sorted(additions)})
    if (original_count, merged_count, additional_count) != (68, 76, 8):
        raise AssertionError("regression inventory differs: " + repr((original_count, merged_count, additional_count)))
    byte_path = "hepta/hia_native_byte_abi.py"
    for name in ("_reference_normalize_exports", "_reference_emit_wrapper"):
        for head in ("main", "a733"):
            same(named(originals[head][byte_path], name), named(final_sources[byte_path], name), byte_path + ":" + head + ":" + name)
    selection_path = "hepta/hia_native_byte_abi_selection.py"
    original_scope = copy.deepcopy(named(originals["a733"][selection_path], "native_byte_abi_scope"))
    original_scope.name = "_native_byte_abi_control_scope"
    same(original_scope, named(final_sources[selection_path], "_native_byte_abi_control_scope"), "original byte ABI control scope")
    byte_tests = methods(final_sources["tests/test_hia_byte_policy_selection.py"])
    if len(byte_tests) != 11:
        raise AssertionError("byte routing source control count differs")
    report["checks"].append({"byte_reference_bodies": "main+a733 exact AST", "control_scope": "definition-name-only projection",
                            "routing_methods_present": 11, "routing_methods_executed": 0})
    contract_path = "tools/hia_selfhost_contract.py"
    source_contract = final_sources[contract_path]
    a733_contract = originals["a733"][contract_path]
    preserved = [node.name for node in nodes(a733_contract)
                 if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and (
                     node.name.startswith("_source_") or node.name.startswith("_SourcePathProtocol")
                     or node.name in ("file_digests", "validate_contract"))]
    for name in preserved:
        same(named(a733_contract, name), named(source_contract, name), contract_path + ":" + name)
    source_files = ast.literal_eval(assignments(source_contract)["SOURCE_FILES"])
    if type(source_files) is not tuple or len(source_files) != 1197 or len(set(source_files)) != 1197:
        raise AssertionError("source contract exact inventory differs")
    missing = sorted(set(final_sources) - set(source_files) - {"setup.py", "MANIFEST.in"})
    if missing:
        raise AssertionError("frozen overlay paths absent from source contract: " + repr(missing))
    def support_fields(text):
        returns = [n for n in named(text, "support_contract").body if isinstance(n, ast.Return) and isinstance(n.value, ast.Dict)]
        if len(returns) != 1:
            raise AssertionError("support contract has no one exact literal return")
        return {ast.literal_eval(k): v for k, v in zip(returns[0].value.keys, returns[0].value.values)}
    old_fields = support_fields(originals["main"][contract_path])
    new_fields = support_fields(source_contract)
    if len(old_fields) != 53 or len(new_fields) != 83 or not set(old_fields) <= set(new_fields):
        raise AssertionError("support field inventory differs")
    extended = {"native_worker_helper_bundle", "native_assembly_source_build"}
    for name in set(old_fields) - extended:
        same(old_fields[name], new_fields[name], "retained main support field:" + name)
    helper_node = assignments(final_sources["hepta/hia_native_helpers.py"])["HELPERS"]
    if not isinstance(helper_node, ast.Dict) or len(helper_node.keys) != 50:
        raise AssertionError("actual helper registration count differs")
    helper_fields = new_fields["native_worker_helper_bundle"]
    helper_values = {ast.literal_eval(k): v for k, v in zip(helper_fields.keys, helper_fields.values)}
    if ast.literal_eval(helper_values["supported_single_image_selectors"]) != 50:
        raise AssertionError("helper contract count differs")
    report["checks"].append({"source_protocol_full_AST": preserved, "source_inventory": 1197,
                            "original_support_fields": 53, "current_support_fields": 83,
                            "explicit_extended_fields": sorted(extended), "actual_helpers": 50})
    generic = "tools/build_hia_json_preflight.py"
    for name in ("current_sources", "admit_cold_build"):
        same(named(originals["main"][generic], name), named(final_sources[generic], name), generic + ":" + name)
    qualifier = "tools/qualify_hia_selfhost.py"
    for name in ("_compile_observation_size", "compile_stage", "invoke"):
        same(named(originals["a733"][qualifier], name), named(final_sources[qualifier], name), qualifier + ":" + name)
    generator = "tools/generate_hia_source_build.py"
    old_assign = assignments(originals["main"][generator])
    new_assign = assignments(final_sources[generator])
    for name in ("BUNDLE_MAGIC", "PACK_MAGIC", "WIRE_LIMIT", "IMAGE_LIMIT", "COMPILER_WORK_BYTES", "IMAGE_AT", "POLICY_WORK_BYTES", "ROLE_NAMES"):
        same(old_assign[name], new_assign[name], generator + ":" + name)
    call_graph = "tests/test_hia_selfhost_call_graph_efficiency.py"
    if final_sources[call_graph] != originals["newmain"][call_graph]:
        raise AssertionError("new main call graph controls changed")
    report["checks"].append({"generic_cold_admission_AST": "preserved", "strict_selfhost_observer_AST": "preserved",
                            "source_build_caps_and_roles_AST": "preserved", "newmain_callgraph_source": "exact bytes"})
    report["status"] = "PASS"
    return report
