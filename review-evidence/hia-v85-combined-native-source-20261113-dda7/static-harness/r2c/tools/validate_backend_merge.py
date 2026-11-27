"""Pure AST preservation checks for backend-family checkpoint 3.

Input is source text, not imported modules. This validator deliberately does
not execute repository code, instantiate a loader, or confer native/cold
qualification. Its scope is the 59-source checkpoint whose index is
45a8275f2a197485379349faf9d8c586fe900647; the later seven-file R4 addendum is
outside this validator's new-test inventory. Other owners may be present in
final_sources, but the assertions below remain exact.

Run validate(final_sources, originals). Original texts are pinned to exact
fixed main/a733 identities. newmain is accepted by the interface but is not
used to silently replace either fixed original.
"""
from __future__ import annotations

import ast
import copy
import hashlib


SCHEMA = "hepta.hia.backend-family-ast-validation.v1"
CHECKPOINT_INDEX = "45a8275f2a197485379349faf9d8c586fe900647"
ORIGINAL_COMMITS = {
    "main": "51bc24b8b03e5adc3da1b2b3490ad5cc7357e8d8",
    "a733": "a733926a2786a3d4a37304bd2d18ebb2eac57ac9",
}
ORIGINAL_IDENTITIES = {
    "main": {
        "hepta/hia_program_native.py": {
            "bytes": 52188,
            "sha256": "84f0ac31384218c0e9f3f0adb41f5551ce3aa6cf84ebec3a5eb70416a021d81a",
            "git_blob": "892558f203f95ca8bd3e4eaf546c1a2556c66a2d"
        },
        "tests/test_hia_core_lowering_native.py": {
            "bytes": 29243,
            "sha256": "931615c9ed55b21212f9d673727451753d89fabcec097eb34949ab18094ac23a",
            "git_blob": "b26403c7f9e81c6adb38b9b713f5300db3b807ae"
        },
        "tests/test_hia_core_emitter_native.py": {
            "bytes": 24474,
            "sha256": "1228b102ac3d4508c3a2641563e0763be73e4b11dfa0f92883f775fc22e713de",
            "git_blob": "1f0cd9e1f95c2536560c0b883c8c1b206016a944"
        },
        "tests/test_hia_machine_plan_native.py": {
            "bytes": 22180,
            "sha256": "070380c1f0f54ab42c1510a16d9d445e6ff356050b42f4298be6d82967951ed1",
            "git_blob": "1835a364a39d99c8b97199eb7af1f568b5e1aa08"
        },
        "tests/test_hia_machine_object_native.py": {
            "bytes": 23841,
            "sha256": "6e90a2ab39e1586221f338aa24382a5d7928007f2ed2633456dec6abbaabd73e",
            "git_blob": "428117f3d98164af369eff4edfa145599ea4c620"
        },
        "tests/test_hia_machine_encoding_native.py": {
            "bytes": 21123,
            "sha256": "e7b2cdba4f19d9ab5471a9ab19bec1f907bc272d8fc3fcc54224b8dd548efdcf",
            "git_blob": "7e4d8167e1cff5e3c23fd243918ab28ae2299015"
        },
        "tests/test_hia_machine_state_native.py": {
            "bytes": 32680,
            "sha256": "44543d97437514eddeb0e83c560dd2cdfa2f765d217c14c8ac61f0c534826902",
            "git_blob": "8b21c4fe89c87e0d3f2811d841dbe94bd8e754bc"
        },
        "tests/test_hia_machine_instructions_native.py": {
            "bytes": 27977,
            "sha256": "fa060050e50027de1953d9a272fe30037e624b097cfa93fdee2824577017c118",
            "git_blob": "8b9b32a4894c9220f25f9735be67fa7a67e93bbc"
        }
    },
    "a733": {
        "hepta/hia_program_native.py": {
            "bytes": 59707,
            "sha256": "4c56f91867420f7160e28819046d338e8eca434cb13ff5a52f3051a9c7562374",
            "git_blob": "7b213f1894e70b32f5c0135706f408637e37359b"
        },
        "tools/hia_native_build_policy.py": {
            "bytes": 19437,
            "sha256": "aa3e14e9259ba9f0162deafb92106ed74b7bd165bd16a9fbd96805ff6c90c2e8",
            "git_blob": "95b4655b39dc8694dc4d70c7cff97210f8b1b909"
        }
    },
    "newmain": {}
}
REQUIRED_ORIGINAL_PATHS = {
    family: tuple(rows) for family, rows in ORIGINAL_IDENTITIES.items()
}
PROGRAM = "hepta/hia_program_native.py"
POLICY = "tools/hia_native_build_policy.py"
RETAINED_FUNCTIONS = (
    "validate_block_layout_plan", "emit_program_machine", "_inspect_object",
    "_read_artifact", "_run_logged", "_host", "compile_program_machine",
    "build_program_machine",
)
# Explicit spellings: leading underscores are not inferred or stripped.
REFERENCE_NAMES = {
    "validate_block_layout_plan": "_reference_validate_block_layout_plan",
    "emit_program_machine": "_reference_emit_program_machine",
    "_inspect_object": "_reference_inspect_object",
    "_read_artifact": "_reference_read_artifact",
    "_run_logged": "_reference_run_logged",
    "_host": "_reference_host",
    "compile_program_machine": "_reference_compile_program_machine",
    "build_program_machine": "_reference_build_program_machine",
}
MAIN_TEST_PATHS = (
    "tests/test_hia_core_lowering_native.py",
    "tests/test_hia_core_emitter_native.py",
    "tests/test_hia_machine_plan_native.py",
    "tests/test_hia_machine_object_native.py",
    "tests/test_hia_machine_encoding_native.py",
    "tests/test_hia_machine_state_native.py",
    "tests/test_hia_machine_instructions_native.py",
)
ALLOWED_TEST_CHANGES = {
    ("tests/test_hia_machine_state_native.py",
     "MachineStateNativeTests.test_backend_identity_and_both_selectors_are_pinned_across_emit"):
        ("hia_machine_state_native.py", "hia_json_wire_native.py"),
    ("tests/test_hia_machine_instructions_native.py",
     "MachineInstructionsNativeTests.test_backend_identity_and_three_selectors_are_pinned_across_emit"):
        ("hia_machine_state_native.py", "hia_machine_instructions_native.py",
         "hia_json_wire_native.py"),
}
RUNTIME_LITERALS = {
    "hepta/hia_core_lowering_control_native.py": (
        "HEPTA_HIA_CORE_LOWERING_CONTROL_MANIFEST",
        "hepta.hia.core-lowering-native.v2",
        "examples/hia_bootstrap/core_lowering.hepta"),
    "hepta/hia_core_emitter_control_native.py": (
        "HEPTA_HIA_CORE_EMITTER_CONTROL_MANIFEST",
        "hepta.hia.core-emitter-control-native.v1",
        "examples/hia_bootstrap/core_emitter.hepta"),
    "hepta/hia_machine_plan_control_native.py": (
        "HEPTA_HIA_MACHINE_PLAN_CONTROL_MANIFEST",
        "hepta.hia.machine-plan-control-native.v1",
        "examples/hia_bootstrap/machine_plan_control.hepta"),
    "hepta/hia_machine_plan_native.py": (
        "HEPTA_HIA_MACHINE_PLAN_MANIFEST",
        "hepta.hia.machine-plan-native.v1",
        "examples/hia_bootstrap/machine_plan.hepta"),
}
FAMILY_LITERALS = {
    "lowering_family": (
        ("native Core lowering", "hia_core_lowering_selection",
         "hia_core_lowering_control_selection",
         "HEPTA_HIA_CORE_LOWERING_MANIFEST",
         "HEPTA_HIA_CORE_LOWERING_CONTROL_MANIFEST",
         "installed_core_lowering", "_admit"), {}),
    "emitter_family": (
        ("native Core emitter", "hia_core_emitter_selection",
         "hia_core_emitter_control_selection",
         "HEPTA_HIA_CORE_EMITTER_MANIFEST",
         "HEPTA_HIA_CORE_EMITTER_CONTROL_MANIFEST",
         "installed_core_emitter", "_admit"), {}),
    "plan_family": (
        ("native machine plan", "hia_machine_plan_native",
         "hia_machine_plan_control_selection",
         "HEPTA_HIA_MACHINE_PLAN_MANIFEST",
         "HEPTA_HIA_MACHINE_PLAN_CONTROL_MANIFEST",
         "installed_machine_plan", "_admit"),
        {"primary_family": "plan-v1", "primary_admit": "_admit_family"}),
    "elf_family": (
        ("native ELF object", "hia_machine_object_selection",
         "hia_machine_elf_selection",
         "HEPTA_HIA_MACHINE_OBJECT_MANIFEST", "HEPTA_HIA_MACHINE_ELF_MANIFEST",
         "installed_machine_object", "_admit"), {}),
}


class ValidationError(ValueError):
    """Failure includes the partial JSON-serializable validation report."""

    def __init__(self, message, report):
        self.report = report
        super().__init__(message)


def _require(condition, message, report):
    if not condition:
        report["status"] = "FAIL"
        report["failure"] = message
        raise ValidationError(message, report)


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _identity(text):
    raw = text.encode("utf-8")
    return {
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "git_blob": hashlib.sha1(
            b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest(),
    }


def _source(sources, path, label, report):
    _require(isinstance(sources, dict), label + " must be a dict", report)
    _require(path in sources, label + " missing " + path, report)
    value = sources[path]
    _require(type(value) is str, label + "/" + path + " must be text", report)
    return value


def _parse(text, label, report):
    try:
        return ast.parse(text, filename=label, mode="exec")
    except (SyntaxError, ValueError, TypeError) as error:
        _require(False, label + ": AST parse failed: " + str(error), report)


def _dump(node):
    # Both sides are parsed by the same interpreter. Source locations alone
    # are omitted; args, decorators, annotations and full bodies are retained.
    return ast.dump(node, annotate_fields=True, include_attributes=False)


def _defs(body, kind, label, report):
    values = [node for node in body if isinstance(node, kind)]
    result = {}
    for node in values:
        _require(node.name not in result, label + " duplicate " + node.name, report)
        result[node.name] = node
    return result


def _function(tree, name, label, report):
    functions = _defs(tree.body, (ast.FunctionDef, ast.AsyncFunctionDef), label, report)
    _require(name in functions, label + " missing function " + name, report)
    return functions[name]


def _class(tree, name, label, report):
    classes = _defs(tree.body, ast.ClassDef, label, report)
    _require(name in classes, label + " missing class " + name, report)
    return classes[name]


def _canonical_function(node, name):
    projected = copy.deepcopy(node)
    projected.name = name
    return projected


def _same_ast(expected, actual, label, report):
    left, right = _dump(expected), _dump(actual)
    _require(left == right, label + ": AST changed", report)
    return {"ast_sha256": _sha(right), "full_ast_equal": True}


def _test_methods(tree, path, report):
    result = {}
    for cls in _defs(tree.body, ast.ClassDef, path, report).values():
        methods = _defs(cls.body, (ast.FunctionDef, ast.AsyncFunctionDef),
                        path + ":" + cls.name, report)
        for name, node in methods.items():
            if name.startswith("test_"):
                key = cls.name + "." + name
                _require(key not in result, path + " duplicate test " + key, report)
                result[key] = node
    return result


def _add_transport_only(node, original_tuple, label, report):
    projected = copy.deepcopy(node)
    matches = []
    for call in ast.walk(projected):
        if not isinstance(call, ast.Call):
            continue
        function_name = (
            call.func.id if isinstance(call.func, ast.Name) else
            call.func.attr if isinstance(call.func, ast.Attribute) else None)
        if function_name != "assert_primitive_bridge_identity_bound":
            continue
        if len(call.args) != 3 or call.keywords:
            continue
        names = call.args[2]
        if not isinstance(names, ast.Tuple):
            continue
        if not all(isinstance(item, ast.Constant) and type(item.value) is str
                   for item in names.elts):
            continue
        if tuple(item.value for item in names.elts) == original_tuple:
            matches.append(names)
    _require(len(matches) == 1,
             label + ": expected exactly one reviewed bridge-dependency tuple", report)
    matches[0].elts.append(ast.Constant(value="hia_machine_transport.py"))
    return projected


def _assignments(tree, name):
    found = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            if any(isinstance(target, ast.Name) and target.id == name
                   for target in node.targets):
                found.append(node.value)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == name:
                found.append(node.value)
    return found


def _single_assignment(tree, name, label, report):
    values = _assignments(tree, name)
    _require(len(values) == 1, label + ": expected one assignment " + name, report)
    return values[0]


def _literal(node, label, report):
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError) as error:
        _require(False, label + ": not a literal: " + str(error), report)


def _call_path(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_path(node.value)
        return None if base is None else base + "." + node.attr
    return None


def _check_router(tree, report):
    label = "hepta/hia_backend_family_selection.py"
    cls = _class(tree, "_FamilySelection", label, report)
    methods = _defs(cls.body, (ast.FunctionDef, ast.AsyncFunctionDef), label, report)
    _require("observe" in methods and "_select" in methods and "_bind" in methods,
             label + ": missing reviewed router methods", report)
    observations = methods["observe"]
    paths = [_call_path(node.func) for node in ast.walk(observations)
             if isinstance(node, ast.Call)]
    _require(sorted(paths) == sorted(
        ("self._route.get", "self._captured", "self._modules")),
        label + ": observe gained selection/admission or another call", report)
    _require(not any(isinstance(node, ast.Name) and node.id == "os"
                     for node in ast.walk(observations)),
             label + ": observe reads ambient environment", report)
    selection = methods["_select"]
    guards = [
        (index, node) for index, node in enumerate(selection.body)
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.BoolOp)
        and isinstance(node.test.op, ast.And)
        and [_dump(value) for value in node.test.values] == [
            _dump(ast.Name(id="old_path", ctx=ast.Load())),
            _dump(ast.Name(id="new_path", ctx=ast.Load()))]
    ]
    _require(len(guards) == 1, label + ": dual-selector guard changed", report)
    index, guard = guards[0]
    _require(len(guard.body) == 1 and isinstance(guard.body[0], ast.Raise)
             and not guard.orelse,
             label + ": dual-selector guard no longer solely refuses", report)
    raised = guard.body[0].exc
    _require(isinstance(raised, ast.Call) and _call_path(raised.func) == "ValueError",
             label + ": dual-selector refusal type changed", report)
    admission_positions = []
    for position, statement in enumerate(selection.body):
        if any(isinstance(node, ast.Call)
               and isinstance(node.func, ast.Call)
               and _call_path(node.func.func) == "getattr"
               and any(isinstance(arg, ast.Attribute) and
                       _call_path(arg) in (
                           "self.primary_admit", "self.installed", "self.control_admit")
                       for arg in node.func.args)
               for node in ast.walk(statement)):
            admission_positions.append(position)
    _require(admission_positions and all(position > index for position in admission_positions),
             label + ": an admission call precedes dual-selector refusal", report)
    actual_families = {}
    for name, (arguments, keywords) in FAMILY_LITERALS.items():
        call = _single_assignment(tree, name, label, report)
        _require(isinstance(call, ast.Call) and _call_path(call.func) == "_FamilySelection",
                 label + ": unexpected factory for " + name, report)
        got_args = tuple(_literal(arg, label + ":" + name, report) for arg in call.args)
        _require(all(item.arg is not None for item in call.keywords),
                 label + ": family has unpacked keywords " + name, report)
        got_keywords = {item.arg: _literal(item.value, label + ":" + name, report)
                        for item in call.keywords}
        _require(len(got_keywords) == len(call.keywords)
                 and got_args == arguments and got_keywords == keywords,
                 label + ": family names, selectors or admission API changed: " + name,
                 report)
        actual_families[name] = {"arguments": list(got_args), "keywords": got_keywords}
    return {
        "scope": "SOURCE_STRUCTURE_ONLY_NOT_RUNTIME_QUALIFICATION",
        "observe_calls": paths,
        "dual_refusal_before_admission_statements": True,
        "families": actual_families,
    }


def validate(final_sources, originals):
    report = {
        "schema": SCHEMA, "status": "STARTED", "checkpoint_index": CHECKPOINT_INDEX,
        "scope": "PURE_STDLIB_AST_AND_LITERAL_VALIDATION_NO_PRODUCT_IMPORTS",
        "original_commits": dict(ORIGINAL_COMMITS),
        "original_inputs": {}, "final_inputs": {},
        "retained_functions": [], "retained_policy_methods": [],
        "main_test_modules": [], "intentional_test_changes": [],
        "native_or_cold_qualification": False,
        "implementation_hash_body_compared": False,
        "newmain_used_as_implicit_original": False,
        "test_method_counts_are_declared_not_runtime_loader_counts": True,
    }
    _require(isinstance(final_sources, dict), "final_sources must be a dict", report)
    _require(isinstance(originals, dict), "originals must be a dict", report)
    parsed_originals = {}
    for family, files in ORIGINAL_IDENTITIES.items():
        if not files:
            continue
        _require(family in originals, "missing original family " + family, report)
        parsed_originals[family] = {}
        report["original_inputs"][family] = {}
        for path, identity in files.items():
            text = _source(originals[family], path, "originals/" + family, report)
            actual_identity = _identity(text)
            _require(actual_identity == identity,
                     family + "/" + path + ": fixed original bytes changed", report)
            report["original_inputs"][family][path] = actual_identity
            parsed_originals[family][path] = _parse(
                text, "originals/" + family + "/" + path, report)
    parsed_final = {}

    def final(path):
        if path not in parsed_final:
            text = _source(final_sources, path, "final_sources", report)
            report["final_inputs"][path] = _identity(text)
            parsed_final[path] = _parse(text, "final_sources/" + path, report)
        return parsed_final[path]

    original_backend = parsed_originals["a733"][PROGRAM]
    original_policy = parsed_originals["a733"][POLICY]
    for name in RETAINED_FUNCTIONS:
        reference = REFERENCE_NAMES[name]
        expected = _canonical_function(
            _function(original_backend, reference, "a733/" + PROGRAM, report), name)
        actual = _canonical_function(
            _function(final(PROGRAM), reference, "final/" + PROGRAM, report), name)
        row = {"name": name, "original_definition": reference,
               "final_definition": reference, "normalization": "ROOT_DEF_NAME_ONLY"}
        row.update(_same_ast(expected, actual, "retained " + name, report))
        # The authoring policy copy must match its own original AND the same
        # retained backend body; no policy callback or replacement is admitted.
        prior_policy = _canonical_function(
            _function(original_policy, name, "a733/" + POLICY, report), name)
        actual_policy = _canonical_function(
            _function(final(POLICY), name, "final/" + POLICY, report), name)
        _same_ast(prior_policy, actual_policy, "policy original " + name, report)
        _same_ast(expected, actual_policy, "policy/backend " + name, report)
        row["policy_original_and_backend_equal"] = True
        report["retained_functions"].append(row)
    _require(len(report["retained_functions"]) == 8,
             "retained-function denominator changed", report)

    # New factory __new__ adapters are intentionally not original policy bodies.
    # Every other direct method and its order is checked against BOTH heads.
    for class_name in ("_Function", "_Emitter"):
        selected = _class(final(PROGRAM), class_name, "final/" + PROGRAM, report)
        got = _defs(selected.body, (ast.FunctionDef, ast.AsyncFunctionDef),
                    "final/" + class_name, report)
        got = {name: node for name, node in got.items() if name != "__new__"}
        for family in ("main", "a733"):
            before = _class(parsed_originals[family][PROGRAM], class_name,
                            family + "/" + PROGRAM, report)
            expected = _defs(before.body, (ast.FunctionDef, ast.AsyncFunctionDef),
                             family + "/" + class_name, report)
            expected = {name: node for name, node in expected.items()
                        if name != "__new__"}
            _require(tuple(expected) == tuple(got),
                     class_name + ": original " + family + " method IDs/order changed", report)
            for name, method in expected.items():
                value = _same_ast(method, got[name],
                                  family + ":" + class_name + "." + name, report)
                report["retained_policy_methods"].append({
                    "original": family, "method": class_name + "." + name, **value})

    changed = set()
    for path in MAIN_TEST_PATHS:
        before = _test_methods(parsed_originals["main"][path], "main/" + path, report)
        after = _test_methods(final(path), "final/" + path, report)
        _require(tuple(before) == tuple(after), path + ": declared test IDs/order changed", report)
        _require(bool(before), path + ": no original test methods found", report)
        rows = []
        module = path[:-3].replace("/", ".")
        for name, method in before.items():
            key = (path, name)
            expected = method
            if key in ALLOWED_TEST_CHANGES:
                expected = _add_transport_only(
                    method, ALLOWED_TEST_CHANGES[key], path + ":" + name, report)
                changed.add(key)
                report["intentional_test_changes"].append({
                    "id": module + "." + name,
                    "change": "APPEND_ONE_EXACT_BRIDGE_DEPENDENCY",
                    "before_tuple": list(ALLOWED_TEST_CHANGES[key]),
                    "after_tuple": list(ALLOWED_TEST_CHANGES[key])
                                   + ["hia_machine_transport.py"],
                    "all_other_method_ast_unchanged": True,
                })
            row = _same_ast(expected, after[name], path + ":" + name, report)
            rows.append({"id": module + "." + name, **row})
        report["main_test_modules"].append({
            "path": path, "declared_method_count": len(rows),
            "ordered_ids": [row["id"] for row in rows], "methods": rows})
    _require(changed == set(ALLOWED_TEST_CHANGES),
             "reviewed intentional test changes missing or extra", report)

    literals = []
    for path, (selector, schema, source_path) in RUNTIME_LITERALS.items():
        tree = final(path)
        _require(_literal(_single_assignment(tree, "SELECTOR", path, report),
                          path + ":SELECTOR", report) == selector,
                 path + ": selector changed", report)
        _require(_literal(_single_assignment(tree, "SCHEMA", path, report),
                          path + ":SCHEMA", report) == schema,
                 path + ": schema changed", report)
        call = _single_assignment(tree, "SOURCE", path, report)
        _require(isinstance(call, ast.Call)
                 and _call_path(call.func) == "_source_resource_path"
                 and len(call.args) == 1 and not call.keywords,
                 path + ": SOURCE no longer uses one reviewed resource literal", report)
        _require(_literal(call.args[0], path + ":SOURCE", report) == source_path,
                 path + ": source resource changed", report)
        literals.append({"path": path, "selector": selector, "schema": schema,
                         "source": source_path})
    report["family_runtime_literals"] = literals
    report["router"] = _check_router(final("hepta/hia_backend_family_selection.py"), report)
    report["status"] = "PASS"
    return report
