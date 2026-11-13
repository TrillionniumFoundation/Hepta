"""Generate the complete checker custody closure from actual source ASTs.

No project modules are imported or executed. The former semantic Core role list
is retained independently of this physical closure. Only the three exact
reviewed CPython import templates are synthetic relative-import edges.
"""
from __future__ import annotations

import argparse
import ast
from hashlib import sha256
import json
from pathlib import Path
import pprint

ROOT = Path(__file__).resolve().parents[1]
BEGIN = "# BEGIN GENERATED CHECKER CUSTODY"
END = "# END GENERATED CHECKER CUSTODY"
REVIEWED_IMPORTS = {
    "schema": "hia.checker.reviewed-host-import.v1",
    "template_source_sha256": "f58b477c044929b8228fc7dc30f66ba33c377654c521098c2f2bdbfe9a93af93",
    "templates": {
        "_one_member_template": "def _one_member_template():\n    from ._module import _member\n    return _member\n",
        "_three_member_template": "def _three_member_template():\n    from ._module import _a, _b, _c\n    return _a, _b, _c\n",
        "_five_member_template": "def _five_member_template():\n    from ._module import _a, _b, _c, _d, _e\n    return _a, _b, _c, _d, _e\n"
    },
    "authoring_files": {
        "tools/hia_core_emitter_ir.py": "d543037d9382c810db244f148624b457ac73089b149654496af8376b5c83c122",
        "tools/hia_byte_wrapper_ir.py": "7abe77dcfdcb1cdf1f8ae03649e0a52e3a6198e97f921d54d2f19b9e53ac2df3",
        "tools/hia_core_emitter_policy.py": "0821450ec2b88f0333389a48d888cd86f9a4808f5fc4948018d1165b1cbb36e6",
        "tools/hia_byte_wrapper_policy.py": "f4981dd874fdb27712a64a7d53afceed3f8d8b780d4f99a13186f69a7f332d8b"
    },
    "actual_import_targets": {
        "tools/hia_core_emitter_policy.py": [
            [
                "hia_machine_plan",
                [
                    "code_options"
                ]
            ],
            [
                "hia_native_byte_abi",
                [
                    "emit_wrapper"
                ]
            ]
        ],
        "tools/hia_byte_wrapper_policy.py": [
            [
                "hia_program",
                [
                    "SCALARS"
                ]
            ],
            [
                "hia_program_native",
                [
                    "IMPORTS",
                    "_LOADER_HOOKS",
                    "_reject"
                ]
            ],
            [
                "hia_program_native",
                [
                    "MAX_FRAME_BYTES",
                    "_ARG_REGS",
                    "_normalize",
                    "_prologue",
                    "_reject"
                ]
            ]
        ]
    }
}


def _literal_assignments(tree):
    result = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                result[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                pass
    return result


def _unique_names(values, label):
    if (type(values) is not tuple
            or any(type(value) is not str or not value.endswith(".py")
                   or Path(value).name != value for value in values)
            or len(values) != len(set(values))):
        raise ValueError("checker inventory requires unique repository module names: " + label)
    return values


def validate_host_import_templates(root):
    path = root / "hepta/hia_host_import.py"
    raw = path.read_bytes()
    if sha256(raw).hexdigest() != REVIEWED_IMPORTS["template_source_sha256"]:
        raise ValueError("reviewed host import adapter bytes changed")
    tree = ast.parse(raw, filename=str(path))
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    for name, source in REVIEWED_IMPORTS["templates"].items():
        expected = ast.parse(source).body[0]
        if name not in functions or ast.dump(functions[name], include_attributes=False) != ast.dump(expected, include_attributes=False):
            raise ValueError("host import template AST differs: " + name)
    # Full adapter bytes bind the existing co_names/co_varnames/co_consts
    # guards and code.replace/FunctionType construction; no generic AST edge
    # exemption is inferred from a name beginning with an underscore.
    for name in ("member_importer", "members_importer"):
        node = functions.get(name)
        if node is None:
            raise ValueError("reviewed host import binding mechanism is missing")
        replacements = [call for call in ast.walk(node) if isinstance(call, ast.Call)
                        and isinstance(call.func, ast.Attribute) and call.func.attr == "replace"]
        if len(replacements) != 1 or {keyword.arg for keyword in replacements[0].keywords} != {
                "co_names", "co_varnames", "co_consts"}:
            raise ValueError("reviewed host import binding mechanism changed")
    targets = []
    for relative, expected_hash in REVIEWED_IMPORTS["authoring_files"].items():
        data = (root / relative).read_bytes()
        if sha256(data).hexdigest() != expected_hash:
            raise ValueError("reviewed bounded import author changed: " + relative)
        if relative in REVIEWED_IMPORTS["actual_import_targets"]:
            observed = [(node.module, tuple(alias.name for alias in node.names))
                        for node in ast.walk(ast.parse(data))
                        if isinstance(node, ast.ImportFrom) and node.level]
            expected = [(module, tuple(names)) for module, names in
                        REVIEWED_IMPORTS["actual_import_targets"][relative]]
            if observed != expected:
                raise ValueError("reviewed actual import target inventory changed")
            for module, names in expected:
                target = module + ".py"
                if not (root / "hepta" / target).is_file():
                    raise ValueError("reviewed import target is missing: " + target)
                targets.append((relative, target, names))
    return tuple(targets)


def _imports(raw, filename):
    tree = ast.parse(raw, filename=filename)
    found, external = [], []
    class Visit(ast.NodeVisitor):
        def __init__(self):
            self.scope = []
        def _body(self, node):
            self.scope.append(node.name)
            self.generic_visit(node)
            self.scope.pop()
        visit_FunctionDef = _body
        visit_AsyncFunctionDef = _body
        visit_ClassDef = _body
        def visit_ImportFrom(self, node):
            aliases = tuple(alias.name for alias in node.names)
            if node.level or node.module == "hepta" or (node.module or "").startswith("hepta."):
                found.append((node.level, node.module, aliases,
                              ".".join(self.scope), node.lineno))
            else:
                external.append((filename, ".".join(self.scope), "from", node.module or "", aliases))
            self.generic_visit(node)
        def visit_Import(self, node):
            for alias in node.names:
                if alias.name == "hepta" or alias.name.startswith("hepta."):
                    found.append((0, alias.name, (), ".".join(self.scope), node.lineno))
                else:
                    external.append((filename, ".".join(self.scope), "import", alias.name, ()))
            self.generic_visit(node)
    Visit().visit(tree)
    return tree, tuple(found), tuple(external)


# These are separate physical-provider boundaries, not ambient checker-owner
# admissions. Helper table registrations are validated from their actual AST.
# No provider dictionary or serialized observation is an executable capability.
EXTERNAL_SELECTOR_ROLES = {
    "HEPTA_HIA_WORKER_REPORT_MANIFEST": "worker-report-wire-protocol",
    "HEPTA_HIA_JSON_WIRE_MANIFEST": "bounded-json-wire-provider",
    "HEPTA_HIA_AGENT_ARTIFACT_STORE_MANIFEST": "artifact-namespace-legacy-alias",
    "HEPTA_HIA_ARTIFACT_PUBLICATION_MANIFEST": "artifact-publication-provider",
}


def selector_declarations(root, checker_declarations):
    helper_path = Path(root) / "hepta/hia_native_helpers.py"
    helper_declarations = _literal_assignments(ast.parse(helper_path.read_bytes()))
    helpers = helper_declarations["HELPERS"]
    if type(helpers) is not dict:
        raise ValueError("native helper declarations are not a fixed map")
    roles = dict(EXTERNAL_SELECTOR_ROLES)
    for key, target in helpers.items():
        if (type(key) is not str or not key.startswith("HEPTA_HIA_")
                or not key.endswith("_MANIFEST")
                or type(target) is not tuple or len(target) != 2
                or any(type(part) is not str or not part.isidentifier() for part in target)):
            raise ValueError("native helper provider declaration differs")
        roles[key] = "physical-helper-provider"
    native = checker_declarations["NATIVE_OWNERS"]
    held = checker_declarations["HELD_NATIVE_OWNERS"]
    if set(native) & set(held):
        raise ValueError("held semantic owners overlap ambient semantic owners")
    roles.update({key: "semantic-checker-owner" for key in native})
    roles.update({key: "held-semantic-checker-owner" for key in held})
    return roles



def registry_targets(root, checker_declarations):
    """Expand only the reviewed literal registries consumed by real loaders."""
    rows = []
    for field in ("NATIVE_OWNERS", "HELD_NATIVE_OWNERS", "CAPTURED_NATIVE_OWNERS"):
        for selector, record in checker_declarations[field].items():
            indexes = (0, 2) if field == "CAPTURED_NATIVE_OWNERS" else (0,)
            for index in indexes:
                rows.append(("hia_checker_identity.py", field, record[index] + ".py",
                             (selector, record[index + 1])))
    helper = _literal_assignments(ast.parse((Path(root) / "hepta/hia_native_helpers.py").read_bytes()))
    for selector, record in helper["HELPERS"].items():
        rows.append(("hia_native_helpers.py", "HELPERS", record[0] + ".py", (selector, record[1])))
    for selector, views in helper["FACTORY_VIEWS"].items():
        if type(views) is not tuple:
            raise ValueError("native helper factory-view inventory differs")
        for record in views:
            if type(record) is not tuple or len(record) != 2:
                raise ValueError("native helper factory view differs")
            rows.append(("hia_native_helpers.py", "FACTORY_VIEWS", record[0] + ".py",
                         (selector, record[1])))
    bundles = _literal_assignments(ast.parse(
        (Path(root) / "hepta/hia_checker_bundle_identity.py").read_bytes()))["BUNDLE_NATIVE_OWNERS"]
    for selector, record in bundles.items():
        if type(record) is not tuple or len(record) != 5:
            raise ValueError("checker bundle registry differs")
        for index in (0, 3):
            rows.append(("hia_checker_bundle_identity.py", "BUNDLE_NATIVE_OWNERS",
                         record[index] + ".py", (selector, record[index + 1])))
    workers = _literal_assignments(ast.parse(
        (Path(root) / "hepta/hia_worker_scheduling_bundle.py").read_bytes()))["FAMILIES"]
    for family, record in workers.items():
        if type(record) is not tuple or len(record) != 2:
            raise ValueError("worker scheduling family registry differs")
        rows.append(("hia_worker_scheduling_bundle.py", "FAMILIES",
                     "hia_" + record[0] + "_selection.py", (family,)))
        rows.append(("hia_worker_scheduling_bundle.py", "FAMILIES",
                     record[1] + ".py", (family,)))
    family_tree = ast.parse((Path(root) / "hepta/hia_backend_family_selection.py").read_bytes())
    routes = []
    for node in family_tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id == "_FamilySelection"):
            name = node.targets[0].id
            args = node.value.args
            if (len(args) != 7 or any(not isinstance(arg, ast.Constant)
                                      or type(arg.value) is not str for arg in args)):
                raise ValueError("backend family literal route requires review")
            routes.append(name)
            for index in (1, 2):
                rows.append(("hia_backend_family_selection.py", name,
                             args[index].value + ".py", (args[index+2].value,)))
    if routes != ["lowering_family", "emitter_family", "plan_family", "elf_family"]:
        raise ValueError("backend family route inventory differs")
    continuation_tree = ast.parse((Path(root) / "hepta/hia_native_continuation_selection.py").read_bytes())
    tables = [node.value for node in continuation_tree.body if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == "_FAMILIES" for target in node.targets)]
    if len(tables) != 1 or not isinstance(tables[0], ast.Dict):
        raise ValueError("continuation family registry differs")
    stems = {}
    for key, value in zip(tables[0].keys, tables[0].values):
        if (not isinstance(key, ast.Constant) or type(key.value) is not str
                or not isinstance(value, ast.Tuple) or len(value.elts) != 2
                or not isinstance(value.elts[0], ast.Constant)
                or type(value.elts[0].value) is not str
                or not isinstance(value.elts[1], ast.Name)
                or key.value in stems):
            raise ValueError("continuation family row requires review")
        stems[key.value] = value.elts[0].value
        rows.append(("hia_native_continuation_selection.py", "_FAMILIES",
                     "hia_" + value.elts[0].value + "_selection.py",
                     (key.value, value.elts[1].id)))
    if stems != {key: value[0] for key, value in workers.items()}:
        raise ValueError("worker and public continuation families differ")
    for source, field, target, _ in rows:
        if Path(target).name != target or not (Path(root) / "hepta" / target).is_file():
            raise ValueError("literal registry target is missing: " + source + ":" + field + ":" + target)
    return tuple(rows)



# Exact syntax and enclosing scope of the finite registry import mechanisms.
# Their possible module values are expanded by registry_targets. A new generic
# import call is a review failure, not permission to leave a target unbound.
REVIEWED_REGISTRY_IMPORT_CALLS = {
    "hia_checker_identity.py": {
        "_held_native_identity": [
            "importlib.import_module(\".\" + module_name, __package__)"
        ],
        "_capture_selected_owners": [
            "importlib.import_module(\".\" + record[0], __package__)"
        ],
        "checker_native_selection": [
            "importlib.import_module(\".\" + module_name, __package__)"
        ]
    },
    "hia_checker_bundle_identity.py": {
        "_module": [
            "importlib.import_module(\".\" + name, __package__)"
        ]
    },
    "hia_native_helpers.py": {
        "NativeHelpersBinding.__init__": [
            "importlib.import_module(\".\" + module_name, __package__)",
            "importlib.import_module(\".\" + view_module_name, __package__)"
        ]
    },
    "hia_worker_scheduling_bundle.py": {
        "NativeWorkerSchedulingBinding.__init__": [
            "import_module('.' + FAMILIES[kind][1], __package__)"
        ],
        "NativeWorkerSchedulingBinding.capture_base": [
            "import_module('.' + authority.HELPERS[selector][0], __package__)"
        ],
        "NativeWorkerSchedulingBinding.capture_scheduler": [
            "import_module('.hia_' + FAMILIES[kind][0] + '_selection', __package__)"
        ]
    },
    "hia_native_continuation_selection.py": {
        "installed_native_continuation": [
            "import_module('.hia_'+module_name+'_selection',__package__)"
        ]
    },
    "hia_backend_family_selection.py": {
        "_FamilySelection._modules": [
            "importlib.import_module(\".\" + self.bundle_module, __package__)",
            "importlib.import_module(\".\" + self.control_module, __package__)"
        ]
    }
}


# These three retained proof/validation consumers import the same literal hosted solver.
# It is not a repository registry target or an HIA semantic capability. Keep
# the exact source scope and Call AST, and record the actual literal provider.
REVIEWED_EXTERNAL_IMPORT_CALLS = {
    "hia_proof_contract.py": {
        "_safe_core_method_reference": (
            'importlib.import_module("z3")',
        ),
    },
    "hia_safe_core.py": {
        "validate_safe_core_artifact": (
            'importlib.import_module("z3")',
        ),
    },
    "hia_translation_validation.py": {
        "_z3_module": (
            'importlib.import_module("z3")',
        ),
    },
}


def _dynamic_imports(tree, filename):
    observed = []
    class Visit(ast.NodeVisitor):
        def __init__(self):
            self.scope = []
        def _body(self, node):
            self.scope.append(node.name)
            self.generic_visit(node)
            self.scope.pop()
        visit_FunctionDef = _body
        visit_AsyncFunctionDef = _body
        visit_ClassDef = _body
        def visit_Call(self, node):
            called = node.func
            name = called.id if isinstance(called, ast.Name) else (
                called.attr if isinstance(called, ast.Attribute) else "")
            if name in ("import_module", "__import__"):
                scope = ".".join(self.scope)
                shape = ast.dump(node, include_attributes=False)
                allowed = REVIEWED_REGISTRY_IMPORT_CALLS.get(filename, {}).get(scope, ())
                expected = {ast.dump(ast.parse(value, mode="eval").body, include_attributes=False)
                            for value in allowed}
                if shape in expected:
                    role = "finite-reviewed-registry"
                else:
                    external_calls = REVIEWED_EXTERNAL_IMPORT_CALLS.get(filename, {}).get(scope, ())
                    external_shapes = {ast.dump(ast.parse(value, mode="eval").body,
                                                include_attributes=False)
                                       for value in external_calls}
                    if shape not in external_shapes:
                        raise ValueError("unreviewed dynamic import mechanism: " + filename + ":" + scope)
                    if (not isinstance(called, ast.Attribute)
                            or not isinstance(called.value, ast.Name)
                            or called.value.id != "importlib" or called.attr != "import_module"
                            or len(node.args) != 1 or node.keywords
                            or not isinstance(node.args[0], ast.Constant)
                            or type(node.args[0].value) is not str
                            or not node.args[0].value.isidentifier()):
                        raise ValueError("reviewed external import is not one literal hosted provider")
                    role = "hosted-literal-provider:" + node.args[0].value
                observed.append((filename, scope, shape, role))
            self.generic_visit(node)
    Visit().visit(tree)
    return tuple(observed)

def _selector_occurrences(tree, source_name):
    rows = []
    class Visit(ast.NodeVisitor):
        def __init__(self):
            self.scope = []
        def _body(self, node):
            self.scope.append(node.name)
            self.generic_visit(node)
            self.scope.pop()
        visit_FunctionDef = _body
        visit_AsyncFunctionDef = _body
        visit_ClassDef = _body
        def visit_Assign(self, node):
            names = [target.id for target in node.targets if isinstance(target, ast.Name)]
            # The generated inventory contains records of these literals.
            # Its data must not recursively count itself as an executable site.
            if source_name == "hia_checker_identity.py" and any(name in (
                    "CORE_SOURCE_FILES", "CHECKER_IMPORT_EDGES",
                    "CHECKER_SOURCE_ROLES", "CHECKER_SELECTOR_OCCURRENCES",
                    "CHECKER_SELECTOR_ROLES", "CHECKER_EXTERNAL_IMPORTS",
                    "CHECKER_DYNAMIC_IMPORTS") for name in names):
                return
            self.generic_visit(node)
        def visit_Constant(self, node):
            if (type(node.value) is str and node.value.startswith("HEPTA_HIA_")
                    and node.value.endswith("_MANIFEST")):
                rows.append((source_name, ".".join(self.scope), node.value))
    Visit().visit(tree)
    return rows


def checked_inventory(root=ROOT):
    root = Path(root)
    checker = root / "hepta/hia_checker_identity.py"
    declarations = _literal_assignments(ast.parse(checker.read_bytes()))
    semantic = _unique_names(declarations["SEMANTIC_CORE_SOURCE_FILES"], "semantic")
    mechanisms = _unique_names(declarations["MECHANISM_SOURCE_FILES"], "mechanisms")
    actual_targets = validate_host_import_templates(root)
    selector_roles = selector_declarations(root, declarations)
    registry = registry_targets(root, declarations)
    # Mechanism role names remain intact. Their physical dependencies are
    # covered by the same full closure, not exempted because of that role.
    pending = set(semantic) | set(mechanisms)
    for selector, record in declarations["NATIVE_OWNERS"].items():
        if type(record) is not tuple or len(record) != 2:
            raise ValueError("native checker declaration differs")
        pending.add(record[0] + ".py")
    for selector, record in declarations["HELD_NATIVE_OWNERS"].items():
        if type(record) is not tuple or len(record) != 2:
            raise ValueError("held checker declaration differs")
        pending.add(record[0] + ".py")
    for selector, record in declarations["CAPTURED_NATIVE_OWNERS"].items():
        if type(record) is not tuple or len(record) != 4:
            raise ValueError("captured checker declaration differs")
        pending.update((record[0] + ".py", record[2] + ".py"))
    pending.update(target for _author, target, _names in actual_targets)
    pending.update(target for _source, _field, target, _aliases in registry)
    names, edges, details, sources, selectors, external, dynamic = set(), [], [], {}, [], [], []
    while pending:
        name = min(pending)
        pending.remove(name)
        if name in names:
            continue
        path = root / "hepta" / name
        if Path(name).name != name or not path.is_file():
            raise ValueError("checker physical dependency is missing or not a flat module: " + name)
        raw = path.read_bytes()
        sources[name] = sha256(raw).hexdigest()
        tree, imports, outside = _imports(raw, name)
        external.extend(outside)
        actual_dynamic = _dynamic_imports(tree, name)
        dynamic.extend(actual_dynamic)
        for source, scope, _shape, role in actual_dynamic:
            if role.startswith("hosted-literal-provider:"):
                external.append((source, scope, "dynamic", role.split(":", 1)[1], ()))
        occurrences = _selector_occurrences(tree, name)
        for _source, _scope, key in occurrences:
            if key not in selector_roles:
                raise ValueError("unreviewed checker dependency selector: " + key + " in " + name)
        selectors.extend(occurrences)
        names.add(name)
        for level, module, aliases, scope, line in imports:
            original_module = module
            if level == 0:
                if module == "hepta":
                    module = None if aliases else "__init__"
                elif module.startswith("hepta."):
                    module = module[len("hepta."):]
                else:
                    raise ValueError("unclassified absolute repository import")
            elif level != 1:
                raise ValueError("checker relative import depth requires review: " + name)
            if module == "_module":
                if name != "hia_host_import.py" or scope not in REVIEWED_IMPORTS["templates"]:
                    raise ValueError("unreviewed synthetic import edge")
                targets = [("_module", "reviewed-opcode-template")]
            elif module is None:
                targets = []
                for alias in aliases:
                    target = alias + ".py"
                    if not (root / "hepta" / target).is_file():
                        raise ValueError("checker package attribute import requires explicit review: " + name + ":" + alias)
                    targets.append((target, "custody"))
            else:
                target = module + ".py"
                targets = [(target, "public-VM-runtime" if target == "hia_program_runtime.py" else "custody")]
            for target, role in targets:
                edge = (name, scope, level, original_module or "", aliases, target, role)
                edges.append(edge)
                details.append({"source": name, "scope": scope, "line": line,
                                "target": target, "role": role})
                if role == "custody" and target not in names:
                    pending.add(target)
    for author, target, aliases in actual_targets:
        if target not in names:
            raise ValueError("actual native import target escaped the complete closure")
        edges.append((author, "reviewed-native-import", 1, target[:-3], aliases, target, "bound-template-target"))
    for source, field, target, aliases in registry:
        if target not in names:
            raise ValueError("bound registry target escaped source custody")
        edges.append((source, field, 0, target[:-3], aliases, target, "registry-bound-target"))
    # Duplicates remain counted: removing one of two real imports changes the
    # inventory even if the target set itself happens to remain unchanged.
    ordered_edges = tuple(sorted(edges))
    roles = {name: tuple(role for role, inventory in (
        ("semantic-core", semantic), ("semantic-mechanism", mechanisms))
        if name in inventory) or ("custody-dependency",) for name in sorted(names)}
    return {"names": tuple(sorted(names)), "edges": ordered_edges,
            "semantic_core": semantic, "semantic_mechanisms": mechanisms,
            "roles": roles, "sources": sources, "details": details,
            "external_imports": tuple(sorted(external)),
            "dynamic_imports": tuple(sorted(dynamic)),
            "selector_roles": selector_roles,
            "selector_occurrences": tuple(sorted(selectors)),
            "actual_template_targets": actual_targets, "registry_targets": registry,
            "template_source_sha256": REVIEWED_IMPORTS["template_source_sha256"]}


def generated_block(inventory):
    return (BEGIN + "\nCHECKER_CUSTODY_GENERATED = True\nCORE_SOURCE_FILES = " +
            pprint.pformat(inventory["names"], width=100, sort_dicts=False) +
            "\nCHECKER_IMPORT_EDGES = " +
            pprint.pformat(inventory["edges"], width=100, sort_dicts=False) +
            "\nCHECKER_SOURCE_ROLES = " +
            pprint.pformat(inventory["roles"], width=100, sort_dicts=False) +
            "\nCHECKER_DYNAMIC_IMPORTS = " +
            pprint.pformat(inventory["dynamic_imports"], width=100, sort_dicts=False) +
            "\nCHECKER_EXTERNAL_IMPORTS = " +
            pprint.pformat(inventory["external_imports"], width=100, sort_dicts=False) +
            "\nCHECKER_SELECTOR_ROLES = " +
            pprint.pformat(inventory["selector_roles"], width=100, sort_dicts=True) +
            "\nCHECKER_SELECTOR_OCCURRENCES = " +
            pprint.pformat(inventory["selector_occurrences"], width=100, sort_dicts=False) +
            "\n" + END)


def replace_block(source, replacement):
    if source.count(BEGIN) != 1 or source.count(END) != 1:
        raise ValueError("checker generated custody boundaries differ")
    first, last = source.index(BEGIN), source.index(END) + len(END)
    return source[:first] + replacement + source[last:]


def check(root=ROOT):
    root = Path(root)
    inventory = checked_inventory(root)
    path = root / "hepta/hia_checker_identity.py"
    original = path.read_text()
    expected = replace_block(original, generated_block(inventory))
    if original != expected:
        raise ValueError("checker source custody inventory is stale")
    return inventory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    inventory = checked_inventory(args.root)
    path = args.root / "hepta/hia_checker_identity.py"
    original = path.read_text()
    expected = replace_block(original, generated_block(inventory))
    if args.check:
        if original != expected:
            raise SystemExit("checker source custody inventory is stale")
    else:
        path.write_text(expected)
        # Report the actual post-generation source bytes, including this file.
        inventory = check(args.root)
    if args.report:
        args.report.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"files": len(inventory["names"]), "edges": len(inventory["edges"]),
                      "semantic_core": len(inventory["semantic_core"]),
                      "mechanism_roles": len(inventory["semantic_mechanisms"]),
                      "native_qualification": False}, sort_keys=True))


if __name__ == "__main__":
    main()
