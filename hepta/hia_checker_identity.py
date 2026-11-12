"""Identity of the Core checker and its explicitly selected native owners.

Source bytes alone cannot identify a checker which delegates to native images.
This module records both the reviewed Python dependency closure and the actual
immutable mappings returned by the existing native loaders. Some loaders
initialize their fixed table or transport emitter; identity capture does not
invoke a business-policy entry or treat a digest as a correctness theorem.
The host Python/loader and absence of hostile process mutation remain assumed.
"""
from __future__ import annotations

from hashlib import sha256
from dataclasses import dataclass
import importlib
import json
import os
from pathlib import Path


CORE_SOURCE_FILES = (
    'hia_front_continuation.py',
    'hia_front_runtime.py',
    'hia_front_selection.py',
    'hia_core_verification_native.py',
    'hia_core_verification_ports.py',
    'hia_core_verification_selection.py',
    'hia_exception_delivery.py',
    "hia_checker_identity.py", "hia_native_helpers.py", "hia_program.py", "hia_program_composite.py",
    "hia_capability_flow.py", "hia_opcodes.py", "hia_schema.py",
    "hia_json_preflight.py", "hia_json_decode.py", "hia_json_preflight_native.py",
    "hia_json_decode_native.py", "hia_json_canonical_native.py",
    "hia_sha256_native.py", "hia_sha256_stream_native.py",
    "hia_function_shape_native.py", "hia_program_shape_native.py",
    "hia_instruction_policy_native.py", "hia_core_admission_native.py",
    "hia_capability_renaming_native.py", "hia_composite_types_native.py",
    "hia_task_helpers_native.py", "hia_composite_functions_native.py",
    "hia_composite_functions_errors.py", "hia_composite_function_tokens.py",
    "hia_composite_constructor_native.py", "hia_composite_constructor_errors.py",
    "hia_composite_outer_native.py",
    "hia_native_value_graph.py", "hia_nominal_admission_native.py",
    "hia_nominal_function_native.py", "hia_nominal_module_native.py",
    "hia_nominal_terminators_native.py", "hia_call_primitive_native.py",
    "hia_record_transitions_native.py", "hia_record_operations_native.py",
    "hia_enum_operations_native.py", "hia_enum_match_native.py",
    "hia_task_operations_native.py", "hia_task_helper_cache_native.py",
    "hia_program_execution_native.py",
    "hia_static_budget.py", "hia_static_budget_native.py", "hia_heap_bound.py",
    "hia_heap_bound_native.py", "hia_heap_live_native.py", "hia_heap_payload_native.py",
    # Ordinary Core call erasure imports this fixed physical allocator.
    # Its Code qualname helper is conservatively covered by the same bytes;
    # no Code planning policy or native selector is introduced here.
    "hia_machine_transport.py",
)

# Backend and held-service object bridges remain separate from the pure Core
# import closure. They are still fresh inputs of every checker source identity.
MECHANISM_SOURCE_FILES = (
    'hia_agent_assembly.py',
    'hia_assembly_front_native.py',
    'hia_assembly_front_ports.py',
    'hia_assembly_front_selection.py',
    "hia_service_requests_native.py",
    "hia_service_requests_foreign.py",
    "hia_core_emitter_native.py",
    "hia_core_emitter_selection.py",
    "hia_core_lowering_native.py",
    "hia_core_lowering_selection.py",
    "hia_machine_plan.py",
    "hia_machine_plan_control_native.py",
    "hia_machine_plan_native.py",
    "hia_native_build_foreign.py",
    "hia_native_build_native.py",
    "hia_native_build_selection.py",
    "hia_native_byte_abi.py",
    "hia_native_byte_abi_native.py",
    "hia_native_byte_abi_foreign.py",
    "hia_native_byte_abi_selection.py",
    "hia_proof_contract_foreign.py",
    "hia_proof_contract_native.py",
    "hia_proof_contract_selection.py",
    "hia_service_verification_foreign.py",
    "hia_service_verification_native.py",
)

# The proof owner uses the same complete mechanism inventory. Provider edges
# name external semantic consumers; the original Core closure stays strict.
CHECKER_MECHANISM_SOURCE_FILES = MECHANISM_SOURCE_FILES
CHECKER_MECHANISM_EXTERNAL_PROVIDERS = {
    "hia_agent_assembly.py": ("hia_program_tools.py",),
    "hia_service_requests_native.py": ("hia_agent_service.py",),
    "hia_service_requests_foreign.py": (
        "hia_program_native.py", "hia_safe_core.py", "hia_agent_macro_discovery.py",
        "hia_program_tools.py", "hia_edit_query.py",
        "hia_agent_candidate_native.py"),
    "hia_core_emitter_native.py": ("hia_program_native.py",),
    "hia_core_emitter_selection.py": ("hia_program_native.py",),
    "hia_core_lowering_native.py": ("hia_program_native.py",),
    "hia_core_lowering_selection.py": ("hia_program_native.py",),
    "hia_native_build_foreign.py": ("hia_machine_elf.py", "hia_machine_x64.py",),
    "hia_native_build_native.py": ("hia_program_native.py",),
    "hia_native_build_selection.py": ("hia_program_native.py",),
    "hia_native_byte_abi.py": ("hia_program_native.py",),
    "hia_native_byte_abi_foreign.py": ("hia_program_native.py",),
    "hia_native_byte_abi_native.py": ("hia_program_native.py",),
    "hia_proof_contract_foreign.py": ("hia_safe_core.py",),
    "hia_proof_contract_native.py": ("hia_proof_contract.py",),
    "hia_service_verification_native.py": ("hia_agent_service.py", "hia_program_native.py", "hia_safe_core_elf.py",),
}

# Exact verifier and checked-replay selectors. Finite-context checks also execute
# the public VM; binding only its Python caller would omit a selected HIA image.
# New semantic delegations must extend this inventory before proof qualification.
NATIVE_OWNERS = {
    'HEPTA_HIA_CORE_VERIFICATION_MANIFEST': ('hia_core_verification_selection', 'installed_core_verification'),
    'HEPTA_HIA_ASSEMBLY_FRONT_MANIFEST': ('hia_assembly_front_selection', 'installed_assembly_front'),
    "HEPTA_HIA_NATIVE_BUILD_MANIFEST": ("hia_native_build_selection", "installed_native_build"),
    "HEPTA_HIA_NATIVE_BYTE_ABI_MANIFEST": ("hia_native_byte_abi_selection", "installed_native_byte_abi"),
    "HEPTA_HIA_CORE_EMITTER_MANIFEST": ("hia_core_emitter_selection", "installed_core_emitter"),
    "HEPTA_HIA_MACHINE_PLAN_MANIFEST": ("hia_machine_plan_native", "installed_machine_plan"),
    "HEPTA_HIA_CORE_LOWERING_MANIFEST": ("hia_core_lowering_selection", "installed_core_lowering"),
    "HEPTA_HIA_PROGRAM_EXECUTION_MANIFEST": ("hia_program_execution_native", "installed_program_execution"),
    "HEPTA_HIA_STATIC_BUDGET_MANIFEST": ("hia_static_budget_native", "installed_static_budget"),
    "HEPTA_HIA_HEAP_BOUND_MANIFEST": ("hia_heap_bound_native", "installed_heap_controller"),
    "HEPTA_HIA_HEAP_LIVE_ENGINE_MANIFEST": ("hia_heap_live_native", "installed_heap_live"),
    "HEPTA_HIA_HEAP_PAYLOAD_MANIFEST": ("hia_heap_payload_native", "installed_heap_payload"),
    "HEPTA_HIA_JSON_PREFLIGHT_MANIFEST": ("hia_json_preflight_native", "installed_preflight"),
    "HEPTA_HIA_JSON_DECODE_MANIFEST": ("hia_json_decode_native", "installed_decoder"),
    "HEPTA_HIA_JSON_CANONICAL_MANIFEST": ("hia_json_canonical_native", "installed_canonicalizer"),
    "HEPTA_HIA_SHA256_MANIFEST": ("hia_sha256_native", "installed_hasher"),
    "HEPTA_HIA_SHA256_STREAM_MANIFEST": ("hia_sha256_stream_native", "installed_stream_hasher"),
    "HEPTA_HIA_CAPABILITY_RENAMING_MANIFEST": ("hia_capability_renaming_native", "installed_capability_renaming"),
    "HEPTA_HIA_FUNCTION_SHAPE_MANIFEST": ("hia_function_shape_native", "installed_function_shape"),
    "HEPTA_HIA_PROGRAM_SHAPE_MANIFEST": ("hia_program_shape_native", "installed_program_shape"),
    "HEPTA_HIA_INSTRUCTION_POLICY_MANIFEST": ("hia_instruction_policy_native", "installed_instruction_policy"),
    "HEPTA_HIA_CORE_ADMISSION_MANIFEST": ("hia_core_admission_native", "installed_core_admission"),
    "HEPTA_HIA_COMPOSITE_TYPES_MANIFEST": ("hia_composite_types_native", "installed_composite_types"),
    "HEPTA_HIA_TASK_HELPERS_MANIFEST": ("hia_task_helpers_native", "installed_task_helpers"),
    "HEPTA_HIA_COMPOSITE_FUNCTIONS_MANIFEST": ("hia_composite_functions_native", "installed_composite_functions"),
    "HEPTA_HIA_COMPOSITE_CONSTRUCTOR_MANIFEST": ("hia_composite_constructor_native", "installed_composite_constructor"),
    "HEPTA_HIA_COMPOSITE_OUTER_MANIFEST": ("hia_composite_outer_native", "installed_composite_outer"),
    "HEPTA_HIA_NOMINAL_ADMISSION_MANIFEST": ("hia_nominal_admission_native", "installed_nominal_admission"),
    "HEPTA_HIA_NOMINAL_FUNCTION_MANIFEST": ("hia_nominal_function_native", "installed_nominal_function"),
    "HEPTA_HIA_NOMINAL_MODULE_MANIFEST": ("hia_nominal_module_native", "installed_nominal_module"),
    "HEPTA_HIA_NOMINAL_TERMINATORS_MANIFEST": ("hia_nominal_terminators_native", "installed_nominal_terminators"),
    "HEPTA_HIA_CALL_PRIMITIVE_MANIFEST": ("hia_call_primitive_native", "installed_call_primitive"),
    "HEPTA_HIA_RECORD_TRANSITIONS_MANIFEST": ("hia_record_transitions_native", "installed_record_transitions"),
    "HEPTA_HIA_RECORD_OPERATIONS_MANIFEST": ("hia_record_operations_native", "installed_record_operations"),
    "HEPTA_HIA_ENUM_OPERATIONS_MANIFEST": ("hia_enum_operations_native", "installed_enum_operations"),
    "HEPTA_HIA_ENUM_MATCH_MANIFEST": ("hia_enum_match_native", "installed_enum_match"),
    "HEPTA_HIA_TASK_OPERATIONS_MANIFEST": ("hia_task_operations_native", "installed_task_operations"),
    "HEPTA_HIA_TASK_HELPER_CACHE_MANIFEST": ("hia_task_helper_cache_native", "installed_task_helper_cache"),
}

# These owners belong to a service which already admitted and retained its
# executable. They are not ambient Core-checker selectors: reading their
# current environment path would name different code after a selector change.
# A proof caller must explicitly supply its held capability. The default Core
# checker selection, including all ordinary callers, remains unchanged.
HELD_NATIVE_OWNERS = {
    "HEPTA_HIA_SERVICE_REQUESTS_MANIFEST": ("hia_service_requests_native", "NativeRequestsImage"),
    "HEPTA_HIA_PROOF_CONTRACT_MANIFEST": ("hia_proof_contract_native", "NativeProofContractImage"),
    "HEPTA_HIA_SERVICE_VERIFICATION_MANIFEST": ("hia_service_verification_native", "NativeVerificationImage"),
    "HEPTA_HIA_SERVICE_EMISSION_MANIFEST": ("hia_service_emission_native", "NativeEmissionImage"),
    "HEPTA_HIA_SERVICE_CONTEXT_MANIFEST": ("hia_service_context_native", "NativeContextImage"),
}

# Backend rederivation captures an ordinary selection for the duration of its
# emit, including an explicit absence. Its identity must name the mapping
# actually used in that scope, while later independent consumers re-admit the
# then-current ambient selector. These hooks return only admitted capabilities;
# serialized evidence cannot choose or override one.
CAPTURED_NATIVE_OWNERS = {
    'HEPTA_HIA_CORE_VERIFICATION_MANIFEST': ('hia_core_verification_selection', 'captured_checker_owner', 'hia_core_verification_native', 'NativeCoreVerification'),
    'HEPTA_HIA_ASSEMBLY_FRONT_MANIFEST': ('hia_assembly_front_selection', 'captured_checker_owner', 'hia_assembly_front_native', 'NativeAssemblyFront'),
    "HEPTA_HIA_NATIVE_BUILD_MANIFEST": (
        "hia_native_build_selection", "captured_checker_owner",
        "hia_native_build_native", "NativeBuild"),
    "HEPTA_HIA_NATIVE_BYTE_ABI_MANIFEST": (
        "hia_native_byte_abi_selection", "captured_checker_owner",
        "hia_native_byte_abi_native", "NativeByteABI"),
    "HEPTA_HIA_CORE_EMITTER_MANIFEST": (
        "hia_core_emitter_selection", "captured_checker_owner",
        "hia_core_emitter_native", "NativeCoreEmitter"),
    "HEPTA_HIA_MACHINE_PLAN_MANIFEST": (
        "hia_machine_plan_native", "captured_checker_owner",
        "hia_machine_plan_control_native", "NativeMachinePlanControl"),
    "HEPTA_HIA_CORE_LOWERING_MANIFEST": (
        "hia_core_lowering_selection", "captured_checker_owner",
        "hia_core_lowering_native", "NativeCoreLowering"),
}


@dataclass(frozen=True, eq=False)
class HeldNativeOwner:
    """Actual immutable mapping and exact bytes from one admitted selection.

    This in-process capability is never reconstructed from proof evidence.
    Cached mappings can be shared by several independent admission records;
    their manifest/source bytes must not overwrite one another on the image.
    """
    selector: str
    image: object
    manifest: bytes
    source: bytes


def _held_manifest_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate held native manifest field")
        result[key] = value
    return result


def _held_native_identity(binding):
    if type(binding) is not HeldNativeOwner:
        raise ValueError("held checker owner requires its admitted in-process capability")
    if type(binding.selector) is not str:
        raise ValueError("held checker selector must be an exact string")
    if binding.selector in HELD_NATIVE_OWNERS:
        if binding.selector in NATIVE_OWNERS or binding.selector in CAPTURED_NATIVE_OWNERS:
            raise ValueError("service-held checker owner overlaps an ordinary selector")
        module_name, factory_name = HELD_NATIVE_OWNERS[binding.selector]
    elif binding.selector in CAPTURED_NATIVE_OWNERS:
        record = CAPTURED_NATIVE_OWNERS[binding.selector]
        if (binding.selector not in NATIVE_OWNERS or type(record) is not tuple
                or len(record) != 4 or any(type(part) is not str for part in record)):
            raise ValueError("captured checker type is outside its reviewed ordinary owner")
        module_name, factory_name = record[2:]
    else:
        raise ValueError("held checker owner is outside the explicit capability inventory")
    module = importlib.import_module("." + module_name, __package__)
    if type(binding.image) is not getattr(module, factory_name):
        raise ValueError("held checker mapping differs from its native owner type")
    if (type(binding.manifest) is not bytes or not 0 < len(binding.manifest) <= 16384
            or type(binding.source) is not bytes or not 0 < len(binding.source) <= 8 << 20):
        raise ValueError("held checker admission does not retain exact bounded input bytes")
    record = json.loads(binding.manifest, object_pairs_hook=_held_manifest_pairs)
    fields = {"schema", "source_sha256", "image_path", "image_sha256", "compiler_sha256"}
    if (type(record) is not dict or set(record) != fields or record["schema"] != module.SCHEMA
            or any(type(record[name]) is not str or len(record[name]) != 64
                   or any(char not in "0123456789abcdef" for char in record[name])
                   for name in ("source_sha256", "image_sha256", "compiler_sha256"))):
        raise ValueError("held checker manifest differs from its admitted schema")
    image_name = record["image_path"]
    if (type(image_name) is not str or not image_name or image_name in (".", "..")
            or any(ord(char) < 32 for char in image_name) or Path(image_name).name != image_name):
        raise ValueError("held checker image must have its admitted sibling basename")
    mapped = _mapped_identity(binding.image)
    source_sha256 = sha256(binding.source).hexdigest()
    if mapped["image_sha256"] != record["image_sha256"] or source_sha256 != record["source_sha256"]:
        raise ValueError("held checker bytes differ from their admitted identity")
    return {"manifest_sha256": sha256(binding.manifest).hexdigest(), "schema": record["schema"],
            "sources": {"image": source_sha256}, "images": {"image": mapped}, "child_manifests": {}}


def hold_native_owner(selector, image, manifest, source):
    """Retain one already-admitted mapping without rereading mutable paths."""
    binding = HeldNativeOwner(selector, image, manifest, source)
    _held_native_identity(binding)
    return binding


def checker_source_identity(extra_files=()):
    """Hash the same Core closure for each consumer, retaining its own inputs."""
    names = set(CORE_SOURCE_FILES) | set(MECHANISM_SOURCE_FILES) | set(extra_files)
    return {name: sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in sorted(names)}


def _manifest_bytes(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError("checker native manifest exceeds its fixed identity bound")
    return raw


def _mapped_identity(image):
    # A cached immutable image can intentionally survive replacement of its
    # backing file. Identify that loaded mapping, not whatever now occupies the
    # old pathname. The existing loader performs all schema and source checks.
    from .hia_json_preflight_native import NativeHiaJsonImage, MAX_IMAGE_BYTES
    if not isinstance(image, NativeHiaJsonImage):
        raise ValueError("checker owner did not return its native image")
    raw = image._mapping[:]
    if not 0 < len(raw) <= MAX_IMAGE_BYTES or sha256(raw).hexdigest() != image.image_sha256:
        raise ValueError("checker native mapping differs from its loaded identity")
    return {"image_sha256": image.image_sha256, "image_bytes": len(raw)}


def checker_native_selection(*, held_owners=()):
    """Bind each admitted verifier mapping without running a business-policy entry.

    Configured owners are conservatively bound even when a particular input
    does not visit them. No serialized receipt can select code for this call.
    """
    if type(held_owners) is not tuple:
        raise ValueError("held checker owners must be an explicit immutable capability tuple")
    captured = {}
    for key, record in CAPTURED_NATIVE_OWNERS.items():
        if (key not in NATIVE_OWNERS or key in HELD_NATIVE_OWNERS
                or type(record) is not tuple or len(record) != 4
                or any(type(part) is not str for part in record)):
            raise ValueError("captured checker hook is outside the reviewed owner inventory")
        module_name, hook_name = record[:2]
        module = importlib.import_module("." + module_name, __package__)
        observation = getattr(module, hook_name)()
        if (type(observation) is not tuple or len(observation) != 2
                or type(observation[0]) is not bool):
            raise ValueError("captured checker owner observation is malformed")
        if observation[0]:
            binding = observation[1]
            if binding is not None and (type(binding) is not HeldNativeOwner or binding.selector != key):
                raise ValueError("captured checker owner differs from its declared selector")
            captured[key] = None if binding is None else _held_native_identity(binding)
        elif observation[1] is not None:
            raise ValueError("uncaptured checker owner supplied a capability")
    selected = {key: os.environ.get(key) or None for key in sorted(NATIVE_OWNERS)}
    result = {}
    for key, path in selected.items():
        if key in captured:
            result[key] = captured[key]
            continue
        if path is None:
            result[key] = None
            continue
        module_name, loader_name = NATIVE_OWNERS[key]
        module = importlib.import_module("." + module_name, __package__)
        raw = _manifest_bytes(path)
        sources = ({"image": module.SOURCE} if hasattr(module, "SOURCE") else module.SOURCES)
        source_identity = {name: sha256(source.read_bytes()).hexdigest()
                           for name, source in sorted(sources.items())}
        children = {}
        if hasattr(module, "SOURCES"):
            value = json.loads(raw)
            children = {name: _manifest_bytes(Path(path).parent / component)
                        for name, component in sorted(value["kernels"].items())}
        owner = getattr(module, loader_name)(path)
        images = {"image": owner} if hasattr(owner, "_mapping") else owner.images
        if set(images) != set(sources):
            raise ValueError("checker native image/source inventory differs")
        image_identity = {name: _mapped_identity(image) for name, image in sorted(images.items())}
        # Bundle loading follows each separately validated child manifest.
        # Retain those exact bytes too; parent pathname text is not their identity.
        if hasattr(owner, "images"):
            if children != {name: _manifest_bytes(Path(path).parent / component)
                            for name, component in sorted(value["kernels"].items())}:
                raise ValueError("checker child manifest changed during identity capture")
        if (raw != _manifest_bytes(path)
                or source_identity != {name: sha256(source.read_bytes()).hexdigest()
                                       for name, source in sorted(sources.items())}):
            raise ValueError("checker native manifest/source changed during identity capture")
        result[key] = {"manifest_sha256": sha256(raw).hexdigest(), "schema": module.SCHEMA,
                       "sources": source_identity, "images": image_identity,
                       "child_manifests": {name: sha256(child).hexdigest()
                                           for name, child in children.items()}}
    if ({key: path for key, path in selected.items() if key not in captured}
            != {key: os.environ.get(key) or None for key in sorted(NATIVE_OWNERS) if key not in captured}):
        raise ValueError("checker native selection changed during identity capture")
    for binding in held_owners:
        identity = _held_native_identity(binding)
        if binding.selector in result:
            raise ValueError("held checker selection repeats or overrides an ambient owner")
        result[binding.selector] = identity
    return result


def checker_digest(extra_files=()):
    identity = {"source_identity": checker_source_identity(extra_files),
                "native_selection": checker_native_selection()}
    return sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
