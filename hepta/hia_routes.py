"""Explicit standalone HIA input routes, with no source or migration adapter."""
from .hia_program import verify_program
from .hia_schema import schema_registry

class RouteRejected(ValueError):
    pass

def route_inventory():
    # Discovery is a detached description, never admission or a proof receipt.
    # Core schema support and proof support have different domains. Removing a
    # source frontend must not erase the v8 admission / v1-v7 proof boundary.
    versions = schema_registry()
    versions.pop("legacy_nominal", None)
    versions["admitted_primitive_schemas"] = ["hepta.hia.program.v" + str(v) for v in range(1, 9)]
    latest = versions["latest_core_schema"].rsplit(".", 1)[-1]
    return {"schema":"hepta.hia.routes.v2", "inputs":[
                {"route":"standalone-hia", "input":"primitive v1-" + latest + " / composite v1-v4",
                 "adapter":"hepta.hia_program.verify_program", "admission":"supported",
                 "origin_required":False},
                {"route":"agent-assembly", "input":"hia-asm.v1 explicit primitive v6/v7/v8",
                 "adapter":"hepta.hia_agent_assembly.assemble_program", "admission":"supported",
                 "origin_required":False, "implicit_schema_guessing":False}],
            "versions":versions,
            "optimization_profiles":[
                {"checker":"hepta.hia_translation_validation.validate_translation",
                 "scope":"primitive v1-v7; selected public scalar function; acyclic values and first traps",
                 "selection":"explicit hosted API, not an installed CLI action",
                 "success":"proved", "other_outcomes":["disproved","unknown"],
                 "resource_or_call_rewrites":False, "receipt_grants_admission":False, "v8_qualified":False},
                {"checker":"hepta.hia_optimization.verify_optimization",
                 "scope":"primitive v1-v7; whole module; unchanged CFG, interfaces and ordered resource/call skeleton",
                 "selection":"explicit hosted API, not an installed CLI action",
                 "success":"verified", "other_outcomes":["rejected","unknown","timeout"],
                 "resource_or_call_rewrites":False, "receipt_grants_admission":False, "v8_qualified":False}],
            "authority":"hepta.hia_program.verify_program", "implicit_fallback_allowed":False,
            "backends":[
                {"backend":"direct-machine","entry":"hepta.hia_program_native.build_program_machine",
                 "same_standalone_core":True,"selection":"hia build --backend native; direct API",
                 "llvm_ir_used":False,"assembler_used":False,"fallback_used":False},
                {"backend":"direct-llvm","entry":"hepta.hia_program_llvm.build_program_native",
                 "same_standalone_core":True,"selection":"explicit reference/research tool only",
                 "agent_entry_allowed":False,"fallback_used":False},
                {"backend":"interpreter","entry":"hepta.hia_program_runtime.execute_program",
                 "same_standalone_core":True,"selection":"explicit reference/research tool only",
                 "agent_entry_allowed":False,"fallback_used":False}] }

def admit_route(route, payload, **context):
    if context:raise RouteRejected("E_HIA_ROUTE_CONTEXT: standalone inputs accept no source override")
    if route=="agent-assembly":
        from .hia_agent_assembly import assemble_program
        return verify_program(assemble_program(payload))
    if route=="standalone-hia":
        return verify_program(payload)
    raise RouteRejected("E_HIA_ROUTE_UNSUPPORTED: "+str(route))

def execute_route(route, payload, function, arguments, *, backend="interpreter", **limits):
    if backend!="interpreter":
        raise RouteRejected("E_HIA_ROUTE_BACKEND: no implicit fallback")
    from .hia_program_runtime import execute_program
    return execute_program(admit_route(route,payload),function,arguments,**limits)
