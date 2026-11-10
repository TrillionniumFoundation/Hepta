"""Explicit standalone HIA input routes, with no source or migration adapter."""
from .hia_program import verify_program

class RouteRejected(ValueError):
    pass

def route_inventory():
    return {"schema":"hepta.hia.routes.v2", "inputs":["standalone-hia", "agent-assembly"],
            "authority":"hepta.hia_program.verify_program", "implicit_fallback_allowed":False,
            "versions": {
                "latest_core_schema": "hepta.hia.program.v8",
                "admitted_primitive_schemas": ["hepta.hia.program.v" + str(v) for v in range(1, 9)]},
            "optimization_profiles": [
                {"entry": "hepta.hia_optimization.verify_optimization",
                 "scope": "primitive v1-v7; compositional scalar rewrites with unchanged resource/CFG interfaces",
                 "v8_qualified": False},
                {"entry": "hepta.hia_translation_validation.validate_translation",
                 "scope": "primitive v1-v7; selected public scalar function, acyclic bit-vector/trap profile",
                 "v8_qualified": False}],
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
