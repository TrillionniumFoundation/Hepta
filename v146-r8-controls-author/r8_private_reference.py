"""Test-only exact R8 reference; no public profile admission or native authority."""
__package__ = 'hepta'
from hashlib import sha256
from hepta.hia_linux_file_roundtrip import (
    HIAProgramRejected, LinuxStartupSnapshot, verify_linux_file_roundtrip_program,
    _checked_startup, _execute, FILE_BUFFER_LIMIT, OUTPUT_LIMIT, WORKSPACE_LIMIT,
)
PROFILE = 'hepta.test-only.u32-r8-roundtrip-reference.v1'
COMPONENT_PINS = {'linux.roundtrip.representation': 'cca0b52ca56a84782fd4ac41f5fbed56c64ebaf8c29ce60885d23b11920cb886',
                  'linux.roundtrip.semantic': '83953e66677fa0cd7f63f3b1742276d954537df71487c3cd4a6eef9486e3e4de'}

def _checked_components(values):
    from .hia_agent_assembly import assemble_program
    if type(values) is not tuple or len(values) != 2:
        raise HIAProgramRejected("exact two frozen HIA component sources required", "E_HIA_LINUX_FILE_ROUNDTRIP_COMPONENT")
    result = {}
    for (name, expected), raw in zip(COMPONENT_PINS.items(), values):
        if type(raw) is not bytes or sha256(raw).hexdigest() != expected:
            raise HIAProgramRejected("frozen component source mismatch", "E_HIA_LINUX_FILE_ROUNDTRIP_COMPONENT")
        result[name] = assemble_program(raw)
    return result


def execute_linux_file_roundtrip(program, function, arguments, *, provider, startup, components,
                        max_steps=1000000, max_heap_bytes=16 * 1024 * 1024,
                        allocation_fail_at=None, max_call_depth=256):
    checked = verify_linux_file_roundtrip_program(program)
    startup = _checked_startup(startup)
    components = _checked_components(components)
    if (type(function) is not str or function != "f0"
            or type(arguments) not in (list, tuple) or not callable(provider)
            or type(max_steps) is not int or not 1 <= max_steps <= 10000000
            or type(max_heap_bytes) is not int or not 0 <= max_heap_bytes <= 1024 * 1024 * 1024
            or type(max_call_depth) is not int or not 1 <= max_call_depth <= 256
            or allocation_fail_at is not None
               and (type(allocation_fail_at) is not int or allocation_fail_at < 1)):
        raise HIAProgramRejected("invalid profile boundary/provider/limits", "E_HIA_INPUT")
    buffers = tuple(arguments)
    if len(buffers) != 3 or any(type(raw) is not bytes or len(raw) > limit
            for raw, limit in zip(buffers, (FILE_BUFFER_LIMIT, OUTPUT_LIMIT, WORKSPACE_LIMIT))):
        raise HIAProgramRejected("exact file borrow <=8 MiB+1 and output/workspace <=1 MiB required",
                                 "E_HIA_LINUX_FILE_ROUNDTRIP_ABI")
    return _execute(checked, function, buffers, provider, startup, components, max_steps=max_steps,
        max_heap_bytes=max_heap_bytes, allocation_fail_at=allocation_fail_at,
        max_call_depth=max_call_depth)


def execute_program(program, function, arguments, *, max_steps=1_000_000,
                    max_heap_bytes=16 * 1024 * 1024, allocation_fail_at=None,
                    max_call_depth=256, bounded_resource_limits=None,
                    profile=None, linux_stdio_provider=None,
                    linux_process_startup=None, linux_process_provider=None, linux_cli_components=None,
                    linux_file_provider=None, linux_file_render_components=None,
                    linux_file_roundtrip_components=None):
    if linux_file_roundtrip_components is not None and not (
            type(profile) is str and profile == PROFILE):
        raise HIAProgramRejected('roundtrip components require their exact profile',
                                 'E_HIA_LINUX_FILE_ROUNDTRIP_PROFILE')
    if type(profile) is not str or profile != PROFILE:
        raise HIAProgramRejected('exact test-only R8 reference required',
                                 'E_HIA_LINUX_FILE_ROUNDTRIP_PROFILE')
    if (bounded_resource_limits is not None or linux_stdio_provider is not None
            or linux_process_provider is not None or linux_cli_components is not None
            or linux_file_render_components is not None):
        raise HIAProgramRejected('separate file-render authority required',
                                 'E_HIA_LINUX_FILE_RENDER_PROFILE')
    result = error = None
    try:
        result = execute_linux_file_roundtrip(program, function, arguments,
            provider=linux_file_provider, startup=linux_process_startup,
            components=linux_file_roundtrip_components, max_steps=max_steps,
            max_heap_bytes=max_heap_bytes, allocation_fail_at=allocation_fail_at,
            max_call_depth=max_call_depth)
        return result
    except BaseException as caught:
        error = caught
        raise
    finally:
        from r8_common import observe_private_vm
        observe_private_vm(arguments, result, error)
