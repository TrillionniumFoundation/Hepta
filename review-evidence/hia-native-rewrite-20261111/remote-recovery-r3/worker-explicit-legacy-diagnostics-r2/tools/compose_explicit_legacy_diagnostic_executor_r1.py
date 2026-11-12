"""Separate fixed mechanical publication extension for explicit legacy diagnostics.

New development authoring only. The original R9 executor is retained byte-for-byte
apart from one reversible top-level semantic-output tail. No JSON, schema, enum,
message selection or child result interpretation is added to the executor.
"""
from __future__ import annotations
from hashlib import sha256

ORIGINAL_BYTES=23760
ORIGINAL_SHA256="9e94102fe9001493ca7bf175a9e97e066d4cb1e9f4d65239985f43a00f1eb22f"
ORIGINAL_GIT="abe604f05363765de915eec75207bf94b582a9f9"
BEFORE="""    jne semantic_write
    mov edi,2
    jmp terminate

abi_error:
"""
AFTER="""    jne semantic_write
    # Only the actual top-level importer can own this additional result slot.
    # Header fields and UTF-8 bytes are issued by HIA, never interpreted here.
    cmp qword ptr [r15+ROLE],46
    jne semantic_done
    cmp qword ptr [r15+57*32],0
    je semantic_done
    cmp qword ptr [r15+BORROWED+57*8],0
    jne abi_error
    cmp qword ptr [r15+57*32+24],1
    jne abi_error
    mov rdx,[r15+57*32+8]
    test rdx,rdx
    jz abi_error
    cmp qword ptr [r15+57*32+16],rdx
    jb abi_error
    mov edi,57
    xor esi,esi
    call range_view
    mov rsi,rax
semantic_owned_view_write:
    mov edi,2
    mov eax,1
    syscall
    cmp rax,-4
    je semantic_owned_view_write
    test rax,rax
    jle early_io
    add rsi,rax
    sub rdx,rax
    jne semantic_owned_view_write
semantic_done:
    mov edi,2
    jmp terminate

abi_error:
"""

def source(original):
    assert type(original) is bytes
    assert len(original)==ORIGINAL_BYTES and sha256(original).hexdigest()==ORIGINAL_SHA256
    text=original.decode("utf-8")
    assert text.count(BEFORE)==1
    changed=text.replace(BEFORE,AFTER,1)
    assert changed.count(AFTER)==1 and changed.replace(AFTER,BEFORE,1)==text
    # Exactly one owner-scoped output tail: all old calls, rights, child cleanup,
    # masks, raw admission and final success output remain the original bytes.
    return changed.encode("utf-8"),dict(
        schema="hia-explicit-legacy-diagnostic-executor-derivation-r1",
        status="NEW_SOURCE_ONLY_NOT_EXECUTED",
        original=dict(bytes=ORIGINAL_BYTES,sha256=ORIGINAL_SHA256,gitsha=ORIGINAL_GIT),
        candidate=dict(bytes=len(changed.encode()),sha256=sha256(changed.encode()).hexdigest()),
        replacements=[dict(before=BEFORE,after=AFTER)],
        whole_inverse_byte_equal=True,original_event128_emitted_first=True,
        actual_slot=57,require_actual_owner_role=46,require_owned_and_readonly=True,
        actual_logical_extent_only=True,parse_semantic_header=False,
        choose_or_format_public_message=False,
        original_child_context_and_cleanup_unchanged=True,
        original_call_RWW_masks_unchanged=True,
        original_stdin_and_success_stdout_unchanged=True,
        ordinary_P16_route_changed=False,
        new_AST=0,new_assembler=0,new_B3=0,new_native=0)
