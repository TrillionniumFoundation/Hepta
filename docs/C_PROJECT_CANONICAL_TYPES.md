# Project migration: declaration-backed typedef types

Parent: #28 `dad04e275bc2a646e11c4c6ddbdf44729a6f8a7a`.
This repair is confined to the independent captured-project C translator.
Earlier scalar typedef fixes did not change this implementation. #29 is a
workflow-only child and is not imported; current #14 remains a separate line.

## Defined-input miscompilation

The public migrate_c_project API accepted this valid C11 program:

    typedef signed int uint32_t;
    int probe(void) {
        uint32_t x = -1;
        if (x < 0) return 1;
        return 0;
    }

The original returns 1. The generated safe core used u32 and returned 0.
Separate Clang19 -O2 executables called their own matching int(void) entry
functions; no mismatched ABI call was executed. The captured dependencies were
reverified. Return-only `typedef unsigned long long int32_t` also incorrectly
selected i32 for a 4294967296ULL return. These are type-lowering defects, not
claims that every accepted project is incorrect or that foreign safety is proved.

## Minimal resolution rule

Only C builtin names have builtin meaning. Each actual captured Clang TU now
provides a separate top-level typedef context, including system-header types.
Clang desugared types take precedence; otherwise nonbuiltin spellings resolve
recursively through that TU's typedef declarations, with cycle detection.
Return-only signatures and pointer/contract element strings use the same context.
No name can borrow a typedef from a different TU through the global alias audit.
Existing cross-TU alias and record conflict rejection is retained. System types
supply context only, not extra translated declarations or omitted inventory.

Existing size_t/ptrdiff_t usize/isize spelling is retained only after actual
canonical signedness and pointer-width agreement. Unsupported qualifiers,
pointers as values, atomics, arrays and unresolved types remain fail-closed.
No scalar helper, C++ bridge, ABI convention policy or capture/publication code
changes. In particular, the separately reproduced project type-level ms_abi
acceptance remains unresolved; this patch must not be cited as its repair.

## Evidence scope

The initial four regression methods failed five assertions on frozen #28,
including the 1 versus 0 native differential. Additional tests cover TU-local
resolution, same/conflicting aliases and missing/cyclic type rejection.
Exact final focused/full results accompany the draft. No historical gate or
remote CI claim qualifies this new source. No whole-language equivalence,
formal refinement, arbitrary C/C++ support, hardware or provider qualification.
