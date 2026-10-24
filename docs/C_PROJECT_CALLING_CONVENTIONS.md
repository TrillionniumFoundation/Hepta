# Reject unlowered project function calling conventions

Exact parent #31: `e51ae5188ddf8a3cc5f01a28b2ab806209e04334`.
This is a separate captured-project translator defect from earlier scalar
calling-convention and project typedef repairs.

## Compile-only original/generated evidence

The public project API accepted valid C11:

    int __attribute__((ms_abi)) special(int value) { return value; }

Clang19 represents the convention in FunctionDecl.type.qualType as
`int (int) __attribute__((ms_abi))`; its children need not include an Attr node.
The generated real Rust bridge instead exports `special` as unsafe extern C.
On this x86-64 Linux host, original Clang19 -O2 assembly reads its argument from
ECX; the actual generated Rust1.90 -O assembly reads EDI. Both artifacts were
compiled to assembly only. No foreign call, mismatched ABI call or generated
program execution was used as evidence.

## Minimal boundary

Every project function declaration, including prototypes and definitions, must
have a plain complete function type shape before lowering its return/arguments.
This rejects type-level attribute suffixes and inherited conventions instead
of guessing a limited list of ABI names. Existing child-attribute rejection
remains in place. Ordinary builtin/typedef returns and ordinary contracted
pointer parameters retain their existing handling. Function-type typedefs,
function pointers and other unsupported shapes are not added to the language.

The initial three test methods failed ten negative subcases on exact #31:
four conventions in two positions, plus inherited ms_abi/vectorcall with a
typedef return. The ordinary signature positive already passed. Exact final
focused/full results accompany the draft. The gate is conservative; it does
not prove all foreign ABI behavior or implementations correct, and it does not
qualify additional targets, physical hardware or arbitrary C/C++ conversion.

No change to typedef resolution, capture/inventory, publication, scalar helper,
C++ bridge or workflow. No remote CI queried, merge or security-setting change.
