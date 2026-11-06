# HIA systems dialect and whole-kernel translation

This implementation adds a distinct, explicit systems dialect,
**hepta.hia.system.v1**, without changing the accepted language or proofs of the
existing HIA safe Core v1–v8. It exists to represent the actual operations of
configured Linux translation units, including unsafe memory operations.

The native LLVM 20 codec imports a module into typed JSON records. Its decoder
constructs a new LLVM module from those records. It does not parse serialized
LLVM function text, clone source instructions, retain an opaque bitcode payload,
or fall back to compiling a C function when reconstruction fails. Every decoded
module must pass the LLVM verifier.

This is a compiler-assisted translation of existing kernel semantics into a
new HIA systems representation. It does not establish that Linux has become
memory-safe, that all supported Linux configurations have been translated, or
that NDU improves performance. Those conclusions require separate coverage and
measurement evidence.

## Build and CLI

Use the pinned LLVM 20.1.8 development package and a matching compiler:

    cmake -S tools/hia_system -B /tmp/hia-system-build \
      -DLLVM_DIR=/path/to/llvm-20/lib/cmake/llvm
    cmake --build /tmp/hia-system-build -j

The command-line interface is:

    hia-system encode input.bc output.hia.json
    hia-system decode input.hia.json output.bc
    hia-system inspect input.hia.json output.receipt.json

Encode accepts a module through LLVM's IR reader and verifies it before import.
Decode reads only the HIA document, constructs fresh objects, checks typed
references and all required operations, resolves forward references and
metadata cycles, and runs the verifier before writing bitcode. Inspect performs
the same reconstruction and verification, then counts its functions, blocks,
instructions, memory operations, atomics and assembly calls. It is not a
substitute for a coverage manifest or a kernel boot test.

Nonzero exit with HIA_SYSTEM_REJECT reports an unsupported or malformed
construct. A caller must treat it as a failed translation, not a reason to use
the original compiler output for that unit.

## Document contract

The schema identifier is hepta.hia.system.v1; llvm_major is exactly 20 and the
profile is unsafe-systems-explicit-memory. This version deliberately binds the
instruction semantics and ABI attributes to LLVM 20. The accompanying JSON
Schema describes the container and data records. The native decoder's
per-operation checks are normative for executable semantics.

The module object retains the source filename, target triple, full data layout,
module assembly bytes and debug-format flag. Each translation unit retains its
own target contract. There is no global assumption that every object in an
x86-64 kernel build uses 64-bit pointers, the kernel code model, or the same PIC
options. The Kbuild wrapper must also retain the original code-generation and
target options.

The types array represents scalar types, arbitrary-width integers, opaque
pointers with address spaces, function signatures, arrays, fixed and scalable
vectors, identified and literal structures, and explicit target-extension
types. Identified structures are allocated before their bodies, preserving
recursive references.

Stable IDs identify symbols, arguments, basic blocks and instruction results.
Each reference includes its declared type. The decoder allocates all globals,
functions, arguments and blocks before reading initializers or bodies. Forward
SSA instruction references use typed temporary arguments; binding the actual
result replaces every use. An unresolved or type-changing reference is an
error. Temporaries cannot become output parameters or surviving fallback
values.

Values are structured records for integers, bit-exact floating constants,
null/zero/undef/poison/token-none/target-none, aggregate elements, byte arrays, block
addresses, constant operations, inline assembly, metadata values and symbol
references. Constant operations contain an opcode, typed operands, flags and,
where applicable, GEP source type, no-wrap flags and in-range bounds. Actual
assembly text is permitted only in explicitly typed inline-assembly records or
the module assembly field. Byte data, assembly and metadata strings use hex to
retain arbitrary byte values.

Global records preserve linkage, visibility, DLL storage, unnamed-address
semantics, DSO locality, thread-local mode, partition, sanitizer metadata,
section, alignment and comdat. Variables additionally preserve mutability,
externally-initialized status, initializer, global attributes and per-global
code model. Aliases retain aliasees. Indirect functions retain resolvers.

Function records preserve exact symbol and argument names, argument order,
calling convention, all attribute slots, GC name, personality, prefix/prologue
constants, basic-block order and instruction order. Instruction records
preserve opcodes, typed operands, result type and explicit opcode-specific
properties. Metadata attaches after reconstruction of the SSA graph.

Attributes have separate enum, integer, string, type, constant-range and
constant-range-list representations. Numeric attribute payloads are unsigned
decimal strings so that values above the JSON signed-integer range are exact.
Types and attribute category must agree on reconstruction.

Metadata has separate string, constant, local-value and tuple representations.
Tuple distinctness, cycles, named-metadata order and attachment kind names are
retained. Metadata kind registration order is represented explicitly because
it can affect canonical printing. Module flags, source-location arrays,
alias scopes and ordinary annotations are therefore data, not discarded
comments.

Specialized debug metadata is represented by explicit node classes, scalar
fields and metadata references. The current LLVM 20.1.8 profile supports
DIFile, DICompileUnit, DIBasicType, DIDerivedType, DICompositeType,
DISubroutineType, DISubprogram, DILocation, DILocalVariable, DILexicalBlock,
DILexicalBlockFile, DIGlobalVariable, DIGlobalVariableExpression, DISubrange,
DIExpression, DIEnumerator, DILabel, DIAssignID and DIArgList. Recursive types
and scopes use tracked temporary forward references followed by replacement
with freshly constructed specialized nodes. Unlisted classes reject.

Ordered dbg_declare, dbg_value, dbg_assign and dbg_label records are stored
at their exact instruction or trailing-block positions, with typed location,
variable, expression, label and assignment references. No debug text is
embedded and no record is converted into an opaque instruction. Original
per-unit debug flags remain unchanged, including the unconditional -g used by
Linux real-mode boot C even with CONFIG_DEBUG_INFO_NONE=y. These paths require
their own real boot-unit roundtrip qualification in addition to the 53 core
opcode/structure checks.

## Required whole-build gates

A whole-kernel experiment must record its exact Linux revision, .config,
compiler versions, code-generation flags, source and dependency inputs, and
all target compiler invocations. A compile_commands.json restricted to .o
commands is insufficient: generated -S files and boot, compressed, real-mode
and vDSO objects are part of the denominator. Host build tools use HOSTCC and
are a separate category from target kernel code.

For every accepted C translation unit:

1. Obtain the typed frontend module using the original options with LLVM
   optimization passes disabled.
2. Import that module into a retained HIA document.
3. Decode a fresh module from the HIA document alone.
4. Compare complete canonical llvm-dis output against the frontend module,
   ignoring only the first ModuleID path comment.
5. Run the original optimization and code-generation pipeline once on the
   reconstructed module.
6. Preserve Kbuild's object postprocessing, dependencies and link recipes.

The canonical equality check must retain attributes, metadata, ordering,
flags and source_filename. It must not remove a differing property merely to
make a unit pass. An HIA mutation test that changes an executable opcode and
changes the resulting native program is also required; source artifacts must
be unavailable during replay so that accidental fallback is observable.

A full kernel outcome requires an inventory with zero unexplained target
fallbacks, successful link and boot, correctness workloads, and whole-system
measurements. Compiler reconstruction identity is a useful guard, but is not
a proof of kernel correctness or a performance result. NDU comparison needs
matched revisions/configuration/toolchains and distinct HIA-without-NDU and
HIA-with-NDU runs, including compilation costs, image size, boot, workload
throughput/latency, memory usage and failure rates. Results must state the
measured configuration and workloads rather than generalizing to every
Linux configuration.

## Basic-block use order

Every basic block explicitly records `use_order`, an ordered list of user values
and operand indices. Reconstruction validates that this list is a bijection over
the freshly created uses, including blockaddress constants, and restores it before
writing bitcode with LLVM use-list preservation enabled. This preserves exact
predecessor presentation and iteration order without dropping canonical-IR lines
or weakening the full roundtrip equality gate. Missing, duplicate, foreign, or
out-of-range use references reject.
