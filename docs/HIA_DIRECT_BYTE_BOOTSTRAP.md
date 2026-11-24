# Direct borrowed bytes and real HIA bootstrap components

The borrowed-byte ABI is used by native HIA toolchain components. This document
also describes the narrow `components.hepta` lexer and constant compiler; those
finite components are distinct from the complete bounded self-host compiler.
Whole-source and release acceptance belong to
[HIA_SELF_HOSTING_CORE.md](HIA_SELF_HOSTING_CORE.md) and the actual current
source-bound evidence.

## Direct byte boundary

The ordinary scalar invocation contract remains separate. A caller opts into
the direct borrowed-byte profile with an immutable export manifest. HIA emits
the instruction bytes and ELF object; the native linker constructs the final
image. Publication rederives the original Core and exact manifest, so changing
an extent or wrapper cannot reuse an old image or receipt.

The profile name is
`hepta.hia.program.direct-linux-x86_64-borrowed-bytes.v1`. Its manifest is an
immutable tuple of unique `(function_name, maximum_bytes)` pairs. Each bound is
an exact integer from 1 through 1,048,576. Each function accepts one through eight
`readbuf`/`mutbuf` parameters, optionally mixed with ordinary scalar inputs, and
returns one `u32`. An existing explicit scalar export contract or normalized
nominal signature cannot silently gain a foreign-resource entrypoint. Owners,
chains and returned loans are not exposed across this boundary.

| HIA parameter | SysV AMD64 C arguments |
| --- | --- |
| `readbuf` | `const uint8_t *data, uint64_t length` |
| `mutbuf` | `uint8_t *data, uint64_t length` |
| Scalar | Its existing scalar C representation |

Parameters expand in their original order, including calls spanning register and
stack arguments. The external return is `uint64_t`: high 32 bits are ABI status,
low 32 bits preserve the entire Core `u32` result, including `UINT32_MAX`.

| ABI status | Meaning |
| --- | --- |
| 0 | All numeric admission checks passed; Core returned normally |
| 1 | A range exceeds its frozen extent |
| 2 | A nonempty range has a null pointer |
| 3 | Unsigned pointer-plus-length wraps |
| 4 | Two nonempty ranges overlap and at least one is mutable |

The wrapper checks every range and every conflicting pair before entering Core.
Admission errors leave caller bytes unchanged. Adjacent ranges, overlapping
read-only ranges, and empty ranges are permitted. Actual allocation provenance,
allocated size and liveness cannot be inferred from integer pointer checks.
Native callers must supply live storage for the whole synchronous call, exclusive
mutable ranges and no concurrent mutation of read-only ranges.

This explicitly named direct profile permits existing verified Core loops and internal calls. Internal
type, effect, bounds, ownership and loan checks remain required. The profile does
not prove termination or implement interpreter step/heap/call quotas. A later
Core trap can follow earlier writes; there is no general transactional rollback.

## Source-verified disposable invocation

The native source-bound invocation path accepts admitted Core and captured
bytes. It builds the selected Core through the direct backend and runs the
captured image in a disposable process under the native owner. Caller-supplied
pointers and replaceable executable names are not invocation authority. The
runner creates separate owned allocations; mutable observations are returned
explicitly rather than exposing reusable process pointers.

The child uses a wall deadline, CPU and address-space limits, process ownership,
parent-death termination and exact opened-artifact identity. Real abort and
nonterminating Core tests verify failure containment. This is not a security
claim about arbitrary hostile native binaries or an authority to adopt code.
The result retains build cost and invocation cost separately; a timeout or trap
has no completed output and is never converted to success.

## What is actually implemented in HIA

The checked-in
[`components.hepta`](../examples/hia_bootstrap/components.hepta) is the complete
source of 31 HIA functions. Its first function `compile_flat` implements the
standard flat-image three-buffer ABI and delegates to the same
`compile_constant` HIA function. The installed self-host compiler can assemble
this exact source. This does not change the original named lexer and compiler
calls or the finite input language `compile_constant` accepts. Its checked-in HIA bytes are the compilation input. No source generator
participates in the native lexer, parser or emitter calls.

### ASCII assembly lexer

`lex_assembly(source, target)` scans the bytes supplied at invocation. Its HIA
implementation recognizes identifiers/opcode spellings, decimal tokens,
punctuation, quoted ASCII strings and the JSON short escapes. It rejects invalid
bytes, unterminated strings and unsupported escapes. This finite lexer excludes
Unicode strings and `\u` escapes; it is not the full general HIA attribute parser.

A successful Core result is the token count. Each output record contains three
little-endian `u32` values: token kind, source start and exclusive source end.
Kinds are 1 for identifiers, 2 for decimals, 3 for strings, and `128 + ASCII`
for punctuation. The lexer first validates/counts the entire input, then checks
output capacity, then emits. Invalid input returns `0xffffffff`; insufficient
capacity returns `0xfffffffe`; both leave output unchanged.

The qualification executes this HIA lexer on its **entire actual HIA source**
and compares all token records with an independent test-only scanner. This proves
actual own-source reading/tokenization in the tested profile, not self-compilation.

### Finite assembly parser, validator and x86 emitter

`compile_constant(source, target)` accepts this explicitly frozen subset of the
existing line-based `hia-asm.v1` grammar:

```text
hia-asm.v1 hepta.hia.program.v8 scalar_seed
exports(answer)
fn answer() -> (u64) effects() entry(entry)
block entry()
  result:u64 = const() {"value":42}
  ret(result)
end
```

Module, function, block and value identifiers may change within the existing
128-character ASCII rule. The HIA parser validates actual export/function,
entry/block and definition/return name matches. The decimal literal must be a
canonical unsigned `u64`; overflow and leading zeros are rejected. The profile
uses LF lines and retains the existing grammar's required adjacency and attribute
separation. Other types, operators, extra functions and signatures are unsupported.

Only after complete source validation and output-capacity checking does the HIA
emitter write `movabs rax, <parsed u64>; ret`, producing 11 actual x86-64 bytes.
The Core result is 11 on success, `0xffffffff` for invalid/unsupported source or
`0xfffffffe` for insufficient output capacity. Rejection leaves output unchanged.
Changing the input literal changes the emitted immediate and the observed native
return value. No precomputed output program is embedded or copied as a substitute
for parsing. Qualification must package these actual HIA-produced instruction bytes with
the admitted native packer and execute the result independently. A historical
hosted packaging receipt does not qualify that current path.

## Finite-component scope and later self-hosting

The table below describes `components.hepta` and its original finite compiler.
The separate [fixed-Core self-hosting compiler](HIA_SELF_HOSTING_CORE.md) now
implements native HIA parsing, semantic validation and x86 generation for all
constructs in its own full source. Its separate qualification runs B0 through
B3 and propagates a code-generation modification through a new fixed point.
The finite-component qualifier intentionally retains its narrower claims.

| Stage | Finite-component state |
| --- | --- |
| Initial component image | The admitted native source builder compiles the exact component HIA source |
| HIA component execution | HIA performs real own-source lexing and finite source parsing/validation/instruction generation |
| B1 complete toolchain | **Not achieved:** the finite parser cannot compile its own full source |
| B2 / B3 | **Not achieved:** no HIA-built whole-toolchain generation exists to rebuild the next generation |
| Changed-toolchain self-rebuild | **Not achieved:** source-literal changes are verified; toolchain self-rebuild is a different requirement |

The stronger gate requires a fixed sufficient Core subset with an HIA parser,
semantic validator and machine encoder that process their own implementations.
The separate self-hosting path emits position-independent flat machine images,
so successors need no object writer or linker. Future generations must actually
execute these HIA implementations, and source modifications must propagate into
a rebuilt toolchain. Calling an initial seed repeatedly, copying a known image,
or tokenizing one's own source does not satisfy that gate.

## Current qualification boundary

The source-bound qualification retains exact input bytes, the complete declared
case inventory, native observations and expected own-source refusal of the
finite compiler. A missing or skipped case cannot qualify a component. Its
checks can pass while whole-toolchain self-hosting remains unestablished by
that component alone. The independent seed and complete B0/B1/B2/B3/M1/M2/M3
chain have separate inputs, receipts and obligations.

The final source contract and [CURRENT.md](CURRENT.md) select actual current
evidence. Earlier hosted component observations remain historical provenance.
Neither component tests nor source identity establish a universal compiler
theorem, arbitrary native-code safety or execution authority.
