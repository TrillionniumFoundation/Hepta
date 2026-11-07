# Direct borrowed bytes and real HIA bootstrap components

This candidate adds an **explicit direct-machine byte ABI** and two toolchain
components whose executable implementations are written in HIA. It does **not**
complete compiler self-hosting. In particular, the small HIA compiler rejects
its own larger source as unsupported; B1 whole-toolchain, B2 and B3 remain open.

## Direct byte boundary

The ordinary direct backend and eleven Agent tools keep their scalar invocation
contract. Research code opts into the separate byte profile explicitly:

```python
from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program_native import emit_program_machine, compile_program_machine

program = assemble_program(source_bytes)
image = emit_program_machine(
    program, foreign_buffer_exports=(("compile_constant", 1048576),)
)
receipt = compile_program_machine(
    image, program=program, output="/tmp/new-components.so", linker="ld"
)
```

The direct emitter generates the instructions and ELF object itself. GNU `ld`
links that existing object. Neither an external assembler nor LLVM generates
these instructions. Publication independently re-emits the original Core and
the exact immutable export manifest, so changing the bound or wrapper bytes
cannot reuse the old machine image.

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

Unlike the separate acyclic LLVM foreign-buffer experiment, this explicitly named
direct profile permits existing verified Core loops and internal calls. Internal
type, effect, bounds, ownership and loan checks remain required. The profile does
not prove termination or implement interpreter step/heap/call quotas. A later
Core trap can follow earlier writes; there is no general transactional rollback.

## Source-verified disposable invocation

`hepta.hia_native_byte_runner.invoke_byte_program` accepts HIA Core and bytes,
builds that Core through the direct backend, and runs it in a disposable Linux
process. It accepts no caller-supplied native pointer or arbitrary executable.
All ranges are separate owned copies; the parent receives mutable bytes as
explicit results and its original bytearrays remain unchanged.

```python
from pathlib import Path
from hepta.hia_agent_assembly import assemble_program
from hepta.hia_native_byte_runner import invoke_byte_program

program = assemble_program(
    Path("examples/hia_bootstrap/components.hiaasm").read_bytes()
)
result = invoke_byte_program(
    program, "lex_assembly",
    [b"result:u64 = const() {\"value\":42}\n", bytearray(4096)],
    timeout_ms=30000,
)
```

The child uses a wall deadline, CPU and address-space limits, process ownership,
parent-death termination and exact opened-artifact identity. Real abort and
nonterminating Core tests verify failure containment. This is not a security
claim about arbitrary hostile native binaries or an authority to adopt code.
The result retains build cost and invocation cost separately; a timeout or trap
has no completed output and is never converted to success.

## What is actually implemented in HIA

The checked-in
[`components.hiaasm`](../examples/hia_bootstrap/components.hiaasm) is the complete
source of 30 HIA functions. The Python authoring script can reproduce that source
but does not participate in the native lexer/parser/emitter calls.

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
for parsing. The test harness packages these HIA-produced instruction bytes with
the existing Python ELF writer and GNU linker, then executes them independently.
That packaging remains an explicit host dependency.

## Finite-component scope and later self-hosting

The table below describes `components.hiaasm` and its original finite compiler.
The separate [fixed-Core self-hosting compiler](HIA_SELF_HOSTING_CORE.md) now
implements native HIA parsing, semantic validation and x86 generation for all
constructs in its own full source. Its separate qualification runs B0 through
B3 and propagates a code-generation modification through a new fixed point.
The finite-component qualifier intentionally retains its narrower claims.

| Stage | Finite-component state |
| --- | --- |
| B0 seed | Python parses/checks the component HIA source and emits its native implementation |
| HIA component execution | HIA performs real own-source lexing and finite source parsing/validation/instruction generation |
| B1 complete toolchain | **Not achieved:** the finite parser cannot compile its own full source |
| B2 / B3 | **Not achieved:** no HIA-built whole-toolchain generation exists to rebuild the next generation |
| Changed-toolchain self-rebuild | **Not achieved:** source-literal changes are verified; toolchain self-rebuild is a different requirement |

The stronger gate requires a fixed sufficient Core subset with an HIA parser,
semantic validator and machine encoder that process their own implementations.
The separate self-hosting path emits position-independent flat machine images,
so successors need no object writer or linker. Future generations must actually
execute these HIA implementations, and source modifications must propagate into
a rebuilt toolchain. Calling the Python seed repeatedly, copying a known image,
or tokenizing one's own source does not satisfy that gate.

## Reproduction

```sh
python -B -m unittest tests.test_hia_native_byte_abi tests.test_hia_bootstrap_components -v
python -B tools/qualify_hia_bootstrap_components.py --output /tmp/new-bootstrap-result.json
```

The qualifier records source hashes, complete test inventory, actual native
observations, unsupported own-source compilation and open bootstrap stages.
Missing/skipped tests cannot qualify it. Its component checks can pass while
`self_hosted` and whole-toolchain B1/B2/B3 remain false. No universal correctness,
performance improvement, production connector deployment or self-hosting claim
follows from this delivery.
