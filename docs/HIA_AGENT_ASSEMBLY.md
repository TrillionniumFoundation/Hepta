# Compact HIA assembly for Agent authoring

`hepta.hia_agent_assembly` adds a deterministic text spelling of **primitive
HIA v6/v7**. It addresses redundant JSON syntax without changing execution,
inventing a second integer/ownership semantics, or trusting a model's claims.
The complete translated program passes the existing `verify_program` checker.

```text
hia-asm.v1 hepta.hia.program.v6 sums
exports(total)
fn total(a:u32,b:u32) -> (u64) effects() entry(entry)
block entry(a:u32,b:u32)
  a64:u64 = int.cast(a) {"mode":"wrap"}
  b64:u64 = int.cast(b) {"mode":"wrap"}
  answer:u64 = int.add.wrap(a64,b64)
  ret(answer)
end
```

The example widens each input **before** addition. The frontend does not choose
that repair. Replacing those instructions with a wrapping `u32` addition would
produce a different, well-typed program with different behavior. Type/ownership
admission alone is not proof of the requested functional specification.

## Grammar and explicit semantics

| Text | Exact primitive Core object |
| --- | --- |
| `hia-asm.v1 <schema> <module>` | Explicit `schema` and `module`; exactly one header |
| `exports(f,g)` | Optional explicit scalar export list; absence and `exports()` stay distinct |
| `fn f(a:u32) -> (u64) effects(trap) entry(start)` | Function name, parameter/result types, effect list, and entry block |
| `block start(a:u32)` | Closed SSA block with all incoming values explicit |
| `x:u64 = int.cast(a) {"mode":"wrap"}` | One typed instruction result, exact opcode, argument list, strict JSON attributes |
| `owner:buffer,ok:bool = buffer.try_new(n)` | Multiple typed results; omitted attributes mean the empty object only |
| `_ = owner.drop(owner)` | Zero-result instruction; cleanup remains an explicit operation |
| `ret(x,y)` | Return the named values |
| `jump next(owner,n)` | Explicit destination and all edge arguments |
| `branch condition yes(a) no(b)` | Explicit condition and two complete edges |
| `trap overflow` | Explicit trap terminator and code |
| `end` | End the function after a complete block terminator |

Function parameters must equal the entry block parameters, exactly as required
by Core. Types, integer wrapping/checked modes, calls, effects, ownership moves,
borrow endings, cleanup, CFG edges, and trap behavior are never inferred. Every
opcode and attribute is checked by the existing Core verifier. The parser has
no expression evaluator, optimizer, automatic renamer, cast inserter, destructor
inserter, or special knowledge of study tasks.

Whitespace and blank lines are accepted; line endings are LF or CRLF. There is
no comment syntax or multiline attribute object in this version. Names use the
same bounded ASCII spelling as Core. JSON attributes reject duplicate keys,
nonstandard constants, excess nesting, and malformed input.

Historical Core schemas and nominal composite documents are rejected by this
text frontend. Their existing explicit adapters/elaborator remain responsible
for those inputs. In particular, rendering a composite document does not silently
discard its nominal layout or produce a misleading identity round trip.

## APIs and CLI

```python
from hepta.hia_agent_assembly import (
    assemble_program, render_assembly, diagnose_assembly,
)

checked = assemble_program(source_text)  # complete verify_program check
compact = render_assembly(checked)      # verifies exact canonical Core round trip
diagnostic = diagnose_assembly(compact)
```

The integrated CLI exposes `hia import-assembly`, `hia render-assembly`, and
`hia check-assembly`; use each command's `--help` for its file arguments.
The explicit `agent-assembly` route ends at the same checked Core used by the
ordinary interpreter and LLVM backend.

`render_assembly` rechecks the input, constructs the complete representation,
assembles it again, and requires byte-for-byte equality of canonical Core.
Function/block/operation order, schema, module, attributes, explicit exports,
and all operational payloads are preserved. It fails if the representation
exceeds its own bounds. A smaller representation is not a semantic proof.

Syntax errors have a 1-based line number. Semantic errors retain the original
Core error code and use `phase: core_verification`; their line is `null`, rather
than guessing a location for a cross-block or ownership error. A diagnostic
with `accepted: true` states that syntax and Core admission passed. It explicitly
has `deployment_authority: false`, `safety_certificate: false`, and
`native_artifact_created: false`. The ordinary native build, proof, receipt,
and loaded-image checks still apply.

## Bounds

The frontend enforces a 1 MiB UTF-8 source limit and 16,384 lines, 16 KiB per line,
256 functions, 4,096 blocks, 16,384 operations, and 256 items per list. Attribute
JSON is preflighted before allocation with 2,048 nodes and depth 16. The existing
Core byte/node/depth/type/ownership bounds apply afterwards. Neither excessive
source nor a forged diagnostic can skip those checks.

## Qualification and the Agent experiment

The implementation controls cover actual mathematical output, checked overflow,
ownership moves, overlapping loans, missing cleanup, cross-block loan provenance,
v7 recursive chains and allocation refusal, export preservation, cross-function
interface upgrades, duplicate keys, unsupported profiles, and bounded input.

```bash
python -B -m unittest tests.test_hia_agent_assembly -v
python -B tools/qualify_hia_agent_assembly.py --out /tmp/new-assembly-qualification \
  --clang /absolute/path/to/clang
```

The qualification tool keeps original Core, rendered text, reassembled Core,
emitted LLVM equality, actual VM values/resource observations, and optional
native build/mapping evidence. The registered kernels supply an independent
arithmetic oracle. A run without `--clang` is explicitly VM-only; missing native
execution does not count as a pass of native qualification. Byte counts are
reported as byte counts, with token counts unknown.

The separate
[`hia_agent_assembly_v4_20261030`](../experiments/hia_agent_assembly_v4_20261030/README.md)
study compares compact HIA, original JSON HIA, and Rust with four new maintenance
and API-upgrade tasks and the same two pinned model families. All three arms
receive complete project context, task information, public feedback, and the
same generation budgets. JSON/compact HIA start from exactly the same Core;
their comparison isolates representation within this finite task set. The Rust
comparison is reported separately. All actual tokens, failed attempts, timeouts,
native validation and preparation costs remain observable. Reference programs,
mock orchestration controls, and parser tests never count as model successes.

The previous 16-cell negative study stays frozen. Neither concise syntax nor
passing frontend controls establishes Agent productivity, Rust superiority,
general compiler correctness, or globally optimal code.
