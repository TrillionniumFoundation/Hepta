# Compact HIA assembly for Core and Agent authoring

`hepta.hia_agent_assembly` provides a deterministic spelling of primitive HIA
Core. It changes representation, not arithmetic, ownership or execution rules.
The complete translated document passes `verify_program`. No high-level source
language or migration frontend is used or installed.

## Explicit syntax

```text
hia-asm.v1 hepta.hia.program.v8 sum_core
fn sum(a:u32,b:u32) -> (u32) effects() entry(entry)
block entry(a:u32,b:u32)
  answer:u32 = int.add.wrap(a,b)
  ret(answer)
end
```

Use `assemble_program` and `render_assembly` from the actual local module for the
versioned grammar and complete roundtrip. Functions declare all parameters,
results, effects and entry blocks. Blocks declare explicit typed parameters,
ordered operations and a terminator. Operands, results, branch arguments and
resource origins remain typed and named. Attributes, when required by an opcode,
are explicit JSON objects. A syntax spelling is never a substitute for complete
Core admission.

Primitive v8 function headers may declare `return_loans(["input",null])` for
borrowed results. Contracts identify original formals; absence and an explicit
contract are different. Mutation, owner moves/drops, initialized byte ranges,
loan endings and control-flow joins retain their Core rules. Unsupported types,
operations or capacity must be rejected, not interpreted under a different
schema or a producer-selected ABI.

## Agent import and editing

Discover current catalog/profile identities and references with `hia_describe`.
Retain authored text with `hia_artifact` using the schema's UTF-8 source form.
For `hia_candidate`, use the returned complete artifact reference with explicit
`hia-asm.v1` import format. Artifact retention and verified Core admission are
separate operations. Core JSON import likewise uses an artifact reference and
its explicit format; an inline object is not a replacement for that contract.

For local hosted use, the installed `hia` entry provides `import-assembly`,
`render-assembly`, `verify`, `edit-query`, `edit-apply` and object `build` commands.
Consult the actual command help for argument/field names. Edits bind the exact
source snapshot and revision; stale or invalid candidates publish no changed
program. Every accepted edit undergoes complete Core verification.

A request key identifies an actual operation, not a retry counter. After a known
rejection, changed arguments require their proper new identity. After acceptance
or an unknown outcome, observe the original operation rather than inventing a
new key to replay it. Profile, worker, source and catalog identities are distinct;
copy their actual returned values and administrator pins.

## Native and host boundaries

The selfhosted compiler admits a documented bounded assembly profile. The native
stdio application currently supports only capabilities, verification and compile
with explicit flat/ELF/executable build profiles. That is not native Agent editing
or persistence. Hosted authoring, artifact capture, JSON transport, hashing,
authorization, SQLite and durable recovery remain host-owned until independently
replaced and qualified.

The installed package carries this actual discovery document as a source-bound
resource. Missing resources or an altered administrator source identity must not
fall back to cwd, HOME or a different checkout. A passing representation test or
finite native witness is not general native-only delivery or production approval.
