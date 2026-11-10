# HIA Core assembly for Agent tools

HIA assembly is an explicit spelling of checked Core, not a separate high-level
source language. `hia import-assembly input.hiaasm -o new.core.json` produces a
new file only after whole-program verification; `hia check-assembly` checks
without publishing, and `hia render-assembly` renders admitted primitive Core.

```text
hia-asm.v1 hepta.hia.program.v8 sample
fn calculate(x:u32) -> (u32) effects() entry(entry)
block entry(x:u32)
  one:u32 = const() {"value":1}
  answer:u32 = int.add.wrap(x,one)
  ret(answer)
end
```

The header names the exact Core schema and module. Optional `exports(name,...)`
occurs once before any function. Every function explicitly declares parameters,
result types, effects and entry block. Core v8 may also declare
`return_loans(["formal",null,...])` for its exact parameter-bound borrowed result
origins. Instructions use `name:type` outputs (or `_` for no output), an opcode,
explicit arguments and an optional strict JSON attribute object. Multiple
outputs are comma separated. There is no expression synthesis or inferred cast.

Blocks declare their incoming typed values. Terminators are `ret(values)`,
`jump target(values)`, `branch condition yes(values) no(values)` or `trap CODE`.
Every block must terminate and every function ends with `end`. Forward labels
are names, not source order assumptions. Identifiers are bounded ASCII names;
LF and CRLF are accepted, not arbitrary Unicode line separators. `hia catalog`
is the authoritative discoverable instruction/type/attribute inventory.

The hosted assembly parser accepts only the existing explicit v6/v7/v8 primitive
profiles and always invokes the Core verifier. Native selfhost assembly has its
separately pinned bounded profile in HIA_SELFHOST_CORE_SUPPORT.json; do not
assume every hosted feature is available in the native compiler. Ownership,
borrow lifetimes, effects, SSA, call signatures and CFG joins remain checked.
There is no source-language fallback or automatic repair. Hosted import/render
still needs Python and is not native-only Agent delivery.
