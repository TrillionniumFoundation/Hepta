# Finite native instruction search

This stage searches actual x86-64 instruction sequences below the HIA/LLVM
rewrite layer. It is an offline qualification profile, separate from the
multiversion runtime. Custom assembly is not admitted to that runtime by this
module.

The implementation exhausts a deliberately small grammar, proves each
candidate's **HIA instruction model** equivalent or inequivalent to a scalar
specification using Z3, and checks the exact machine bytes produced by the
local assembler. The native qualifier compares those artifacts with actual
Clang 20+ LLVM `-O3` output.

A successful `finite_minimum_encoded_bytes_proved` result means a minimum
**within the complete declared grammar, under the trusted instruction model
and encoder**. It does not establish minimum runtime, a minimum among all x86
programs, whole-program optimality, or a machine-checked compiler/ISA
refinement theorem.

## Complete grammar and cost

The entry is Linux x86-64 SysV `uint64_t calculate(uint64_t)`. Input `x` is in
RDI, result/scratch is RAX, and every sequence ends with exactly one `ret`.
The finite specification is `x + offset` modulo 2^64, with an offset in
`[-16,16]`; the frozen qualification workload uses 12.

| Form, including the fixed return | Immediate domain | Recipes |
|---|---|---:|
| `mov rdi,rax; ret` | No immediate | 1 |
| `lea k(rdi),rax; ret` | `k = -16..16` | 33 |
| `mov rdi,rax; add k,rax; ret` | `k = -16..16` | 33 |
| `imul m,rdi,rax; add k,rax; ret` | `m ∈ {-1,0,1,2,3,4}`, `k ∈ {-16,-12,0,12,16}` | 30 |
| `mov rdi,rax; add a,rax; add b,rax; ret` | `a,b ∈ {-12,-1,0,1,4,8,12}` | 49 |
| **Complete enumeration** | | **146** |

The table describes operand roles; generated assembly uses AT&T syntax.
Cost is the actual encoded function body length, including `ret`. ELF
headers, alignment, dynamic-linking metadata, build time and runtime are
separate quantities. Candidates tie by a stable recipe ID. Selection happens
before timing, so timing noise cannot change the byte-minimum claim.

For `x+12`, seven sequences are equivalent: `lea 12`, `mov;add 12`,
`imul 1;add 12`, and the four two-add pairs `(0,12)`, `(12,0)`, `(4,8)`,
`(8,4)`. Their encoded lengths are respectively 5, 8, 9, and 12 bytes. The
five-byte sequence is:

```asm
leaq 12(%rdi), %rax       # 48 8d 47 0c
ret                     # c3
```

This statement concerns the declared domain. It does not rule out another
instruction outside the grammar, a different calling convention, or a
different cost metric.

## Behavioral proof and instruction effects

`enumerate_candidates()` returns recipes, regenerated HIA models, expected
encoded bytes and stable identities. It attaches no approval. Each recipe
is independently passed to `validate_translation()` against the canonical
baseline; the existing translation validator re-runs the canonical verifier
and asks Z3 about **all 2^64 typed inputs**. A disproof includes a concrete
counterexample replayed by the canonical interpreter. One unresolved proof
is enough to withhold the finite minimum certificate, even when the shortest
accepted candidate has already been proved.

The model preserves low-64-bit wrapping arithmetic. Signed 8-bit immediates
are modeled by their sign-extended value modulo 2^64. `lea` computes an
address value without dereferencing it; noncanonical intermediate address
values therefore do not introduce memory accesses. Low-word multiplication
uses the same modular result for signed and unsigned interpretations.

The permitted machine effects are explicit:

- `mov` and `lea` write RAX and preserve flags.
- `add` writes RAX and the arithmetic CF, PF, AF, ZF, SF and OF flags.
- `imul` writes RAX, defines CF/OF, and leaves PF/AF/ZF/SF undefined.
- The fixed `ret` reads the caller's ABI return address, transfers RIP and
  advances RSP by eight bytes. A valid caller stack is an execution
  assumption.
- RDI, callee-saved registers and DF stay unchanged. There are no calls,
  explicit loads/stores, branches, pushes, pops, spills, allocations,
  resource handles or configurable registers. Arithmetic flags are not
  language outputs under this ABI.

The Python instruction model and byte encoder are part of the trusted
computing base. HIA SMT equivalence is not a formal proof that the physical
processor implements that model. The canonical verifier, Z3, assembler,
linker, loader and host hardware are also trusted. This profile does not
extend whole-language memory/resource guarantees to arbitrary foreign or
generated machine code.

## Assembly and artifact admission

`build_candidate(baseline, candidate, output, *, clang, timeout_ms=2000)`
first reconstructs the recipe from the closed grammar. It rejects added
fields, modified HIA models, modified expected bytes, register overrides,
unlisted operations and boolean/noninteger immediates. A serialized
`proved` field is rejected. A fresh translation proof must bind the schema,
profile, function, scope and both canonical/input hashes; a previously
returned search receipt is not sufficient.

The builder regenerates a small `.S` file and invokes actual Clang 20+ with
`-shared -nostdlib`, an explicitly nonexecutable stack, RELRO and immediate
binding. The driver and implementation bytes are identified before and
after compilation/publication. Output uses the repository's no-replace,
exact-byte publication mechanism.

The actual shared-library bytes must pass both the existing ELF ABI
inspector and a narrower gate:

- ELF64 Linux/SysV x86-64 shared object, one global default `STT_FUNC`
  export named `calculate`.
- The symbol starts at, and covers, the only executable section. The sole
  executable load segment contains exactly that body.
- The symbol's address, size and section offset agree with the actual
  loader mapping. Allocated section mappings are checked; overlapping load
  pages, unexpected zero-fill and unsupported permissions/alignments reject.
- Dynamic symbol/string/hash tables must describe allocated, actually
  mapped bytes. The symbol inventory is exactly the null entry and
  `calculate`; every supported hash bloom, bucket and chain entry is
  reconstructed, preventing shadow metadata or out-of-inventory lookups.
- No imported symbols, dependencies, relocations, constructor/destructor
  arrays, dynamic initializers/finalizers, IFUNC resolver, TLS or unreviewed
  dynamic-loader hooks are admitted.
- Exported machine bytes must exactly match the closed encoder, including
  the final `ret`; matching assembly text or a claimed artifact hash does
  not suffice.

These checks apply to locally generated output from the trusted assembler.
They are not a general-purpose ELF sandbox, a proof of dynamic-loader
semantics, or protection against a malicious same-user host changing files
while native programs execute. The offline qualifier records actual file
hashes before and after child execution. It does not publish these custom
machine-code artifacts into the multiversion runtime.

## Frozen native comparison

`tools/qualify_hia_x86_search.py` writes the complete protocol before search
or measurement. It records source hashes and rejects a campaign if sources
change during execution. The complete 146-candidate proof table is retained,
including all disproofs and counterexamples.

Every model-equivalent recipe is freshly proved again, assembled, inspected
and retained. The LLVM baseline is independently built through the existing
direct HIA-to-LLVM compiler. Both the baseline and **all seven** equivalent
native recipes receive:

1. Eight explicit boundary probes in separate native-executing children,
   including unsigned wraparound and the signed midpoint.
2. Seven timed C-loop trials of 200,000 calls each, with 20,000 warmup calls
   per trial. The order rotates by trial and reverses on odd trials.
3. Identical deterministic input streams and an independent modular formula
   checksum, with elapsed/CPU time, context switches and page faults retained.

All raw successful and failed samples are retained. Failed samples cannot
be discarded or retried to obtain a favorable result. The displayed timing
envelope is the maximum absolute deviation from the median, rounded up per
call; it is **not** a statistical confidence interval. Indirect calls,
C-loop overhead, page/cache placement and host noise are part of the
measurement. Byte minimum and runtime performance are reported separately.

The first completed qualification decided all 146 models, proved seven,
and executed 56 timed samples: **11.2 million timed native calls**, plus
64 explicit boundary calls and warmup. The selected five-byte body was
**identical to the LLVM `-O3` baseline body**. Every empirical timing
envelope overlapped the baseline envelope. This is a useful negative
control: the mechanism runs, while the evidence does not establish a
runtime improvement over LLVM.

## API and execution

```python
from hepta.hia_x86_search import search_affine_candidates, build_candidate

search = search_affine_candidates(offset=12, timeout_ms=2000)
assert search["finite_minimum_encoded_bytes_proved"]
receipt = build_candidate(
    search["baseline"], search["selected_candidate"], "/new/path/candidate.so",
    clang="clang-20",
)
```

The optional Z3 dependency is required for successful proof. Missing solver
or timeout cannot approve a build. The public
`inspect_candidate_artifact(data, candidate)` checks bytes without executing
them. `exported_code(data)` only observes a mapped export body; its result
alone never authorizes arbitrary code.

```sh
python tools/qualify_hia_x86_search.py \
  --clang /path/to/clang-20 \
  --artifacts /new/path/x86-search-artifacts \
  --output /new/path/x86-search-report.json

HEPTA_CLANG=/path/to/clang-20 python -m unittest tests.test_hia_x86_search -v
```

The qualifier's schema is
`hepta.hia.x86-finite-search-qualification.v1`. Top-level `ok` means the
bounded mechanism completed under its declared assumptions. It deliberately
keeps `global_optimality_established`, `native_backend_refinement_proved`
and `runtime_improvement_established` false. This provides a concrete,
auditable lower-instruction search stage on which larger instruction models
and independently verified code-generation boundaries can later be built.
