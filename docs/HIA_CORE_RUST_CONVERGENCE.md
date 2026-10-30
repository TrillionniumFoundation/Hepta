# Core, Rust and source-custody convergence

This integration starts from public `192d2cbba7e49bde3b03af73685ecf96f6fb1b05`
(PR405). That branch and the separately qualified
`147d39c4a9d3ded00fb5d22439493bc006a8b76d` raw-record candidate diverge at
`1669ddc05a918e7c01b17e9262d4461130d44aaa`. Neither qualification can be
relabeled as an execution of this combined tree. New observations must name
the exact combined commit and actual tool and executable bytes.

## Existing implementation retained

PR405 already contains the same Rust `scalar_vm.rs` and `byte_memory.rs` as
the raw-record candidate, including bound-v3 budgets and bound-v4 exact wide
failure indices. Those Machine and ledger files are unchanged here. Its
Python differential wrapper also already owns a sealed Linux memfd image and
the process group until execution and cleanup settle; that implementation is
retained unchanged.

The newer opcode catalog, schema registry, immutable runtime argument
snapshot, source routes and LLVM lowering remain the integration base. The
newer composite-v4 resolver retains nested field paths, exact generated entry
identities, and ownership checks over bounded flattened layouts. In
particular, empty record DAGs do not regain recursive ownership expansion.

## Restored finite raw Rust path

The missing native nominal front pass is restored from public147. Its
`--composite-record-normalize` and `--composite-record-run-bound-v1` commands
accept only the declared monomorphic, acyclic Copy-record subset of raw
`hepta.hia.composite.v1`. They preserve nominal and zero-width SSA identities,
original public entry eligibility, and whole-module refusals before erasure
to the existing primitive-v6 Core. The existing Rust checker independently
admits that Core, and execution calls the existing bound-v4 Machine. There is
no additional evaluator or checker authority.

All the [candidate's input and expansion limits](HIA_RUST_COPY_RECORD_CANDIDATE.md)
remain in place. Resource-bearing fields, generics, enums, tasks, partial
records and later composite schemas remain outside that raw path, even in
unused declarations. Primitive byte resources inside functions retain their
existing admitted semantics. Previously fixed expansion guards still charge
reference and parameter widths before copying names or materializing result
layouts.

The direct raw-CLI qualification launches the native executable without
Python on its search path, binds its raw input and output, and checks its
executable bytes before and after. It does **not** use the separate Python
differential wrapper's sealed memfd. These are distinct process-custody
boundaries; neither establishes a hostile-host deployment theorem.

## Both composite-v4 origin forms

The [current field-origin grammar](HIA_COMPOSITE_RETURNED_LOANS_V4.md) remains
the general admitted v4 form. The original string annotation is restored
only for an original primitive `readbuf` or `mutbuf` formal with sufficient
permission. It reaches the same origin resolver as the object form with an
empty field path. It cannot name a record, generated slot, block-local alias,
owner, or scalar. Original invalid string and nonobject annotations retain
their `E_HIA_LOAN` refusal category.

The mixed-form control compares exact primitive Core bytes for equivalent
annotations through a CFG join, then refuses a record-name string, a local
alias, and swapped origins. Existing source-derived export checks remain
mandatory. Conditional emission of absent nonloan annotations follows the
newer resolver; v1/v2/v3 keep their original schemas and normalization rules.

The original 13-method primitive-origin corpus remains under its exact test
IDs. Its fixture bodies live in a support module outside `test_*.py`
discovery, with three named wrapper classes in the existing test module.
The newer 15-method field-origin corpus remains intact. One separate
mixed-form method makes that module's discovery 29 distinct IDs, without
imported TestCase aliases or duplicate execution.

## Source and linker custody

The selective P3 change comes from `e6d5ccc2c5d1bfc8479f92b0385428ac578c358a`,
also based on exact405. The scalar C importer reads and rechecks the admitted
canonical source path, so a retargeted caller ancestor alias cannot substitute
different source bytes or conceal a changed canonical file. Direct leaf
source symlinks refuse; supported hosts retain `O_NOFOLLOW`. Frozen stdin,
directory-fd publication, artifact ownership, and the newer direct IR guards
remain intact. This adds no C syntax or inferred foreign lifetime contract.

The shared ELF linker context restores the previously qualified identity and
cleanup obligations. A generic `lld` or `rust-lld` gets an owned temporary
`ld.lld` spelling of the selected executable. Both the original selection and
the driver alias are rechecked on context exit. Its temporary spelling is
removed after normal or exceptional exit. A context failure prevents a trial
from reporting success.

Filecheck and the newer Legacy/IR-PGO trials keep that context alive across
their actual builds and executions. IR-PGO resource linking uses that same
driver. The newer dispatcher/space-preserving argument controls and bound-IR
target-profile checks are retained. These exit identity checks detect drift;
they are not sealed executable custody and do not prevent every hostile
pathname race before a child starts.

## Executable qualification scope

The reviewed safety selection contains 340 distinct selectors in 36 scoped
capabilities. It retains all 277 selectors from405 and all 126 from147. Their
union is 323: 46 of147's selectors were absent from405. The additional 17 are
ten previously unselected field-origin methods, the mixed-form method, and
six canonical source-provenance methods. The canonical matrix hash fixes
this scope; loading or hashing the selection is not execution evidence.

Required combined-source runs retain separate denominators:

| Gate | Scope |
| --- | --- |
| Full Rust crate | All existing checker, protocol and Machine tests, including raw Copy records |
| Raw Copy-record collector | 9 methods; exact native normalization, exports, executions and refusals |
| Bound-v4 collector | 8 methods; original envelopes, ordered containers, exact wide indices and ledgers |
| Original composite-v4 collector | 13 methods; primitive-formal origins, partial states, Rust and direct LLVM |
| Current composite-v4 corpus | 15 methods plus the separate mixed-form control |
| Current shared guards | Catalog, argument snapshot, sealed execution custody, source/contract/workflow and linker/native-failure controls |
| Scalar C migration workflow selection | The current 27-module selection, including all six source-provenance methods |

Full gate and both host-matrix workflows register the new integration branch
additively. Their existing triggers, exact-head checkout, failure handling,
budgets and permissions remain unchanged. A workflow registration or local
pass is not evidence that a hosted matrix ran on the same commit.

Production admission still belongs to Python `verify_program`. The explicit
raw Rust path is a candidate subset, not a production switch. Bound-v4 policy
and scalar transport ceilings remain; whole-module admission, original entry
restrictions and v1-v3 refusals are not weakened. Logical payload accounting
is not RSS, a finite virtual-address cap is not a general memory bound, and
this integration does not change the optimization policy or establish broad
P0-P7 closure, backend refinement, or whole-language soundness.
