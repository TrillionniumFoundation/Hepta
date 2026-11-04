# Shared transport composition research

This candidate retains the failed `abaaf9423cc0a36b361df60893bc139a6bfc75f9`
experiment and changes proof generation. It is independent of the f2 production
candidate, which lacks the PR 603 proof-chain dependencies.

Eight new Lean lemmas prove byte-list reassociation with symbolic parameters.
Concrete certificates instantiate these lemmas and retain each key-domain,
ordered-field, child-serialization and child-parsing premise. Serialization
spines that are already definitionally equal use `exact` directly. The complete
original theorem statements, data, inputs, subject sets, and ten negative
certificates are retained; the helpers add eight checked subjects.

Version 2 moves the complete generic Raw/parser/Structured layer, including its
35 original subjects and eight shared lemmas, byte for byte from SyntaxData to
Baseline. The first 837 concrete certificates are repartitioned as 256, 290 and
291 subjects across SyntaxData, CertPart01 and CertPart02. All later declarations
and final negative coordinates remain unchanged. The first four module counts
are therefore 99, 256, 290 and 291; no process is added and no original subject is
removed. Declaration order and the existing parent graph are preserved.

Version 3 also reuses earlier proofs for identical literal byte facts and field
key domain/parser propositions. The first occurrence keeps its original proof;
later occurrences keep their complete original statements and refer to that
earlier theorem. Literal lists, lengths and parser suffixes are matched exactly.
Every proposed reference must still be checked by Lean. The generation table
stores theorem names, never cached Boolean results or accepted inventories. No
new axiom, executable evaluator, import or process is introduced. Two additional
symbolic lemmas establish that atomic string parsing/serialization is independent
of the positive fuel/depth values. This rule explicitly excludes zero budgets
and is not applied to numbers, arrays or objects. They let later equal string
literals reuse the earliest actual proof even when their call budgets differ.
Both new lemmas are additional printed, kernel-checked subjects: Baseline now
has 101 subjects, and every original subject multiplicity remains intact.

The source-only validator reconstructs every prior proof byte from actual
candidate declarations after reversing the actual module layout and checking
each authorized replacement and unchanged complete statement. It then invokes
the existing nocode, relocation, and earlier
full data/source inverse validators. Source checks alone never grant proof
authority; every replacement and new helper must pass the pinned Lean kernel.

## Execution contract

The versioned `seven-shared-acceptance-v3` protocol fixes `--threads=1` for every
Lean invocation. This reduces worker concurrency and does not increase a time,
source, module, log, evidence, or cleanup allowance. The same 60 seconds per
process, 540-second launch deadline including preparation, 600-second outer
deadline, eleven-process limit, 81 frozen files, and independent full replay
remain mandatory. All 780 support identity paths remain pinned. The repository
source identity closes over the original 239 files and twelve additions.

Run a fresh full acceptance under the unchanged outer timeout:

```sh
timeout 600s python -m tools.check_core_seven_shared \
  --lean /absolute/path/to/lean-4.19.0/bin/lean \
  --output-directory /absolute/path/to/fresh-evidence
```

Replay consumes actual frozen source, raw logs, module bytes, process observations,
and pinned external bytes. A caller-supplied status flag or a partial profiler
run cannot replace replay. Even successful narrow syntax acceptance leaves all
twelve wider obligations unproved and every production/runtime admission closed.

## Evidence classification

The original data-only proposal and its CertPart02 timeout remain preserved.
Initial single-module profiling reused previously checked parent modules and is
explicitly **nonaccepting**. With one worker, the eight shared helpers completed
in 1.114 seconds and the rewritten CertPart02 in 3.202 seconds; these observations
are neither a fresh full proof-chain acceptance nor a production performance
claim. Full acceptance and source mutation test results must be recorded
separately after the complete execution finishes.

The v1 full-input inverse and hostile mutation tests, plus the unchanged-budget
and independent-replay contract tests, completed on 2026-11-04: **15 tests in
96.375 seconds, all passing**. Mutations include weakened theorem statements, substituted
child certificates, changed data, missing helper/original subjects, injected
axioms, forged authority flags, and incomplete cleanup observations.

The subsequent fresh v1 acceptance at commit
`4dfc514ece3fdf91f634f8abba9123af5163a9a3` **failed**. Baseline checked 56 subjects
in 14.629626412 seconds; SyntaxData reached its unchanged process timeout at
60.000291167 seconds. No later stage launched. The complete run, including
preparation, took 186.946952821 seconds. Its retained RESULT SHA256 is
`a7d88e42c7e20f43561131c866252ae111779d1ef9bdd6544772ab0ac5689f8f`
under `/home/qian-qi/work/hia-safe-core-shared-acceptance-20261104-r1`.

A separate diagnostic adding 31 extra generic `noncomputable` headers also timed
out; that transformation is not adopted. Version 2 addresses the observed module
work distribution. Its fresh full acceptance must be measured independently;
neither repartitioning nor successful source tests grant proof acceptance.

The first v2 source test run retained one test failure: a new assertion incorrectly
assumed the old schedule printed each subject globally once. It already contains
61 repeated subject occurrences across modules. The corrected assertion compares
the complete old and new subject multiplicities, allowing only the eight new
helpers; it does not remove or weaken an existing protocol check.

After that correction, the complete v2 source/mutation and acceptance-contract
suite passed: **16 tests in 104.602 seconds**, durable job
`1a1a4c91c02-fc05-13ba`. This is source-validation evidence, not a successful
fresh Lean acceptance.

The subsequent fresh v2 acceptance at commit
`0cfa643c57cebf35ccec18a897559db01ffa9f87` passed Baseline/SyntaxData/CertPart01/
CertPart02 with 99/256/290/291 subjects in 17.828485657/44.377083243/25.989604885/
23.142246607 seconds. CertPart03 then **failed** at 60.000747313 seconds. Total
wall time including preparation was 314.774392679 seconds. The retained RESULT
SHA256 is `c91ff62fa304c2ef54039e1c257ea56be414625a70f2bd9b0cfcacf4a6f07250`
under `/home/qian-qi/work/hia-safe-core-shared-acceptance-20261104-r2`.

Nonaccepting isolation measured the Part03 import in 1.750290540 seconds and its
initial unchanged `linear_bounds` proof slice in 2.500763680 seconds. Neither
isolated success qualifies the full module. Version 3 targets repeated literal
proof reduction; its fresh complete acceptance remains mandatory.

The two new atomic-string lemmas passed the pinned Lean kernel in an isolated
check taking 0.678905773 seconds; both reported no axiom dependencies. The v3
complete input/inverse, hostile mutation and acceptance-contract suite then
passed **17 tests in 132.131 seconds**, durable job `1a1a4dd2819-fc05-14e2`.
These results remain distinct from fresh full-chain acceptance.
