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

The versioned `seven-shared-acceptance-v6` protocol fixes `--threads=1` for every
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

The fresh v3 run at `6905cffc0508727ef97597bcacbdc9628d95d1a8` failed in CertPart02
after 22.019751280 seconds, with an application type mismatch when `linear_p151`
reused `linear_p6`. Baseline/SyntaxData/CertPart01 had passed (101/256/290 subjects).
Lean emitted error-recovery `sorryAx` dependencies after that error and exited 1;
the stage and full run were rejected. No resulting module was admitted. The
retained RESULT SHA256 is
`fd193c57da12b4e6a2652d18401d9b0da1fbd390aa283500c6a389e2f10da18d`,
total wall time 247.482644445 seconds, under the r3 evidence root.

Both original byte aliases in that case expand to exactly the same 13 bytes.
The generated parser application had replaced the original byte alias with a
constructed quote/list spine without an explicit representation bridge. Version
4 retains the first parser theorem's actual Raw and byte aliases and requires
three kernel-checked equalities: the leading-quote shape, equality of the byte
aliases, and equality of the Raw aliases. One new generic theorem performs these
explicit rewrites; all ten previous helper subjects remain. Baseline therefore
has 102 subjects. Independent handwritten Lean controls preserve the real
6-to-151 example and separately alter its closing quote byte.

The new explicit representation helper passed the pinned kernel in 0.577142405
seconds. The independent handwritten positive control passed in 0.593522859
seconds; its changed-closing-byte negative control was rejected with exit 1 in
0.532415422 seconds. The entire formerly failing Part02 then checked all 291
subjects in 22.152103628 seconds without error-recovery axioms. These diagnostic
modules reused the previously checked parent and added a helper import, so they
are explicitly nonaccepting. Their durable job `1a1a4ee9f7c-fc05-15fb` then ran
the full source/inverse and acceptance-contract suite: **17 tests in 122.837
seconds, all passing**.

The fresh v4 acceptance at `f63511595e556177d1565d4f7e7f3d50c75ea588` failed
in CertPart03 after 60.000279301 seconds. Baseline, SyntaxData, CertPart01 and
CertPart02 checked 102, 256, 290 and 291 subjects in 17.947752704, 41.249657321,
26.054124214 and 21.734902182 seconds. Its total wall time including preparation
was 397.626573798 seconds. Cleanup completed in 0.165990874 seconds; no later
stage or final independent replay was reached. RESULT SHA256 is
`f991eac9736d619dd903325b6c25b892ff850097f42d2614edf8816b9e5b6bde`, under
`/home/qian-qi/work/hia-safe-core-shared-acceptance-20261104-r4`. This failed
candidate, its exact source export and its git bundle remain preserved.

## Version 5: one fixed dependency-safe boundary extension

The actual v4 source contains a contiguous 600-declaration prefix at the start
of CertPart03: `linearRaw`, `linearBytes`, three original transport theorems,
and all 595 `linear_bf0000` through `linear_bf0594` facts. Version 5 appends this
prefix, byte for byte, to CertPart02. `linear_length`, `linear_byte_range` and
`linear_transport` remain in CertPart03, so all root owners remain unchanged.
The eleven subject counts become 102, 256, 290, 889, 1057, 807, 1297, 1297,
1297, 75 and 1. There is no proof-body change relative to v4.

The source validator independently checks all 7,685 definitions, 4,215 original
transport theorems and 2,975 auxiliary facts, the actual literal import graph,
and all known transport references against their actual declaration positions
and imported ancestors. The audit found 45,994 such references. The concatenated
global declaration sequence remains identical. The inverse removes the fixed
600-declaration suffix from the actual Part02, restores it to the actual Part03,
and requires every recovered v4 source byte, subject and metadata field to match
before replaying all earlier inverses. A manifest records the exact moved-byte
hash and fixed boundary; it does not authorize a caller-selected partition.

Missing or duplicated moved declarations, a forged boundary, an actual future
reference and a changed literal import have explicit hostile controls. Version
5 retains all process, preparation, outer, source, module, log and evidence
limits. Its targeted diagnostics and source tests cannot substitute for a
fresh full eleven-stage acceptance and independent replay.

The v5 source, inverse, hostile-boundary and unchanged-budget suite passed all
20 tests in 133.256 seconds. Its first nonaccepting diagnostic failed before
proof checking because the newly created module-prefix directory shadowed the
separate prior parent directory. A new diagnostic copied only the three parent
modules after verifying their hashes against the preserved successful v4
receipts. That corrected diagnostic **failed**: CertPart02 reached the same
60-second limit at 60.000930714 seconds. Both roots are preserved under
`/home/qian-qi/work/hia-safe-core-partition-controls-20261104-r1` and `-r2`.
No v5 full acceptance was attempted; the failed candidate has a separate
source export and git bundle in `hia-safe-core-delivery-20261104-v5`.

## Version 6: distribute the preceding prefix too

The v5 diagnostic shows that the complete linear prefix does not fit within
Part02's remaining allowance. Version 6 therefore also moves the first 154
original certificates from the old Part02 into Part01. The earlier cumulative
cuts change from 256/546/837 to fixed 256/700/837 before the same 600-declaration
linear prefix is moved. The eleven subject counts are now 102, 256, 444, 735,
1057, 807, 1297, 1297, 1297, 75 and 1. This is a new fixed layout, not a retry
of the timed-out layout. It introduces no proof-body or theorem-statement edit.

The inverse first removes the exact 600-declaration actual Part02 suffix,
restores the preceding actual rows to 256/546/837, and requires complete byte
equality with the v4 layout. The same independent actual import/reference
checks and all earlier full inverses remain. The additional manifest cut field
has a hostile forged-cut control. All original budgets and eleven processes
remain unchanged; fresh complete acceptance is still mandatory.

The v6 complete source/inverse, hostile-mutation and unchanged-budget suite
passed **20 tests in 143.183 seconds**. The subsequent diagnostic reused only
the hash-verified, checked v4 Baseline and SyntaxData modules. It checked all
444 Part01 subjects in 41.758393769 seconds and all 735 Part02 subjects in
40.155894844 seconds. Part03 then **timed out** at 60.000332206 seconds, with
1,057 expected subjects and no buffered inventory emitted. Durable job
`1a1a5128524-fc05-1867` and all actual sources, module bytes, raw streams and
observations remain under
`/home/qian-qi/work/hia-safe-core-partition-controls-20261104-r3`.

This diagnostic does not establish full acceptance or rule out every possible
safe partition. It establishes that this exact two-boundary redistribution
retains the complete source and dependency invariants but still exceeds the
Part03 process allowance. The earlier failed layout is immutable commit
`65f49765bc248fdb0dfc6bc84f71c6990f543fcf`, tree
`b6556f64dece19847770d7edd429d8c6e35568d7`. Its export includes an explicit
nonaccepting outcome and both retained diagnostic failures. A fresh full v6
protocol run must record its own terminal outcome separately; this document
does not claim that such a run passed.


## Version 7: exact-bound compound certificate references

The frozen v6 fresh acceptance at `ce1dd749ffaf7b0905e55473164f79741facb08c`
failed in CertPart03 at 60.000790060 seconds. Its first four modules checked
102, 256, 444 and 735 subjects. Total wall time, including preparation, was
339.817342764 seconds. The original RESULT SHA256 is
`96a0999c91ea120f96b1708325a53cc1462f56765ace38f0f5e33d36f9efafca`;
all sources, receipts and raw logs remain in the original r5 evidence root.
No later stage or independent final replay was reached.

The next cost reduction preserves the complete v6 partition and every original
theorem statement. For a closed non-string Raw literal, it can replace a fresh
serializer or parser proof with a reference to an earlier checked certificate
only when the actual encoded byte list, the complete Raw constructor text and
both numeric bounds are identical. Qualified byte aliases are resolved in their
defining namespace. Free Raw identifiers, nonliteral byte expressions, cycles,
different fuel or depth, forward references and nonancestor modules do not
qualify. The new rule adds no helper theorem, executable oracle or axiom. Lean
still checks the original full target and its imported proof dependencies.

A separate inverse layer restores every actual v6 declaration byte, subject and
metadata field, then requires the complete eleven module SHA256 values to match
the retained ce1/r5 files before all older source inverses are replayed. The
first four generated modules are unchanged. There are 806 candidate references:
403 serializers and 403 parsers, with 154 in Part03 and 164/162/164/162 in
Part04 through Part07. The complete actual transport reference count increases
from 45,994 to 46,800. All 7,685 definitions, 4,215 transport theorems and 2,975
auxiliary facts, their global order and printed-subject multiplicities remain.

Independent handwritten controls distinguish actual Raw data, encoded bytes,
both bounds and import visibility. Separate Lean controls exercise equal data
with a different byte-list representation, then change only the target Raw,
bytes, fuel or depth while leaving the earlier certificate untouched. These
controls and source tests are diagnostics only. Version 7 retains eleven
registered processes, 60-second process limits, 540-second launch/preparation
budget, 600-second outer limit, and every prior source/module/log/evidence cap.
Only a fresh complete run and independent final replay can establish the narrow
CoreSyntax connection; all twelve wider production obligations remain unproved
and grant no admission authority.

The v7 source/inverse and unchanged-contract suite passed all 29 tests in
194.686 seconds (outer observation 195.175035422 seconds). The independent Lean
positive control passed with four axiom-free subjects; all four target-only
negative mutations exited 1 and were rejected. Their error-recovery sorryAx
output is retained as negative evidence. These results are diagnostics only;
the following frozen candidate requires a separately recorded full terminal
acceptance and final independent replay.

## Version 8: fixed scheduling of existing dependency queries

The first complete v7 acceptance at
`3f0ef24a89bdce70dfa5f5a5ac5d62d5faa6b0cd` failed in CertPart02 at
60.000951165 seconds, after Baseline, SyntaxData and Part01 passed their
102/256/444 subjects. Preparation and all observations totalled 322.677038663
seconds. RESULT SHA256 is
`97fd880faa4bcb259e485c2031117b8b540b2fcac1360ba2410af5206a75a017`,
under the preserved `proof-shared-v7-r1` evidence root. Part02 was byte-identical
to ce1/r5; this run did not reach the new compound references in Part03.
The failed result is retained and is not replaced by a repeat of the same run.

A nonaccepting profile inserted immediate dependency-query markers after the
original Part02 theorem declarations. It finished in 21.933820066 seconds, but
omitted module export and duplicated the original tail queries. It therefore
cannot qualify the stage. A different, bounded diagnostic moved each existing
query to its own theorem without adding or removing any query and included
actual `-o` module export. It used the original process/log/cleanup collector
and hash-verified checked parents. Part02 checked 735 subjects in 27.579669899
seconds; Part03 checked 1,057 subjects in 53.441099143 seconds, including its
154 v7 compound references. Both inventories passed. The complete source,
module, raw-output and parent receipts are retained under
`proof-print-schedule-v8-diagnostic-r1`. This was a nonexclusive CPU4 run,
with a separate NDU experiment on CPU12, and is not a comparative timing claim
or a fresh full-chain acceptance.

Version 8 fixes this query placement for SyntaxData and CertPart01 through
CertPart07. It moves exactly the existing 7,190 transport `#print axioms`
commands immediately after their corresponding theorem declarations. No
declaration, theorem statement, proof body, query, query multiplicity or
non-query source byte changes relative to v7. The source byte count of every
module is unchanged. Baseline and both final consumer modules are unchanged.

The inverse removes the actual query commands, retains every other actual byte
and reconstructs the original sorted query suffix from the actual subject names.
It requires all eleven complete generated module hashes to equal the frozen
v7 files, then replays the v7/v6 and every older inverse. It also requires the
unique forward schedule, exact subject inventory and metadata. Missing,
duplicated, substituted or delayed queries have independent controls. The
manifest binds both the old and new print sequences; the actual fresh process
output must still satisfy the original complete inventory checker.

All eleven registered stages, original declarations, process/source/module/log
caps, 540-second preparation-and-launch budget and 600-second outer limit
remain unchanged. Complete fresh acceptance and the independent final replay
are still required; the twelve wider production obligations remain unproved.

## v9: kernel-checked consumer rewrites and actual combined source closure

This candidate targets the concrete consumer elaboration failures exposed after
v8 completed its first nine stages. Lean generated the original mutually recursive
`rawDecEq` through an irreducible well-founded wrapper. Diagnostic kernel checks
could not reduce even `Raw.str [1] = Raw.str [1]` with that decision procedure.
The original monolithic `decide +kernel` then hid its application-type mismatch
behind a second recursion failure in diagnostic pretty printing. The original
errors, error-recovery `sorryAx`, timeouts, and diagnostic failures remain evidence.

The generic Raw datatype, equality procedures, syntax relation, extractor, and
all original theorem statements remain unchanged. In each positive extraction
proof, universally quantified local theorems rewrite string-tag `if` and
`decide` expressions into constructor matching. Lean checks these theorems by
cases, and separately checks every one of the 58 original relation conjuncts.
The existing whole-tree bounds proof is reused. The three malformed-syntax
rejections project necessary clauses of `extract_sound` (clauses 27, 46, and 17)
and use constructor disjointness. The stale-descriptor rejection uses the
already-checked positive extraction. No native evaluator result is trusted.

The changed-final-byte datum retains its original name, List Nat type, and
complete 14,466-byte value. Its representation shares the actually declared
`linear_g0` and `linear_v0_0` prefix and retains the original final byte 93.
A local, general append-cancellation theorem proves the unchanged rejection
against the original closing byte 125 without repeatedly reducing the concrete
common prefix. This one inert datum is `noncomputable`; its value is still a
transparent kernel definition. All 7,685 original transport data definitions,
4,215 transport theorems, 2,975 auxiliary facts, and the original subject
multiplicities remain.

The inverse consumes the actual candidate theorem headers, actual proof bodies,
actual byte-expression text, and actual earlier List Nat definitions. The already
registered independent `core_byte_facts_dag` grammar and bounded evaluator reject
unknown, cyclic, forward, malformed, or oversized byte dependencies. All prior
byte declarations are read in declaration order, and the 595 definitions reachable
from the original linearBytes root are checked. The complete recovered old
consumer must have SHA256
`4a175bdb55f0a26c6bf8bafe20ddf72752d547f4241239490e8ecef906fe37eb`.
Then the existing v8 print-schedule inverse, v7 exact-bound proof inverse, v6
partition inverse, and every earlier original-source validator still run.
The existing ten negative-source coordinates and all eleven module boundaries
are retained.

The actual combined base is
`d33d559469cb620387c7e2b4bed57e1661a9fa51`, not the independently measured v8
research branch. Its compiler_hash reads all 184 top-level `hepta/*.py` files.
The old 251-path registration omitted five actual byte-read inputs:

- `hepta/hia_byte_sum.py`
- `hepta/hia_entry_layout.py`
- `hepta/hia_ndu_dynamic.py`
- `hepta/hia_ndu_raw_model.py`
- `hepta/hia_ndu_raw_session.py`

The first combined-source control also exposed two omitted direct identity reads:
`experiments/hia_initialization_frontiers_20261103/CORE_MODEL_CONNECTION.md` and
`experiments/hia_initialization_frontiers_20261103/UNSIGNED_STEP_CONNECTION.md`.
Their absence was caught as `unknown/incomplete_extraction`, not as a changed
Core program. Both files are restored byte-for-byte from frozen v8 and included
in the identity. The unchanged four-slice requirement is retained.

The updated plan binds all 258 source paths with canonical commitment
`36af03771b8b81803d90baafc92fd290d9e6cadbb03e7e135a99beae804bb0f0`.
`source_paths()` also compares the actual top-level glob to that registered set,
so a missing or additional Python input is rejected before identity construction.
These five files are byte-read dependencies; this does not assert that their
runtime branches execute in this proof profile.

The 60 s per-process limit, 540 s preparation/launch limit, 600 s outer limit,
eleven processes, source/module/log/cleanup limits, 780 support paths, pinned
Lean binary, and independent complete-evidence replay remain unchanged.
Targeted diagnostics are not full acceptance. Only a fresh complete run on the
exact final combined commit can establish the narrow Core syntax connection.
All twelve wider obligations remain unproved, and all production admission,
Python-exporter refinement, operational-Core bridge, body-prefix refinement,
and broader safety or optimization authority remain denied.
