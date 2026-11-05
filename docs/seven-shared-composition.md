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

## v10: final wrong-arm rejection and repeated reference construction

The first fresh combined v9 run at
`2d964d27b068b3eb0b19e72ea4132eefd12d4360` passed the first ten registered
stages, including all 75 consumer subjects in 15.381031663 seconds. WrongArm,
the eleventh stage, exited 1 after 4.007495654 seconds. Its original monolithic
`decide +kernel` produced a kernel error, followed by diagnostic pretty-print
recursion failure and error-recovery `sorryAx`. This was a proof failure, not
a time-limit failure. The actual run stopped before final reconstruction and
independent replay. Its inner wall time was 495.656681267 seconds; the outer
observation was 496.094883981 seconds. The failed RESULT SHA256
`f3bb324d8ef1ea9cdea2b079f9eb0f541f3028a2a7c418b2ce4b9feb9d74206f`
and every source, process receipt and error are retained.

Version 10 preserves the complete original wrong-arm implementation, including
its deliberate then-to-else edge mutation, the original hint and the exact
negated target. A local universally quantified theorem derives equality with
the proposed descriptor from any successful extraction. Projecting the
descriptor's actual `incoming` field then contradicts the original target's
field. The finite field inequality is checked by the pinned Lean kernel; no
native evaluator or unchecked lemma is used. The corrected complete module
passed a nonaccepting, same-parent diagnostic in 5.156632080 seconds with only
`propext` and `Quot.sound`. An earlier diagnostic failed because the local
Descriptor type name was not qualified in the reopened namespace; that failure
is retained too.

The source inverse replaces only this fixed proof body, uses the actual target
header, and requires the complete recovered WrongArm SHA256
`19c5e8a8725026a2eed1910920a9c28d6e80436b3cdaa8afdd6fd4ce2b94c3cc`.
The proof has one source line, so original rejection coordinates, module graph,
subject counts and the generic extractor remain unchanged. After this recovery,
the existing consumer, query-scheduling, compound-proof and every older source
inverse still run.

A separate pure-Python diagnostic reconstructed the actual v9 source evidence
in 104.201129023 seconds. A finer diagnostic found that one generated
seven-source reference took 27.227843006 seconds, including four original-plan
validation calls and twenty complete structured-input checks. Those diagnostic
costs are not evidence that the failed v9 run reached or timed out in final
replay; it did not reach that phase.

The acceptance plan now constructs this untrusted ancestor reference using
`_reference_seven`. The private helper derives the same eleven source files and
the same manifest bytes without issuing an acceptance result. The public legacy
builders and validators are unchanged. In both preparation and actual-evidence
reconstruction, the complete actual candidate still reaches the existing
shared-to-nocode-to-relocated inverse. That inverse separately invokes the
original seven-source validator on the reference and on the separately recovered
actual candidate. Both gates remain mandatory, and the original byte-fact,
Raw/input, manifest, subject and dependency checks still execute. Regression
controls compare every reference source and manifest byte against the old
public builder and inject failures at each of the two actual old gates.

The structured-input checker also preserves its exact List Nat type, range and
expanded-length checks while performing its element identity scan through
`operator.is_`, `type`, `map` and `itertools.repeat`. Only exact builtin ints
reach `bytes` conversion. Boolean values, integer subclasses, custom metaclass
equality and custom `__index__` conversions remain rejected without invoking
those user callbacks. The original per-alias `MAX_BYTES` check, all Raw checks,
and all later complete-value comparisons remain. No acceptance Boolean or
cross-validation result is cached.

An independent fixed-order diagnostic ran all five actual inputs once through
the old checker, an id-set candidate and an identity-map candidate. The totals
were 3.581398293, 3.739137027 and 2.929904012 seconds respectively. All fifteen
complete outputs matched the frozen original outputs; all 45 type/boundary
controls passed, including 39 actual full-verifier fault injections. This is
exploratory diagnostic evidence, not a statistical performance qualification.
The identity-map candidate is used; the slower id-set candidate is retained as
an unselected experiment.

The CI workflow now calls the shared full-acceptance and independent-replay
entry points. A separate source-controls job executes the fixed 43 test IDs
from the two shared test modules, records collection/start/finish IDs, and
rejects skips, expected failures, unexpected successes or incomplete execution.
It checks the exact clean commit before and after the suite, retains failure
output, and acquires no Lean checker. Its source-only results grant no proof or
production authority. The kernel job keeps its original fifteen-minute job
limit and the unchanged eleven-process, 60/540/600-second protocol. The actual
258 source paths and their frozen path-set commitment remain unchanged.

After the test child exits with code zero, a separate Python process requires a
complete successful RESULT with the fixed 43-ID commitment, exact collected,
started and finished inventories, zero failure/skip counts, and matching clean
source identities before and after execution. Missing, malformed, duplicate-key
or incomplete JSON is rejected. The inner runner records BaseException failures,
but that is not a substitute for the external receipt check. Both Z3 version
checks use explicit exit codes and remain effective under Python optimization.
A synthetic clean-Git diagnostic exercised the actual inline runner and receipt
gate under `-O`: all 25 expected outcomes were observed, including rejection of
SystemExit(0), os._exit(0), missing or damaged receipts, incomplete IDs and changed
source identities. These are source-control fault tests, not a CI execution or
kernel acceptance claim.

The local complete 43-test suite passed with every fixed ID collected, started
and finished, no skips or expected failures, and unchanged measured source.
A separate nonexclusive diagnostic measured actual preparation at
67.758620305 seconds and reconstruction of all 23 actual source artifacts at
61.603523611 seconds. Both retained all source inverses and all 258 input hashes.
This diagnostic ran no Lean and measured one reconstruction. The full qualifier
still performs both its finalization reconstruction and the independent
evidence-replay reconstruction inside the original 600-second limit; neither is
omitted or inferred from this timing diagnostic.

The final combined commit still requires a fresh full acceptance and independent
replay. All twelve wider production obligations remain unproved.

## Literal source indexing after the full v10 run

The desktop run at b47ce924 completed all eleven fresh Lean stages, including
the original wrong-arm negation. Finalization wrote its inner RESULT after
558.870179933 seconds. The subsequent internal evidence replay did not finish
before the unchanged 600-second overall deadline: the actual qualifier exited
124 after 600.079463180 seconds. The inner passed record is not an accepted full
run. A separate later evidence replay completed in 73.055962129 seconds; it
does not retroactively turn that deadline failure into success.

One bounded cProfile diagnostic then completed both actual preparation and
reconstruction in 274.529666898 seconds, with all 23 source artifacts and all
258 input hashes unchanged. Its 146.070123766-second preparation and
127.548251013-second reconstruction include profiling overhead. Each phase
still executed forty structured-source verifications, two seven-source gates
and two byte-fact gates.

The two selected hotspots repeatedly scan complete strings: scheduling each
query used a whole-module count and replace, and each auxiliary name was checked
against the entire original source for declaration collisions. The implementation
now indexes every literal `def ` and `theorem ` marker from each actual source.
Candidate keys stop at a literal ASCII space; exact full-string matches still
decide the result. There is no identifier normalization, line anchor, word
boundary, or cached acceptance result. Empty names, Unicode, embedded markers,
and names containing spaces retain the original substring semantics.

For ordinary unique independent theorem spans, query scheduling builds its
result once from the original source slices. Explicitly noncanonical raw text,
self-overlap, or intersecting spans automatically use the original sequential
count/replace behavior. This fallback has no caller-selectable mode, catches no
unrelated validation error, and cannot hide missing or duplicated ordinary
declarations. The original inverse, fixed hashes, source byte counts, query
inventory, actual reference and recovered-candidate gates all remain.

The original 43 source controls remain, with three added controls for literal
occurrences, automatic fallback parity with an independent old-algorithm oracle,
and exact equality of all eleven v10 module hashes and manifest bytes. The
actual modules must use the indexed path. Both CI inventory checks now bind all
46 IDs; kernel, source-control and evidence budgets are unchanged. The fixed
old-then-new cost comparison and final integrated qualification are separate
evidence, with no repeated qualification attempt chosen for timing luck.

## Restricted data parsing after the full v11 run

The desktop qualifier at 0c8a91003aee2732308bb654d0e1f941ae561728 again
completed all eleven fresh Lean stages. Its inner RESULT was written after
553.393567603 seconds, but the whole command exited 124 at
600.047503236 seconds before the internal evidence replay completed. The
separate later replay completed in 55.874570337 seconds. These are distinct
observations: the original full run remains a deadline failure, and no stage
results from separate attempts are combined into acceptance.

The existing complete cProfile identified the original Raw-string predicate
and expression lexer as further repeated work. In each profiled phase, the
string predicate performed 13,411,832 Python generator steps. Five retained
real inputs contain 2,510 fully literal decimal-list definitions out of 7,685;
their spelling uses commas with no whitespace. This covers about 64.55 percent
of decimal tokens in their right-hand sides. Counts and profiled times identify
a candidate; they do not predict a completed run within the budget.

For exact parser-created Raw objects, string conversion checks an exact
builtin list and exact builtin integer identities before constructing bytes.
It rejects constructor range/overflow errors with the original Raw-string
domain error, then checks the original allowed ASCII bytes using a C-level
deletion filter. The accepted range is still 32 through 126, excluding 34 and
92. Empty strings remain valid. No length cap is added, and no user integer
conversion, metaclass equality, or list-subclass iterator is admitted. A
non-exact Raw subclass keeps the original attribute-read sequence and errors;
the other Raw constructors are unchanged.

The expression parser has one strict fast sublanguage: an exact builtin string
containing either an empty list or a comma-separated list of canonical
nonnegative ASCII decimal integers, with no whitespace. Each number is either
zero or starts with 1 through 9. A full match creates a fresh list with the
original Python integer conversion; its integer range and overlong-digit
exception are unchanged. Every nonmatching spelling uses the entire original
lexer, including leading zeros, Unicode whitespace, constructors, aliases,
append/cons operators, and nested lists. No exception is swallowed, no JSON
parser broadens the grammar, and no parsed value or acceptance result is cached.

Three new controls compare the string domain and subclass reads with the frozen
old conversion, compare the strict sublanguage and fallback with an independent
copy of the old lexer, and run the complete verifier on all five actual inputs
with both implementations. The existing 46 controls remain, including both
mandatory old validation gates and exact eleven-module/manifest equality.
Both CI inventory checks now bind all 49 actual test IDs. All source inverses,
actual-byte hashes, theorem statements, subject multiplicities, eleven stages,
and 60/540/600-second limits remain unchanged.

The fixed old-then-new cost diagnostic and fresh qualification of the next
combined commit remain separate requirements. No success is inferred from the
restricted fast paths. All twelve wider production obligations remain open,
with DENY_ALL authority.
