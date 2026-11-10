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

## Explicit compiler-input closure after the cache integration (2026-11-05)

The integrated source `e5f416992e1a81097f9f99135d4bb59bc37f04df` adds
`hepta/hia_result_cache.py` and `hepta/hia_result_cache_audit.py` to the inputs
read by `pipeline.compiler_hash`. Its first complete qualification correctly
stopped in preparation: the previously reviewed 258-path identity did not
contain these files. That failed run remains failed; it launched no Lean stage.

The explicit `ADDITIONS` tuple now includes those two files and
`tests/test_core_seven_shared_source_closure.py`. The new fixed closure is
**261 paths**, with canonical commitment
`5758e93bc7e92d4b10370593c3f20b713741b7530d977507a1430c6eb9cfb0eb`.
Removing exactly those three names recovers all 258 original names and the
unchanged old commitment
`36af03771b8b81803d90baafc92fd290d9e6cadbb03e7e135a99beae804bb0f0`.
The actual top-level compiler inventory is now 186 Python files. It is still
compared exactly against the declared closure: an extra or missing filename
rejects before external identity construction. No dynamic filename admission
or weakening of the fixed commitment was added.

The 780 support paths and their commitment are unchanged, as are all schemas,
eleven Lean stages, subject/negative inventories, byte-reading checks, original
validators, per-file caps and process/cleanup/launch/outer budgets. The five new
filename controls have their own CI job and exact inventory; they do not enter
the historical 46/207/705 inventories. The six existing acceptance-contract
tests retain their IDs and now assert the reviewed 261/186 path counts.

Actual source construction was checked on the integrated compiler inputs
before handoff. `prepare()` passed its unchanged original validation and
negative-coordinate gates in a 59.076-second source-only observation. The
independent frozen count/replace oracle matched every actual print-scheduled
module byte. All eleven existing v10 source hashes and the manifest digest
`373f18422dd9aebcdcd754c05242860fd0b5216533b81e49caaf00909414f990`
remained identical; no generated-source hash or proof statement was updated.
The new filename checks plus the unchanged acceptance tests passed 11/11 with
no failures, errors or skips. The fixed identity encoding also fits the old
144,713-byte file cap; a size check does not authenticate support contents.

These are preparation and regression observations, not a new Lean acceptance.
The final combined source still requires fresh complete eleven-stage execution
and replay under its own exact identity. The earlier failed integrated run
cannot acquire that status from these checks.

## Cleanup receipt consumer repair (2026-11-05)

The shared diagnostic collector records `cleanup_deadline_exceeded` independently
of eventual drain/reap success. Its seven-certificate consumer previously omitted
that field from the exact process schema and the exact setup-start record, so an
otherwise successful real child was rejected. The consumer now retains and checks
the field, including exact Boolean type, the cleanup-incomplete equation, and the
condition that completed captures cannot be late. Byte-facts and the older
partition/declaration capture and presentation paths validate the same cleanup
facts and bind persisted terminal status to its stage and manifest. Unknown seven
process fields remain refused; no collector deadline or output budget is enlarged.

Three fragmentation controls now explicitly set the test-only `READ_CHUNK` to 1:
child writes separated by 2 ms never guaranteed distinct PTY/pipe reads. This
changes neither a production budget nor the original test IDs. The independent
timeout fixture also accelerates only its process phase: its original 100x clock
accidentally reduced the independent two-second cleanup budget to about 20 ms of
wall time. The clock now remains continuous and resumes normal rate when the real
group-kill cleanup starts; the declared 60/2-second limits are unchanged. Existing
mock-only legacy orchestration fixtures now supply internally consistent terminal
cleanup facts instead of placeholder JSON. No mock outcome becomes proof evidence.
The byte-facts/seven fragmentation writers queue finite payloads and remain live
until the collector stops them, with independent finite wall watchdogs. These
quota controls explicitly hold a model clock until the real group-kill attempt,
then resume continuous 1x time for cleanup. Actual reads, writes and fsync remain;
this is no claim of one-second filesystem throughput. The process/cleanup
constants, outer 180s limit and separate real-deadline tests remain unchanged.
Terminal JSON decoding rejects duplicate keys and
non-finite numbers, including exponent overflow, without requiring canonical
whitespace from older valid serializers.
The independent
four-method `test_core_capture_cleanup_replay` module exercises actual child
capture, late real-wait observations, rehashed cleanup lies and the strict seven
round trip. It has its own CI job outside the historical 46/207/705 inventories.

That exact new test filename is added to the fixed source identity closure:
**262** paths, commitment
`aceff8673d12c027792c8bf080afeb5d63c4770103018823c5cd710e3ed6517b`.
Removing it recovers all **261** prior paths and commitment
`5758e93bc7e92d4b10370593c3f20b713741b7530d977507a1430c6eb9cfb0eb`.
All 186 compiler module paths, 780 support paths, schemas, per-file caps, stage
counts, and 180/600-second qualification budgets remain unchanged. These controls
are diagnostic protocol tests, not Lean execution or proof/admission authority.

## Combined S3 verification input closure (2026-11-05)

The combined candidate extends the intermediate 262-path closure above with
three separately reviewed regression modules: structured-source reconstruction,
partition parsing and bounded parallel full-file hashing. The new exact closure
has **265 paths**, commitment
`ffc0f4bd9585328bb21e99d0fe3bac7717b65d823a72cb5de9987886018055db`.
Removing exactly these three paths recovers the 262-path commitment above;
removing all four newly added validation modules recovers all 261 S2 paths and
its original commitment. The five explicit closure controls retain their IDs
and verify that every original 258 path and all 186 compiler modules remain.

The 24 cost controls (10 + 6 + 8) have a separate fixed-inventory CI job.
The four cleanup-replay controls also keep their separate job. All four modules
are included in the actual composition regression command. The original 207,
705 and 46 inventories and workflow bodies remain unchanged, as do the original
36 composition commands, 34 result flags, 780 support paths and all existing
process, cleanup, byte, launch and outer limits.

The source optimizations preserve generated statements and all validation
gates. Full external bytes are reread with at most two hash workers; Lean still
uses one thread. The combined runner registers CPUs 20 and 21 for proof and
replay, including the hashing resource change. No stat-only or cached digest
substitutes for a read. This paragraph is a source registration, not a successful
proof or composition receipt; the exact combined commit requires fresh execution.

## Unified native candidate source closure (2026-11-07)

Candidate `117f568b198894d3e209977adf3b88aa2773af2a` added five top-level
compiler modules without extending the reviewed source identity. The shared
acceptance source controls and initialization frontier closure controls rejected
that candidate with `complete actual compiler_hash input set`. Shared kernel
acceptance then stopped during preparation with zero Lean invocations. Those
failed observations remain failures; this repair does not rewrite their records.

The explicit `P0_P3_ADDITIONS` tuple now binds these exact filenames:

- `hepta/hia_agent_macro_discovery.py`
- `hepta/hia_agent_macro_policy.py`
- `hepta/hia_machine_plan.py`
- `hepta/hia_native_byte_abi.py`
- `hepta/hia_native_byte_runner.py`

The new identity contains **328 source paths**, including all **203** actual
top-level compiler Python modules, with canonical path commitment
`77fb9af75d987acab91d224cf47c5e6734f8c6eb9c4fa895064fba306289a016`.
Removing exactly those five names recovers the historical **323-path** tuple and
its unchanged commitment
`d999ff7dc718330771ddb745dbed6a5a7ecdcdea8f9011e35f0a07417f09b9c0`.
Both commitments are checked before constructing an external source identity;
the earlier projections and all 780 support paths remain fixed. Extra or
missing actual compiler filenames still reject, and each new filename has an
omission regression within the existing five-control inventory.

The maximum canonical identity encoding grows from **156,044** to **156,678**
bytes. Exactly **634** bytes move from the raw-log reserve (**808,560** to
**807,926**) to the metadata reserve (**235,920** to **236,554**). The total
increase over the legacy 239-source identity is **11,965** bytes. The historical
323-source maximum encoding is separately asserted in the budget test. The
one-MiB evidence/display ceiling, 4,096-byte display allowance, source/module
limits, process/cleanup/launch/outer budgets, schemas, proof statements and
eleven-stage inventory are unchanged. The per-identity cap and aggregate
boundaries still reject one excess byte.

These are explicit source registration and accounting changes. Acceptance of
the repaired source requires fresh complete execution and replay at its own
commit; source-control success cannot confer Lean proof or production authority.

## Reviewed native JSON source identity continuation (v11)

The v11 closed identity has 360 source records, including the 217 actual
root-level Python compiler modules. Its 23 explicitly named JSON additions bind
five bridge modules, four HIA application sources and their authoring/build/
driver/conformance inputs. The entire prior 337-path v10 checkpoint and every
older projection retain their independent exact commitments; discovery of an
extra module still refuses rather than broadening the accepted closure.

The maximal identity encoding is now 160,877 bytes. Exactly 3,066 bytes are
transferred from the raw-log allocation to metadata: metadata reserve 240,753,
raw global 803,727, display 4,096; their sum remains 1,048,576 bytes. Source,
module, container, per-stage, process and time caps are unchanged. The v10
identity remains 157,811 bytes in the historical projection. These accounting
controls and finite tests do not grant broader proof or execution authority.


## Reviewed SHA-256 source identity continuation (v12)

The combined native JSON/SHA continuation has 369 explicitly listed source
records, including all 219 actual top-level compiler package modules. Nine
reviewed one-shot/incremental SHA source, loader, authoring, build and test
paths are added. Unlisted or absent package filenames still fail before
external identity construction; no filesystem-discovered permissive list is used.
The complete v11 360-path JSON projection and all preceding projections retain
their exact independent commitments. Protocol v12 never relabels a v11 receipt.

The exact maximal identity is 162,045 bytes. Its extra 1,168 bytes are transferred
from raw logs to metadata: metadata reserve 241,921, raw-log allowance 802,559.
The aggregate evidence/container envelope, source/module/process caps and owner
deadlines remain unchanged. Exact-boundary/one-byte-over tests remain in force.
These are source-identity and accounting controls, not proof of the new hash
algorithm or of whole-stack equivalence.

## Reviewed native JSON CLI identity continuation (v13)

Four explicitly reviewed native ELF packer, authoring, build and conformance
paths extend the exact source set to373records; all219actual package modules
and the frozen369-pathv12SHA projection remain independently pinned. No new
package filename is inferred or admitted by discovery. The current commitment
is `61cbcf8e3082972e390ce512d12abd141c17b5262f324dacb80791bf73712f55`.

The maximal identity is162581bytes. Its536additionalbytes transfer from raw
logs to metadata:242457metadata/802023raw/4096display, preserving1048576total.
Source/module/process/container limits and owner deadlines are unchanged.
Protocolv13does not relabel any earlier receipt or extend proof authority.
## Historical export-fork SHA-256 identity continuation (v12)

The combined native JSON/SHA implementation binds exactly365 source records,
including218 actual root-level Python compiler modules. Five explicitly named
SHA-256 HIA source, loader, generator, builder and conformance inputs extend the
unchanged360-path v11 checkpoint. All older independently committed projections
remain exact; extra/missing compiler modules and reclassified historical
additions are still rejected. This identity addition does not declare Python
rewritten or make the optional SHA payload backend a default.

Maximum identity encoding adds exactly631 bytes to161508. Those631 bytes move
from raw logs to metadata: metadata241384, raw803096, display4096; the sum remains
1048576. All source/module/container/process/time budgets are unchanged. The
standalone selfhost export qualifier remains bound by its own complete support
and release inventories; this shared proof profile does not silently acquire
additional compiler or proof semantics.

## Combined native JSON CLI / export identity continuation (v15)

Five explicitly reviewed export implementation, case, child, qualifier and
conformance paths extend the373-path v13identity to378paths, still including
all219package modules. The independent historical projections remain exact.
The current commitment is
`33d85f096323946e67ae7f9bc7006d1c5996a16234f689c8be83eac33ff2c535`.
v14names a separate source fork; no receipt is relabelled to this combined v15.

The maximal identity is163236bytes. Its655-byte increase transfers from raw
logs to metadata:243112metadata/801368raw/4096display, still1048576total.
Source/module/container/process caps and owner deadlines are unchanged.
Omissions, discovery mismatches, reclassified additions and one excess byte
continue to refuse. This registers actual source and accounting, not general
proof authority or whole-stack implementation equivalence.


## Integrated native observer identity continuation (v16)

Five actual observer implementation/reference/conformance inputs and its
cold-exported protocol document extend the378-path v15identity to384paths;
all219package modules and every prior independent projection remain pinned.
The current exact path commitment is
`5f77c57c507313d1e48179bbcd096dee04e481f071f530f2d8dc9d9cba89acc7`.
Removing exactly these six reviewed paths recovers the unchanged378-path v15
commitment; altered classifications, omissions and unreviewed names refuse.

The maximal canonical identity is164058bytes,822more than the v15maximum.
These822bytes transfer from raw logs to metadata:243934metadata,800546raw and
4096display still sum to1048576. Source/module/container/process budgets and
owner deadlines are unchanged. Identity registration neither proves arbitrary
machine code safe nor establishes whole-stack HIA equivalence.

### Source lexer identity extension (v14 candidate)

The reviewed source identity now has370paths, commitment
`414e724f72c675c8cf7139da0710af16ec4417b4926a334b3f5c3c171b3b44f4`,
including all219actual root compiler modules and five exact native source
lexer inputs. Removing precisely those five paths preserves the historical
365-path SHA-256 commitment; every preceding projection remains independently
checked. Maximum identity162169bytes transfers661bytes from raw logs to
metadata (242045metadata +802435raw +4096display =1048576). No source, module,
process, time, aggregate evidence/container or authority cap is expanded.

## Unified native CLI, observer and source lexer identity (v17)

The integrated tuple adds the five explicitly reviewed source lexer paths to
the 384-path v16 observer/CLI/export identity. It now contains 389 paths and all
220 actual top-level compiler package modules. Its exact path commitment is
`16c29da84032d30fea440763f05f27eebc2e3327f5db9eabd2871d34cd96770c`.
Removing exactly those five paths recovers the v16 commitment; independently
removing the exact incremental-SHA, CLI, export and observer additions recovers
the 370-path v14 lexer fork. The older 365-path SHA identity and every preceding
linear projection remain pinned. Unexpected names, missing actual compiler
inputs and changed addition classifications still refuse before admission.

The maximum canonical identity is164719bytes, exactly661more than v16. Those661
bytes transfer from raw logs to metadata:244595metadata +799885raw +4096display
still equals1048576. All process, source, module, container, per-stage and time
budgets are unchanged. Registering a combined identity does not qualify combined
execution: the merged executable source needs a fresh complete qualification.
