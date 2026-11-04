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
