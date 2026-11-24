# Independent Slot consumer and terminal lifetime gate

This gate proves a specific lifecycle contract alongside the original strict
observation gate. It does not replace that gate, change a production reference
count operation, set a GC threshold, insert collection, or authorize a complete
installed release.

## Observations and authority

The existing, frozen original observer still executes every case. The exact
original production methods and the selected native public implementation use the
same declared fake providers. The native lane still goes through the actual
source-bound mechanical capsule and controller.

A separate GDB process reads Python object memory at the original
'observer.consumer_release.end' list insertion. It reads the complete event list,
outcome, SQL effects, complete request packets, fault and unraisable state, and
every registered provider's weakref target, type, and reference count. It verifies
that the original result, args, kwargs, and subject locals have been released.
The observer's original JSON copy then proceeds unchanged.

The probe handles list growth separately: length can change before the new item
pointer is stored, so it follows the C resize return and item store where needed.
It also records the later case-sealed boundary. That later boundary follows the
original allocating consumer JSON copy and is a separate diagnostic comparison.

All object decoding and serialization by the new probe happen in GDB's process.
GDB installs ordinary breakpoints and hardware watchpoints and enables selected
GC probes. The probe makes no target Python calls, creates no target Python
objects, and changes no source file or GC policy. Complete traced raw observation
files must equal the corresponding earlier untraced lane byte for byte. A
difference fails that evidence check; the driver does not rerun until it obtains
a preferred result.

The final release check reads the original observer's separately declared
post-seal GC phase. Every case must have no remaining registered provider
weakrefs and no unraisable exception. No additional collection is inserted.

## Required facts

The semantic_gate passes only when all four complete runs finish naturally,
source and command custody match, the probe matches its committed bytes, the
runtime/layout profile matches, and all of these facts hold:

- All 248 original and 7,574 derived cases run in frozen order in both lanes.
- Every complete traced raw file matches its earlier untraced lane.
- Every external consumer snapshot agrees with the original observer's consumer
  serialization, including every event.
- The full consumer boundary, including provider types and reference counts,
  matches between original and native.
- The original terminal collection releases every registered provider without an
  unraisable exception.
- Actual native controller entries all return, with no retained-method fallback.

The report separately retains the original strict status, its original
comparisons, and every case-sealed difference. A passing consumer/terminal
component does not turn an original strict HOLD into a pass. The CLI exit status
is specifically the consumer/terminal component's status.

## Reproduction

The baseline is the observations directory from the unmodified
SlotMechanicalV5NativeTests.test_00_full_original248_derived7574_original_first_native_v5
run. It contains complete original-first raw captures, command records, source
freeze, native capsule selection, and strict independent readback.

Run from a checkout containing this gate, with a new evidence directory:

~~~sh
/usr/bin/python3 -B tools/qualify_hia_slot_consumer_lifetime.py \
  --root /absolute/path/to/the/baseline-source-checkout \
  --baseline /absolute/path/to/complete/observations \
  --evidence /absolute/path/to/new/external-lifetime-evidence
~~~

The driver runs both complete original groups before either complete native
group. It derives exact target commands and initial environments from the
baseline, preserving the native capsule wrapper, source freeze and compiler
selection. Only the output directory changes. Every command has an owned
process group and a finite deadline; interruption is not a passing result.

The reader can independently recheck existing captures without importing the
production implementation:

~~~sh
/usr/bin/python3 -B tools/read_hia_slot_consumer_lifetime.py \
  --root /absolute/path/to/the/baseline-source-checkout \
  --baseline /absolute/path/to/complete/observations \
  --evidence /absolute/path/to/external-lifetime-evidence
~~~

The labels.json file maps four complete capture directories. It may be supplied
with --labels when reading a preexisting capture. This changes directory names,
not case selection or comparison policy.

The shipped profile pins the independently checked ROG CPython 3.14.4 Ubuntu
binary and GDB binary. It records the actual interpreter, frame, dictionary,
list, tuple, Unicode and weakref layout used by the probe. A different executable
is rejected before a new target is started. A different runtime needs independent
layout verification and a separately reviewed profile, not merely a relaxed
binary check.

## Verified scope on 2026-11-24

The probe's exact committed bytes completed both lanes' 7,822 cases naturally on
source 35068b189a0f9042c64cd7e1cb45d0c0933e9b93, with the separately built native
V5 component. All four raw files exactly matched their untraced baseline.

The full consumer boundary had zero different cases, including every registered
provider's type and reference count. All final registered provider weakrefs were
empty, and all unraisable lists were empty. The native controller returned all
12,072 entries for original248 and all 337,820 entries for derived7574, with no
retained-method call.

Ten derived cases still differed at the later case-sealed boundary. The
unchanged original strict reader retained 15 different derived cases / 75 leaves
and HOLD. Selected-case GC stacks directly show collection occurring inside the
original observer's JSON encoding or decoding. Collection during the first copy
can change the later seal state; collection during the final copy can change the
raw final event record.

The repeat controls must be described precisely. Original-versus-original
same-command repetitions matched. Native same-source repetitions differed in
12 cases when only the output directory changed. Separate original-only runpy
driver and preload controls changed 3, 15 or 16 cases. These are distinct observed
conditions; they are not a claim that every identical original invocation is
nondeterministic.

## Limits

This is a source-bound, explicit development component gate with declared fake
providers. It does not establish installed-worker, service, CLI, network, release
installation or complete repository closure.

Reference counts, registered weakrefs and matching boundary behavior do not
enumerate arbitrary C-stack ownership or prove absence of every possible
unregistered object leak. The separate heap ownership regression and selected
post-DECREF graph diagnostics retain their own scopes. The old strict gate
remains open wherever its unchanged report says HOLD.
