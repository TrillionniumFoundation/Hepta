# Original cold timing audit

This is read-only analysis of the preserved exact608 desktop r2 failure, plus separate custody of two accidentally triggered evidence-branch CI runs. No product was rerun, no remote request was made, and no deadline, phase, reference or evidence requirement changed.

## Measured facts and limits

The desktop run still ends in HOLD: source354/354 passed, but the inner cold owner timed out under the original180-second budget. Its original index has26 completed sealed stages out of38. The subsequent full retained discovery did not execute. All original records remain unchanged in parent6156635db138a571d57feaedd4bcc3e19bf89eea.

The first phase starts73.137309847 seconds after the recorded qualification-start event. The six individual generation receipts total8.127982230 wall seconds and7.676193621 native seconds. This is not a measurement of the whole B0/reference/observer preparation interval. The17 original reference worker reports and B0/observer receipts are the next missing inputs; no durations are invented for them.

Each chain worker occupies about24.8 seconds. Their archive completions lag by3.64 and6.76 seconds, but the next owned workers already started before either chain archive finished. The existing archive lane is already separate and bounded. Adding archive tail delays to worker times would overstate the serial path. In the fully observed73.1373-to151.7013 interval, only3.96261 worker-seconds of the two slots are unoccupied by phase children; this includes all host validation and process transition time, and does not mean CPU idle or archive-only overhead.

The26 sealed directories comprise1,233,294,661 original bytes and22,318 files, compressed to26,241,542 bytes. This analysis reads their original process receipts; it does not independently replay the binary phase archives again.

A separate exact75-by-two prefix A/B, retained at448e06ef8a90b284d98631ba0e09512ec91445a8, observed7.765729965 seconds for the original transport and3.344434360 for the HIA observer. The4.421295605-second difference belongs to that later development experiment and is not substituted for this failed run or a complete cold qualification.

## Unreplaced CI outcomes

The existing primary run43055732930 completed cold in99.255905195 seconds, and PR run43055748691 in130.805543727 seconds. The PR actually checked out synthetic merge d1a26b4a63f93ec6f54805da75f960226ac5d0eb with the same e7c29a source tree. The additional exact608 source-custody-branch run43055736686 still failed at180.178098861 seconds with34 of38 phases. All three remain separately preserved in60aeeff4c56b4827ce36ffa4b31ea91fc5345c4d.

Two prior evidence commits unintentionally triggered ordinary CI because their messages lacked [skip ci]. This folder preserves the actual different heads, trees, events, steps and all four returned decoded job logs:

- 43083500067: f53540a5798d1e15d510678706b462f3e202b186 / tree1c6eddc08a0b5fb4f417331d4cf9a1dc172f9cfd. Source354 passed; native cold failed6/11 and downstream product steps were skipped.
- 43084835552:6156635db138a571d57feaedd4bcc3e19bf89eea / treecd4efae11dd0e80e3ea317b5a5546c5725f25291. Both source and native jobs ended SUCCESS; the log reports cold11/11.

Both trees preserve every original608 leaf byte and mode, but neither head or complete tree is608. These events do not replace the original desktop result. Their raw artifact metadata is retained here; the two ZIPs have not been downloaded or replayed by this analysis. GitHub currently reports expiration on2026-11-18. No retry was requested and no favorable outcome was selected in place of a failure.

## Files

- CAUSE.json binds every claim to exact original report blobs and15 actual source files.
- PHASE-INTERVALS.json lists the26 original worker/archive intervals on their common monotonic clock.
- EXISTING-ORIGINAL-READ-PLAN.json is an unexecuted list of exact existing paths to resolve missing preparation timings.
- extra-ci/ contains returned REST bodies, decoded job logs with their original leading BOM retained, and a separate terminal summary. These are returned decoded API text, not an independently downloaded logs ZIP.
- MANIFEST.json binds all new file bytes and Git blobs. No existing source, test or original report is changed.

No hardware, OOM, throttling, host-load or compression-only cause is inferred. The duplicate discarded frame in native_observer.invoke is a source-level small optimization candidate without measured savings; early refusal, foreign byte-subclass behavior and complete transported/raw observations must be preserved before it can be accepted.
