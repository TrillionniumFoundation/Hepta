# Worker exception context: original failures and surviving evidence

Implementation commit: `b6c36189fb45adcf26c2528346d14021b9873b05`.
This is development evidence, not matching-source cold or whole-project qualification.

The complete two-module run executed all 33 loaded test IDs: 13 JSON wire
methods and 20 worker report methods. Loaded and executed IDs match exactly;
errors, failures, skips, expected failures and unexpected successes are all
zero. The original run log and report retain the exact denominator, interpreter,
source pins and before/after pin comparison. The unittest log reports 75.426s.

The archive retains the original e65 eight active-exception-context failures,
their r3 fixed observations, the later f9 four ambient-chain failures and their
r4 fixed observations. The new formal ambient-chain method additionally checks
direct and indirect links, UUID/code mutation points, and callback failure
propagation. These controls are independent of the original 19-method r3 run;
that earlier passing run did not contain the later-discovered chain cases.

The HIA policy source is `fb711313a455c6a6c7ab4202a7c3d44a19bd10ccddcad9af36d312f7c40f5104`,
and its development image is `0e1e0c829f303240d28721ed83f86d3153dfdf2ce933320c5763a8358a06d833`.
The r4 source changed the mechanical exception activation bridge and tests;
the policy and wire images were unchanged. The archive includes the actual r3
development bundle and compiler bytes, original request/receipt files, and the
exact source transfer prepared for the separate Python 3.14 probe.

## Original fixture loss during environment reset

The original run's create-only fixture directories were retained and a complete
973-file archive plus member manifest was verified locally. The cloud runtime
then reset `/tmp` before that archive was uploaded. Those fixture files and the
complete archive are lost. `custody.json` records the observed sizes/hashes and
the missing member manifest; it does not claim recovery. The original textual
logs, observations and full run report survived in the workspace and were read
back byte-for-byte. `surviving-originals.zip` is a new archive of those actual
surviving files, not a reconstruction of the lost fixture archive.

All 40 payload members and the included `MEMBERS.json` were read back; payload
SHA256, sizes, inventory and ZIP CRC checks passed. `archive-readback.json`
contains the archive identity. The fixture-directory paths in the original
run report are historical and no longer exist after the reset.

The separate Python 3.14 context probe's first process-start response timed
out. Its execution status remains unknown at this checkpoint. A controlled
file-info follow-up was refused for its path; that refusal says nothing about
the probe's result. No Python 3.14 context success is counted here.

Arbitrary foreign recursive resource-threshold equivalence and foreign-key
stored-hash access on runtimes without the private export remain explicit
limits in the implementation documentation. No retained owner is deleted.
