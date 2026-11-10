# Core admission cost: measured optimization, unchanged qualification

The retained GitHub run 42812866277 on commit
`a4fa435cb641df1eee88cde1ae2e85b6e0733686` failed the original
180-second cold qualification deadline. Artifact 13762513077 records 32
completed passing phases and six incomplete phases, not a qualification pass.
All 325 exported source payloads and all 17 independent reference payload
digests were checked against the corresponding local source and references.
The remote names reference took 29.823 seconds, versus 14.357 seconds locally.
Other timing differences prevent attributing the entire timeout to one function.

A separate read-only `cProfile` run of the same names reference identified
5.924 million `_json_string_bytes` calls and 51.8 million `ord` calls. Its
profiled wall time is diagnostic overhead, not comparable qualification timing.
The reference payload digest remained identical.

This change counts safe ASCII JSON string bytes without a Python character
loop. The original lower-bound refusal is still first. Unsafe ASCII and all
non-ASCII strings retain the original exact escape, UTF-8 and surrogate checks.
It does not allocate an encoded copy, cache admitted objects, skip a verification
pass, or alter byte/node/depth limits. Independent tests compare actual stdlib
JSON wire lengths, exhaustive ASCII pairs, Unicode width edges, surrogates and
pre-encoding refusal, in addition to the existing mutable-snapshot controls.

Fresh independent reference workers now start the measured longest families
first. Every family is still computed in its own process and completed before
B0; source manifests, payload and PID checks are unchanged. The two-worker
budget and native qualification phase ordering are unchanged. The original
180-second deadline, three-second cleanup budget, native witnesses, process
controls and resource limits remain unchanged.

These changes are hosted admission/reference optimizations, not replacement of
the host bridge. A local speed measurement does not establish a remote fix;
only actual fixed-source remote evidence can qualify that environment. Core
installation, persistence, modules/build and whole native delivery obligations
remain open. Prior failed qualification artifacts are retained unchanged.
