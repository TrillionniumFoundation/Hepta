# Exact failed Core reader diagnostics — unexecuted draft

This draft reads only artifact **13915070523**, **7,381,515 bytes**, SHA-256
`57e3f0db194d961e64dd4773b04dddf373fe5ca02ea2763924d0ec5040d2a2f8`.
It does not run the previous reader again. Run **43152508792** remains an actual
failure. Its owned read step succeeded; its separate finalizer failed. Three
independent full-log tool reads returned Transport closed. The exact reason is
not yet recovered. The 240-second finalizer and 389-second observed duration
suggest a possible deadline/log-volume issue, but this is not a finding of cause.

## What is read and printed

The worker uses the unchanged official metadata / 302 / independent anonymous GET
functions and the original 900-second owner with 3-second cleanup. It verifies the
complete fixed ZIP digest and reads every allowed member through its full CRC,
SHA-256 and Git-blob digest. The original download and partial download are kept
only after bound closed cleanup. Neither ZIP body enters logs.

The twenty original diagnostic targets are the fourteen previously pinned
authoring control files, the five failed-reader control files and RESULT.json.
Every absent or refused target is listed. A missing RESULT.json is not fabricated.
Historical controls require their exact original hashes. The failed-reader JSON
files must bind its actual run, source control commit, workflow commit, policy
and private root; stdout/stderr must match its bound guardian. The finalizer
rechecks those mappings and the complete ZIP inventory independently.

The 39 assembly files and ABI are observed only through file identity/hash
inventory. No assembly or ABI body is printed. Only fixed flat names and the old
fixed partial-custody aliases are accepted. A single optional original public-root
prefix is explicitly declared; arbitrary ZIP prefixes and paths are refused.

All present original diagnostics plus at most five new diagnostic-control records
must fit **512 KiB raw**. Framing is **8 KiB per chunk** and **1 MiB total stdout**,
with complete per-frame and per-file SHA, manifest and late END after result
readback. Provider timestamps and setup logs are not application frame bytes.
Overflow is HOLD, never truncation. Missing original diagnostics remain explicit;
a completed diagnostic stream never upgrades the original failed operation.

## Review and execution state

This is source only: no Python parse, native compiler, Core VM, product suite or
cold qualification was run. `workflow.template.yml` is outside .github and still
contains `__CONTROL_COMMIT__`. Root review and a separately frozen exact A/B
identity are required before Root creates any execution ref. The old queued
reader and all earlier failure/UNKNOWN records remain unchanged.

The fixed transport, original process guardian and owner are byte-preserved.
File reads and creates use the previously reviewed held-descriptor parent-chain
mechanism from Core control revision 986a. New selection and diagnostic framing
are separate code and have not inherited an execution PASS.
