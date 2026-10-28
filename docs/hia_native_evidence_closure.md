# Native mapping and measurement cleanup evidence

The earlier reconciled source qualification retained two explicit evidence
limitations: a separate background measurement runtime had no post-close
snapshot, and the adaptive/owned-state scalar image mappings were checked at
admission but not serialized individually. The earlier records remain unchanged.

`AdaptiveRuntime.snapshot()` now returns a detached `native_images` inventory.
Each admitted token includes its Core identity, artifact identity, state identity,
and the actual kernel mapping observation obtained before the first native call.
The mapping records its checker implementation digest, device/inode, file length,
kernel seal mask and entry offsets/permissions. This is an admission-time
observation; it does not claim to be a fresh mapping scan at snapshot time.

The adaptive and owned-state qualifiers retain both scalar image observations
and compare each to the still-open descriptor used to retain the actual binary.
The owned-state driver keeps its separate export mapping receipt. The optional
fresh-deployment measurement also retains its own two scalar image observations.
Copies returned to callers cannot change internal mappings or grant execution
authority. Closed runtimes have no active image capabilities in the inventory;
their release receipts separately report closed, unknown and pending states.

The background qualifier now reads and checks the measurement runtime after its
context has closed. A successful result requires no remaining generations, zero
pending resources, and observed native/identity release plus directory absence.
That additional measurement retirement is reported separately from the main
runtime's retirements. Unknown release is a failed qualification, never an
inferred successful cleanup.

These additions improve evidence for the declared Linux native profiles. They
do not prove that arbitrary foreign libraries are safe, that all process-wide
loader references have disappeared, that removed pathnames can never be
recreated, or that a serialized mapping receipt authorizes deployment.
