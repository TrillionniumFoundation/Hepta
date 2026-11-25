# Native public proof cancellation

The public proof process owns and reaps its normalizer/proof child on SIGTERM,
SIGINT and SIGHUP. Request/reply protocols, all seven packer pieces, the two
8 MiB child limits and the 16 MiB parent limit are unchanged. The proof deadline
profile in `HIA_PUBLIC_PROOF_DEADLINE.md` is unchanged.

The mechanical adapter publishes two fixed code addresses to the HIA owner.
HIA installs the three Linux signal dispositions and an owned GS workspace
base. The fixed handler stores the first received signal and sets a separate
aligned cancellation word to exactly one. It performs no process or proof
policy. The existing qualified preparation-process role receives that owned
word capability; its unchanged cancellation path kills and waits for its own
child and closes captured descriptors. HIA then closes parent-owned images and
streams, restores the original default disposition and re-raises the received
signal. A blocked stdout write re-enters the same HIA close/raise path.

Internal metadata is w136/w144 for the two fixed mechanical addresses, w896
for the boolean cancellation word, w904 for the first signal, and w33824 for
the HIA-created Linux sigaction record. These are private workspace fields,
not caller-selectable executable capabilities. The parent has no live child
while it is still reading the initial request. SIGKILL cannot be intercepted;
this component makes no additional SIGKILL or arbitrary-signal guarantee.

## Actual evidence

Nine process tests send all three signals during actual normalization, actual
primitive proof and a full stdout pipe. Each of the first six pauses its actual
owned child with SIGSTOP before cancelling the parent. Thus natural child
completion cannot satisfy the test. The external observer acts as a subreaper:
no escaped child, adopted zombie or remaining child PID is accepted. Parent
return status is the original signal, and interrupted proof computation emits
no completed receipt. Those six cases complete cleanup in approximately
0.16–0.17 seconds on the measured host. The three output cases observe the
actual full 65536-byte pipe, have already reaped their children, and finish
signal exit in approximately 4–6 milliseconds. Those timings are measured
results, not a scheduling guarantee.

Three additional process-group tests and three incomplete-request tests pass.
The native HIA packer passes 42 extent/capacity/canary checks, including exact
byte reconstruction of this full image. Eight actual syscall-injection tests
cover EPERM/EINTR at GS installation and each signal-disposition installation;
none launches a child or reports a proof. The new full parent also passes the
unchanged original 16 semantic tests and all 113 native proof calls.

The first development handler stored the signal number in the process's
boolean word. Only SIGHUP then matched the qualified role's exact value-one
contract. That defect and the overly weak natural-completion observation are
retained; the corrected test stops the child first. Separate observer failures
assumed an obsolete pipe-wait name and UTF-8 /proc comm bytes. The final observer
uses actual pipe capacity and parses /proc stat as bytes. Neither failure was
fixed by changing product limits, proof assertions or original deadlines.

This closes this cancellation component. Typed public argument adaptation,
remaining public custody/fault integration, multiversion coordination and
final native-only build/installation remain separate obligations. A signal
handler does not establish proof soundness or execution authority.
