# One original R20 fresh admission: authored execution package

This package is authored and statically checked, not executed or published.
It observes one call to the original tools.build_hia_json_preflight.current_sources.
There is no warmup product scan, business test, compiler invocation, Native image,
VM, provider replacement, memo, clock adjustment, or automatic retry.

The source checkout is exactly 26fd6c4c1a71dc970ae11b00c8a9ff74c5c8508d,
tree 84df4b42f1e20fd7d0c7229e658cf3b458984ffb, all 3,177 source files.
The source manifest and 1,551-file fresh map are original actual archive bytes,
checked against both complete historical source snapshots and their prior
readback. They describe 58,637,295 fresh file bytes. The historical expired
method still failed; this diagnostic does not repeat it or repair its deadline.

inputs/EXECUTION-INPUTS.json is the executable observer input schema. Its
function_source has exactly bytes, git_blob and sha256; the old author PLAN is
preserved separately and is never passed as --inputs. The derived inventory
markers are 1795/1800 and the expected fast-path guard count is 1,823.

The run_case function is byte-for-byte the original diagnostic supervisor:
one remaining shared 1,800-second child wait, original 3-second timeout cleanup,
same process-group check, original environment and -B launch. This supervisor
does not assert ECHILD or use a subreaper. The original two 30-second Clang/ld
version probes remain before the group clock; Linux x86-64, Python 3.14.4, Z3
4.15.4.0 and workflow installation pins remain unchanged. Neither probe compiles
a product. Parent and child source guards read complete source bytes and warm
filesystem caches outside measured product intervals; no uninstrumented
3-second/5-second deadline result or performance improvement is inferred.

The observer is the exact Root-authored cb72677174d33fc858f3e4f105928d1fce1c0cd4
version, including terminal save handling. Missing C events, unmatched frames,
provider/source drift, timeout, incomplete output, cleanup or saving errors
remain failures. The parent requires both the real exit code and child report;
a report written before a later stdout failure cannot override the failing exit.
There is one child launch attempt and no retry path.

The workflow differs from the previous actual diagnostic only in five labels:
workflow name, dedicated push branch, job id, observation step label, artifact
name. Both checkouts, exact source ref, Python setup, complete Clang/GPG/apt and
pip blocks, command, 40-minute job limit, always upload, artifact paths and
retention stay byte-for-byte. No branch/ref/CI operation is authorized by this
package. A separate explicit Root authorization is required for publication and
the single execution; Surface remains the designated publisher.

Future command from the workflow work directory:

    python -B harness/tools/run_phase.py --source source --harness harness --evidence evidence

The evidence directory must not exist. Raw PROCESS.json/stdout/stderr are under
evidence/case-0; observer reports/events/current map are under
evidence/case-0/observations. Source/harness before-after and supervisor REPORT
remain at evidence/. The workflow always uploads evidence and all harness
inputs/tools, preserving failures. It never uses continue-on-error.
