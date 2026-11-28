# Complete Core v2 source registration

The normal merge preserves all v1 Core sources and adds the separate Core39 v2
implementation. All 59 incoming source files were read back at the exact submitted
hashes. Native source registration adds 42 HIA files and two ABI resources.
The complete source contract adds 51 new paths plus three existing runtime files
that were previously missing from its explicit list. All previous members remain.

The original complete CoreLoweringSourceTests and CoreEmitterSourceTests ran without
method, assertion or budget changes: six passed and two failed. Both failures are the
unchanged unqualified-cold admission assertions. The still-unfrozen generated release
source contract refuses the evolving union before their expected matching-cold error.
These failures remain failures. Their tests and builder validation order are not changed.
The final source contract must be regenerated after the remaining Worker and Runtime
integration, then the same complete eight-method gate must pass.

The initial registration controller also stopped on its mistaken expectation of only
51 missing source paths; the complete actual closure required 54. Its full output and
all before-files are retained. This commit makes no final cold or product qualification
claim. All records in the archive have complete SHA256 and mode readback.
