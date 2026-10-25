# P0/P4/P6 source-bound integration hardening (2026-10-25)

Exact upstream PR #48 commit: e84fba15b347a9e23b0d6e607224031668d8207f.
This is an incremental Draft contribution, not a language-release qualification.

## P4: hidden C++ preprocessing

The strict cpp2hepta L1 pilot had rejected lines beginning with # but not the
equivalent C++20 %: preprocessing digraph. Clang also accepts directives after
comments and directives formed by physical line splicing. These forms were
reproduced with real Clang 17 at -std=c++20 -Werror.

Since this L1 translator has no build-configuration or preprocessor capture,
any # or %: token sequence or backslash-newline in the source now rejects
conservatively, even inside comments/strings. More permissive handling
requires a project-aware source-identity and macro model.

## P6: canonical semantic evidence

The existing read-only Agent semantic query previously checked that HSIR
supplied a 64-character SHA-256 string, not that the hash matched its payload.
It now recomputes the digest using the sole canonical semantic IR serializer,
requires the known v0 prototype claim flags to be false, and rejects malformed
native-validation metadata as a structured WorkspaceError.

## P0: bounded qualification

The exact-head workflow runs the C++ L1 and Agent semantic-inspection test
suites including the new negative controls. A scoped success is not equivalent
to the full release gate on the new integration HEAD. None of P0-P7 or P01-P12
is marked complete by this change. whole_project_blockers_closed=false.
