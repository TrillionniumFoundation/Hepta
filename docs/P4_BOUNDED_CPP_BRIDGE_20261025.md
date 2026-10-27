# P4: bounded native C++ contract bridge invocation

The `hepta.cpp_contracts._command` entry previously used unbounded
`subprocess.run(capture_output=True)` during C++20 bridge generation.
C++ diagnostics and third-party headers are untrusted inputs and can generate
very large output before the existing timeout or nonempty-object checks fire.

The bridge now reuses the existing `hepta.clang_capture.run_bounded`, with
64KB stdout, 256KB stderr, zero compiler stdin and the command's explicit
timeout (default 90 seconds). Errors remain fail-closed:
output/encoding exceedance -> `E_CPP_CAPTURE`; timeout/launch ->
`E_CPP_ENV`; nonzero compiler exit -> `E_CPP_NATIVE`.
A valid C++ object and Hepta native reference validation are still required.

The command budgets, failure paths and one real C++20/std::vector native
object compilation are covered by `tests.test_cpp_contract_capture`.
An independent local Clang++17 probe compiled that object at the same
budgets and returned exit status 0. Complete Hepta bridge qualification has
not been executed in this isolated container. This is not a compiler sandbox,
general safe C++/STL migration, ABI proof or a production-language completion.
`whole_project_blockers_closed=false`.
