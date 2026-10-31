# Conditional cleanup callbacks

These two callbacks are authored Hepta integration applications, **not** files
from Microsoft GSL. The qualification combines each callback with unchanged,
hash-locked GSL 3.1.0 and 4.0.0 headers from `tests/fixtures/gsl_final_action`.
Actual GSL value/move constructors, destructor, and instantiated `finally`
factory are captured and lowered with each callback body.

The original C++ application uses separate entry, consumer and callback
translation units, move transfer, early returns, nested guards and exception
unwinding. Its Hepta integration client still comes from the explicitly authored
`examples/cpp/gsl_final_action/client.hepta`; that client is not claimed as an
automatically translated C++ exception implementation. The expansion here is
bounded const-local and conditional callback semantics, not arbitrary callable
capture, asynchronous lifetime inference or native allocator migration.
