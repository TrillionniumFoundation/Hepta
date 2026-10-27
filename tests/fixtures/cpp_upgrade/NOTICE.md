# Unmodified upstream release fixtures

The two `json.hpp` files are the exact nlohmann/json release assets for
3.11.3 and 3.12.0. Their official published SHA-256 identities, source URLs,
sizes and per-version MIT license files are recorded in `lock.json`.
No upstream library source has been modified.

These fixtures exercise an actual C++ library upgrade through the same
authored API adapter and generated Hepta bridge. They do not represent a
translation of nlohmann/json into Hepta. System headers and the C++ runtime
remain separate dependencies whose observed identities are recorded during
the qualification.
