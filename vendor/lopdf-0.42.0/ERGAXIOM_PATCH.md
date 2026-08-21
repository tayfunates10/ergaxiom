# Ergaxiom lopdf 0.42.0 MSRV patch

Source: crates.io `lopdf` 0.42.0 fetched through Cargo and SHA-256 verified against Ergaxiom `main`'s Cargo.lock.

Security: this is the 0.42.0 release containing the bounded PDF array/dictionary nesting fix for RUSTSEC-2026-0187. The parser depth logic is retained unchanged.

Compatibility patch: upstream declares Rust 1.85 but one `BaseEncoding` `let`-chain uses syntax unavailable on Rust 1.85. Ergaxiom rewrites exactly that expression to semantically equivalent nested `if let` statements.

Dependency surface: Ergaxiom disables lopdf default features, so optional `time`, `chrono`, `jiff`, and `rayon` are not pulled into this runtime.

Formatting/provenance policy: the vendored upstream source layout is preserved instead of being bulk-reformatted by Ergaxiom's workspace-wide rustfmt gate. The vendor-local `rustfmt.toml` sets `disable_all_formatting = true`; Ergaxiom-owned workspace members remain subject to the normal formatting gate. Repository `.gitattributes` likewise exempts only this checksum-verified vendor tree from whitespace normalization/checks.
