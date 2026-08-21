# Ergaxiom lopdf 0.42.0 MSRV patch

Source: crates.io `lopdf` 0.42.0 fetched through Cargo and SHA-256 verified against Ergaxiom `main`'s Cargo.lock.

Security: this is the 0.42.0 release containing the bounded PDF array/dictionary nesting fix for RUSTSEC-2026-0187. The parser depth logic is retained unchanged.

Compatibility patch: upstream declares Rust 1.85 but one `BaseEncoding` `let`-chain uses syntax unavailable on Rust 1.85. Ergaxiom rewrites exactly that expression to semantically equivalent nested `if let` statements.

Dependency surface: Ergaxiom disables lopdf default features, so optional `time`, `chrono`, `jiff`, and `rayon` are not pulled into this runtime.
