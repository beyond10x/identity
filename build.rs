//! Publishes one fact `src/lib.rs` uses to refuse the `local-login` feature outside a development
//! build: whether this profile optimizes.
//!
//! The `local-login` feature mints an Identity session for a typed mailbox with no upstream
//! provider, so it must never reach a shipped artifact. `debug_assertions` alone cannot enforce
//! that: `RUSTFLAGS='-C debug-assertions=yes' cargo build --release` forces the assertion back on
//! in an optimizing profile, which cleared the language-level guard and let the route compile.
//!
//! `OPT_LEVEL` cannot be forced the same way. Cargo derives it from the resolved profile before it
//! spawns rustc, and `RUSTFLAGS` codegen flags never feed back into it — a build script reads the
//! profile's optimization level, not the flags an attacker adds. Every shipped artifact optimizes
//! (`opt-level` is not `0`); only a development build leaves it at `0`. So the presence of
//! `optimized_build` is a truth about the artifact that no environment variable, `RUSTFLAGS`
//! entry, or custom-profile assertion override can undo.

fn main() {
    // The output depends only on this script and the profile's optimization level.
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-env-changed=OPT_LEVEL");
    // Declare the cfg so `unexpected_cfgs` stays quiet under `-D warnings`.
    println!("cargo::rustc-check-cfg=cfg(optimized_build)");

    let opt_level = std::env::var("OPT_LEVEL").unwrap_or_default();
    if opt_level != "0" {
        println!("cargo::rustc-cfg=optimized_build");
    }
}
