//! Starts the real `identity` binary with a workstation configuration that names no upstream
//! identity provider.
//!
//! A default build must refuse that configuration exactly as it always has. A `local-login` build
//! must start and open its loopback listener, because the local sign-in form needs no provider;
//! it must still refuse a listener another machine could reach. Nothing here contacts a network:
//! the only socket is an ephemeral loopback listener the binary opens itself.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const AUDIENCE_REGISTRY: &str = r#"{"version":"identity.audiences/2","session":["urn:example:console"],"access":[{"audience":"urn:example:resource-api","scopes":["resource.read"]}]}"#;

/// A fresh private state directory under Cargo's per-target scratch space.
fn database_path(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("{label}-{}-{nanos}", std::process::id()))
        .join("private")
        .join("identity.sqlite3")
}

/// The README's workstation configuration with no `IDENTITY_UPSTREAM_*` variable at all.
fn workstation(label: &str, listen: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_identity"));
    command
        .env_clear()
        .env("RUST_LOG", "info")
        .env("IDENTITY_LISTEN", listen)
        .env("IDENTITY_PUBLIC_ORIGIN", "http://127.0.0.1:8080")
        .env("IDENTITY_TENANT_ID", "local")
        .env("IDENTITY_AUDIENCE_REGISTRY_JSON", AUDIENCE_REGISTRY)
        .env("IDENTITY_DATABASE_PATH", database_path(label))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// Runs a process that is expected to exit on its own, bounded by a deadline.
fn exit_with_stderr(mut child: Child) -> (i32, String) {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let mut stderr = String::new();
            child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            return (status.code().unwrap_or(-1), stderr);
        }
        if std::time::Instant::now() > deadline {
            child.kill().unwrap();
            panic!("identity did not exit within 20 s");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(not(feature = "local-login"))]
#[test]
fn a_default_build_without_an_upstream_issuer_refuses_to_start() {
    let child = workstation("default-no-upstream", "127.0.0.1:0")
        .spawn()
        .unwrap();
    let (code, stderr) = exit_with_stderr(child);
    assert_eq!(code, 1, "{stderr}");
    assert!(
        stderr.contains("IDENTITY_UPSTREAM_ISSUER is required"),
        "a default build still requires the upstream issuer: {stderr}"
    );
}

#[cfg(feature = "local-login")]
#[test]
fn a_local_login_build_without_an_upstream_provider_opens_its_loopback_listener() {
    use std::io::{BufRead, BufReader};
    use std::sync::mpsc;

    let mut child = workstation("local-no-upstream", "127.0.0.1:0")
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (lines, received) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if lines.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut seen = Vec::new();
    let listening = loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match received.recv_timeout(remaining) {
            Ok(line) if line.contains("identity listening") => break true,
            Ok(line) => seen.push(line),
            Err(_) => break false,
        }
    };
    let _ = child.kill();
    let output = child.wait_with_output().unwrap();
    assert!(
        listening,
        "a local-login build must start without an upstream provider; stdout {seen:?}, stderr {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(feature = "local-login")]
#[test]
fn a_local_login_build_without_an_upstream_provider_still_refuses_a_reachable_listener() {
    let child = workstation("local-no-upstream-reachable", "0.0.0.0:0")
        .spawn()
        .unwrap();
    let (code, stderr) = exit_with_stderr(child);
    assert_eq!(code, 1, "{stderr}");
    assert!(
        stderr.contains("serves only a loopback listener"),
        "the loopback-only runtime refusal still applies: {stderr}"
    );
}

#[cfg(feature = "local-login")]
#[test]
fn a_local_login_build_with_a_partial_upstream_still_names_the_missing_issuer() {
    let child = workstation("local-partial-upstream", "127.0.0.1:0")
        .env("IDENTITY_UPSTREAM_CLIENT_ID", "client")
        .spawn()
        .unwrap();
    let (code, stderr) = exit_with_stderr(child);
    assert_eq!(code, 1, "{stderr}");
    assert!(
        stderr.contains("IDENTITY_UPSTREAM_ISSUER is required"),
        "a half-configured upstream is refused, not silently dropped: {stderr}"
    );
}
