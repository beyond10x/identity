//! Additional, operator-selected roots for the ordinary upstream OIDC transport.

use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use openidconnect::reqwest::{Certificate, ClientBuilder};

const MAX_CA_BYTES: u64 = 1024 * 1024;

pub(crate) fn with_ca_bundle(builder: ClientBuilder, path: Option<&Path>) -> Result<ClientBuilder> {
    let Some(path) = path else { return Ok(builder) };
    let file = std::fs::File::open(path).context("open IDENTITY_UPSTREAM_CA_BUNDLE")?;
    let mut bytes = Vec::new();
    file.take(MAX_CA_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read IDENTITY_UPSTREAM_CA_BUNDLE")?;
    ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= MAX_CA_BYTES,
        "IDENTITY_UPSTREAM_CA_BUNDLE must contain between 1 byte and 1 MiB"
    );
    let certificates = Certificate::from_pem_bundle(&bytes)
        .context("parse IDENTITY_UPSTREAM_CA_BUNDLE as PEM certificates")?;
    ensure!(
        !certificates.is_empty(),
        "IDENTITY_UPSTREAM_CA_BUNDLE contains no certificates"
    );
    Ok(certificates
        .into_iter()
        .fold(builder, ClientBuilder::add_root_certificate))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture {
        directory: std::path::PathBuf,
        server: Option<Child>,
    }
    impl Fixture {
        fn new() -> Self {
            let directory = std::env::temp_dir().join(format!(
                "identity-ca-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&directory).unwrap();
            Self {
                directory,
                server: None,
            }
        }
        fn certificate(&self, name: &str) -> std::path::PathBuf {
            let cert = self.directory.join(format!("{name}.pem"));
            let key = self.directory.join(format!("{name}.key"));
            assert!(
                Command::new("openssl")
                    .args([
                        "req",
                        "-x509",
                        "-newkey",
                        "rsa:2048",
                        "-nodes",
                        "-days",
                        "1",
                        "-subj",
                        "/CN=local-test",
                        "-addext",
                        "subjectAltName=IP:127.0.0.1",
                        "-keyout"
                    ])
                    .arg(key)
                    .arg("-out")
                    .arg(&cert)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .expect("openssl is required for the real TLS regression")
                    .success()
            );
            cert
        }
    }
    impl Fixture {
        fn server_certificate(&self, cert: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
            let leaf = self.directory.join("server.pem");
            let leaf_key = self.directory.join("server.key");
            let request = self.directory.join("server.csr");
            let extensions = self.directory.join("server.ext");
            std::fs::write(&extensions, "basicConstraints=critical,CA:FALSE\nsubjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n").unwrap();
            assert!(
                Command::new("openssl")
                    .args([
                        "req",
                        "-newkey",
                        "rsa:2048",
                        "-nodes",
                        "-subj",
                        "/CN=local-provider",
                        "-keyout"
                    ])
                    .arg(&leaf_key)
                    .arg("-out")
                    .arg(&request)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .unwrap()
                    .success()
            );
            assert!(
                Command::new("openssl")
                    .args(["x509", "-req", "-days", "1", "-in"])
                    .arg(request)
                    .arg("-CA")
                    .arg(cert)
                    .arg("-CAkey")
                    .arg(self.directory.join("provider.key"))
                    .arg("-CAcreateserial")
                    .arg("-extfile")
                    .arg(extensions)
                    .arg("-out")
                    .arg(&leaf)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .unwrap()
                    .success()
            );
            (leaf, leaf_key)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Some(server) = self.server.as_mut() {
                let _ = server.kill();
                let _ = server.wait();
            }
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[tokio::test]
    async fn only_the_selected_ca_allows_the_https_provider() {
        let mut fixture = Fixture::new();
        let cert = fixture.certificate("provider");
        let unrelated = fixture.certificate("unrelated");
        let (leaf, leaf_key) = fixture.server_certificate(&cert);
        let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        fixture.server = Some(
            Command::new("openssl")
                .args([
                    "s_server",
                    "-quiet",
                    "-www",
                    "-accept",
                    &address.to_string(),
                    "-cert",
                ])
                .arg(&leaf)
                .arg("-key")
                .arg(&leaf_key)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while std::net::TcpStream::connect(address).is_err() {
            assert!(Instant::now() < deadline, "TLS fixture did not start");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let url = format!("https://{address}/");
        let client = |path| {
            with_ca_bundle(
                ClientBuilder::new()
                    .timeout(Duration::from_secs(3))
                    .no_proxy(),
                path,
            )
            .unwrap()
            .build()
            .unwrap()
        };
        assert!(
            client(None).get(&url).send().await.is_err(),
            "default roots must reject the private CA"
        );
        assert!(
            client(Some(unrelated.as_path()))
                .get(&url)
                .send()
                .await
                .is_err(),
            "an unrelated selected CA must not admit the provider"
        );
        assert!(
            client(Some(cert.as_path()))
                .get(&url)
                .send()
                .await
                .unwrap()
                .status()
                .is_success()
        );
        let wrong_name = format!("https://localhost:{}/", address.port());
        assert!(
            client(Some(cert.as_path()))
                .get(wrong_name)
                .send()
                .await
                .is_err(),
            "adding a CA must not disable hostname verification"
        );
    }

    #[test]
    fn invalid_configured_bundles_refuse() {
        let fixture = Fixture::new();
        let path = fixture.directory.join("roots.pem");
        assert!(with_ca_bundle(ClientBuilder::new(), Some(&path)).is_err());
        for bytes in [
            Vec::new(),
            b"invalid certificate data".to_vec(),
            vec![b'a'; usize::try_from(MAX_CA_BYTES).unwrap() + 1],
        ] {
            std::fs::write(&path, bytes).unwrap();
            assert!(with_ca_bundle(ClientBuilder::new(), Some(&path)).is_err());
        }
    }
}
