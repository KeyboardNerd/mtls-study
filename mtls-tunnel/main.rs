use clap::Parser;
use std::io::BufReader;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio_rustls::rustls::{
    self, Certificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

// ----- CA -----
const CA_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBYTCCAQagAwIBAgIUGpagj2/D3XrMffJ9oDeuCFk2LCQwCgYIKoZIzj0EAwIw
FTETMBEGA1UEAwwKZXotbXRscy1jYTAgFw03NTAxMDEwMDAwMDBaGA80MDk6MDEw
MTAwMDAwMFowFTETMBEGA1UEAwwKZXotbXRscy1jYTBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABKnkXf692S/Fsmbd3SIvDqOQGVw4WoaMTbEuFMI/MhTIGufgnyeD
5w2T66MW+HVUIWQdqpdg6g2ITcD2NAkwWpOjMjAwMB0GA1UdDgQWBBQalqCPb8Pd
esx98n2gN64IWTYsJDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0kAMEYC
IQCb/ibWoNqSbX1eEshCIM/m8bapHYC7NlyvM7DXvEkInQIhAPBYvT4TTPsBKE2N
Mf0LLrGQjGkP9rOr6lD5P2du4pi9
-----END CERTIFICATE-----"#;

// ----- Server -----
const SERVER_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBUjCB+qADAgECAhUApUaQrApR/cJmCBq46CU/YVUVRJUwCgYIKoZIzj0EAwIw
FTETMBEGA1UEAwwKZXotbXRscy1jYTAgFw03NTAxMDEwMDAwMDBaGA80MDk2MDEw
MTAwMDAwMFowFTETMBEGA1UEAwwKc2VydmVyLnRjYTBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABFbm/qUU2fRzId/ZYx85Wyxlp2dFXONTZEV1VKlhZR8uccDsgUCY
HAgBWuue/f98XehiVEHA3HblDCRnh9N4P+6jJTAjMCEGA1UdEQQaMBiCCnNlcnZl
ci50Y2GCCnNlcnZlci50Y2EwCgYIKoZIzj0EAwIDRwAwRAIgGnRfawSlnzC1nYM+
XrfyJlw8kV95t/Ygmb7+TZSmAw8CICesttA0jqyxmvOuBP1oLeG0OsovKPH9U/ku
fSmlOH0y
-----END CERTIFICATE-----"#;
const SERVER_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgRBHt2agKZVIq6uLw
uH9kbbtsi3jCGN3DN6X3DUDceXehRANCAARW5v6lFNn0cyHf2WMfOVssZadnRVzj
U2RFdVSpYWUfLnHA7IFAmBwIAVrrnv3/fF3oYlRBwNx25QwkZ4fTeD/u
-----END PRIVATE KEY-----"#;

// ----- Client -----
const CLIENT_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBUzCB+qADAgECAhUA1049hLKjtjJeCkVkAAeeoA9YEngwCgYIKoZIzj0EAwIw
FTETMBEGA1UEAwwKZXotbXRscy1jYTAgFw03NTAxMDEwMDAwMDBaGA80MDk2MDEw
MTAwMDAwMFowFTETMBEGA1UEAwwKY2xpZW50LnRjYTBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABCl+xSpLzp8LgDHl8j+w3bfJzlh7tw99NtFCEcCLYdV86eULRuKb
fMtwtOLH8v2YPgYcb3vKE94ArdX3mv8iK72jJTAjMCEGA1UdEQQaMBiCCmNsaWVu
dC50Y2GCCmNsaWVudC50Y2EwCgYIKoZIzj0EAwIDSAAwRQIgBNRRPBGKzr7JPYL7
N8QdkPY+LOW04ELuFuw+O0qNY+0CIQCLtcU7QUWs2b97dr1aRe8iKYDP7jvIxLDC
QAAkxkbMAg==
-----END CERTIFICATE-----"#;
const CLIENT_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgvGStdUjaQG3cghOF
lSq3koM56YBmG+QhDEWfJ0eEryihRANCAAQpfsUqS86fC4Ax5fI/sN23yc5Ye7cP
fTbRQhHAi2HVfOnlC0bim3zLcLTix/L9mD4GHG97yhPeAK3V95r/Iiu9
-----END PRIVATE KEY-----"#;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long, value_parser)]
    role: String,

    #[clap(long, value_parser)]
    uds_path: String,
}

fn load_certs_from_pem(pem: &str) -> Vec<Certificate> {
    let mut reader = BufReader::new(pem.as_bytes());
    rustls_pemfile::certs(&mut reader)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect()
}

fn load_key_from_pem(pem: &str) -> PrivateKey {
    let mut reader = BufReader::new(pem.as_bytes());
    let key = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .unwrap()
        .remove(0);
    PrivateKey(key)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.role == "server" {
        // Server Mode (Side B)
        let _ = std::fs::remove_file(&args.uds_path);
        let listener = UnixListener::bind(&args.uds_path)?;
        println!("Rust Server listening on {}", args.uds_path);

        let cert_chain = load_certs_from_pem(SERVER_CERT_PEM);
        let private_key = load_key_from_pem(SERVER_KEY_PEM);

        let mut ca_store = RootCertStore::empty();
        for cert in load_certs_from_pem(CA_CERT_PEM) {
            ca_store.add(&cert)?;
        }
        let client_verifier = rustls::server::AllowAnyAuthenticatedClient::new(ca_store);

        let config = ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(Arc::new(client_verifier))
            .with_single_cert(cert_chain, private_key)?;
        let acceptor = TlsAcceptor::from(Arc::new(config));

        loop {
            let (stream, _) = listener.accept().await?;
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls_stream = match acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("TLS Accept error: {}", e);
                        return;
                    }
                };

                println!("TLS Connection established!");
                let msg = b"Hello Client";
                tls_stream.write_all(msg).await.unwrap();

                let mut buf = [0u8; 1024];
                let n = tls_stream.read(&mut buf).await.unwrap();
                println!("Server received: {}", String::from_utf8_lossy(&buf[..n]));
            });
        }
    } else {
        // Client Mode (Side A)
        let stream = loop {
            match UnixStream::connect(&args.uds_path).await {
                Ok(s) => break s,
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    continue;
                }
            }
        };

        let cert_chain = load_certs_from_pem(CLIENT_CERT_PEM);
        let private_key = load_key_from_pem(CLIENT_KEY_PEM);

        let mut ca_store = RootCertStore::empty();
        for cert in load_certs_from_pem(CA_CERT_PEM) {
            ca_store.add(&cert)?;
        }

        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(ca_store)
            .with_client_auth_cert(cert_chain, private_key)?;

        let connector = TlsConnector::from(Arc::new(config));
        let domain = rustls::ServerName::try_from("server.tca")?;

        let mut tls_stream = connector.connect(domain, stream).await?;
        println!("TLS Client Connected!");

        let mut buf = [0u8; 1024];
        let n = tls_stream.read(&mut buf).await?;
        println!("Client received: {}", String::from_utf8_lossy(&buf[..n]));

        let msg = b"Hello Server";
        tls_stream.write_all(msg).await?;
    }

    Ok(())
}
