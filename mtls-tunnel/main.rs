use clap::Parser;
use futures_core::Stream;
use hyper::Uri;
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use tower::service_fn;

pub mod tunnel {
    tonic::include_proto!("tunnel");
}

use tunnel::{
    tunnel_client::TunnelClient,
    tunnel_server::{Tunnel, TunnelServer},
    EchoRequest, EchoResponse,
};

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

    #[clap(long, value_parser, default_value = "/tmp/mtls.sock")]
    uds_path: String,
}

#[derive(Debug, Default)]
pub struct MyTunnel {}

#[tonic::async_trait]
impl Tunnel for MyTunnel {
    async fn echo(&self, request: Request<EchoRequest>) -> Result<Response<EchoResponse>, Status> {
        println!("Got a request: {:?}", request);

        let reply = EchoResponse {
            message: format!("Echo: {}", request.into_inner().message),
        };

        Ok(Response::new(reply))
    }

    type EchoStreamStream =
        Pin<Box<dyn Stream<Item = Result<EchoResponse, Status>> + Send + Sync + 'static>>;

    async fn echo_stream(
        &self,
        request: Request<EchoRequest>,
    ) -> Result<Response<Self::EchoStreamStream>, Status> {
        println!("Got a stream request: {:?}", request);

        let (tx, rx) = mpsc::channel(4);

        tokio::spawn(async move {
            for i in 0..5 {
                let reply = EchoResponse {
                    message: format!("Echo stream {}: {}", i, request.get_ref().message),
                };
                tx.send(Ok(reply)).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        });

        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.role == "server" {
        let cert = SERVER_CERT_PEM.to_string();
        let key = SERVER_KEY_PEM.to_string();
        let server_identity = Identity::from_pem(cert, key);

        let ca_cert = Certificate::from_pem(CA_CERT_PEM);

        let tls_config = ServerTlsConfig::new()
            .identity(server_identity)
            .client_ca_root(ca_cert);

        let tunnel = MyTunnel::default();
        let uds_path = args.uds_path.clone();

        // Remove the old socket if it exists
        let _ = std::fs::remove_file(&uds_path);
        let listener = UnixListener::bind(uds_path)?;
        let listener_stream = UnixListenerStream::new(listener);

        println!("TunnelServer listening on {}", args.uds_path);

        Server::builder()
            .tls_config(tls_config)?
            .add_service(TunnelServer::new(tunnel))
            .serve_with_incoming(listener_stream)
            .await?;
    } else {
        let server_ca_cert = Certificate::from_pem(CA_CERT_PEM);
        let client_cert = CLIENT_CERT_PEM.to_string();
        let client_key = CLIENT_KEY_PEM.to_string();
        let client_identity = Identity::from_pem(client_cert, client_key);

        let tls_config = ClientTlsConfig::new()
            .domain_name("server.tca")
            .ca_certificate(server_ca_cert)
            .identity(client_identity);

        let uds_path = Arc::new(args.uds_path.clone());

        // We need to use a custom connector to connect to a UDS.
        let channel = Endpoint::try_from("https://[::]:50051")? // dummy URI
            .tls_config(tls_config)?
            .connect_with_connector(service_fn(move |_: Uri| {
                let uds_path = uds_path.clone();
                async move { UnixStream::connect(uds_path.as_ref()).await }
            }))
            .await?;

        let mut client = TunnelClient::new(channel);

        // Unary call
        let request = tonic::Request::new(EchoRequest {
            message: "hello".into(),
        });
        let response = client.echo(request).await?;
        println!("RESPONSE={:?}", response);

        // Stream call
        let request = tonic::Request::new(EchoRequest {
            message: "hello stream".into(),
        });
        let mut stream = client.echo_stream(request).await?.into_inner();
        while let Some(response) = stream.message().await? {
            println!("STREAM RESPONSE={:?}", response);
        }
    }

    Ok(())
}
