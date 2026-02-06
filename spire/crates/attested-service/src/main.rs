mod agent;

use tonic::transport::Server;

use spiffe_rustls::{mtls_client, mtls_server, TrustDomainPolicy};
use spiffe::SpiffeId;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_rustls::TlsAcceptor;
use std::sync::Arc;
use futures_util::StreamExt;
use boring::pkey::PKey;
use boring::rsa::Rsa;
use spiffe::WorkloadApiClient;
use spiffe::X509Context;
use spiffe::TrustDomain;
use proto_schema::ca_authority::echo_service_server::EchoServiceServer;

#[derive(Default)]
pub struct MyService {}

#[tonic::async_trait]
impl proto_schema::ca_authority::echo_service_server::EchoService for MyService {
    async fn echo(
        &self,
        request: tonic::Request<proto_schema::ca_authority::EchoRequest>,
    ) -> Result<tonic::Response<proto_schema::ca_authority::EchoResponse>, tonic::Status> {
        Ok(tonic::Response::new(proto_schema::ca_authority::EchoResponse {
            message: format!("Hello, {}!", request.into_inner().message),
        }))
    }
}



use proto_schema::ca_authority::echo_service_client::EchoServiceClient;
use proto_schema::ca_authority::EchoRequest;
use proto_schema::proxy::debug_proxy_server::{DebugProxy, DebugProxyServer};
use proto_schema::proxy::{CallEchoRequest, CallEchoResponse};

#[derive(Default)]
pub struct DebugProxyImpl {}

#[tonic::async_trait]
impl DebugProxy for DebugProxyImpl {
    async fn call_echo(
        &self,
        request: tonic::Request<CallEchoRequest>,
    ) -> Result<tonic::Response<CallEchoResponse>, tonic::Status> {
        let req = request.into_inner();
        let address = req.address;
        let sni = req.sni;
        let message = req.message;

        println!("Proxying request to address: {}, sni: {}", address, sni);

        // Calculate source inside the handler or share it? 
        // For simplicity, we can create a new source or use a shared one. 
        // Initializing source allows us to be fresh.
        let source = spiffe::X509Source::new().await.map_err(|e| tonic::Status::internal(e.to_string()))?;

        // Custom rule using a closure
        let auth = |peer: &SpiffeId| {
            println!("xxx Peer: {}", peer);
            true 
        };

        let client_cfg = mtls_client(source)
            .authorize(auth)
            .trust_domain_policy(
                TrustDomainPolicy::LocalOnly("example.org".try_into().map_err(|e: spiffe::SpiffeIdError| tonic::Status::internal(e.to_string()))?)
            )
            .with_alpn_protocols(&[b"h2"]) 
            .build()
            .map_err(|e| tonic::Status::internal(e.to_string()))?;
        
        let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
        let sni_clone = sni.clone();
        let address_clone = address.clone();

        let channel = tonic::transport::Endpoint::from_shared(format!("http://{}", address))
            .map_err(|e| tonic::Status::internal(e.to_string()))?
            .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
                let tls_connector = tls_connector.clone();
                let sni = sni_clone.clone();
                let address = address_clone.clone();
                async move {
                    let stream = tokio::net::TcpStream::connect(&address).await?;
                    let tls_stream = tls_connector.connect(sni.try_into().unwrap(), stream).await?;
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(hyper_util::rt::TokioIo::new(tls_stream))
                }
            }))
            .await
            .map_err(|e| tonic::Status::internal(e.to_string()))?;

        let mut client = EchoServiceClient::new(channel);

        let echo_req = tonic::Request::new(EchoRequest {
            message,
        });

        let response = client.echo(echo_req).await?;
        
        Ok(tonic::Response::new(CallEchoResponse {
            response: format!("{:?}", response.into_inner()),
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    
    let port = args.iter().position(|r| r == "--port")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.parse::<u16>().unwrap())
        .unwrap_or(9001);

    let proxy_port = args.iter().position(|r| r == "--proxy-port")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.parse::<u16>().unwrap())
        .unwrap_or(50051);

    println!("Starting Attested Service (Echo + Proxy)...");
    
    // Workload API Setup
    let socket_path = format!("unix:/tmp/spiffe-workload-api-{}.sock", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
    std::env::set_var("SPIFFE_ENDPOINT_SOCKET", &socket_path);
    println!("SPIFFE_ENDPOINT_SOCKET={}", socket_path);

    // Generate private key for the agent
    let rsa = Rsa::generate(2048)?;
    let private_key = PKey::from_rsa(rsa)?;

    // Start Agent
    let value = socket_path.clone();
    let value = value.strip_prefix("unix:").unwrap_or(&value).to_string();
    tokio::spawn(async move {
        if let Err(e) = agent::run_server(value, private_key).await {
            eprintln!("Workload API server failed: {}", e);
        }
    });

    // Wait for agent
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Start Echo Service (mTLS)
    let echo_server = {
        let source = spiffe::X509Source::new().await?;
        let auth = |peer: &SpiffeId| {
            println!("xxx Peer: {}", peer);
            true 
        };
        let server_config = mtls_server(source)
            .authorize(auth)
            .trust_domain_policy(TrustDomainPolicy::LocalOnly("example.org".try_into()?))
            .with_alpn_protocols(&[b"h2"])
            .build()?;
        
        let addr: std::net::SocketAddr = format!("[::1]:{}", port).parse()?;
        println!("Echo Service (mTLS) listening on {}", addr);
        
        let listener = TcpListener::bind(addr).await?;
        let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
        let incoming = TcpListenerStream::new(listener).filter_map(move |r| {
            let tls_acceptor = tls_acceptor.clone();
            async move {
                match r {
                    Ok(socket) => match tls_acceptor.accept(socket).await {
                        Ok(tls_stream) => Some(Ok::<_, std::io::Error>(tls_stream)),
                        Err(e) => { eprintln!("TLS accept error: {}", e); None }
                    },
                    Err(e) => { eprintln!("TCP accept error: {}", e); None }
                }
            }
        });

        Server::builder()
            .add_service(EchoServiceServer::new(MyService::default()))
            .serve_with_incoming(incoming)
    };

    // Start Debug Proxy (Plaintext)
    let proxy_server = {
        let addr: std::net::SocketAddr = format!("[::1]:{}", proxy_port).parse()?;
        println!("Debug Proxy listening on {}", addr);
        let reflection_service_v1 = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(proto_schema::proxy::FILE_DESCRIPTOR_SET)
            .build_v1()?;
        let reflection_service_v1alpha = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(proto_schema::proxy::FILE_DESCRIPTOR_SET)
            .build_v1alpha()?;

        Server::builder()
            .add_service(reflection_service_v1)
            .add_service(reflection_service_v1alpha)
            .add_service(DebugProxyServer::new(DebugProxyImpl::default()))
            .serve(addr)
    };

    // Run both
    tokio::try_join!(echo_server, proxy_server)?;

    Ok(())
}
