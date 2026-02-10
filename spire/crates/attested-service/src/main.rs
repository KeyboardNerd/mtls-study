mod agent;

use tonic::transport::Server;
use clap::Parser;

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_rustls::TlsAcceptor;
use std::sync::Arc;
use futures_util::StreamExt;
use boring::pkey::PKey;
use boring::rsa::Rsa;

use proto_schema::ca_authority::echo_service_server::EchoServiceServer;
use proto_schema::registry::registry_client::RegistryClient;
use proto_schema::registry::RegistrationRequest;
use crate::agent::{AttestationManager, InProcessClientCertResolver, InProcessServerCertResolver};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, default_value_t = 9001)]
    port: u16,

    #[arg(long, default_value_t = 50051)]
    proxy_port: u16,

    #[arg(long, default_value = "localhost")]
    sni: String,

    #[arg(long)]
    registry_addr: Option<String>,

    #[arg(long, default_value = "127.0.0.1")]
    bind_ip: String,
}

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

pub struct DebugProxyImpl {
    manager: Arc<AttestationManager>,
}

impl DebugProxyImpl {
    pub fn new(manager: Arc<AttestationManager>) -> Self {
        Self { manager }
    }
}

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

        // Build rustls config manually for Client
        let roots = {
            let mut roots = rustls::RootCertStore::empty();
            if let Some(bundle) = self.manager.get_trust_bundle() {
                 match rustls::pki_types::CertificateDer::try_from(bundle) {
                     Ok(cert) => {
                         if let Err(e) = roots.add(cert) {
                             println!("DebugProxy: Failed to add DER cert to root store: {}", e);
                         }
                     }
                     Err(e) => println!("DebugProxy: Failed to parse trust bundle as DER cert: {}", e),
                 }
            }
            roots
        };


        // Re-do builder chain correctly for custom resolver + standard verifier
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(Arc::new(roots)) // Why Arc? rustls 0.23 might take Arc or value? 
            .with_client_cert_resolver(Arc::new(InProcessClientCertResolver(self.manager.clone())));

        let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
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
                    // We must use a valid DNS name for SNI/Validation. 
                    // If SNI is a SPIFFE ID, this might fail DNS parsing.
                    // But usually SNI is a hostname.
                    let domain = rustls::pki_types::ServerName::try_from(sni.as_str())
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Invalid SNI: {}", e)))?
                        .to_owned();
                        
                    let tls_stream = tls_connector.connect(domain, stream).await?;
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

async fn register_to_registry(registry_addr: String, sni: String, port: u16, ip: String) -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to registry at {}", registry_addr);
    let mut client = RegistryClient::connect(registry_addr).await?;
    
    let request = tonic::Request::new(RegistrationRequest {
        sni: sni.clone(),
        ip: ip.clone(),
        port: port as i32,
    });
    
    let response = client.register(request).await?;
    println!("Registered {} -> {}:{} : {:?}", sni, ip, port, response.into_inner());
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::CryptoProvider::install_default(
        rustls::crypto::ring::default_provider(),
    );

    let args = Args::parse();
    
    let port = args.port;
    let proxy_port = args.proxy_port;
    let sni = args.sni;
    let registry_addr = args.registry_addr;
    let bind_ip = args.bind_ip;

    println!("Starting Attested Service (Echo + Proxy)... Bind: {}, Port: {}, Proxy Port: {}, SNI: {}", bind_ip, port, proxy_port, sni);
    
    // Workload API Setup
    let socket_path = format!("unix:/tmp/spiffe-workload-api-{}.sock", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
    // We still set it for external sidecars if needed, but we don't use it internally
    std::env::set_var("SPIFFE_ENDPOINT_SOCKET", &socket_path);
    println!("SPIFFE_ENDPOINT_SOCKET={}", socket_path);

    // Generate private key for the agent
    let rsa = Rsa::generate(2048)?;
    let private_key = PKey::from_rsa(rsa)?;

    // Create Manager
    let manager = Arc::new(AttestationManager::new(private_key));
    
    // Start Manager Refresh Loop
    let output_manager = manager.clone();
    tokio::spawn(async move {
        output_manager.start_refresh_loop().await;
    });

    // Start UDS Server (Optional, but keeping for compatibility with sidecars if they look at the path)
    // let uds_manager = manager.clone();
    // let value = socket_path.clone();
    // let value = value.strip_prefix("unix:").unwrap_or(&value).to_string();
    // tokio::spawn(async move {
    //     if let Err(e) = agent::run_server(value, uds_manager).await {
    //         eprintln!("Workload API server failed: {}", e);
    //     }
    // });

    // Wait for agent to get first cert?
    // We can poll until manager.get_certified_key().is_some()
    loop {
        if manager.get_certified_key().is_some() {
             break;
        }
        println!("Waiting for SVID attestation...");
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    // Register with Registry if address provided
    if let Some(addr) = registry_addr {
        let sni_clone = sni.clone();
        let bind_ip_clone = bind_ip.clone();
        tokio::spawn(async move {
            if let Err(e) = register_to_registry(addr, sni_clone, port, bind_ip_clone).await {
               eprintln!("Failed to register: {}", e);
            }
        });
    }

    // Wait for the manager to have the trust bundle
    loop {
        if manager.get_trust_bundle().is_some() {
            println!("Trust bundle is available.");
            break;
        }
        println!("Waiting for trust bundle...");
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    // Start Echo Service (mTLS)
    let echo_server = {
        let manager_clone = manager.clone();
        
        // Build Server Verifier
        let roots = {
             let mut roots = rustls::RootCertStore::empty();
             if let Some(bundle) = manager_clone.get_trust_bundle() {
                 match rustls::pki_types::CertificateDer::try_from(bundle) {
                     Ok(cert) => {
                         if let Err(e) = roots.add(cert) {
                             eprintln!("Failed to add DER cert to root store: {}", e);
                         }
                     }
                     Err(e) => eprintln!("Failed to parse trust bundle as DER cert: {}", e),
                 }
            } 
            roots
        };
        
        // Use basic WebPki verifier with NO client auth? No, we WANT client auth (mTLS).
        // .with_client_cert_verifier(WebPkiClientVerifier...)
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| format!("Verifier build error: {}", e))?;
            
        let server_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(InProcessServerCertResolver(manager_clone.clone())));
            
        // We probably need ALPN h2
        let mut server_config = server_config;
        server_config.alpn_protocols = vec![b"h2".to_vec()];

        let addr: std::net::SocketAddr = format!("{}:{}", bind_ip, port).parse()?;
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

    // Start Debug Proxy (Plaintext gRPC, but calls Echo via mTLS)
    let proxy_server = {
        let addr: std::net::SocketAddr = format!("{}:{}", bind_ip, proxy_port).parse()?;
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
            .add_service(DebugProxyServer::new(DebugProxyImpl::new(manager.clone())))
            .serve(addr)
    };

    // Run both
    tokio::try_join!(echo_server, proxy_server)?;

    Ok(())
}
