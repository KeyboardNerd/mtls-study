use proto_schema::ca_authority::ca_service_client::CaServiceClient;
use proto_schema::ca_authority::AttestationRequest;
use boring::pkey::PKey;
use boring::x509::{X509Req, X509Extension};
use boring::x509::extension::SubjectAlternativeName;
use boring::hash::MessageDigest;
use boring::stack::Stack;
use tonic::{Request, Response, Status};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use std::path::Path;
use tokio::net::UnixListener;
use boring::pkey::Private;
use tokio_stream::wrappers::UnixListenerStream;
use std::sync::Arc;

use proto_schema::workload::spiffe_workload_api_server::{SpiffeWorkloadApi, SpiffeWorkloadApiServer};
use proto_schema::workload::{
    X509svidRequest, X509svidResponse, X509svid, 
    X509BundlesRequest, X509BundlesResponse, 
    JwtsvidRequest, JwtsvidResponse, 
    ValidateJwtsvidRequest, ValidateJwtsvidResponse, 
    JwtBundlesRequest, JwtBundlesResponse
};

#[derive(Debug)]
pub struct AttestationManager {
    private_key: PKey<Private>,
    certified_key: std::sync::RwLock<Option<Arc<rustls::sign::CertifiedKey>>>,
    trust_bundle: std::sync::RwLock<Option<Vec<u8>>>,
}

impl AttestationManager {
    pub fn new(private_key: PKey<Private>) -> Self {
        Self {
            private_key,
            certified_key: std::sync::RwLock::new(None),
            trust_bundle: std::sync::RwLock::new(None),
        }
    }

    pub fn get_certified_key(&self) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.certified_key.read().unwrap().clone()
    }

    pub fn get_trust_bundle(&self) -> Option<Vec<u8>> {
        self.trust_bundle.read().unwrap().clone()
    }

    pub async fn update_cert(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let response = self.get_attested_cert().await?;
        
        if let Some(svid) = response.svids.first() {
            let cert_der = svid.x509_svid.clone();
            let key_der = svid.x509_svid_key.clone();
            
            let certs = vec![rustls::pki_types::CertificateDer::from(cert_der)];
            let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(key_der)
            );
            
            let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
                .map_err(|_| "Failed to parse private key for rustls")?;
                
            let certified_key = Arc::new(rustls::sign::CertifiedKey::new(certs, signing_key));
            
            *self.certified_key.write().unwrap() = Some(certified_key);
            *self.trust_bundle.write().unwrap() = Some(svid.bundle.clone());
            println!("Updated internal cached SVID");
        }
        
        Ok(())
    }

    pub async fn start_refresh_loop(self: Arc<Self>) {
        loop {
            if let Err(e) = self.update_cert().await {
                eprintln!("Failed to update cert: {}", e);
            }
            // Refresh every hour or so, but for study maybe faster
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }

    pub async fn get_attested_cert(&self) -> Result<X509svidResponse, Box<dyn std::error::Error + Send + Sync>> {
        println!("xxxx Test Test Test");
        let spiffe_id = "spiffe://example.org/operator/dev-jobs/publisher/keyboardnerd.dev/workload/mtls-study/v/1.0.1";
        let (csr_der, endorsement_report) = {
            let mut req_builder = X509Req::builder()?;
            req_builder.set_pubkey(&self.private_key)?;
            // 1. Create a Stack to hold all extensions
            let mut extensions = Stack::new()?;

            // 2. Prepare the context (needed for constructing extensions)
            let context = req_builder.x509v3_context(None);
            // -- Key Usage (Critical for SPIFFE) --
            let key_usage = X509Extension::new(
                None, 
                Some(&context), 
                "keyUsage", 
                "critical, digitalSignature, keyEncipherment"
            )?;
            extensions.push(key_usage)?;

            // -- Basic Constraints --
            let basic_constraints = X509Extension::new(
                None, 
                Some(&context), 
                "basicConstraints", 
                "critical, CA:FALSE"
            )?;
            extensions.push(basic_constraints)?;

            // -- SAN (SPIFFE ID) --
            let mut san_builder = SubjectAlternativeName::new();
            san_builder.uri(spiffe_id);
            san_builder.dns("*.example.org");
            san_builder.dns("localhost");
            san_builder.dns("*.op.example.org");
            // Make it critical as per SPIFFE spec for empty subjects
            san_builder.critical(); 
            let san_ext = san_builder.build(&context)?;
            extensions.push(san_ext)?;

            // -- Extended Key Usage --
            let eku = X509Extension::new(
                None, 
                Some(&context), 
                "extendedKeyUsage", 
                "serverAuth, clientAuth"
            )?;
            extensions.push(eku)?;

            // 4. Finally, add the entire stack to the request builder
            req_builder.add_extensions(&extensions)?;
            req_builder.sign(&self.private_key, MessageDigest::sha256())?;
            let csr = req_builder.build();
            let csr_der = csr.to_der()?;

            // 3. Mock hardware quote (binding to pubkey)
            let endorsement_report = b"MOCK_HARDWARE_QUOTE_BOUND_TO_PUBKEY".to_vec();
            
            (csr_der, endorsement_report)
        };

        // 4. Remote Attestation with hardware evidence.
        // TODO: Configuration for CA address
        let mut client = CaServiceClient::connect("http://[::1]:9000").await?;
        let request = tonic::Request::new(AttestationRequest {
            csr_der,
            endorsement_report,
        });

        let response = client.sign_attested_svid(request).await?.into_inner();

        Ok(X509svidResponse {
            svids: vec![X509svid {
                spiffe_id: spiffe_id.to_string(),
                x509_svid: response.certificate_chain,
                x509_svid_key: self.private_key.private_key_to_der_pkcs8()?,
                bundle: response.trust_bundle,
                hint: "internal".to_string(),
            }],
            crl: vec![],
            federated_bundles: Default::default(),
        })
    }
}

#[derive(Debug)]
pub struct InProcessClientCertResolver(pub Arc<AttestationManager>);

impl rustls::client::ResolvesClientCert for InProcessClientCertResolver {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.0.get_certified_key()
    }
    
    fn has_certs(&self) -> bool {
        true
    }
}

#[derive(Debug)]
pub struct InProcessServerCertResolver(pub Arc<AttestationManager>);

impl rustls::server::ResolvesServerCert for InProcessServerCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.0.get_certified_key()
    }
}

pub struct WorkloadApiServerImpl {
    manager: Arc<AttestationManager>,
}

impl WorkloadApiServerImpl {
    pub fn new(manager: Arc<AttestationManager>) -> Self {
        Self {
            manager,
        }
    }
}

#[tonic::async_trait]
impl SpiffeWorkloadApi for WorkloadApiServerImpl {
    type FetchX509SVIDStream = ReceiverStream<Result<X509svidResponse, Status>>;
    type FetchX509BundlesStream = ReceiverStream<Result<X509BundlesResponse, Status>>;
    type FetchJWTBundlesStream = ReceiverStream<Result<JwtBundlesResponse, Status>>;

    async fn fetch_x509svid(
        &self,
        _request: Request<X509svidRequest>,
    ) -> Result<Response<Self::FetchX509SVIDStream>, Status> {
        let (tx, rx) = mpsc::channel(1);
        let manager = self.manager.clone();
        
        tokio::spawn(async move {
            match manager.get_attested_cert().await {
                Ok(svid) => {
                    if let Err(e) = tx.send(Ok(svid)).await {
                        eprintln!("Failed to send X509SVID response: {}", e);
                    }
                }
                Err(e) => {
                    eprintln!("Attestation failed: {}", e);
                    let _ = tx.send(Err(Status::internal(format!("Failed to attest: {}", e)))).await;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn fetch_x509_bundles(
        &self,
        _request: Request<X509BundlesRequest>,
    ) -> Result<Response<Self::FetchX509BundlesStream>, Status> {
        println!("fetch_x509_bundles");
        Err(Status::unimplemented("Not implemented"))
    }

    async fn fetch_jwtsvid(
        &self,
        _request: Request<JwtsvidRequest>,
    ) -> Result<Response<JwtsvidResponse>, Status> {
        println!("fetch_jwtsvid");
        Err(Status::unimplemented("Not implemented"))
    }

    async fn fetch_jwt_bundles(
        &self,
        _request: Request<JwtBundlesRequest>,
    ) -> Result<Response<Self::FetchJWTBundlesStream>, Status> {
        println!("fetch_jwt_bundles");
        Err(Status::unimplemented("Not implemented"))
    }

    async fn validate_jwtsvid(
        &self,
        _request: Request<ValidateJwtsvidRequest>,
    ) -> Result<Response<ValidateJwtsvidResponse>, Status> {
        println!("validate_jwtsvid");
        Err(Status::unimplemented("Not implemented"))
    }
}

// pub async fn run_server(path: impl AsRef<Path>, manager: Arc<AttestationManager>) -> Result<(), Box<dyn std::error::Error>> {
//     let path = path.as_ref();
//     if path.exists() {
//         tokio::fs::remove_file(path).await?;
//     }
    
//     let listener = UnixListener::bind(path)?;
//     let stream = UnixListenerStream::new(listener);
    
//     println!("Workload API listening on {:?}", path);
//     // Start the background refresh loop if not already running (actually, main should start it)
//     // Here we just serve the UDS
    
//     tonic::transport::Server::builder()
//         .add_service(SpiffeWorkloadApiServer::new(WorkloadApiServerImpl::new(manager)))
//         .serve_with_incoming(stream)
//         .await?;
        
//     Ok(())
// }
