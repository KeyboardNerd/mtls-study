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

use proto_schema::workload::spiffe_workload_api_server::{SpiffeWorkloadApi, SpiffeWorkloadApiServer};
use proto_schema::workload::{
    X509svidRequest, X509svidResponse, X509svid, 
    X509BundlesRequest, X509BundlesResponse, 
    JwtsvidRequest, JwtsvidResponse, 
    ValidateJwtsvidRequest, ValidateJwtsvidResponse, 
    JwtBundlesRequest, JwtBundlesResponse
};

pub async fn get_attested_cert(private_key: PKey<Private>) -> Result<X509svidResponse, Box<dyn std::error::Error + Send + Sync>> {
    let spiffe_id = "spiffe://example.org/operator/dev-jobs/publisher/keyboardnerd.dev/workload/mtls-study/v/1.0.1";
    let (csr_der, endorsement_report) = {
        let mut req_builder = X509Req::builder()?;
        req_builder.set_pubkey(&private_key)?;
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
        // Using the builder is safer, but you can also use X509Extension::new(...)
        let mut san_builder = SubjectAlternativeName::new();
        san_builder.uri(spiffe_id);
        san_builder.dns("*.example.org");
        // All acceptable operator domains should also live here.
        // The front should be isolate_name, publisher_id, and selector.
        // At most they can only occupy 63 characters.
        // isolate_name / publisher_id should only be at most 24 chars long.
        // selector can be at most 25 chars long. ( base36 chars encoding, 25 chars.)
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
        req_builder.sign(&private_key, MessageDigest::sha256())?;
        let csr = req_builder.build();
        let csr_der = csr.to_der()?;

        // 3. Mock hardware quote (binding to pubkey)
        let endorsement_report = b"MOCK_HARDWARE_QUOTE_BOUND_TO_PUBKEY".to_vec();
        
        (csr_der, endorsement_report)
    };

    // 4. Remote Attestation with hardware evidence.
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
            x509_svid_key: private_key.private_key_to_der_pkcs8()?,
            bundle: response.trust_bundle,
            hint: "internal".to_string(),
        }],
        crl: vec![],
        federated_bundles: Default::default(),
    })
}

pub struct WorkloadApiServerImpl {
    private_key: PKey<Private>,
}

impl WorkloadApiServerImpl {
    pub fn new(private_key: PKey<Private>) -> Self {
        Self {
            private_key,
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
        let private_key = self.private_key.clone();
        // Spawn a task to handle the request (proto-typical one-shot response for now)
        tokio::spawn(async move {
            match get_attested_cert(private_key).await {
                Ok(svid) => {
                    if let Err(e) = tx.send(Ok(svid)).await {
                        eprintln!("Failed to send X509SVID response: {}", e);
                    }
                }
                Err(e) => {
                    println!("not ok");
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

// I don't like this because the private key is unnecessarily exposed to the socket.
// We should use a local channel without going through socket instead.
pub async fn run_server(path: impl AsRef<Path>, private_key: PKey<Private>) -> Result<(), Box<dyn std::error::Error>> {
    let path = path.as_ref();
    if path.exists() {
        tokio::fs::remove_file(path).await?;
    }
    
    let listener = UnixListener::bind(path)?;
    let stream = UnixListenerStream::new(listener);
    
    println!("Workload API listening on {:?}", path);
    
    tonic::transport::Server::builder()
        .add_service(SpiffeWorkloadApiServer::new(WorkloadApiServerImpl::new(private_key)))
        .serve_with_incoming(stream)
        .await?;
        
    Ok(())
}
