use tonic::{transport::Server, Request, Response, Status};
use proto_schema::ca_authority::ca_service_server::{CaService, CaServiceServer};
use proto_schema::ca_authority::{AttestationRequest, SignedCertResponse};
use boring::x509::{X509, X509Name, X509Req};
use boring::pkey::{PKey, Private};
use boring::hash::MessageDigest;
use boring::rsa::Rsa;

pub struct MyAuthority {
    pub ca_key: PKey<Private>,
    pub ca_cert: X509,
}

impl MyAuthority {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let rsa = Rsa::generate(2048)?;
        let pkey = PKey::from_rsa(rsa)?;
        
        let mut name = X509Name::builder()?;
        name.append_entry_by_text("CN", "My Hardware Root CA")?;
        let name = name.build();

        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        
        let serial = boring::bn::BigNum::from_u32(1)?.to_asn1_integer()?;
        builder.set_serial_number(&serial)?;
        
        let not_before = boring::asn1::Asn1Time::days_from_now(0)?;
        builder.set_not_before(&not_before)?;
        
        let not_after = boring::asn1::Asn1Time::days_from_now(3650)?;
        builder.set_not_after(&not_after)?;

        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?;
        builder.set_pubkey(&pkey)?;
        builder.sign(&pkey, MessageDigest::sha256())?;
        let cert = builder.build();

        Ok(Self { ca_key: pkey, ca_cert: cert })
    }
}

#[tonic::async_trait]
impl CaService for MyAuthority {
    async fn sign_attested_svid(
        &self,
        request: Request<AttestationRequest>,
    ) -> Result<Response<SignedCertResponse>, Status> {
        let req = request.into_inner();

        if req.endorsement_report.is_empty() {
            return Err(Status::unauthenticated("Hardware attestation failed"));
        }

        let csr = X509Req::from_der(&req.csr_der)
            .map_err(|_| Status::invalid_argument("Invalid CSR DER"))?;
        
        let mut builder = X509::builder()
            .map_err(|_| Status::internal("Failed to create X509 builder"))?;
        builder.set_version(2)
            .map_err(|_| Status::internal("Failed to set version"))?;
        
        let serial = boring::bn::BigNum::from_u32(100)
            .map_err(|_| Status::internal("BN error"))?
            .to_asn1_integer()
            .map_err(|_| Status::internal("ASN1 error"))?;
        builder.set_serial_number(&serial)
            .map_err(|_| Status::internal("Failed to set serial"))?;
        
        let not_before = boring::asn1::Asn1Time::days_from_now(0)
            .map_err(|_| Status::internal("Time error"))?;
        builder.set_not_before(&not_before)
            .map_err(|_| Status::internal("Failed to set not_before"))?;
        
        let not_after = boring::asn1::Asn1Time::days_from_now(365)
            .map_err(|_| Status::internal("Time error"))?;
        builder.set_not_after(&not_after)
            .map_err(|_| Status::internal("Failed to set not_after"))?;

        builder.set_subject_name(csr.subject_name())
            .map_err(|_| Status::internal("Failed to set subject"))?;
        builder.set_issuer_name(self.ca_cert.subject_name())
            .map_err(|_| Status::internal("Failed to set issuer"))?;
        
        let pubkey = csr.public_key()
            .map_err(|_| Status::internal("Failed to get pubkey from CSR"))?;
        builder.set_pubkey(&pubkey)
            .map_err(|_| Status::internal("Failed to set pubkey"))?;
        
        if let Ok(extensions) = csr.extensions() {
            for ext in extensions {
                builder.append_extension(ext)
                    .map_err(|_| Status::internal("Failed to append extension"))?;
            }
        }
        
        builder.sign(&self.ca_key, MessageDigest::sha256())
            .map_err(|_| Status::internal("Signing failed"))?;
        
        let signed_cert = builder.build();
        let cert_der = signed_cert.to_der()
            .map_err(|_| Status::internal("Failed to encode cert"))?;

        Ok(Response::new(SignedCertResponse {
            certificate_chain: cert_der,
            trust_bundle: self.ca_cert.to_der().unwrap_or_default(),
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:9000".parse()?;
    let ca = MyAuthority::new()?;

    println!("CA Authority listening on {}", addr);

    Server::builder()
        .add_service(CaServiceServer::new(ca))
        .serve(addr)
        .await?;

    Ok(())
}
