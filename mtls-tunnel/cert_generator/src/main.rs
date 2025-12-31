//! A small utility to generate the necessary PEM files for the mTLS example.
use rcgen::{Certificate, CertificateParams, DistinguishedName, IsCa, SanType};

fn main() {
    // Generate the CA certificate
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "ez-mtls-ca");
    let ca_cert = Certificate::from_params(ca_params).unwrap();
    let ca_pem = ca_cert.serialize_pem().unwrap();
    let ca_key_pem = ca_cert.serialize_private_key_pem();

    println!("// ----- CA ----- ");
    println!("const CA_CERT_PEM: &str = r#\"{}\"#;", ca_pem.trim());
    println!("const CA_KEY_PEM: &str = r#\"{}\"#;", ca_key_pem.trim());

    // Generate the server certificate
    let mut server_params = CertificateParams::new(vec!["server.tca".to_string()]);
    server_params.distinguished_name = DistinguishedName::new();
    server_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "server.tca");
    server_params
        .subject_alt_names
        .push(SanType::DnsName("server.tca".to_string()));
    let server_cert = Certificate::from_params(server_params).unwrap();
    let server_pem = server_cert.serialize_pem_with_signer(&ca_cert).unwrap();
    let server_key_pem = server_cert.serialize_private_key_pem();

    println!("\n// ----- Server ----- ");
    println!("const SERVER_CERT_PEM: &str = r#\"{}\"#;", server_pem.trim());
    println!("const SERVER_KEY_PEM: &str = r#\"{}\"#;", server_key_pem.trim());

    // Generate the client certificate
    let mut client_params = CertificateParams::new(vec!["client.tca".to_string()]);
    client_params.distinguished_name = DistinguishedName::new();
    client_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "client.tca");
    client_params
        .subject_alt_names
        .push(SanType::DnsName("client.tca".to_string()));
    let client_cert = Certificate::from_params(client_params).unwrap();
    let client_pem = client_cert.serialize_pem_with_signer(&ca_cert).unwrap();
    let client_key_pem = client_cert.serialize_private_key_pem();

    println!("\n// ----- Client ----- ");
    println!("const CLIENT_CERT_PEM: &str = r#\"{}\"#;", client_pem.trim());
    println!("const CLIENT_KEY_PEM: &str = r#\"{}\"#;", client_key_pem.trim());
}
