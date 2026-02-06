use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tonic::{transport::Server, Request, Response, Status};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use proto_schema::registry::registry_server::{Registry, RegistryServer};
use proto_schema::registry::{RegistrationRequest, RegistrationResponse};

#[derive(Debug, Default)]
struct RegistryImpl {
    // SNI -> IP
    records: Arc<RwLock<HashMap<String, Ipv4Addr>>>,
}

#[tonic::async_trait]
impl Registry for RegistryImpl {
    async fn register(
        &self,
        request: Request<RegistrationRequest>,
    ) -> Result<Response<RegistrationResponse>, Status> {
        let req = request.into_inner();
        println!("Received registration: {:?}", req);

        let ip: Ipv4Addr = req.ip.parse().map_err(|_| Status::invalid_argument("Invalid IP"))?;
        
        // Normalize SNI: remove trailing dot if present
        let sni = req.sni.trim_end_matches('.').to_string();

        let mut records = self.records.write().await;
        records.insert(sni, ip);

        Ok(Response::new(RegistrationResponse {
            success: true,
            message: "Registered".to_string(),
        }))
    }
}

async fn run_dns_server(records: Arc<RwLock<HashMap<String, Ipv4Addr>>>) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("127.0.0.1:10053").await?;
    println!("DNS Server listening on 127.0.0.1:10053");

    let mut buf = [0u8; 512];

    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("DNS recv error: {}", e);
                continue;
            }
        };

        let data = &buf[..len];
        
        let request = match Message::from_vec(data) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("Failed to parse DNS message: {}", e);
                continue;
            }
        };

        let mut response = Message::new();
        response.set_id(request.id());
        response.set_message_type(MessageType::Response);
        response.set_op_code(OpCode::Query);
        response.set_recursion_desired(request.recursion_desired());
        response.set_recursion_available(true);
        response.set_response_code(ResponseCode::NoError);

        if let Some(query) = request.queries().first() {
            response.add_query(query.clone());
            
            let name_str = query.name().to_string();
            let name_key = name_str.trim_end_matches('.').to_string();
            
            println!("DNS Query: {} ({})", name_str, query.query_type());

            if query.query_type() == RecordType::A {
                let records = records.read().await;
                if let Some(ip) = records.get(&name_key) {
                    let mut record = Record::new();
                    record.set_name(query.name().clone());
                    record.set_rr_type(RecordType::A);
                    record.set_ttl(1); // Short TTL
                    record.set_data(Some(RData::A(hickory_proto::rr::rdata::A(*ip))));
                    record.set_dns_class(query.query_class());
                    response.add_answer(record);
                } else {
                     // If not found, we could return NXDomain, but for now let's just return NoError with unused answers or NXDomain logic can be improved.
                     // Actually, if we are authoritative, we should return NXDomain if not found.
                     // But strictly speaking we are just a hacky resolver.
                     response.set_response_code(ResponseCode::NXDomain);
                }
            }
        }

        let response_bytes = match response.to_vec() {
            Ok(b) => b,
            Err(e) => {
                eprintln!("Failed to serialize DNS response: {}", e);
                continue;
            }
        };

        if let Err(e) = socket.send_to(&response_bytes, src).await {
            eprintln!("Failed to send DNS response: {}", e);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let records = Arc::new(RwLock::new(HashMap::new()));
    
    let records_dns = records.clone();
    tokio::spawn(async move {
        if let Err(e) = run_dns_server(records_dns).await {
            eprintln!("DNS Server crashed: {}", e);
        }
    });

    let addr = "[::1]:9090".parse()?;
    let registry = RegistryImpl { records };

    println!("Registry gRPC listening on {}", addr);

    Server::builder()
        .add_service(RegistryServer::new(registry))
        .serve(addr)
        .await?;

    Ok(())
}
