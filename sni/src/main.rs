use boring::ssl::{
    NameType, SelectCertError, SslAcceptor, SslConnector, SslFiletype, SslMethod, SslVerifyMode,
};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

fn main() {
    // Start the server in a separate thread
    let server_handle = thread::spawn(|| {
        run_server();
    });

    // Give server a moment to start
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Start the client
    run_client();

    server_handle.join().unwrap();
}

fn run_server() {
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();

    // 1. Load Server Identity
    acceptor
        .set_private_key_file("server.key", SslFiletype::PEM)
        .unwrap();
    acceptor
        .set_certificate_chain_file("server.pem")
        .unwrap();

    // 2. Enforce mTLS: Require and Verify Client Certificate
    acceptor.set_ca_file("ca.pem").unwrap();
    acceptor.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);


    let acceptor = Arc::new(acceptor.build());
    let listener = TcpListener::bind("127.0.0.1:8443").unwrap();

    println!("[Server] Listening on localhost:8443...");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let acceptor = acceptor.clone();
                thread::spawn(move || {
                    match acceptor.accept(stream) {
                        Ok(mut stream) => {
                            let mut buf = [0; 1024];
                            // Read client data
                            match stream.read(&mut buf) {
                                Ok(len) => {
                                    println!(
                                        "[Server] Client said: {}",
                                        String::from_utf8_lossy(&buf[..len])
                                    );
                                    stream.write_all(b"Hello from Server").unwrap();
                                }
                                Err(e) => eprintln!("[Server] Read error: {}", e),
                            }
                        }
                        Err(e) => eprintln!("[Server] Handshake failed: {:?}", e),
                    }
                });
            }
            Err(e) => eprintln!("[Server] Connection failed: {}", e),
        }
    }
}

fn run_client() {
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    // FIX: Custom Callback to debug the specific mismatch error
    connector.set_verify_callback(SslVerifyMode::PEER, |ok, ctx| {
        // If verification passed, just return true
        if ok {
            return true;
        }

        // If verification FAILED, we print why.
        // We know this is likely the Hostname Mismatch if we are testing that scenario.
        println!("\n[DEBUG] !!! VERIFICATION FAILURE DETECTED !!!");
        println!("[DEBUG] Depth: {}", ctx.error_depth());

        if let Some(cert) = ctx.current_cert() {
            // A. Print the Subject (CN)
            print!("[DEBUG] Certificate Subject (CN): ");
            for entry in cert.subject_name().entries() {
                if let Ok(s) = entry.data().as_utf8() {
                    print!("'{}' ", s);
                }
            }
            println!();

            // B. Print the SANs
            println!("[DEBUG] Certificate SANs (Subject Alternative Names):");
            if let Some(sans) = cert.subject_alt_names() {
                for san in sans {
                    if let Some(dns) = san.dnsname() {
                        println!("        - Type: DNS, Value: '{}'", dns);
                    } else if let Some(uri) = san.uri() {
                        println!("        - Type: URI, Value: '{}' (Ignored by standard verifier)", uri);
                    } else {
                        // FIX: Do not use {:?} here, as GeneralName does not implement Debug
                        println!("        - Type: Other (IP, Email, or RID)");
                    }
                }
            } else {
                println!("        (No SANs found in certificate)");
            }
        }
        println!("[DEBUG] ------------------------------------------------\n");

        // Return false to confirm the handshake failure
        false
    });
    // 1. Trust the CA
    connector.set_ca_file("ca.pem").unwrap();

    // 2. Provide Client Identity
    connector
        .set_private_key_file("client.key", SslFiletype::PEM)
        .unwrap();
    connector
        .set_certificate_chain_file("client.pem")
        .unwrap();

    let connector = connector.build();
    let stream = TcpStream::connect("127.0.0.1:8443").unwrap();

    let mut config = connector.configure().unwrap();

    //config.set_use_server_name_indication(true).unwrap();
    // FIX 3: Use `set_hostname` to set the SNI
    //config.set_hostname("deadbeef").unwrap();

    // Disable hostname verification because cert is "localhost" but SNI is "deadbeef"
    config.set_verify_hostname(false);

    match config.connect("deadbeef", stream) {
        Ok(mut stream) => {
            println!("[Client] Connected!");
            stream.write_all(b"Hello from Client").unwrap();

            let mut buf = [0; 1024];
            let len = stream.read(&mut buf).unwrap();
            println!(
                "[Client] Server replied: {}",
                String::from_utf8_lossy(&buf[..len])
            );
        }
        Err(e) => eprintln!("[Client] Failed to connect: {:?}", e),
    }
}
