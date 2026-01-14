# gRPC mTLS Tunnel over Unix Domain Socket

This project demonstrates a mutual TLS (mTLS) handshake for a gRPC service over a Unix Domain Socket (UDS). It includes a server and a client that authenticate each other using self-signed certificates and then communicate using both unary and streaming gRPC calls.

## How it works

The project consists of three main parts:

1.  **Certificate Generator**: A utility to generate the necessary self-signed certificates for the CA, server, and client.
2.  **gRPC Service Definition**: A `proto/tunnel.proto` file defines a simple `Tunnel` service with `Echo` (unary) and `EchoStream` (server streaming) RPCs.
3.  **gRPC mTLS Tunnel**: A client and server that communicate over a UDS using gRPC with mTLS enabled.

The server binds to a specified UDS path, configures mTLS with the server's certificate and key, and trusts the CA certificate for client authentication. It then serves the `Tunnel` gRPC service.

The client connects to the server's UDS, configures mTLS with its own certificate and key, and trusts the server's certificate. It then makes both a unary `Echo` call and a streaming `EchoStream` call to the server.

## Usage

To run the server:

```bash
cargo run --bin main -- --role server --uds-path /tmp/mtls.sock
```

To run the client:

```bash
cargo run --bin main -- --role client --uds-path /tmp/mtls.sock
```
