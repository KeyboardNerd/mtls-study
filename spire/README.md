# SPIFFE mTLS Study

This project is a study and implementation of mTLS using SPIFFE concepts in Rust. It consists of a workload agent (`attested-service`) and a mock Certificate Authority (`ca-authority`).

## Components

-   **Attested Service**: Acts as a SPIFFE workload or agent. It handles SVIDs, mTLS connections, and provides a proxy for egress traffic.
-   **CA Authority**: A mock Certificate Authority that signs SVIDs for the attested service.
-   **Proto Schema**: Shared Protocol Buffers definitions.

## Prerequisites

-   Rust (latest stable recommended)
-   `protoc` (Protocol Buffers compiler)

## Running the Project

### 1. Start the CA Authority

The CA Authority listens on `[::1]:9000` by default.

```bash
cargo run --bin ca-authority
```

### 2. Start the Attested Service

Run the attested service, specifying the service port and the proxy port.

```bash
cargo run --bin attested-service -- --port 9005 --proxy-port 50055
```

## Testing

You can use `grpcurl` to test the services.

Example command to query the Attested Service:

```bash
grpcurl -plaintext -d '{
  "address": "[::1]:9005",
  "sni": "deadbeef.deadbeef"
}' [::1]:9005 endpoint.Endpoint/Connect
```
