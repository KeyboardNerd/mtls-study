# SPIFFE mTLS Study

This project is a study and implementation of mTLS using SPIFFE concepts in Rust. It consists of a workload agent (`attested-service`) and a mock Certificate Authority (`ca-authority`).

## Components

-   **Attested Service**: Acts as a SPIFFE workload or agent. It handles SVIDs, mTLS connections, and provides a proxy for egress traffic.
-   **CA Authority**: A mock Certificate Authority that signs SVIDs for the attested service.
-   **Proto Schema**: Shared Protocol Buffers definitions.
-   **DNS Registry**: A dynamic DNS server and registry service that allows the Attested Service to register its IP and SNI for service discovery.
-   **Envoy Proxy**: Used as a sideline proxy to route traffic based on SNI, demonstrating a transparent service mesh shutdown.

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

## Running the Demo with Envoy

A comprehensive demo script is provided to spin up a full environment with the CA, DNS Registry, two Attested Services, and an Envoy proxy.

### Prerequisites for Demo

-   Docker (for running Envoy)
-   `cargo`

### Running the Demo Script

The `demo_envoy.sh` script automates the build and execution of all components.

```bash
./demo_envoy.sh
```

This script will:
1.  Build all crates.
2.  Start the **CA Authority**.
3.  Start the **DNS Registry**.
4.  Start **Service A** (Port 9005, Proxy 50055) and **Service B** (Port 9005, Proxy 50056).
    -   Each service registers itself with the DNS Registry.
5.  Start **Envoy** via Docker (listening on host network).
6.  Verify connectivity:
    -   **Service A -> Envoy -> Service B** (using SNI routing)
    -   **Service B -> Envoy -> Service A**

### Manual Steps (for reference)

If you wish to run components manually:

#### 1. Start DNS Registry

```bash
cargo run --bin dns-registry
```
*Listens on `[::1]:9090` (gRPC) and `127.0.0.1:10053` (DNS)*

#### 2. Start Attested Services

Service A:
```bash
cargo run --bin attested-service -- \
  --bind-ip 127.0.0.2 \
  --port 9005 \
  --proxy-port 50055 \
  --sni service-a.example.org \
  --registry-addr http://[::1]:9090
```

Service B:
```bash
cargo run --bin attested-service -- \
  --bind-ip 127.0.0.3 \
  --port 9005 \
  --proxy-port 50056 \
  --sni service-b.example.org \
  --registry-addr http://[::1]:9090
```

#### 3. Start Envoy

```bash
docker run -d --name envoy \
    -v $(pwd)/envoy/envoy.yaml:/etc/envoy/envoy.yaml \
    --network host \
    envoyproxy/envoy:v1.30-latest
```
