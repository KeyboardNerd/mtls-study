# Gemini Instructions

This document provides context and instructions for the Gemini AI assistant working on this repository.

## Project Structure

-   `crates/proto-schema`: Contains Protocol Buffer definitions (`.proto`) and build script. Shared by other crates.
-   `crates/ca-authority`: A mock CA service that signs certificates.
-   `crates/attested-service`: The main workload service implementing SPIFFE logic, mTLS, and proxying.

## Key Commands

### Building

```bash
cargo build
```

### Running Components

**CA Authority:**
```bash
cargo run --bin ca-authority
```
*Listens on `[::1]:9000`*

**Attested Service:**
```bash
cargo run --bin attested-service -- --port 9005 --proxy-port 50055
```
*Listens on port 9005 (gRPC) and 50055 (Proxy)*

### Testing

Use `grpcurl` for manual testing of gRPC endpoints.

## Development Notes

-   **Protobufs**: When modifying `.proto` files in `crates/proto-schema`, ensure they are correctly recompiled. `build.rs` handles this.
-   **Ignored Files**: The `target/` directories are ignored via `.gitignore`.
-   **Dependencies**: Key crates include `tonic` (gRPC), `tokio` (Async runtime), `boring` (BoringSSL bindings), and `spiffe` related crates.

## Common Tasks

-   **Adding new protos**: Update `crates/proto-schema/proto/`, add to `build.rs`, and re-export in `lib.rs`.
-   **Debugging**: Use `println!` or `tracing` (if configured) to debug async flows.
