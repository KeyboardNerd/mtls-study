#!/bin/bash
set -e

# Build
cargo build --bin dns-registry
cargo build --bin attested-service
cargo build --bin ca-authority

# Cleanup
pkill -f dns-registry || true
pkill -f attested-service || true
pkill -f ca-authority || true
docker rm -f envoy || true

# Start CA Authority
echo "Starting CA Authority..."
./target/debug/ca-authority &
CA_PID=$!
sleep 2

# Start DNS Registry
echo "Starting DNS Registry..."
./target/debug/dns-registry &
REGISTRY_PID=$!
sleep 2

# Start Service A
echo "Starting Service A (Bind 127.0.0.2, Port 9005, Proxy 50055, SNI service-a.example.org)..."
./target/debug/attested-service --bind-ip 127.0.0.2 --port 9005 --proxy-port 50055 --sni service-a.example.org --registry-addr http://[::1]:9090 &
SERVICE_A_PID=$!

# Start Service B
echo "Starting Service B (Bind 127.0.0.3, Port 9005, Proxy 50056, SNI service-b.example.org)..."
./target/debug/attested-service --bind-ip 127.0.0.3 --port 9005 --proxy-port 50056 --sni service-b.example.org --registry-addr http://[::1]:9090 &
SERVICE_B_PID=$!

sleep 5

# Start Envoy
echo "Starting Envoy..."
docker run -d --name envoy \
    -v $(pwd)/envoy/envoy.yaml:/etc/envoy/envoy.yaml \
    --network host \
    envoyproxy/envoy:v1.30-latest

sleep 5

# Verify
# Verify A -> Envoy -> B
echo "Verifying Service A -> Envoy -> Service B..."
grpcurl -plaintext -d '{
    "address": "127.0.0.1:10000",
    "sni": "service-b.example",
    "message": "Hello from A via Envoy"
}' 127.0.0.2:50055 proxy.DebugProxy/CallEcho

# Verify B -> Envoy -> A
echo "Verifying Service B -> Envoy -> Service A..."
grpcurl -plaintext -d '{
    "address": "127.0.0.1:10000",
    "sni": "service-a.example",
    "message": "Hello from B via Envoy"
}' 127.0.0.3:50056 proxy.DebugProxy/CallEcho

# Cleanup
kill $CA_PID
kill $REGISTRY_PID
kill $SERVICE_A_PID
kill $SERVICE_B_PID
docker rm -f envoy
