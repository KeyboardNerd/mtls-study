#!/bin/bash
set -e

# 1. Create CA
openssl req -x509 -new -nodes -keyout ca.key -out ca.pem -days 365 -config ca.conf

# 2. Generate Server Key & CSR with SPIFFE ID in SAN
# We use -addext to inject the URI SAN
openssl req -newkey rsa:2048 -keyout server.key -out server.csr -nodes \
    -subj "/CN=localhost" \
    -addext "subjectAltName = URI:spiffe://example.org/server"

# Sign Server Cert (Crucial: use -copy_extensions copy to keep the SAN)
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out server.pem -days 365 \
    -copy_extensions copy

# 3. Generate Client Key & CSR (Client can also have a SPIFFE ID)
openssl req -newkey rsa:2048 -keyout client.key -out client.csr -nodes \
    -subj "/CN=client" \
    -addext "subjectAltName = URI:spiffe://example.org/client"

openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out client.pem -days 365 \
    -copy_extensions copy

echo "Certificates generated with SPIFFE SANs."
