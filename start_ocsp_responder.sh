#!/bin/bash
# Start OCSP Responder for testing

PORT=2560
CERTS_DIR="certs"
OCSP_DIR="ocsp_test"

mkdir -p $OCSP_DIR

echo "============================================================"
echo "Starting OCSP Responder"
echo "============================================================"
echo "Port: $PORT"
echo "CA Certificate: $CERTS_DIR/sub-ca.crt"
echo "CA Key: $CERTS_DIR/sub-ca.key"
echo "Index: $CERTS_DIR/index.txt"
echo ""
echo "Press Ctrl+C to stop"
echo "============================================================"
echo ""

openssl ocsp -port $PORT \
    -index $CERTS_DIR/sub-ca_index.txt \
    -CA $CERTS_DIR/sub-ca.crt \
    -rkey $CERTS_DIR/sub-ca.key \
    -rsigner $CERTS_DIR/sub-ca.crt \
    -text \
    -out $OCSP_DIR/ocsp.log 2>&1
