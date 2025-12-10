#!/bin/bash
# Test OCSP Stapling for SMTP Relay Server

echo "============================================================"
echo "OCSP Stapling Test"
echo "============================================================"

# Check if OCSP responder is running
if ! nc -z localhost 2560 2>/dev/null; then
    echo "[FAIL] OCSP responder is not running on port 2560"
    echo "   Please start it first: ./start_ocsp_responder.sh"
    exit 1
fi

echo "[OK] OCSP responder is running"

# Check if SMTP server is running
if ! nc -z localhost 8465 2>/dev/null; then
    echo "[FAIL] SMTP server is not running on port 8465"
    echo "   Please start it first:"
    echo "   python3 smtp_server_multidomain.py --chainfile certs/chain.pem --issuer-cert certs/sub-ca.crt"
    exit 1
fi

echo "[OK] SMTP server is running"

echo ""
echo "Testing OCSP Stapling with OpenSSL..."
echo ""

# Test OCSP stapling
openssl s_client -connect localhost:8465 \
    -status \
    -CAfile certs/root-ca.crt \
    -verify_return_error \
    -verify 2 \
    < /dev/null 2>&1 | tee ocsp_test/ocsp_stapling_test.log

echo ""
echo "============================================================"
echo "Test Results"
echo "============================================================"

if grep -q "OCSP Response Status: successful" ocsp_test/ocsp_stapling_test.log; then
    echo "[OK] OCSP Stapling is working!"
    echo "   OCSP response was stapled in TLS handshake"
elif grep -q "OCSP Response Status" ocsp_test/ocsp_stapling_test.log; then
    echo "[WARN]  OCSP response found but status may not be successful"
    grep "OCSP Response Status" ocsp_test/ocsp_stapling_test.log
else
    echo "[FAIL] OCSP Stapling not detected"
    echo "   Check that:"
    echo "   1. OCSP responder is running (./start_ocsp_responder.sh)"
    echo "   2. SMTP server has OCSP stapling enabled"
    echo "   3. Certificates have OCSP URLs configured"
fi

echo ""
echo "Full test log saved to: ocsp_test/ocsp_stapling_test.log"

