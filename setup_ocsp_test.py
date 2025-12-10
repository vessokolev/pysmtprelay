#!/usr/bin/env python3
"""
Setup OCSP Stapling Test Environment

Creates:
1. Root CA certificate
2. Sub-CA certificate (signed by Root CA)
3. Server certificate (signed by Sub-CA)
4. CRL files for Sub-CA and Root CA
5. Certificate chain file
6. OCSP responder configuration

This creates a complete certificate hierarchy for testing OCSP stapling.
"""
import os
import subprocess
import shutil
from pathlib import Path

# Directory structure
CERTS_DIR = Path("certs")
OCSP_DIR = Path("ocsp_test")
OCSP_DIR.mkdir(exist_ok=True)
CERTS_DIR.mkdir(exist_ok=True)

# OCSP responder port
OCSP_PORT = 2560

def run_command(cmd, check=True):
    """Run a shell command."""
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, check=check)
    if result.returncode != 0 and check:
        print(f"Error: {result.stderr}")
    return result

def create_openssl_config(filename, content):
    """Create OpenSSL configuration file."""
    with open(filename, 'w') as f:
        f.write(content)
    print(f"[OK] Created: {filename}")

def setup_root_ca():
    """Create Root CA certificate and key."""
    print("\n" + "="*60)
    print("Creating Root CA")
    print("="*60)
    
    # Root CA private key
    run_command(['openssl', 'genrsa', '-out', 'certs/root-ca.key', '4096'])
    
    # Root CA certificate
    root_ca_config = f"""[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
C = US
ST = Test State
L = Test City
O = Test Organization
OU = Root CA
CN = Root CA

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
"""
    create_openssl_config('certs/root-ca.conf', root_ca_config)
    
    run_command(['openssl', 'req', '-new', '-x509', '-days', '3650',
                 '-key', 'certs/root-ca.key', '-out', 'certs/root-ca.crt',
                 '-config', 'certs/root-ca.conf', '-extensions', 'v3_ca'])
    
    print("[OK] Root CA created: certs/root-ca.crt")

def setup_sub_ca():
    """Create Sub-CA certificate signed by Root CA."""
    print("\n" + "="*60)
    print("Creating Sub-CA")
    print("="*60)
    
    # Sub-CA private key
    run_command(['openssl', 'genrsa', '-out', 'certs/sub-ca.key', '4096'])
    
    # Sub-CA certificate request (without extensions that need issuer)
    sub_ca_config = f"""[req]
distinguished_name = req_distinguished_name
req_extensions = v3_sub_ca
prompt = no

[req_distinguished_name]
C = US
ST = Test State
L = Test City
O = Test Organization
OU = Sub CA
CN = Sub CA

[v3_sub_ca]
subjectKeyIdentifier = hash
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
"""
    create_openssl_config('certs/sub-ca.conf', sub_ca_config)
    
    # Create certificate request
    run_command(['openssl', 'req', '-new', '-key', 'certs/sub-ca.key',
                 '-out', 'certs/sub-ca.csr', '-config', 'certs/sub-ca.conf'])
    
    # Create signing config with extensions that need issuer
    sub_ca_signing_config = f"""[v3_sub_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
authorityInfoAccess = @ocsp_info

[ocsp_info]
OCSP;URI = http://localhost:{OCSP_PORT}
"""
    create_openssl_config('certs/sub-ca-signing.conf', sub_ca_signing_config)
    
    # Sign with Root CA (add OCSP URL and authorityKeyIdentifier during signing)
    run_command(['openssl', 'x509', '-req', '-days', '1825',
                 '-in', 'certs/sub-ca.csr', '-CA', 'certs/root-ca.crt',
                 '-CAkey', 'certs/root-ca.key', '-CAcreateserial',
                 '-out', 'certs/sub-ca.crt', '-extensions', 'v3_sub_ca',
                 '-extfile', 'certs/sub-ca-signing.conf'])
    
    print("[OK] Sub-CA created: certs/sub-ca.crt")

def setup_server_cert():
    """Create server certificate signed by Sub-CA."""
    print("\n" + "="*60)
    print("Creating Server Certificate")
    print("="*60)
    
    # Server private key
    run_command(['openssl', 'genrsa', '-out', 'certs/server-key.pem', '2048'])
    
    # Server certificate request (without extensions that need issuer)
    server_config = f"""[req]
distinguished_name = req_distinguished_name
req_extensions = v3_server
prompt = no

[req_distinguished_name]
C = US
ST = Test State
L = Test City
O = Test Organization
OU = SMTP Server
CN = localhost

[v3_server]
subjectKeyIdentifier = hash
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
IP.1 = 127.0.0.1
IP.2 = ::1
"""
    create_openssl_config('certs/server.conf', server_config)
    
    # Create certificate request
    run_command(['openssl', 'req', '-new', '-key', 'certs/server-key.pem',
                 '-out', 'certs/server.csr', '-config', 'certs/server.conf'])
    
    # Create signing config with extensions that need issuer
    server_signing_config = f"""[v3_server]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
authorityInfoAccess = @ocsp_info

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
IP.1 = 127.0.0.1
IP.2 = ::1

[ocsp_info]
OCSP;URI = http://localhost:{OCSP_PORT}
"""
    create_openssl_config('certs/server-signing.conf', server_signing_config)
    
    # Sign with Sub-CA (add OCSP URL and authorityKeyIdentifier during signing)
    run_command(['openssl', 'x509', '-req', '-days', '365',
                 '-in', 'certs/server.csr', '-CA', 'certs/sub-ca.crt',
                 '-CAkey', 'certs/sub-ca.key', '-CAcreateserial',
                 '-out', 'certs/server-cert.pem', '-extensions', 'v3_server',
                 '-extfile', 'certs/server-signing.conf'])
    
    print("[OK] Server certificate created: certs/server-cert.pem")
    
    # Add server certificate to Sub-CA index file for OCSP
    # Format: status_flag expiration_date revocation_date serial_number filename
    try:
        import subprocess
        result = subprocess.run(
            ['openssl', 'x509', '-in', 'certs/server-cert.pem', '-noout', '-serial', '-dates', '-subject'],
            capture_output=True, text=True, check=True
        )
        # Parse serial number
        serial = None
        not_before = None
        for line in result.stdout.split('\n'):
            if line.startswith('serial='):
                serial = line.split('=')[1].strip()
            elif 'notBefore=' in line:
                # Format: notBefore=Dec  8 21:18:22 2025 GMT
                # Convert to YYMMDDHHMMSSZ format
                parts = line.split('=')[1].strip().split()
                if len(parts) >= 5:
                    month_map = {'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
                                'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
                                'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'}
                    month = month_map.get(parts[0], '01')
                    day = parts[1].zfill(2)
                    time_parts = parts[2].split(':')
                    hour = time_parts[0].zfill(2)
                    minute = time_parts[1].zfill(2)
                    second = time_parts[2].zfill(2) if len(time_parts) > 2 else '00'
                    year = parts[3][-2:]  # Last 2 digits
                    not_before = f"{year}{month}{day}{hour}{minute}{second}Z"
        
        if serial and not_before:
            # Add entry to index file: V (valid), expiration date, empty revocation date, serial, unknown, subject
            subject = subprocess.run(
                ['openssl', 'x509', '-in', 'certs/server-cert.pem', '-noout', '-subject'],
                capture_output=True, text=True, check=True
            ).stdout.strip().replace('subject=', '').replace(' ', '/')
            
            index_entry = f"V\t{not_before}\t\t{serial}\tunknown\t{subject}\n"
            with open('certs/sub-ca_index.txt', 'a') as f:
                f.write(index_entry)
            print(f"[OK] Added server certificate to OCSP index: {serial}")
    except Exception as e:
        print(f"Warning: Could not add server certificate to OCSP index: {e}")

def create_certificate_chain():
    """Create certificate chain file (Sub-CA + Server)."""
    print("\n" + "="*60)
    print("Creating Certificate Chain")
    print("="*60)
    
    # Chain: Server cert + Sub-CA cert (Root CA not needed for chain)
    with open('certs/chain.pem', 'w') as chain:
        # Server certificate
        with open('certs/server-cert.pem', 'r') as server:
            chain.write(server.read())
        # Sub-CA certificate
        with open('certs/sub-ca.crt', 'r') as subca:
            chain.write(subca.read())
    
    print("[OK] Certificate chain created: certs/chain.pem")

def generate_crls():
    """Generate CRL files for Root CA and Sub-CA."""
    print("\n" + "="*60)
    print("Generating CRLs")
    print("="*60)
    
    # Update CA configs to include CA database settings
    root_ca_config_full = f"""[ca]
default_ca = CA_default

[CA_default]
dir = {os.path.abspath('certs')}
database = $dir/index.txt
serial = $dir/serial
new_certs_dir = $dir
certificate = $dir/root-ca.crt
private_key = $dir/root-ca.key
RANDFILE = $dir/.rand
x509_extensions = v3_ca
default_days = 365
default_crl_days = 30
default_md = sha256
preserve = no
policy = policy_match

[policy_match]
countryName = match
stateOrProvinceName = match
organizationName = match
organizationalUnitName = optional
commonName = supplied
emailAddress = optional

[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
C = US
ST = Test State
L = Test City
O = Test Organization
OU = Root CA
CN = Root CA

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[crl]
authorityKeyIdentifier = keyid:always
"""
    create_openssl_config('certs/root-ca.conf', root_ca_config_full)
    
    # Create database files for Root CA
    Path('certs/index.txt').touch()
    Path('certs/serial').write_text('01\n')
    
    # Generate Root CA CRL
    run_command(['openssl', 'ca', '-gencrl', '-keyfile', 'certs/root-ca.key',
                 '-cert', 'certs/root-ca.crt', '-out', 'certs/root-ca.crl',
                 '-config', 'certs/root-ca.conf', '-crldays', '30'], check=False)
    
    # Sub-CA config with CA database settings
    sub_ca_config_full = f"""[ca]
default_ca = CA_default

[CA_default]
dir = {os.path.abspath('certs')}
database = $dir/index.txt
serial = $dir/serial
new_certs_dir = $dir
certificate = $dir/sub-ca.crt
private_key = $dir/sub-ca.key
RANDFILE = $dir/.rand
x509_extensions = v3_sub_ca
default_days = 365
default_crl_days = 30
default_md = sha256
preserve = no
policy = policy_match

[policy_match]
countryName = match
stateOrProvinceName = match
organizationName = match
organizationalUnitName = optional
commonName = supplied
emailAddress = optional

[req]
distinguished_name = req_distinguished_name
req_extensions = v3_sub_ca
prompt = no

[req_distinguished_name]
C = US
ST = Test State
L = Test City
O = Test Organization
OU = Sub CA
CN = Sub CA

[v3_sub_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
authorityInfoAccess = @ocsp_info

[ocsp_info]
OCSP;URI = http://localhost:{OCSP_PORT}

[crl]
authorityKeyIdentifier = keyid:always
"""
    create_openssl_config('certs/sub-ca.conf', sub_ca_config_full)
    
    # Generate Sub-CA CRL
    run_command(['openssl', 'ca', '-gencrl', '-keyfile', 'certs/sub-ca.key',
                 '-cert', 'certs/sub-ca.crt', '-out', 'certs/sub-ca.crl',
                 '-config', 'certs/sub-ca.conf', '-crldays', '30'], check=False)
    
    # Alternative: Use x509 -gencrl (simpler, doesn't require CA database)
    print("Generating CRLs using x509 method...")
    run_command(['openssl', 'x509', '-gencrl', '-keyfile', 'certs/root-ca.key',
                 '-cert', 'certs/root-ca.crt', '-out', 'certs/root-ca.crl',
                 '-days', '30'], check=False)
    
    run_command(['openssl', 'x509', '-gencrl', '-keyfile', 'certs/sub-ca.key',
                 '-cert', 'certs/sub-ca.crt', '-out', 'certs/sub-ca.crl',
                 '-days', '30'], check=False)
    
    if os.path.exists('certs/root-ca.crl') and os.path.exists('certs/sub-ca.crl'):
        print("[OK] CRLs generated:")
        print("   - certs/root-ca.crl")
        print("   - certs/sub-ca.crl")
    else:
        print("[WARN]  CRL generation had issues, but continuing...")

def setup_ocsp_responder():
    """Setup OCSP responder configuration."""
    print("\n" + "="*60)
    print("Setting up OCSP Responder")
    print("="*60)
    
    # OCSP responder configuration
    ocsp_config = f"""[ocsp]
# OCSP Responder configuration

[ca_default]
dir = {os.path.abspath('certs')}
database = $dir/index.txt
serial = $dir/serial
new_certs_dir = $dir
certificate = $dir/sub-ca.crt
private_key = $dir/sub-ca.key
RANDFILE = $dir/.rand
x509_extensions = usr_cert
default_days = 365
default_crl_days = 30
default_md = sha256
preserve = no
policy = policy_match

[policy_match]
countryName = match
stateOrProvinceName = match
organizationName = match
organizationalUnitName = optional
commonName = supplied
emailAddress = optional

[usr_cert]
basicConstraints = CA:FALSE
"""
    create_openssl_config('ocsp_test/ocsp.conf', ocsp_config)
    
    print("[OK] OCSP responder configuration created: ocsp_test/ocsp.conf")
    print(f"\n[TODO] To start OCSP responder, run:")
    print(f"   openssl ocsp -port {OCSP_PORT} -index certs/index.txt \\")
    print(f"                -CA certs/sub-ca.crt -rkey certs/sub-ca.key \\")
    print(f"                -rsigner certs/sub-ca.crt -text")

def create_start_ocsp_script():
    """Create script to start OCSP responder."""
    script = f"""#!/bin/bash
# Start OCSP Responder for testing

PORT={OCSP_PORT}
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

openssl ocsp -port $PORT \\
    -index $CERTS_DIR/index.txt \\
    -CA $CERTS_DIR/sub-ca.crt \\
    -rkey $CERTS_DIR/sub-ca.key \\
    -rsigner $CERTS_DIR/sub-ca.crt \\
    -text \\
    -out $OCSP_DIR/ocsp.log 2>&1
"""
    with open('start_ocsp_responder.sh', 'w') as f:
        f.write(script)
    os.chmod('start_ocsp_responder.sh', 0o755)
    print("[OK] Created: start_ocsp_responder.sh")

def verify_setup():
    """Verify the certificate setup."""
    print("\n" + "="*60)
    print("Verifying Certificate Setup")
    print("="*60)
    
    # Verify Root CA
    result = run_command(['openssl', 'x509', '-in', 'certs/root-ca.crt', '-noout', '-text'], check=False)
    if result.returncode == 0:
        print("[OK] Root CA certificate is valid")
    
    # Verify Sub-CA
    result = run_command(['openssl', 'x509', '-in', 'certs/sub-ca.crt', '-noout', '-text'], check=False)
    if result.returncode == 0:
        print("[OK] Sub-CA certificate is valid")
        # Check for OCSP URL
        if 'OCSP' in result.stdout:
            print("[OK] Sub-CA has OCSP URL")
    
    # Verify Server cert
    result = run_command(['openssl', 'x509', '-in', 'certs/server-cert.pem', '-noout', '-text'], check=False)
    if result.returncode == 0:
        print("[OK] Server certificate is valid")
        # Check for OCSP URL
        if 'OCSP' in result.stdout:
            print("[OK] Server cert has OCSP URL")
    
    # Verify chain
    if os.path.exists('certs/chain.pem'):
        result = run_command(['openssl', 'verify', '-CAfile', 'certs/root-ca.crt',
                             '-untrusted', 'certs/sub-ca.crt', 'certs/server-cert.pem'], check=False)
        if result.returncode == 0:
            print("[OK] Certificate chain is valid")
        else:
            print(f"[WARN]  Chain verification: {result.stderr}")

def main():
    """Main setup function."""
    print("="*60)
    print("OCSP Stapling Test Environment Setup")
    print("="*60)
    
    try:
        setup_root_ca()
        setup_sub_ca()
        setup_server_cert()
        create_certificate_chain()
        generate_crls()
        setup_ocsp_responder()
        create_start_ocsp_script()
        verify_setup()
        
        print("\n" + "="*60)
        print("[OK] Setup Complete!")
        print("="*60)
        print("\nNext steps:")
        print("1. Start OCSP responder (in one terminal):")
        print("   ./start_ocsp_responder.sh")
        print("\n2. In another terminal, start SMTP server:")
        print("   python3 smtp_server_multidomain.py \\")
        print("       --certfile certs/server-cert.pem \\")
        print("       --keyfile certs/server-key.pem \\")
        print("       --chainfile certs/chain.pem \\")
        print("       --issuer-cert certs/sub-ca.crt")
        print("\n3. Test OCSP stapling (in a third terminal):")
        print("   ./test_ocsp_stapling.sh")
        print("\n   Or manually:")
        print("   openssl s_client -connect localhost:8465 \\")
        print("       -status -CAfile certs/root-ca.crt -verify_return_error")
        print("\n" + "="*60)
        
    except Exception as e:
        print(f"\n[FAIL] Error during setup: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == '__main__':
    exit(main())

