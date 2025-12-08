#!/usr/bin/env python3
"""
Generate CA and server X.509v3 certificate for SMTP server.
"""
import os
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

def generate_ca():
    """Generate a simple CA certificate and private key."""
    # Generate CA private key
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Create CA certificate
    ca_subject = ca_issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
    ])
    
    ca_cert = x509.CertificateBuilder().subject_name(
        ca_subject
    ).issuer_name(
        ca_issuer
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).sign(ca_key, hashes.SHA256())
    
    return ca_key, ca_cert

def generate_server_cert(ca_key, ca_cert):
    """Generate server certificate signed by CA."""
    # Generate server private key
    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Create server certificate
    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test SMTP Server"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    
    server_cert = x509.CertificateBuilder().subject_name(
        server_subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        server_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]),
        critical=False,
    ).sign(ca_key, hashes.SHA256())
    
    return server_key, server_cert

def save_certificate(key, cert, key_path, cert_path):
    """Save private key and certificate to files."""
    # Save private key
    with open(key_path, 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    os.chmod(key_path, 0o600)
    
    # Save certificate
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

if __name__ == "__main__":
    print("Generating CA...")
    ca_key, ca_cert = generate_ca()
    
    print("Generating server certificate...")
    server_key, server_cert = generate_server_cert(ca_key, ca_cert)
    
    print("Saving certificates...")
    os.makedirs("certs", exist_ok=True)
    save_certificate(ca_key, ca_cert, "certs/ca-key.pem", "certs/ca-cert.pem")
    save_certificate(server_key, server_cert, "certs/server-key.pem", "certs/server-cert.pem")
    
    print("Done! Certificates saved in certs/ directory:")
    print("  - ca-key.pem (CA private key)")
    print("  - ca-cert.pem (CA certificate)")
    print("  - server-key.pem (Server private key)")
    print("  - server-cert.pem (Server certificate)")

