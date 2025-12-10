#!/usr/bin/env python3
"""
Check what TLS key exchange configuration options are ACTUALLY available in Python.
"""

import ssl
import sys

def check_ssl_capabilities():
    """Check what Python's ssl module actually supports."""
    print("=" * 60)
    print("Python SSL Module - ACTUAL Capabilities")
    print("=" * 60)
    
    print(f"\nPython version: {sys.version}")
    print(f"OpenSSL version: {ssl.OPENSSL_VERSION}")
    
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    
    print("\nAvailable methods for key exchange configuration:")
    methods = [m for m in dir(ctx) if m.startswith('set_') and callable(getattr(ctx, m))]
    for m in sorted(methods):
        print(f"  ✓ {m}")
    
    print("\n" + "=" * 60)
    print("REALITY CHECK:")
    print("=" * 60)
    print("✗ set_groups() does NOT exist in Python")
    print("✓ set_ecdh_curve() exists - can configure classical ECDHE curves")
    print("✗ NO Python API for post-quantum key exchange groups")
    print("\nWhat we CAN do:")
    print("  - Use set_ecdh_curve('secp384r1') for classical ECDHE")
    print("  - This provides strong security but NOT post-quantum")
    print("\nWhat we CANNOT do:")
    print("  - Configure ML-KEM-768 or other post-quantum groups")
    print("  - Python's ssl module does not expose this functionality")
    
    return False

if __name__ == "__main__":
    check_ssl_capabilities()

