#!/usr/bin/env python3
"""
Quick verification script to check SMTP server standards compliance.
Tests basic SMTP protocol compliance.
"""
import smtplib
import ssl
import sys

def test_server(host, port, use_ssl=False):
    """Quick test of SMTP server."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        if use_ssl:
            server = smtplib.SMTP_SSL(host, port, context=context, timeout=5)
        else:
            server = smtplib.SMTP(host, port, timeout=5)
        
        # Test EHLO
        code, response = server.ehlo()
        print(f"EHLO: {code}")
        if isinstance(response, bytes):
            response = response.decode('utf-8', errors='ignore')
        print(f"Response: {response[:200]}")
        
        # Check extensions
        if hasattr(server, 'esmtp_features'):
            print(f"\nESMTP Features: {server.esmtp_features}")
        
        # Check AUTH
        if hasattr(server, 'auth_mechanisms'):
            print(f"AUTH mechanisms: {server.auth_mechanisms}")
        
        server.quit()
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    print("Testing SMTPS (8465)...")
    test_server('127.0.0.1', 8465, use_ssl=True)
    print("\nTesting STARTTLS (8587)...")
    test_server('127.0.0.1', 8587, use_ssl=False)

