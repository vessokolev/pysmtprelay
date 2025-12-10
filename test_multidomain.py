#!/usr/bin/env python3
"""
Test script for multi-domain SMTP server with OAuth2.
Tests domain extraction, routing, and authentication.
"""
import smtplib
import ssl
import base64
import json
import sys
import time
from oauth2_multidomain_provider import oauth2_multidomain_provider, extract_domain

def test_domain_extraction():
    """Test domain extraction function."""
    print("=" * 60)
    print("TEST 1: Domain Extraction")
    print("=" * 60)
    
    test_cases = [
        ("user@example.com", "example.com"),
        ("admin@company.com", "company.com"),
        ("test@test.org", "test.org"),
        ("user@subdomain.example.com", "subdomain.example.com"),
    ]
    
    all_passed = True
    for email, expected_domain in test_cases:
        try:
            domain = extract_domain(email)
            if domain == expected_domain:
                print(f"  [OK] {email} -> {domain}")
            else:
                print(f"  [FAIL] {email} -> {domain} (expected {expected_domain})")
                all_passed = False
        except Exception as e:
            print(f"  [FAIL] {email} -> Error: {e}")
            all_passed = False
    
    return all_passed

def test_oauth2_provider():
    """Test OAuth2 provider multi-domain functionality."""
    print("\n" + "=" * 60)
    print("TEST 2: OAuth2 Provider Multi-Domain")
    print("=" * 60)
    
    provider = oauth2_multidomain_provider
    all_passed = True
    
    # Test authentication
    print("\n2.1 Testing authentication:")
    auth_tests = [
        ("user1@example.com", "password1", True, "example.com"),
        ("employee@company.com", "emp123", True, "company.com"),
        ("user1@example.com", "wrong", False, None),
        ("nonexistent@example.com", "pass", False, None),
    ]
    
    for email, password, expected_success, expected_domain in auth_tests:
        success, domain = provider.authenticate_user(email, password)
        if success == expected_success and domain == expected_domain:
            print(f"  [OK] {email} / {password[:3]}... -> {success}, domain: {domain}")
        else:
            print(f"  [FAIL] {email} / {password[:3]}... -> {success}, domain: {domain} (expected {expected_success}, {expected_domain})")
            all_passed = False
    
    # Test token generation
    print("\n2.2 Testing token generation:")
    token_tests = [
        ("user1@example.com", "password1", "test_client_id", "test_client_secret", True),
        ("employee@company.com", "emp123", "test_client_id", "test_client_secret", True),
        ("user1@example.com", "wrong", "test_client_id", "test_client_secret", False),
    ]
    
    tokens = {}
    for email, password, client_id, client_secret, should_succeed in token_tests:
        token = provider.generate_access_token_with_password(
            email, password, client_id, client_secret
        )
        if (token is not None) == should_succeed:
            print(f"  [OK] {email} -> token: {token[:20] if token else 'None'}...")
            if token:
                tokens[email] = token
        else:
            print(f"  [FAIL] {email} -> token: {token}")
            all_passed = False
    
    # Test token validation
    print("\n2.3 Testing token validation:")
    for email, token in tokens.items():
        info = provider.validate_token(token)
        if info and info.get('user') == email:
            print(f"  [OK] Token for {email} -> valid, domain: {info.get('domain')}")
        else:
            print(f"  [FAIL] Token for {email} -> invalid")
            all_passed = False
    
    # Test domain restrictions
    print("\n2.4 Testing domain restrictions:")
    restriction_tests = [
        ("user1@example.com", "password1", "smtp_client_example", "smtp_secret_example", True),
        ("employee@company.com", "emp123", "smtp_client_example", "smtp_secret_example", False),  # Wrong domain
        ("employee@company.com", "emp123", "smtp_client_company", "smtp_secret_company", True),
    ]
    
    for email, password, client_id, client_secret, should_succeed in restriction_tests:
        token = provider.generate_access_token_with_password(
            email, password, client_id, client_secret
        )
        if (token is not None) == should_succeed:
            print(f"  [OK] {email} with {client_id} -> {'allowed' if token else 'denied'}")
        else:
            print(f"  [FAIL] {email} with {client_id} -> {'denied' if token else 'allowed'} (expected {'allowed' if should_succeed else 'denied'})")
            all_passed = False
    
    return all_passed

def test_smtp_plain_auth(host='localhost', port=8465, use_ssl=False):
    """Test SMTP AUTH PLAIN with multi-domain."""
    print("\n" + "=" * 60)
    print("TEST 3: SMTP AUTH PLAIN (Multi-Domain)")
    print("=" * 60)
    
    all_passed = True
    
    test_cases = [
        ("user1@example.com", "password1", True),
        ("employee@company.com", "emp123", True),
        ("user1@example.com", "wrong", False),
        ("nonexistent@example.com", "pass", False),
    ]
    
    for email, password, should_succeed in test_cases:
        try:
            # Connect (with or without SSL)
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                server = smtplib.SMTP_SSL(host, port, timeout=10, context=context)
            else:
                server = smtplib.SMTP(host, port, timeout=10)
            server.ehlo()
            
            # Authenticate
            try:
                server.login(email, password)
                if should_succeed:
                    print(f"  [OK] {email} / {password[:3]}... -> Authentication successful")
                    server.quit()
                else:
                    print(f"  [FAIL] {email} / {password[:3]}... -> Authentication succeeded (should have failed)")
                    server.quit()
                    all_passed = False
            except smtplib.SMTPAuthenticationError:
                if not should_succeed:
                    print(f"  [OK] {email} / {password[:3]}... -> Authentication failed (as expected)")
                    server.quit()
                else:
                    print(f"  [FAIL] {email} / {password[:3]}... -> Authentication failed (should have succeeded)")
                    server.quit()
                    all_passed = False
            except Exception as e:
                print(f"  [FAIL] {email} -> Error: {e}")
                all_passed = False
        except Exception as e:
            print(f"  [FAIL] {email} -> Connection error: {e}")
            all_passed = False
            time.sleep(0.5)  # Brief delay between tests
    
    return all_passed

def test_smtp_oauth2_auth(host='localhost', port=8465, use_ssl=False):
    """Test SMTP AUTH XOAUTH2 with multi-domain."""
    print("\n" + "=" * 60)
    print("TEST 4: SMTP AUTH XOAUTH2 (Multi-Domain)")
    print("=" * 60)
    
    provider = oauth2_multidomain_provider
    all_passed = True
    
    test_cases = [
        ("user1@example.com", "password1", "test_client_id", "test_client_secret", True),
        ("employee@company.com", "emp123", "test_client_id", "test_client_secret", True),
        ("user1@example.com", "wrong", "test_client_id", "test_client_secret", False),
    ]
    
    for email, password, client_id, client_secret, should_succeed in test_cases:
        try:
            # Generate token
            token = provider.generate_access_token_with_password(
                email, password, client_id, client_secret
            )
            
            if not token and should_succeed:
                print(f"  [FAIL] {email} -> Token generation failed")
                all_passed = False
                continue
            
            if not token:
                print(f"  [OK] {email} -> Token generation failed (as expected)")
                continue
            
            # Connect (with or without SSL)
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                server = smtplib.SMTP_SSL(host, port, timeout=10, context=context)
            else:
                server = smtplib.SMTP(host, port, timeout=10)
            server.ehlo()
            
            # Prepare XOAUTH2 payload
            oauth2_payload = {
                "user": email,
                "authMethod": "XOAUTH2",
                "authToken": token
            }
            oauth2_string = json.dumps(oauth2_payload)
            oauth2_b64 = base64.b64encode(oauth2_string.encode()).decode()
            
            # Authenticate
            try:
                server.docmd("AUTH", f"XOAUTH2 {oauth2_b64}")
                if should_succeed:
                    print(f"  [OK] {email} -> OAuth2 authentication successful")
                    server.quit()
                else:
                    print(f"  [FAIL] {email} -> OAuth2 authentication succeeded (should have failed)")
                    server.quit()
                    all_passed = False
            except smtplib.SMTPException as e:
                if not should_succeed:
                    print(f"  [OK] {email} -> OAuth2 authentication failed (as expected): {e}")
                    server.quit()
                else:
                    print(f"  [FAIL] {email} -> OAuth2 authentication failed (should have succeeded): {e}")
                    server.quit()
                    all_passed = False
            except Exception as e:
                print(f"  [FAIL] {email} -> Error: {e}")
                all_passed = False
        except Exception as e:
            print(f"  [FAIL] {email} -> Error: {e}")
            all_passed = False
            time.sleep(0.5)  # Brief delay between tests
    
    return all_passed

def test_domain_validation(host='localhost', port=8465, use_ssl=False):
    """Test domain validation in MAIL FROM."""
    print("\n" + "=" * 60)
    print("TEST 5: Domain Validation (MAIL FROM)")
    print("=" * 60)
    
    all_passed = True
    
    # Authenticate as user1@example.com
    try:
        # Connect (with or without SSL)
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            server = smtplib.SMTP_SSL(host, port, timeout=10, context=context)
        else:
            server = smtplib.SMTP(host, port, timeout=10)
        server.ehlo()
        server.login("user1@example.com", "password1")
        
        # Test 1: Valid domain match
        try:
            server.mail("user1@example.com")
            print("  [OK] MAIL FROM with matching domain -> Accepted")
        except Exception as e:
            print(f"  [FAIL] MAIL FROM with matching domain -> Rejected: {e}")
            all_passed = False
        
        # Test 2: Invalid domain mismatch
        try:
            server.mail("user1@company.com")  # Different domain
            print("  [FAIL] MAIL FROM with mismatched domain -> Accepted (should be rejected)")
            all_passed = False
        except smtplib.SMTPException as e:
            if "domain" in str(e).lower() or "mismatch" in str(e).lower():
                print("  [OK] MAIL FROM with mismatched domain -> Rejected (as expected)")
            else:
                print(f"  [WARN]  MAIL FROM with mismatched domain -> Rejected (unexpected reason): {e}")
        
        server.quit()
    except Exception as e:
        print(f"  [FAIL] Test setup error: {e}")
        all_passed = False
    
    return all_passed

def main():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("MULTI-DOMAIN SMTP SERVER TEST SUITE")
    print("=" * 60)
    print("\nMake sure the server is running:")
    print("  python3 smtp_server_multidomain.py")
    print("\nPress Enter to start tests...")
    input()
    
    results = []
    
    # Test 1: Domain extraction
    results.append(("Domain Extraction", test_domain_extraction()))
    
    # Test 2: OAuth2 provider
    results.append(("OAuth2 Provider", test_oauth2_provider()))
    
    # Test 3: SMTP PLAIN auth (without SSL for testing)
    results.append(("SMTP AUTH PLAIN", test_smtp_plain_auth(use_ssl=False)))
    
    # Test 4: SMTP OAuth2 auth (without SSL for testing)
    results.append(("SMTP AUTH XOAUTH2", test_smtp_oauth2_auth(use_ssl=False)))
    
    # Test 5: Domain validation (without SSL for testing)
    results.append(("Domain Validation", test_domain_validation(use_ssl=False)))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    all_passed = True
    for test_name, passed in results:
        status = "[OK] PASSED" if passed else "[FAIL] FAILED"
        print(f"  {test_name}: {status}")
        if not passed:
            all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("[OK] ALL TESTS PASSED")
    else:
        print("[FAIL] SOME TESTS FAILED")
    print("=" * 60)
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())

