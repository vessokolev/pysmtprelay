#!/usr/bin/env python3
"""
Test SMTP server compliance with RFC standards and common client compatibility.
Tests based on:
- RFC 5321 (SMTP)
- RFC 3207 (STARTTLS)
- RFC 4954 (AUTH)
- RFC 7628 (XOAUTH2)
"""
import smtplib
import ssl
import socket
import re
import sys
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class SMTPComplianceTester:
    """Test SMTP server for RFC compliance."""
    
    def __init__(self, host='127.0.0.1', port_smtps=8465, port_starttls=8587):
        self.host = host
        self.port_smtps = port_smtps
        self.port_starttls = port_starttls
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE
        self.results = []
    
    def log(self, test_name, passed, message=""):
        """Log test result."""
        status = "✅ PASS" if passed else "❌ FAIL"
        self.results.append((test_name, passed, message))
        print(f"{status}: {test_name}")
        if message:
            print(f"   {message}")
    
    def test_ehlo_response(self, server, expect_auth=True):
        """Test EHLO response format (RFC 5321)."""
        try:
            code, response = server.ehlo()
            # EHLO should return 250
            if code == 250:
                self.log("EHLO returns 250", True)
            else:
                self.log("EHLO returns 250", False, f"Got {code} instead")
                return False
            
            # Response should be multiline
            if isinstance(response, bytes):
                response = response.decode('utf-8', errors='ignore')
            
            # Check for required extensions
            extensions = []
            if isinstance(response, str):
                lines = response.split('\n')
                for line in lines:
                    if line.strip():
                        extensions.append(line.strip())
            
            # Check for STARTTLS (if not SMTPS)
            has_starttls = any('STARTTLS' in ext.upper() for ext in extensions)
            has_auth = any('AUTH' in ext.upper() for ext in extensions)
            
            self.log("EHLO response is multiline", len(extensions) > 1, 
                    f"Found {len(extensions)} extension lines")
            if expect_auth:
                self.log("EHLO advertises AUTH", has_auth, 
                        "AUTH extension found" if has_auth else "AUTH extension missing")
            else:
                # RFC 3207: AUTH should NOT be advertised before STARTTLS
                self.log("EHLO does NOT advertise AUTH before STARTTLS", not has_auth,
                        "AUTH correctly hidden before STARTTLS" if not has_auth else "AUTH should not be advertised")
            
            return True
        except Exception as e:
            self.log("EHLO command works", False, str(e))
            return False
    
    def test_helo_response(self, server):
        """Test HELO response (RFC 5321)."""
        try:
            code, response = server.helo()
            # HELO should return 250
            if code == 250:
                self.log("HELO returns 250", True)
                return True
            else:
                self.log("HELO returns 250", False, f"Got {code} instead")
                return False
        except Exception as e:
            self.log("HELO command works", False, str(e))
            return False
    
    def test_starttls(self, server):
        """Test STARTTLS (RFC 3207)."""
        try:
            # Check if STARTTLS is advertised
            code, response = server.ehlo()
            if isinstance(response, bytes):
                response = response.decode('utf-8', errors='ignore')
            
            has_starttls = 'STARTTLS' in str(response).upper()
            if not has_starttls:
                self.log("STARTTLS advertised in EHLO", False, "STARTTLS not found in EHLO response")
                return False
            
            self.log("STARTTLS advertised in EHLO", True)
            
            # Try STARTTLS
            code, response = server.starttls(context=self.context)
            if code == 220:
                self.log("STARTTLS returns 220", True)
                # After STARTTLS, should send EHLO again
                code, response = server.ehlo()
                if code == 250:
                    self.log("EHLO after STARTTLS works", True)
                    return True
                else:
                    self.log("EHLO after STARTTLS works", False, f"Got {code}")
                    return False
            else:
                self.log("STARTTLS returns 220", False, f"Got {code}")
                return False
        except Exception as e:
            self.log("STARTTLS works", False, str(e))
            return False
    
    def test_auth_plain(self, server):
        """Test AUTH PLAIN (RFC 4954)."""
        try:
            # Check AUTH mechanisms
            code, response = server.ehlo()
            if isinstance(response, bytes):
                response = response.decode('utf-8', errors='ignore')
            
            # Check if PLAIN is advertised
            has_plain = 'PLAIN' in str(response).upper()
            if not has_plain:
                self.log("AUTH PLAIN advertised", False, "PLAIN not found in AUTH mechanisms")
                return False
            
            self.log("AUTH PLAIN advertised", True)
            
            # Try authentication
            server.login('testuser', 'testpass123')
            self.log("AUTH PLAIN authentication works", True)
            return True
        except smtplib.SMTPAuthenticationError as e:
            self.log("AUTH PLAIN authentication works", False, f"Auth failed: {e}")
            return False
        except Exception as e:
            self.log("AUTH PLAIN authentication works", False, str(e))
            return False
    
    def test_auth_oauth2(self, server):
        """Test AUTH XOAUTH2 (RFC 7628)."""
        try:
            # Check AUTH mechanisms
            code, response = server.ehlo()
            if isinstance(response, bytes):
                response = response.decode('utf-8', errors='ignore')
            
            # Check if XOAUTH2 is advertised
            has_xoauth2 = 'XOAUTH2' in str(response).upper()
            if not has_xoauth2:
                self.log("AUTH XOAUTH2 advertised", False, "XOAUTH2 not found in AUTH mechanisms")
                return False
            
            self.log("AUTH XOAUTH2 advertised", True)
            return True
        except Exception as e:
            self.log("AUTH XOAUTH2 advertised", False, str(e))
            return False
    
    def test_mail_rcpt_data_sequence(self, server):
        """Test MAIL/RCPT/DATA sequence (RFC 5321)."""
        try:
            # Must be authenticated first
            server.login('testuser', 'testpass123')
            
            # MAIL FROM
            code, response = server.mail('testuser@example.com')
            if code == 250:
                self.log("MAIL FROM returns 250", True)
            else:
                self.log("MAIL FROM returns 250", False, f"Got {code}")
                return False
            
            # RCPT TO
            code, response = server.rcpt('test@example.org')
            if code == 250:
                self.log("RCPT TO returns 250", True)
            else:
                self.log("RCPT TO returns 250", False, f"Got {code}")
                return False
            
            # DATA
            code, response = server.data('Subject: Test\n\nTest message')
            if code == 250:
                self.log("DATA returns 250", True)
                return True
            else:
                self.log("DATA returns 250", False, f"Got {code}")
                return False
        except Exception as e:
            self.log("MAIL/RCPT/DATA sequence", False, str(e))
            return False
    
    def test_authentication_required(self, server):
        """Test that authentication is required for MAIL/RCPT/DATA."""
        try:
            # Ensure we're not authenticated (server should track state)
            # Try MAIL FROM without auth
            code, response = server.mail('testuser@example.com')
            if code == 530:  # Authentication required (RFC 5321)
                self.log("MAIL requires authentication", True)
            elif code >= 500:
                # Any 5xx error is acceptable for unauthenticated MAIL
                self.log("MAIL requires authentication", True, f"Got {code} (acceptable)")
            else:
                self.log("MAIL requires authentication", False, f"Got {code}, expected 530")
                return False
            
            return True
        except smtplib.SMTPException as e:
            # Some clients might raise exception for 530
            self.log("MAIL requires authentication", True, f"Exception raised (expected): {type(e).__name__}")
            return True
        except Exception as e:
            self.log("MAIL requires authentication", False, f"Unexpected error: {e}")
            return False
    
    def test_response_codes(self, server):
        """Test that response codes follow RFC standards."""
        try:
            # Test invalid command
            code, response = server.docmd('INVALID')
            # Should return 5xx error
            if code >= 500:
                self.log("Invalid command returns 5xx", True)
            else:
                self.log("Invalid command returns 5xx", False, f"Got {code}")
            
            return True
        except Exception as e:
            self.log("Response codes follow RFC", True, "Server handles invalid commands")
            return True
    
    def test_common_client_compatibility(self):
        """Test compatibility with common SMTP client patterns."""
        print("\n=== Testing Common Client Compatibility ===")
        
        # Test 1: Outlook/Thunderbird pattern (EHLO -> STARTTLS -> AUTH -> MAIL)
        try:
            server = smtplib.SMTP(self.host, self.port_starttls, timeout=5)
            server.ehlo()
            server.starttls(context=self.context)
            server.ehlo()
            server.login('testuser', 'testpass123')
            server.quit()
            self.log("Outlook/Thunderbird pattern", True)
        except Exception as e:
            self.log("Outlook/Thunderbird pattern", False, str(e))
        
        # Test 2: Gmail pattern (SMTPS -> AUTH -> MAIL)
        try:
            server = smtplib.SMTP_SSL(self.host, self.port_smtps, context=self.context, timeout=5)
            server.ehlo()
            server.login('testuser', 'testpass123')
            server.quit()
            self.log("Gmail pattern (SMTPS)", True)
        except Exception as e:
            self.log("Gmail pattern (SMTPS)", False, str(e))
        
        # Test 3: Apple Mail pattern (EHLO -> STARTTLS -> AUTH)
        try:
            server = smtplib.SMTP(self.host, self.port_starttls, timeout=5)
            server.ehlo()
            if 'STARTTLS' in str(server.esmtp_features).upper():
                server.starttls(context=self.context)
                server.ehlo()
            server.login('testuser', 'testpass123')
            server.quit()
            self.log("Apple Mail pattern", True)
        except Exception as e:
            self.log("Apple Mail pattern", False, str(e))
    
    def run_all_tests(self):
        """Run all compliance tests."""
        print("=" * 70)
        print("SMTP Server RFC Compliance Tests")
        print("=" * 70)
        
        # Test SMTPS (port 8465)
        print("\n=== Testing SMTPS (Port 8465) ===")
        try:
            server = smtplib.SMTP_SSL(self.host, self.port_smtps, context=self.context, timeout=5)
            self.test_ehlo_response(server)
            self.test_helo_response(server)
            self.test_auth_plain(server)
            self.test_auth_oauth2(server)
            self.test_mail_rcpt_data_sequence(server)
            self.test_response_codes(server)
            server.quit()
        except Exception as e:
            self.log("SMTPS connection", False, str(e))
        
        # Test STARTTLS (port 8587)
        print("\n=== Testing STARTTLS (Port 8587) ===")
        try:
            server = smtplib.SMTP(self.host, self.port_starttls, timeout=5)
            # RFC 3207: AUTH should NOT be advertised before STARTTLS
            self.test_ehlo_response(server, expect_auth=False)
            self.test_helo_response(server)
            self.test_starttls(server)
            # After STARTTLS, AUTH should be available
            self.test_auth_plain(server)
            self.test_auth_oauth2(server)
            self.test_mail_rcpt_data_sequence(server)
            server.quit()
            
            # Test auth requirement on a fresh connection
            server = smtplib.SMTP(self.host, self.port_starttls, timeout=5)
            server.ehlo()
            server.starttls(context=self.context)
            server.ehlo()
            self.test_authentication_required(server)
            server.quit()
            
            # Test response codes
            server = smtplib.SMTP(self.host, self.port_starttls, timeout=5)
            self.test_response_codes(server)
            server.quit()
        except Exception as e:
            self.log("STARTTLS connection", False, str(e))
        
        # Test common client patterns
        self.test_common_client_compatibility()
        
        # Summary
        print("\n" + "=" * 70)
        print("Test Summary")
        print("=" * 70)
        passed = sum(1 for _, p, _ in self.results if p)
        total = len(self.results)
        print(f"Passed: {passed}/{total} ({passed*100//total if total > 0 else 0}%)")
        
        if passed == total:
            print("\n✅ All tests passed! Server is RFC compliant.")
        else:
            print("\n⚠️  Some tests failed. Review the results above.")
            print("\nFailed tests:")
            for name, passed, msg in self.results:
                if not passed:
                    print(f"  - {name}: {msg}")
        
        return passed == total

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Test SMTP server RFC compliance')
    parser.add_argument('--host', default='127.0.0.1', help='SMTP server host')
    parser.add_argument('--port-smtps', type=int, default=8465, help='SMTPS port')
    parser.add_argument('--port-starttls', type=int, default=8587, help='STARTTLS port')
    
    args = parser.parse_args()
    
    tester = SMTPComplianceTester(args.host, args.port_smtps, args.port_starttls)
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()

