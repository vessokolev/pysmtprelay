#!/usr/bin/env python3
"""
Alternative implementation using ctypes to access OpenSSL's SSL_CTX_set1_groups_list
directly, since Python's ssl module doesn't expose set_groups().

This is a workaround until Python's ssl module adds native support.
"""

import ctypes
from ctypes import c_void_p, c_char_p, POINTER, c_int
import ssl

def configure_post_quantum_groups(context, groups):
    """
    Configure TLS 1.3 key exchange groups via OpenSSL directly.
    
    Args:
        context: ssl.SSLContext instance
        groups: List of group names (e.g., ['X25519+ML-KEM-768', 'secp384r1'])
    
    Returns:
        bool: True if configuration succeeded, False otherwise
    """
    try:
        # Load OpenSSL library
        openssl_lib = None
        for lib_name in ['libssl.so.3', 'libssl.so', 'libssl.so.1.1']:
            try:
                openssl_lib = ctypes.CDLL(lib_name)
                break
            except OSError:
                continue
        
        if not openssl_lib:
            print("Error: Could not load OpenSSL library")
            return False
        
        # Define function signature
        # int SSL_CTX_set1_groups_list(SSL_CTX *ctx, const char *groups);
        openssl_lib.SSL_CTX_set1_groups_list.argtypes = [c_void_p, c_char_p]
        openssl_lib.SSL_CTX_set1_groups_list.restype = c_int
        
        # Convert groups list to OpenSSL format (colon-separated)
        groups_str = ':'.join(groups).encode('utf-8')
        
        # Get SSL_CTX pointer from Python's SSLContext
        # This is the tricky part - Python's SSLContext wraps OpenSSL's SSL_CTX
        # We need to access the internal pointer
        
        # Try to get the context pointer
        # Note: This is implementation-dependent and may break with Python updates
        ssl_ctx_ptr = None
        
        # Method 1: Try _context attribute (if it exists)
        if hasattr(context, '_context'):
            ssl_ctx_ptr = context._context
        
        # Method 2: Try to get it from the _ssl module
        # This requires accessing internal implementation details
        try:
            import _ssl
            # _ssl._SSLContext might have the pointer
            # This is very implementation-dependent
            pass
        except:
            pass
        
        if ssl_ctx_ptr is None:
            print("Warning: Could not access SSL_CTX pointer from Python's SSLContext")
            print("This is a limitation of Python's ssl module API")
            return False
        
        # Call OpenSSL function
        result = openssl_lib.SSL_CTX_set1_groups_list(
            c_void_p(ssl_ctx_ptr),
            groups_str
        )
        
        if result == 1:
            print(f"✓ Successfully configured groups: {', '.join(groups)}")
            return True
        else:
            print(f"✗ Failed to configure groups (OpenSSL returned {result})")
            return False
            
    except Exception as e:
        print(f"Error configuring post-quantum groups: {e}")
        return False


if __name__ == "__main__":
    # Test the function
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    
    groups = [
        'X25519+ML-KEM-768',
        'secp256r1+ML-KEM-768',
        'ML-KEM-768',
        'secp384r1',
        'prime256v1',
        'X25519',
    ]
    
    result = configure_post_quantum_groups(ctx, groups)
    print(f"Configuration result: {result}")

