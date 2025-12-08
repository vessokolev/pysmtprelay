#!/usr/bin/env python3
"""
Setup script for OCSP Stapling C Extension

This extension provides access to OpenSSL's OCSP stapling functions
that are not exposed by Python's ssl module.

Based on Exim's OCSP stapling implementation.
"""

from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
import sys

# Check for OpenSSL development headers
try:
    import subprocess
    result = subprocess.run(['pkg-config', '--exists', 'openssl'], 
                          capture_output=True)
    if result.returncode != 0:
        print("Warning: OpenSSL development headers may not be installed")
        print("Install with: sudo apt-get install libssl-dev (Debian/Ubuntu)")
        print("              sudo yum install openssl-devel (RHEL/CentOS)")
except FileNotFoundError:
    print("Warning: pkg-config not found, assuming OpenSSL is available")

# Get Python include directory
import sysconfig
python_include = sysconfig.get_path('include')

# Define the extension module
ocsp_extension = Extension(
    'ocsp_stapling_extension',
    sources=['ocsp_stapling_extension.c'],
    libraries=['ssl', 'crypto'],
    include_dirs=[python_include],
    library_dirs=[],
    extra_compile_args=['-std=c99', '-fPIC'],
    extra_link_args=[],
)

setup(
    name='ocsp_stapling_extension',
    version='0.1.0',
    description='OCSP Stapling C Extension for Python',
    long_description="""
    Python C Extension for OCSP Stapling
    
    Based on Exim's OCSP stapling implementation, this extension provides
    access to OpenSSL's OCSP stapling functions that are not exposed by
    Python's ssl module.
    
    Key features:
    - SSL_CTX_set_tlsext_status_cb() - Set callback for OCSP stapling
    - SSL_CTX_set_tlsext_status_arg() - Set callback argument
    - SSL_set_tlsext_status_ocsp_resp() - Provide OCSP response
    
    This allows Python applications to implement OCSP stapling similar
    to how Exim does it in C.
    """,
    ext_modules=[ocsp_extension],
    zip_safe=False,
    python_requires='>=3.6',
)

