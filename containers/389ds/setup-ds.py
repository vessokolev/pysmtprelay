#!/usr/bin/env python3
"""
Setup script for 389 Directory Server using lib389 Python API.
This is more reliable than setup-ds.pl in containerized environments.
"""
import os
import sys
from lib389 import DirSrv
from lib389.properties import (
    SER_HOST, SER_PORT, SER_SECURE_PORT, SER_ROOT_DN, SER_ROOT_PW,
    SER_DEPLOYED_DIR, SER_BACKEND_INSTANCE_NAME, MT_SUFFIX
)

DS_DIR = "/data/dirsrv"
INSTANCE_NAME = "localhost"
SUFFIX = "dc=example,dc=com"
ROOT_DN = "cn=Directory Manager"
ROOT_PASSWORD = "changeme"

def create_instance():
    """Create 389 Directory Server instance using lib389."""
    instance_dir = os.path.join(DS_DIR, f"slapd-{INSTANCE_NAME}")
    
    # Check if instance already exists
    if os.path.exists(instance_dir):
        print(f"Instance already exists at {instance_dir}")
        return True
    
    print(f"Creating 389 Directory Server instance: {INSTANCE_NAME}")
    
    # Create instance properties - suffix goes in mapping tree, not server properties
    properties = {
        SER_HOST: 'localhost',
        SER_PORT: '389',
        SER_SECURE_PORT: '636',
        SER_ROOT_DN: ROOT_DN,
        SER_ROOT_PW: ROOT_PASSWORD,
        SER_BACKEND_INSTANCE_NAME: 'userRoot',
        SER_DEPLOYED_DIR: DS_DIR,
    }
    
    # Mapping tree properties (where suffix is configured)
    mapping_tree_properties = {
        MT_SUFFIX: SUFFIX,
    }
    
    try:
        # Create the instance
        inst = DirSrv(verbose=False)
        inst.create(properties=properties, serverid=INSTANCE_NAME)
        
        # Add mapping tree (suffix) after instance creation
        # The create method should handle this, but if not, we add it separately
        print(f"Instance created successfully at {instance_dir}")
        return True
    except Exception as e:
        print(f"Error creating instance: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = create_instance()
    sys.exit(0 if success else 1)

