#!/usr/bin/env python3

import os
import rpm
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from rhsm.profile import _is_ostree_system, _get_ostree_deployment_dbpath, _get_immutable_packages

def debug_ostree_setup():
    """Debug the ostree detection and database reading"""
    print("=== Debugging OSTree Detection ===")

    # Check if OSTree is available
    try:
        import gi
        gi.require_version("OSTree", "1.0")
        from gi.repository import OSTree
        print("✓ OSTree library is available")
    except Exception as e:
        print(f"✗ OSTree library not available: {e}")
        return

    # Check if system is ostree
    is_ostree = _is_ostree_system()
    print(f"✓ Is ostree system: {is_ostree}")
    if not is_ostree:
        print("This is not an ostree system, nothing to debug")
        return

    # Get deployment path
    dbpath = _get_ostree_deployment_dbpath()
    print(f"✓ OSTree deployment dbpath: {dbpath}")

    if not dbpath:
        print("✗ No deployment path found")
        return

    if not os.path.exists(dbpath):
        print(f"✗ Deployment path does not exist: {dbpath}")
        return

    print(f"✓ Deployment path exists")

    # List contents
    try:
        contents = os.listdir(dbpath)
        print(f"✓ DB directory contents: {contents}")
    except Exception as e:
        print(f"✗ Cannot list directory: {e}")
        return

    # Test RPM database access with different methods
    print("\n=== Testing RPM Database Access ===")

    # Method 1: Using rootdir parameter (might be wrong)
    print("\nMethod 1: rpm.TransactionSet('/', dbpath)")
    try:
        ts1 = rpm.TransactionSet("/", dbpath)
        ts1.setVSFlags(-1)
        packages1 = list(ts1.dbMatch())
        print(f"  Found {len(packages1)} packages")
        if packages1:
            print(f"  Sample: {packages1[0]['name']}")
    except Exception as e:
        print(f"  Error: {e}")

    # Method 2: Using dbpath parameter
    print(f"\nMethod 2: rpm.TransactionSet(rootdir={os.path.dirname(dbpath)})")
    try:
        rootdir = os.path.dirname(dbpath)
        ts2 = rpm.TransactionSet(rootdir)
        ts2.setVSFlags(-1)
        packages2 = list(ts2.dbMatch())
        print(f"  Found {len(packages2)} packages")
        if packages2:
            print(f"  Sample: {packages2[0]['name']}")
    except Exception as e:
        print(f"  Error: {e}")

    # Method 3: Setting DBPATH environment variable
    print(f"\nMethod 3: Setting DBPATH environment and using default TransactionSet")
    old_dbpath = os.environ.get('DBPATH')
    try:
        os.environ['DBPATH'] = dbpath
        ts3 = rpm.TransactionSet()
        ts3.setVSFlags(-1)
        packages3 = list(ts3.dbMatch())
        print(f"  Found {len(packages3)} packages")
        if packages3:
            print(f"  Sample: {packages3[0]['name']}")
    except Exception as e:
        print(f"  Error: {e}")
    finally:
        if old_dbpath:
            os.environ['DBPATH'] = old_dbpath
        elif 'DBPATH' in os.environ:
            del os.environ['DBPATH']

    # Method 4: Manual path construction
    print(f"\nMethod 4: Direct database file check")
    rpmdb_files = ['Packages', 'Packages.db', 'rpmdb.sqlite']
    for dbfile in rpmdb_files:
        filepath = os.path.join(dbpath, dbfile)
        if os.path.exists(filepath):
            size = os.path.getsize(filepath)
            print(f"  Found {dbfile}: {size} bytes")

    # Test current implementation
    print(f"\n=== Testing Current Implementation ===")
    immutable_packages = _get_immutable_packages()
    print(f"Current implementation found {len(immutable_packages)} immutable packages")

    if immutable_packages:
        print("Sample immutable packages:")
        for i, pkg in enumerate(list(immutable_packages)[:5]):
            print(f"  {pkg}")

if __name__ == '__main__':
    debug_ostree_setup()