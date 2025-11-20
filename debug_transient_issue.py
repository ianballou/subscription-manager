#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from rhsm.profile import _get_immutable_packages
import rpm

def debug_transient_issue():
    """Debug why transient packages are showing as persistent"""
    print("=== Debugging Transient Package Issue ===")

    # Get current packages (overlay database)
    print("Getting current packages from overlay database...")
    current_packages = set()
    ts = rpm.TransactionSet()
    ts.setVSFlags(-1)
    installed = ts.dbMatch()

    for h in installed:
        if h["name"] == "gpg-pubkey":
            continue
        pkg_tuple = (
            h["name"],
            h["version"],
            h["release"],
            h["arch"],
            h["epoch"] or 0
        )
        current_packages.add(pkg_tuple)

    print(f"Current packages: {len(current_packages)}")

    # Get immutable packages
    print("\nGetting immutable packages...")
    immutable_packages = _get_immutable_packages()
    print(f"Immutable packages: {len(immutable_packages)}")

    # Check if htop is in current but not immutable
    htop_in_current = any(pkg[0] == 'htop' for pkg in current_packages)
    htop_in_immutable = any(pkg[0] == 'htop' for pkg in immutable_packages)

    print(f"\nhtop analysis:")
    print(f"  htop in current: {htop_in_current}")
    print(f"  htop in immutable: {htop_in_immutable}")

    if htop_in_current:
        htop_current = next(pkg for pkg in current_packages if pkg[0] == 'htop')
        print(f"  htop in current: {htop_current}")

    if htop_in_immutable:
        htop_immutable = next(pkg for pkg in immutable_packages if pkg[0] == 'htop')
        print(f"  htop in immutable: {htop_immutable}")

    # Check if the sets are identical (which would be the problem)
    if current_packages == immutable_packages:
        print(f"\n❌ PROBLEM FOUND: Current and immutable package sets are identical!")
        print(f"This means the immutable database is reading the same packages as the current database.")
    else:
        only_current = current_packages - immutable_packages
        only_immutable = immutable_packages - current_packages

        print(f"\n✓ Package sets are different:")
        print(f"  Only in current (should be transient): {len(only_current)}")
        print(f"  Only in immutable: {len(only_immutable)}")

        if only_current:
            print(f"  Transient packages:")
            for pkg in list(only_current)[:5]:  # Show first 5
                print(f"    {pkg[0]}-{pkg[1]}-{pkg[2]}.{pkg[3]}")

    # Debug the DBPATH environment variable issue
    print(f"\n=== DBPATH Investigation ===")

    # Check current DBPATH
    current_dbpath = os.environ.get('DBPATH')
    print(f"Current DBPATH environment: {current_dbpath}")

    # Test if DBPATH is being properly restored
    print(f"\nTesting DBPATH manipulation...")

    original_dbpath = os.environ.get('DBPATH')
    test_path = "/some/test/path"

    # Simulate what our function does
    os.environ['DBPATH'] = test_path
    print(f"Set DBPATH to: {os.environ.get('DBPATH')}")

    # Restore
    if original_dbpath is not None:
        os.environ['DBPATH'] = original_dbpath
    elif 'DBPATH' in os.environ:
        del os.environ['DBPATH']

    restored_dbpath = os.environ.get('DBPATH')
    print(f"Restored DBPATH to: {restored_dbpath}")

if __name__ == '__main__':
    debug_transient_issue()