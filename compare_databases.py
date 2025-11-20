#!/usr/bin/env python3

import os
import rpm
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from rhsm.profile import _is_ostree_system, _get_ostree_deployment_dbpath

def get_current_packages():
    """Get packages from current overlay database"""
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

    return current_packages

def get_immutable_packages_fixed():
    """Get packages from immutable database with better error handling"""
    immutable_packages = set()

    dbpath = _get_ostree_deployment_dbpath()
    if not dbpath or not os.path.exists(dbpath):
        print(f"No ostree deployment database path available: {dbpath}")
        return immutable_packages

    print(f"Reading immutable packages from: {dbpath}")

    # Try different methods to access the database
    methods = [
        ("Method 1", lambda: rpm.TransactionSet("/", dbpath)),
        ("Method 2", lambda: rpm.TransactionSet(os.path.dirname(dbpath))),
        ("Method 3", lambda: setup_env_and_create_ts(dbpath))
    ]

    for method_name, create_ts in methods:
        try:
            print(f"\n{method_name}:")
            ts = create_ts()
            ts.setVSFlags(-1)
            installed = ts.dbMatch()

            count = 0
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
                immutable_packages.add(pkg_tuple)
                count += 1

                # Show first few packages for verification
                if count <= 3:
                    print(f"  {h['name']}-{h['version']}-{h['release']}.{h['arch']}")

            print(f"  Total packages: {count}")

            if count > 0:
                print(f"{method_name} worked! Found {count} packages")
                break

        except Exception as e:
            print(f"  Failed: {e}")

    return immutable_packages

def setup_env_and_create_ts(dbpath):
    """Helper to set environment and create TransactionSet"""
    old_dbpath = os.environ.get('DBPATH')
    try:
        os.environ['DBPATH'] = dbpath
        return rpm.TransactionSet()
    finally:
        if old_dbpath:
            os.environ['DBPATH'] = old_dbpath
        elif 'DBPATH' in os.environ:
            del os.environ['DBPATH']

def compare_databases():
    """Compare current vs immutable package databases"""
    print("=== Comparing Current vs Immutable Package Databases ===")

    if not _is_ostree_system():
        print("This is not an ostree system")
        return

    print("Getting current packages...")
    current_packages = get_current_packages()
    print(f"Found {len(current_packages)} current packages")

    print("\nGetting immutable packages...")
    immutable_packages = get_immutable_packages_fixed()
    print(f"Found {len(immutable_packages)} immutable packages")

    if len(immutable_packages) == 0:
        print("\n❌ No immutable packages found - this is the problem!")
        print("The ostree database reading is not working correctly.")
        return

    print("\n=== Analysis ===")

    # Find packages that are only in current (transient)
    transient_packages = current_packages - immutable_packages
    print(f"\nTransient packages ({len(transient_packages)}):")
    for pkg in sorted(list(transient_packages)[:10]):  # Show first 10
        print(f"  {pkg[0]}-{pkg[1]}-{pkg[2]}.{pkg[3]}")
    if len(transient_packages) > 10:
        print(f"  ... and {len(transient_packages) - 10} more")

    # Find packages that are in both (persistent)
    persistent_packages = current_packages & immutable_packages
    print(f"\nPersistent packages ({len(persistent_packages)}):")
    for pkg in sorted(list(persistent_packages)[:10]):  # Show first 10
        print(f"  {pkg[0]}-{pkg[1]}-{pkg[2]}.{pkg[3]}")
    if len(persistent_packages) > 10:
        print(f"  ... and {len(persistent_packages) - 10} more")

    # Check for some expected persistent packages
    expected_persistent = ['kernel', 'systemd', 'bash', 'rpm-ostree']
    print(f"\nChecking expected persistent packages:")
    for expected in expected_persistent:
        found_current = any(pkg[0] == expected for pkg in current_packages)
        found_immutable = any(pkg[0] == expected for pkg in immutable_packages)
        status = "✓" if found_immutable else "❌"
        print(f"  {status} {expected}: current={found_current}, immutable={found_immutable}")

if __name__ == '__main__':
    compare_databases()