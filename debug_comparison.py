#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from rhsm.profile import _get_immutable_packages

def debug_package_comparison():
    """Debug the package comparison logic"""
    print("=== Debugging Package Comparison ===")

    # Get real immutable packages
    immutable_packages = _get_immutable_packages()
    print(f"Found {len(immutable_packages)} immutable packages")

    # Test some known packages
    test_packages = [
        ('systemd', '253.13', '1.el9', 'x86_64', 0),  # This should be in immutable set
        ('fake-package', '1.0.0', '1', 'x86_64', 0),  # This should NOT be in immutable set
    ]

    print(f"\nTesting package comparisons:")
    for pkg_tuple in test_packages:
        is_in_immutable = pkg_tuple in immutable_packages
        print(f"  {pkg_tuple[0]}: {'persistent' if is_in_immutable else 'transient'}")

    # Let's check what systemd actually looks like in the immutable set
    print(f"\nLooking for systemd variants in immutable packages:")
    systemd_packages = [pkg for pkg in immutable_packages if pkg[0] == 'systemd']
    for pkg in systemd_packages[:3]:  # Show first 3 systemd packages
        print(f"  {pkg}")

    # Check the exact tuple format we're using
    print(f"\nChecking tuple format with some sample packages:")
    sample_packages = list(immutable_packages)[:5]
    for pkg in sample_packages:
        print(f"  {pkg} (type: {type(pkg)}, len: {len(pkg)})")

if __name__ == '__main__':
    debug_package_comparison()