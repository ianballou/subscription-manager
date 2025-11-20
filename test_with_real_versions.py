#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from rhsm.profile import _get_immutable_packages, RPMProfile
from unittest.mock import patch

def test_with_real_versions():
    """Test using actual versions from the immutable database"""
    print("=== Testing With Real Package Versions ===")

    # Get real immutable packages
    immutable_packages = _get_immutable_packages()
    print(f"Found {len(immutable_packages)} immutable packages")

    # Find systemd in the immutable set
    systemd_pkg = None
    for pkg in immutable_packages:
        if pkg[0] == 'systemd':
            systemd_pkg = pkg
            break

    if not systemd_pkg:
        print("❌ Could not find systemd in immutable packages")
        return

    print(f"Real systemd package: {systemd_pkg}")

    # Create test with real systemd version and a fake package
    mock_headers = [
        {
            'name': systemd_pkg[0],      # systemd
            'version': systemd_pkg[1],   # 257
            'release': systemd_pkg[2],   # 9.el10_0.1
            'arch': systemd_pkg[3],      # x86_64
            'epoch': systemd_pkg[4],     # 0
            'vendor': 'Red Hat, Inc.'
        },
        {
            'name': 'fake-transient-pkg',
            'version': '1.0.0',
            'release': '1',
            'arch': 'x86_64',
            'epoch': 0,
            'vendor': 'Fake'
        }
    ]

    print(f"\nTesting with real systemd version...")

    with patch('rpm.TransactionSet') as mock_ts_constructor:
        mock_ts = mock_ts_constructor.return_value
        mock_ts.dbMatch.return_value = mock_headers
        mock_ts.setVSFlags = lambda x: None

        # Create profile
        profile = RPMProfile()
        packages = profile.collect()

        print(f"Profile collected {len(packages)} packages")

        for pkg_dict in packages:
            name = pkg_dict['name']
            persistence = pkg_dict.get('persistence', 'NOT SET')
            print(f"  {name}: {persistence}")

            if name == 'systemd':
                if persistence == 'persistent':
                    print("    ✓ systemd correctly identified as persistent")
                else:
                    print(f"    ❌ systemd should be persistent (version: {systemd_pkg})")
            elif name == 'fake-transient-pkg':
                if persistence == 'transient':
                    print("    ✓ fake package correctly identified as transient")
                else:
                    print("    ❌ fake package should be transient")

def test_real_rpm_profile():
    """Test the actual RPM profile without mocking"""
    print(f"\n=== Testing Real RPM Profile ===")

    profile = RPMProfile()
    packages = profile.collect()

    # Count by persistence
    persistent_count = sum(1 for pkg in packages if pkg.get('persistence') == 'persistent')
    transient_count = sum(1 for pkg in packages if pkg.get('persistence') == 'transient')
    no_persistence = sum(1 for pkg in packages if 'persistence' not in pkg)

    print(f"Total packages: {len(packages)}")
    print(f"Persistent: {persistent_count}")
    print(f"Transient: {transient_count}")
    print(f"No persistence field: {no_persistence}")

    # Show some examples
    print(f"\nSample packages:")
    for i, pkg in enumerate(packages[:5]):
        persistence = pkg.get('persistence', 'NOT SET')
        print(f"  {pkg['name']}: {persistence}")

    # Look for specific packages
    important_packages = ['systemd', 'kernel', 'bash', 'rpm-ostree']
    print(f"\nImportant packages:")
    for pkg in packages:
        if pkg['name'] in important_packages:
            persistence = pkg.get('persistence', 'NOT SET')
            print(f"  {pkg['name']}: {persistence}")

if __name__ == '__main__':
    test_with_real_versions()
    test_real_rpm_profile()