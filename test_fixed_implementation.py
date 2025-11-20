#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from rhsm.profile import _get_immutable_packages, RPMProfile

def test_fixed_implementation():
    """Test the fixed immutable packages detection"""
    print("=== Testing Fixed Implementation ===")

    # Test immutable packages function
    immutable_packages = _get_immutable_packages()
    print(f"Fixed implementation found {len(immutable_packages)} immutable packages")

    if len(immutable_packages) > 0:
        print("✓ Immutable packages detection is working!")
        print("Sample immutable packages:")
        for i, pkg in enumerate(list(immutable_packages)[:5]):
            print(f"  {pkg[0]}-{pkg[1]}-{pkg[2]}.{pkg[3]}")
    else:
        print("❌ Still not finding immutable packages")
        return

    # Test full RPM profile
    print(f"\n=== Testing Full RPM Profile ===")

    # Mock a simple test with a few packages
    from unittest.mock import patch

    # Mock RPM headers for testing
    mock_headers = [
        {
            'name': 'systemd',
            'version': '253.13',
            'release': '1.el9',
            'arch': 'x86_64',
            'epoch': 0,
            'vendor': 'Red Hat, Inc.'
        },
        {
            'name': 'fake-transient-pkg',  # This won't be in immutable set
            'version': '1.0.0',
            'release': '1',
            'arch': 'x86_64',
            'epoch': 0,
            'vendor': 'Fake'
        }
    ]

    with patch('rpm.TransactionSet') as mock_ts_constructor:
        # Create a mock transaction set that returns our test packages
        mock_ts = mock_ts_constructor.return_value
        mock_ts.dbMatch.return_value = mock_headers
        mock_ts.setVSFlags = lambda x: None

        # Create profile (this will use our fixed implementation)
        profile = RPMProfile()
        packages = profile.collect()

        print(f"Profile collected {len(packages)} packages")

        for pkg_dict in packages:
            name = pkg_dict['name']
            persistence = pkg_dict.get('persistence', 'NOT SET')
            print(f"  {name}: {persistence}")

            # systemd should be persistent if it's in the immutable set
            if name == 'systemd':
                if persistence == 'persistent':
                    print("    ✓ systemd correctly identified as persistent")
                else:
                    print("    ❌ systemd should be persistent")

            # fake package should be transient
            elif name == 'fake-transient-pkg':
                if persistence == 'transient':
                    print("    ✓ fake package correctly identified as transient")
                else:
                    print("    ❌ fake package should be transient")

if __name__ == '__main__':
    test_fixed_implementation()