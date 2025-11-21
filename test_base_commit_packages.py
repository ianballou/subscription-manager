#!/usr/bin/env python3

import subprocess
import json

def test_base_commit_approach():
    """Test getting base commit packages for bootc transient systems"""
    print("=== Testing Base Commit Package Approach ===")

    try:
        # Get rpm-ostree status
        result = subprocess.run(['rpm-ostree', 'status', '--json'],
                              capture_output=True, text=True, check=True)
        status = json.loads(result.stdout)

        deployments = status.get('deployments', [])
        if not deployments:
            print("No deployments found")
            return

        current = deployments[0]
        print(f"Current deployment: {current.get('checksum', 'unknown')[:10]}")
        print(f"Unlocked: {current.get('unlocked', 'No')}")
        print(f"Base checksum: {current.get('base-checksum', 'None')}")

        # Try to get the rollback deployment as a reference
        if len(deployments) > 1:
            rollback = deployments[1]
            rollback_checksum = rollback.get('checksum')
            print(f"Rollback deployment: {rollback_checksum[:10]}")

            # Try to get packages from rollback deployment
            try:
                print(f"\nTrying rpm-ostree db list on rollback deployment...")
                result = subprocess.run(['rpm-ostree', 'db', 'list', rollback_checksum],
                                      capture_output=True, text=True, check=True)

                packages = result.stdout.strip().split('\n')
                print(f"Found {len(packages)} packages in rollback deployment")

                # Show first few packages
                print("Sample packages from rollback:")
                for pkg in packages[:5]:
                    if pkg.strip():
                        print(f"  {pkg.strip()}")

                # Check if vim-enhanced is in the rollback
                vim_in_rollback = any('vim-enhanced' in pkg for pkg in packages)
                print(f"\nvim-enhanced in rollback: {vim_in_rollback}")

                return packages

            except subprocess.CalledProcessError as e:
                print(f"Failed to get rollback packages: {e}")

        # Try alternative: get current commit info
        print(f"\n--- Alternative: Current Commit Info ---")
        try:
            result = subprocess.run(['ostree', 'show', '--print-metadata-key=rpm.packages',
                                   current.get('checksum')],
                                  capture_output=True, text=True)
            print(f"Ostree metadata result: {result.stdout[:200]}...")
        except Exception as e:
            print(f"Ostree show failed: {e}")

        # Try rpm-ostree db diff
        print(f"\n--- RPM-OSTree DB Diff ---")
        try:
            if len(deployments) > 1:
                rollback_checksum = deployments[1].get('checksum')
                current_checksum = deployments[0].get('checksum')

                result = subprocess.run(['rpm-ostree', 'db', 'diff',
                                       rollback_checksum, current_checksum],
                                      capture_output=True, text=True)
                print(f"Package differences:\n{result.stdout}")
        except Exception as e:
            print(f"rpm-ostree db diff failed: {e}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    test_base_commit_approach()