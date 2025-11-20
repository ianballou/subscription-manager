#!/usr/bin/env python3

import os
import subprocess
import json

def investigate_bootc_structure():
    """Investigate how bootc systems actually store package information"""
    print("=== Investigating bootc/ostree Structure ===")

    # Check if we have rpm-ostree
    try:
        result = subprocess.run(['rpm-ostree', 'status', '--json'],
                              capture_output=True, text=True, check=True)
        status = json.loads(result.stdout)
        print("✓ rpm-ostree available")

        deployments = status.get('deployments', [])
        if deployments:
            current = deployments[0]  # Current deployment
            print(f"Current deployment: {current.get('checksum', 'unknown')[:10]}")
            print(f"Base commit: {current.get('base-checksum', 'N/A')[:10] if current.get('base-checksum') else 'N/A'}")

            # Check for layered packages
            layered = current.get('layered-packages', [])
            requested_packages = current.get('requested-packages', [])

            print(f"Layered packages: {layered}")
            print(f"Requested packages: {requested_packages}")

            if 'vim-enhanced' in layered:
                print("✓ vim-enhanced is a LAYERED package")
            elif 'vim-enhanced' in requested_packages:
                print("✓ vim-enhanced is a REQUESTED package")
            else:
                print("? vim-enhanced not found in layered/requested packages")

    except Exception as e:
        print(f"✗ rpm-ostree error: {e}")

    # Check ostree structure
    print(f"\n--- OSTree Structure ---")

    # Check if /usr/share/rpm is a symlink
    rpm_path = "/usr/share/rpm"
    if os.path.islink(rpm_path):
        target = os.readlink(rpm_path)
        print(f"/usr/share/rpm -> {target}")
    else:
        print(f"/usr/share/rpm is a real directory")

    # Check deployment structure
    try:
        result = subprocess.run(['ostree', 'admin', 'status'],
                              capture_output=True, text=True)
        print(f"OSTree admin status:\n{result.stdout}")
    except Exception as e:
        print(f"ostree admin status error: {e}")

    # Look for different database locations
    print(f"\n--- Alternative Database Locations ---")

    potential_paths = [
        "/sysroot/ostree/repo",
        "/ostree/repo",
        "/var/lib/rpm",
        "/usr/lib/sysimage/rpm",
        "/run/rpm",
    ]

    for path in potential_paths:
        if os.path.exists(path):
            print(f"✓ {path} exists")
            try:
                contents = os.listdir(path)
                if any('rpm' in f.lower() or 'package' in f.lower() for f in contents):
                    print(f"    Contains: {contents}")
            except:
                pass
        else:
            print(f"✗ {path} does not exist")

    # Check if dnf --transient actually works differently
    print(f"\n--- DNF Transient Investigation ---")

    try:
        # Check dnf history to see how vim-enhanced was installed
        result = subprocess.run(['dnf', 'history', 'list', 'vim-enhanced'],
                              capture_output=True, text=True)
        print(f"DNF history for vim-enhanced:\n{result.stdout}")
    except Exception as e:
        print(f"DNF history error: {e}")

if __name__ == '__main__':
    investigate_bootc_structure()