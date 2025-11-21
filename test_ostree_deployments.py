#!/usr/bin/env python3

import os
import rpm
import gi
gi.require_version("OSTree", "1.0")
from gi.repository import OSTree

def explore_ostree_deployments():
    """Explore different OSTree deployments to find the base one"""
    print("=== Exploring OSTree Deployments ===")

    try:
        sysroot = OSTree.Sysroot.new_default()
        assert sysroot.load(None)

        # Get all deployments
        deployments = sysroot.get_deployments()
        print(f"Found {len(deployments)} deployments")

        for i, deployment in enumerate(deployments):
            print(f"\nDeployment {i}:")

            # Get deployment info
            checksum = deployment.get_csum()
            unlocked = deployment.get_unlocked()

            print(f"  Checksum: {checksum}")
            print(f"  Unlocked: {unlocked}")

            # Get deployment directory
            deploy_dir = sysroot.get_deployment_directory(deployment)
            deploy_path = deploy_dir.get_path()
            print(f"  Path: {deploy_path}")

            # Check if this is the booted deployment
            booted = sysroot.require_booted_deployment()
            is_booted = deployment.equal(booted)
            print(f"  Is booted: {is_booted}")

            # Construct RPM database path
            dbpath = rpm.expandMacro('%{_dbpath}')
            rpm_db_path = os.path.join(deploy_path, dbpath.lstrip("/"))

            print(f"  RPM DB path: {rpm_db_path}")
            print(f"  RPM DB exists: {os.path.exists(rpm_db_path)}")

            if os.path.exists(rpm_db_path):
                # Count packages in this deployment
                old_dbpath = os.environ.get('DBPATH')
                try:
                    os.environ['DBPATH'] = rpm_db_path
                    ts = rpm.TransactionSet()
                    ts.setVSFlags(-1)
                    packages = list(ts.dbMatch())

                    package_count = len([p for p in packages if p["name"] != "gpg-pubkey"])
                    print(f"  Package count: {package_count}")

                    # Check if vim-enhanced is in this deployment
                    vim_found = any(p["name"] == "vim-enhanced" for p in packages)
                    print(f"  Contains vim-enhanced: {vim_found}")

                finally:
                    if old_dbpath:
                        os.environ['DBPATH'] = old_dbpath
                    elif 'DBPATH' in os.environ:
                        del os.environ['DBPATH']

        # The key insight: for transient unlocked systems,
        # deployment[1] (rollback) might be the "clean" base
        if len(deployments) > 1:
            print(f"\n=== Using Rollback Deployment as Base ===")
            base_deployment = deployments[1]  # Second deployment (rollback)

            deploy_dir = sysroot.get_deployment_directory(base_deployment)
            deploy_path = deploy_dir.get_path()
            dbpath = rpm.expandMacro('%{_dbpath}')
            base_rpm_db_path = os.path.join(deploy_path, dbpath.lstrip("/"))

            print(f"Base deployment path: {base_rpm_db_path}")
            print(f"Base deployment exists: {os.path.exists(base_rpm_db_path)}")

            if os.path.exists(base_rpm_db_path):
                old_dbpath = os.environ.get('DBPATH')
                try:
                    os.environ['DBPATH'] = base_rpm_db_path
                    ts = rpm.TransactionSet()
                    ts.setVSFlags(-1)
                    packages = list(ts.dbMatch())

                    package_count = len([p for p in packages if p["name"] != "gpg-pubkey"])
                    vim_found = any(p["name"] == "vim-enhanced" for p in packages)

                    print(f"Base package count: {package_count}")
                    print(f"Base contains vim-enhanced: {vim_found}")

                    if not vim_found:
                        print("✓ SUCCESS! Base deployment doesn't have vim-enhanced")
                        print("This means we can use the rollback deployment as 'immutable'")
                    else:
                        print("❌ Base deployment also has vim-enhanced")

                finally:
                    if old_dbpath:
                        os.environ['DBPATH'] = old_dbpath
                    elif 'DBPATH' in os.environ:
                        del os.environ['DBPATH']

    except Exception as e:
        print(f"Error exploring deployments: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    explore_ostree_deployments()