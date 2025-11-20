#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

import rpm
from rhsm.profile import _get_ostree_deployment_dbpath

def deep_debug_databases():
    """Deep debug of the database isolation issue"""
    print("=== Deep Database Debug ===")

    # Get the ostree deployment path
    ostree_dbpath = _get_ostree_deployment_dbpath()
    print(f"OSTree deployment dbpath: {ostree_dbpath}")

    # Method 1: Read current database (overlay)
    print(f"\n--- Current Database (Overlay) ---")
    current_packages = set()
    old_dbpath = os.environ.get('DBPATH')

    try:
        # Make sure we're reading the default database
        if 'DBPATH' in os.environ:
            del os.environ['DBPATH']

        ts1 = rpm.TransactionSet()
        ts1.setVSFlags(-1)
        current_headers = list(ts1.dbMatch())

        for h in current_headers:
            if h["name"] == "gpg-pubkey":
                continue
            current_packages.add((h["name"], h["version"], h["release"], h["arch"], h["epoch"] or 0))

        print(f"Current database packages: {len(current_packages)}")

        # Look for vim-enhanced in current
        vim_in_current = [pkg for pkg in current_packages if pkg[0] == 'vim-enhanced']
        if vim_in_current:
            print(f"vim-enhanced in current: {vim_in_current[0]}")
        else:
            print("vim-enhanced NOT in current")

    finally:
        if old_dbpath:
            os.environ['DBPATH'] = old_dbpath

    # Method 2: Read immutable database (base image)
    print(f"\n--- Immutable Database (Base Image) ---")
    immutable_packages = set()

    try:
        # Set DBPATH to immutable database
        os.environ['DBPATH'] = ostree_dbpath
        ts2 = rpm.TransactionSet()
        ts2.setVSFlags(-1)
        immutable_headers = list(ts2.dbMatch())

        for h in immutable_headers:
            if h["name"] == "gpg-pubkey":
                continue
            immutable_packages.add((h["name"], h["version"], h["release"], h["arch"], h["epoch"] or 0))

        print(f"Immutable database packages: {len(immutable_packages)}")

        # Look for vim-enhanced in immutable
        vim_in_immutable = [pkg for pkg in immutable_packages if pkg[0] == 'vim-enhanced']
        if vim_in_immutable:
            print(f"vim-enhanced in immutable: {vim_in_immutable[0]}")
        else:
            print("vim-enhanced NOT in immutable")

    finally:
        # Restore environment
        if old_dbpath:
            os.environ['DBPATH'] = old_dbpath
        elif 'DBPATH' in os.environ:
            del os.environ['DBPATH']

    # Compare the databases
    print(f"\n--- Comparison ---")

    if current_packages == immutable_packages:
        print("❌ DATABASES ARE IDENTICAL - This is the problem!")
    else:
        only_current = current_packages - immutable_packages
        only_immutable = immutable_packages - current_packages

        print(f"✓ Databases are different:")
        print(f"  Only in current (transient): {len(only_current)}")
        print(f"  Only in immutable: {len(only_immutable)}")

        if only_current:
            print(f"  Transient packages:")
            for pkg in sorted(list(only_current)):
                print(f"    {pkg[0]}")

    # Debug the actual file paths and contents
    print(f"\n--- File System Debug ---")

    # Check if the ostree database path actually exists and differs
    if os.path.exists(ostree_dbpath):
        print(f"✓ Ostree dbpath exists: {ostree_dbpath}")

        # List database files
        db_files = os.listdir(ostree_dbpath)
        print(f"  Database files: {db_files}")

        # Check if it's the same physical location as the overlay
        current_dbpath = rpm.expandMacro('%{_dbpath}')
        print(f"  Current dbpath: {current_dbpath}")
        print(f"  Ostree dbpath: {ostree_dbpath}")

        # Check if they're the same inode (symlink or mount)
        try:
            current_stat = os.stat(current_dbpath)
            ostree_stat = os.stat(ostree_dbpath)

            if current_stat.st_ino == ostree_stat.st_ino:
                print("❌ SAME INODE - The ostree and current paths point to the same database!")
            else:
                print("✓ Different inodes - separate databases")

        except Exception as e:
            print(f"  Error checking inodes: {e}")
    else:
        print(f"❌ Ostree dbpath does not exist: {ostree_dbpath}")

if __name__ == '__main__':
    deep_debug_databases()