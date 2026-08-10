"""Entry script for the standalone executables built by PyInstaller.

Kept separate from bulk_ioc_scanner/cli.py so PyInstaller does not put the
package directory on sys.path and import the same module twice, once as
__main__ and once as bulk_ioc_scanner.cli.
"""
import multiprocessing
import sys

from bulk_ioc_scanner.cli import main

if __name__ == "__main__":
    # Windows spawns rather than forks; without this a frozen build can
    # relaunch itself instead of starting a child process.
    multiprocessing.freeze_support()
    sys.exit(main())
