"""SO2C package exports and `python -m so2c` entry point."""

import sys

from .engine import Analysis, load_elf
from .cli import main

__all__ = ["Analysis", "load_elf", "main", "__version__"]

if __name__ == "__main__":
    sys.exit(main())