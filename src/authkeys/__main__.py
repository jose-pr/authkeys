"""``python -m authkeys`` entry point.

If no subcommand is given, ``resolve`` is assumed, so ``authkeys <user>``
behaves like ``authkeys resolve <user>`` — matching the console script.
"""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
