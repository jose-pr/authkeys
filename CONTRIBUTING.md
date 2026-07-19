# Contributing to authkeys

Thanks for your interest in contributing! Here's how to get started.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/jose-pr/authkeys.git
cd authkeys

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode with test dependencies and the optional extras
# whose tests you want to run (the LDAP test skips without ldap3).
pip install -e ".[dev,http,ldap]"
```

> authkeys resolves keys via the POSIX `pwd`/`grp` databases, so key resolution
> only works on a POSIX host. The package still imports and the test suite still
> runs on any platform (the file source's `pwd` use is faked in tests).

## Running Tests

```bash
pytest
```

Run with coverage:

```bash
pytest --cov=src/authkeys tests/
```

Use `pytest -rs` to see which optional-extra tests were skipped.

## Documentation

```bash
pip install -e ".[docs]"
mkdocs serve          # live preview at http://127.0.0.1:8000
mkdocs build --strict # what CI runs
```

## Code Style

- Follow PEP 8
- Use type hints (quote runtime `X | Y` unions, or add
  `from __future__ import annotations`, for the Python 3.9 floor)
- Keep functions focused and well-named
- Import optional dependencies (`requests`, `ldap3`, `cryptography`) lazily so the
  core stays dependency-free and importable everywhere

## Commit Guidelines

Follow the format: `type: description`

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `test:` Test additions/improvements
- `ci:` CI/workflow changes
- `chore:` Build or tooling changes

Examples:
- `feat: add an HTTP key server subcommand`
- `fix: escape the username in the LDAP filter`
- `docs: document the serve fail-closed behavior`

## Pull Request Process

1. Create a feature branch: `git checkout -b feature/my-feature`
2. Make your changes and add tests
3. Run `pytest` to ensure all tests pass (on the oldest supported Python if you
   can — 3.9)
4. Commit with a clear message (see guidelines above)
5. Push to your fork and open a pull request

## Reporting Issues

When reporting bugs, please include:

- Python version
- authkeys version
- Which source(s) are configured
- Minimal config that reproduces the issue
- Expected vs. actual behavior

## Questions?

Open a discussion or issue on GitHub!
