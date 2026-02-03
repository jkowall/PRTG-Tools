# AGENTS.md

Instructions for AI coding agents working on this repository.

## Commit Signing

**All commits MUST be signed.** Use GPG or SSH signing for all commits to this repository.

```bash
git commit -S -m "your commit message"
```

Ensure your Git configuration has signing enabled:

```bash
git config commit.gpgsign true
```

## Repository Overview

This repository contains tools for PRTG Network Monitor users, including security scanners and network utilities.

## Code Guidelines

- **Language**: Python 3.7+
- **Style**: Follow PEP 8 conventions
- **Documentation**: Include docstrings for all functions and classes
- **Dependencies**: Minimize external dependencies; document any new ones in README.md

## Security Considerations

- Never commit sensitive data (credentials, API keys, community strings)
- Use environment variables for sensitive configuration
- Review all code changes for security implications
- Follow secure coding practices for network tools

## Development Setup

Before making changes, set up your development environment:

```bash
# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On macOS/Linux
# Or: .venv\Scripts\activate  # On Windows

# Install dependencies
pip install -r requirements.txt
```

## Code Quality Tools

This repository uses the following tools for code quality:

- **flake8**: Linting and style checking (configuration in `.flake8`)
- **black**: Code formatting
- **pytest**: Unit testing framework

Use the Makefile targets to run these tools:

```bash
make lint      # Run flake8 to check code style
make format    # Run black to format code
make test      # Run pytest for unit tests
make verify    # Run both linting and tests
```

## Verification Requirements

**Before committing any changes, you MUST run verification:**

```bash
make verify
```

This runs both linting and unit tests. **All checks must pass before committing.**

### Pre-Commit Checklist

1. Run `make format` to auto-format code
2. Run `make verify` to ensure linting and tests pass
3. Fix any linting errors or test failures
4. Only then commit your changes

### Writing Tests

- Add unit tests for new functionality in the `tests/` directory
- Follow existing test patterns in `tests/test_hybrid_audit.py`
- Mock external dependencies (PRTG API, network calls)
- Aim for meaningful test coverage of critical paths

## CI/CD Integration

GitHub Actions automatically runs on all pull requests:

- **Linting**: `flake8` checks code style
- **Tests**: `pytest` runs unit tests

PRs cannot be merged if CI checks fail. See `.github/workflows/ci.yml` for the workflow configuration.

## Testing Guidelines

- Test scripts against non-production networks only
- Verify changes don't break existing functionality
- Include usage examples in documentation

## Git Workflow

**Always use feature branches and pull requests.** Do not push directly to `main`.

### Creating Changes

1. **Create a feature branch** from `main`:

   ```bash
   git checkout main
   git pull origin main
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** and commit with descriptive messages:

   ```bash
   git add .
   git commit -S -m "type(scope): brief description"
   ```

   Use conventional commit types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

3. **Push the branch** to origin:

   ```bash
   git push -u origin feature/your-feature-name
   ```

4. **Open a Pull Request** via GitHub CLI or web interface:

   ```bash
   gh pr create --title "type(scope): brief description" --body "Description of changes"
   ```

### Pull Request Requirements

- Provide clear descriptions of changes
- Reference any related issues
- Ensure all commits are signed (when GPG is available)
- Update documentation as needed
- Wait for review before merging (or self-merge if owner)

### Branch Naming

Use descriptive branch names with prefixes:

- `feature/` - New features or enhancements
- `fix/` - Bug fixes
- `docs/` - Documentation updates
- `refactor/` - Code refactoring
