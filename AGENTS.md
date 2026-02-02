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

## Testing

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
