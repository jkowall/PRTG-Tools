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

## Pull Requests

- Provide clear descriptions of changes
- Reference any related issues
- Ensure all commits are signed
- Update documentation as needed
