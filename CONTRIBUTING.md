# Contributing to Wisp

Thank you for your interest in contributing to wisp! This document provides guidelines and information for contributors.

## Table of Contents

- [Issue Policy](#issue-policy)
- [How to Contribute](#how-to-contribute)
- [Branch Naming Convention](#branch-naming-convention)
- [Code Style Guidelines](#code-style-guidelines)
- [Commit Message Convention](#commit-message-convention)
- [Pull Request Guidelines](#pull-request-guidelines)
- [NIP Implementation Policy](#nip-implementation-policy)
- [Breaking Changes](#breaking-changes)
- [Documentation Requirements](#documentation-requirements)
- [Development Setup](#development-setup)
- [Code of Conduct](#code-of-conduct)
- [License](#license)

## Issue Policy

### Before Opening an Issue

1. **Search existing issues** to ensure your bug or feature request hasn't already been reported
2. **Check the documentation** including the README and configuration examples
3. **Verify you're on the latest version** - many issues are fixed in newer releases

### Reporting Bugs

When reporting a bug, please use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md) and include:

- **Steps to reproduce** - Minimal steps to trigger the bug
- **Expected behavior** - What should happen
- **Actual behavior** - What actually happens, including error messages
- **Environment details**:
  - Wisp version (git commit or release tag)
  - Operating system and version
  - Architecture (x86_64, arm64)
  - Zig version (if building from source)
- **Relevant logs** - Debug output if available

### Requesting Features

When requesting a feature, please use the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md) and include:

- **Problem statement** - What problem does this solve?
- **Proposed solution** - How should it work?
- **NIP reference** - If related to a Nostr NIP, link to it
- **Alternatives considered** - Other approaches you've thought about

Keep in mind wisp's goals: **fast**, **lightweight**, and **simple**. Feature requests should align with these principles.

## How to Contribute

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:

   ```sh
   git clone https://github.com/YOUR_USERNAME/wisp.git
   cd wisp
   ```

3. Add the upstream remote:

   ```sh
   git remote add upstream https://github.com/privkeyio/wisp.git
   ```

### Create a Branch

1. Sync with upstream:

   ```sh
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```

2. Create a new branch following the [naming convention](#branch-naming-convention):

   ```sh
   git checkout -b feature/your-feature-name
   ```

### Make Changes

1. Make your changes, following the [code style guidelines](#code-style-guidelines)
2. Test your changes: `zig build test`
3. Commit your changes following the [commit message convention](#commit-message-convention)

### Submit a Pull Request

1. Push your branch to your fork:

   ```sh
   git push origin feature/your-feature-name
   ```

2. Open a pull request against the `main` branch
3. Fill out the PR template with all required information
4. Wait for CI checks to pass and request a review

## Branch Naming Convention

Use the following prefixes for branch names:

| Prefix | Purpose | Example |
|--------|---------|---------|
| `feature/` | New features | `feature/nip-50-search` |
| `bugfix/` | Bug fixes | `bugfix/connection-timeout` |
| `hotfix/` | Urgent production fixes | `hotfix/memory-leak` |
| `release/` | Release preparation | `release/v0.2.0` |
| `docs/` | Documentation only | `docs/api-reference` |
| `refactor/` | Code refactoring | `refactor/event-handler` |

## Code Style Guidelines

### Zig Formatting

- Run `zig fmt` before committing to ensure consistent formatting
- Follow the [Zig Style Guide](https://ziglang.org/documentation/master/#Style-Guide)

### General Guidelines

- Keep functions small and focused
- Use descriptive variable and function names
- Prefer explicit over implicit behavior
- Handle errors explicitly; avoid ignoring error returns
- Add comments for complex logic, but prefer self-documenting code
- Keep lines under 120 characters when possible

### Project-Specific Conventions

- Use `std.log` for logging with appropriate log levels
- Prefer stack allocation over heap when feasible
- Use `defer` for cleanup to ensure resources are released

## Commit Message Convention

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```commit
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation changes |
| `style` | Formatting, no code change |
| `refactor` | Code restructuring, no behavior change |
| `perf` | Performance improvement |
| `test` | Adding or updating tests |
| `chore` | Maintenance tasks |
| `ci` | CI/CD changes |

### Examples

```commit
feat(spider): add automatic reconnection on disconnect

fix(handler): prevent double-free in connection cleanup

docs(readme): update build instructions for macOS

refactor(storage): simplify LMDB transaction handling
```

### Breaking Changes

For breaking changes, add `!` after the type or add `BREAKING CHANGE:` in the footer:

```commit
feat(config)!: change default port from 7777 to 8080

BREAKING CHANGE: Default port changed. Update your configuration if relying on the default.
```

## Pull Request Guidelines

### Requirements

- **All PRs must pass CI checks** before merging
- **At least one approval** is required for merging
- **No direct pushes to main**; all changes must go through a PR
- Keep PRs focused on a single concern

### PR Description

Include the following in your PR description:

1. **Summary** - What does this PR do?
2. **Motivation** - Why is this change needed?
3. **Testing** - How was this tested?
4. **Breaking changes** - Does this break existing functionality?
5. **Related issues** - Link any related issues (e.g., `Fixes #123`)

### Before Requesting Review

- [ ] Code compiles without warnings: `zig build`
- [ ] All tests pass: `zig build test`
- [ ] Code is formatted: `zig fmt src/*.zig`
- [ ] Documentation is updated if needed
- [ ] Commit messages follow conventions

### Changelog Updates

**Do not include changelog updates in feature/fix PRs.** Changelog entries are managed separately when preparing releases. Maintainers will update `CHANGELOG.md` as part of the release process.

## NIP Implementation Policy

When implementing support for a new [NIP](https://github.com/nostr-protocol/nips):

1. **Check libnostr-z first** - If the NIP requires new protocol-level functionality (event kinds, tags, validation), it must be implemented in [libnostr-z](https://github.com/privkeyio/libnostr-z) first
2. **Open an issue** - Discuss the implementation approach before starting work
3. **Reference the NIP** - Link to the NIP specification in your PR
4. **Update NIP list** - Add the NIP number to the supported NIPs list in README.md
5. **Add tests** - Include tests that verify NIP compliance

### NIP Implementation Workflow

```text
1. Check if NIP requires libnostr-z changes
   ├── Yes → Implement in libnostr-z first, then update wisp
   └── No  → Implement directly in wisp

2. Open issue to discuss approach
3. Create feature branch: feature/nip-XX-description
4. Implement with tests
5. Update documentation
6. Submit PR
```

## Breaking Changes

Breaking changes require careful consideration:

1. **Discuss first** - Open an issue to discuss the breaking change
2. **Document clearly** - Explain what breaks and how to migrate
3. **Use conventional commits** - Mark with `!` or `BREAKING CHANGE:` footer
4. **Update version** - Breaking changes trigger a minor version bump (pre-1.0) or major version bump (post-1.0)
5. **Provide migration guide** - Include migration steps in the PR description

### What Constitutes a Breaking Change

- Removing or renaming configuration options
- Changing default behavior
- Removing support for a NIP
- Changing the database schema
- Modifying the wire protocol in incompatible ways

## Documentation Requirements

### For New Features

- Update README.md if the feature is user-facing
- Add configuration examples to `wisp.toml.example` if applicable
- Include inline code comments for complex logic
- Update the NIP support list if implementing a new NIP

### For Bug Fixes

- Add a comment explaining the fix if the bug was subtle
- Consider adding a test case to prevent regression

### For API Changes

- Document any new command-line options
- Update configuration documentation
- Note any breaking changes prominently

## Development Setup

```sh
# Install dependencies (Ubuntu/Debian)
sudo apt install -y liblmdb-dev libsecp256k1-dev libssl-dev

# Clone and build
git clone https://github.com/privkeyio/wisp && cd wisp
zig build

# Run tests
zig build test

# Build optimized release
zig build -Doptimize=ReleaseFast

# Format code
zig fmt src/*.zig
```

## Code of Conduct

Be respectful and constructive in all interactions. We're all here to build useful software for the Nostr ecosystem.

## License

By contributing to wisp, you agree that your contributions will be licensed under the LGPL-2.1-or-later license.
