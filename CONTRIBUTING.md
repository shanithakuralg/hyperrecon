# Contributing to HyperRecon Pro

We love your input! We want to make contributing to HyperRecon Pro as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

## Development Process

We use GitHub to host code, to track issues and feature requests, as well as accept pull requests.

## Pull Request Process

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes.
5. Make sure your code lints.
6. Issue that pull request!

## Any contributions you make will be under the MIT Software License

In short, when you submit code changes, your submissions are understood to be under the same [MIT License](LICENSE) that covers the project. Feel free to contact the maintainers if that's a concern.

## Report bugs using GitHub's [issue tracker](https://github.com/saurabhtomar/hyperrecon-pro/issues)

We use GitHub issues to track public bugs. Report a bug by [opening a new issue](https://github.com/saurabhtomar/hyperrecon-pro/issues/new).

## Write bug reports with detail, background, and sample code

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

## Development Setup

1. Fork and clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Install development tools: `pip install black flake8 pytest`
4. Run tests: `python -m pytest`

## Coding Style

- Use [Black](https://black.readthedocs.io/) for code formatting
- Follow PEP 8 guidelines
- Add docstrings to all functions and classes
- Use type hints where appropriate

## Adding New Tools

When adding new reconnaissance tools:

1. Create a new utility module in `utils/`
2. Extend the `BaseUtility` class
3. Implement the required `execute()` method
4. Add proper error handling and logging
5. Update configuration files
6. Add tests for the new functionality
7. Update documentation

## License

By contributing, you agree that your contributions will be licensed under its MIT License.

## References

This document was adapted from the open-source contribution guidelines for [Facebook's Draft](https://github.com/facebook/draft-js/blob/a9316a723f9e918afde44dea68b5f9f39b7d9b00/CONTRIBUTING.md)