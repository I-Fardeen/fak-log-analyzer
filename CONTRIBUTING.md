# Contributing to FAK Log Analyzer

Thank you for your interest in contributing to **FAK Log Analyzer**.

FAK Log Analyzer is an open-source Python command-line tool for analyzing web server access logs and extracting traffic, error, operational, and performance intelligence.

Contributions are welcome in the form of bug reports, feature proposals, documentation improvements, tests, code improvements, and other changes that improve the project.

---

## Ways to Contribute

You can contribute by:

- Reporting reproducible bugs
- Proposing new features
- Improving documentation
- Adding or improving tests
- Improving log parsing
- Improving analysis algorithms
- Adding supported log formats
- Improving CLI usability
- Improving reporting formats
- Improving performance
- Reviewing pull requests
- Suggesting improvements to the project architecture

For substantial changes, please open an issue before starting implementation so the proposed approach can be discussed.

---

## Development Requirements

FAK Log Analyzer currently requires:

- Python 3.11 or newer
- Git
- pip

The project uses:

- `pytest` for testing
- `ruff` for linting and formatting
- GitHub Actions for continuous integration

---

## Setting Up the Development Environment

Clone the repository:

```bash
git clone https://github.com/I-Fardeen/fak-log-analyzer.git
cd fak-log-analyzer
````

Install the project with development dependencies:

```bash
pip install -e ".[dev]"
```

Verify the installation:

```bash
fak-log-analyzer --version
```

---

## Running Tests

Run the complete test suite:

```bash
pytest
```

All tests should pass before submitting a pull request.

---

## Code Quality

Run Ruff linting:

```bash
ruff check .
```

Check formatting:

```bash
ruff format --check .
```

Automatically format the project:

```bash
ruff format .
```

A pull request should pass both linting and formatting checks.

---

## Adding Tests

New functionality should include appropriate automated tests.

Tests are located in:

```text
tests/
```

When adding a new feature, consider tests for:

* Normal behavior
* Boundary conditions
* Invalid input
* Empty input
* Malformed input
* Backward compatibility
* Reporter output where applicable
* Integration with existing analysis functionality

For changes to deterministic analysis or finding logic, tests should verify the expected output precisely.

---

## Pull Request Guidelines

Before opening a pull request:

1. Make sure the project installs successfully.
2. Run the complete test suite.
3. Run Ruff linting.
4. Check Ruff formatting.
5. Update documentation when necessary.
6. Update `CHANGELOG.md` when the change is significant.
7. Keep the pull request focused on a specific change.
8. Avoid introducing unnecessary dependencies.
9. Do not include secrets, credentials, private data, or sensitive log files.

Pull requests should clearly explain:

* What was changed
* Why the change was needed
* How the change was implemented
* How the change was tested

---

## Commit Messages

Use concise, descriptive commit messages.

The project generally follows a conventional style such as:

```text
feat: add security intelligence
fix: handle malformed timestamps
docs: update installation instructions
test: add latency threshold tests
refactor: simplify performance analysis
ci: update supported Python versions
chore: update project metadata
```

Keep commits focused and avoid combining unrelated changes.

---

## Adding New Dependencies

Avoid adding dependencies unless they provide clear value to the project.

When a dependency is necessary:

* Explain why it is required.
* Prefer well-maintained open-source packages.
* Consider license compatibility.
* Consider security and maintenance risks.
* Update project metadata appropriately.
* Add or update tests where necessary.

---

## Backward Compatibility

FAK Log Analyzer aims to preserve compatibility with previously supported log formats and CLI behavior.

Changes that affect:

* Input formats
* CLI arguments
* Output schemas
* Python API behavior
* Configuration
* Existing reporter behavior

should be considered carefully and documented when appropriate.

---

## Documentation

Documentation changes are welcome.

Relevant documentation includes:

* `README.md`
* `docs/usage.md`
* `CHANGELOG.md`
* CLI help text
* Source-code docstrings

Documentation should remain technically accurate and consistent with the current implementation.

---

## Reporting Bugs

Before reporting a bug:

1. Search existing issues.
2. Confirm that you are using a supported Python version.
3. Reproduce the problem with the smallest possible input.
4. Include the FAK Log Analyzer version.
5. Include the Python version and operating system.
6. Include relevant error output.

Do not upload real access logs containing sensitive information.

Use the GitHub bug-report form whenever possible.

---

## Feature Requests

Feature proposals should describe:

* The problem being solved
* The intended use case
* The proposed behavior
* Possible alternatives
* Any relevant examples or references

Large architectural changes should be discussed before implementation.

---

## Security Issues

Please do not report security vulnerabilities through public GitHub issues.

Follow the instructions in [`SECURITY.md`](SECURITY.md).

---

## Code of Conduct

Contributors are expected to communicate professionally and respectfully.

Harassment, discrimination, personal attacks, or deliberately disruptive behavior are not acceptable.

---

## License

By contributing to FAK Log Analyzer, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).

---

## Questions

For general questions, feature discussions, or project-related discussions, please use the appropriate GitHub issue or discussion mechanism.

---

Thank you for helping improve FAK Log Analyzer.