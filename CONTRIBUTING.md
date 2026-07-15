# Contributing

Contributions are welcome and appreciated. We accept issues, discussions, documentation improvements, and pull requests across all repositories in this organization.

## Guidelines

- **Keep pull requests focused.** One concern per PR — avoid large, unrelated diffs. Split substantial changes into smaller, reviewable units.
- **Discuss first.** For significant changes, open an issue or discussion before implementation so the approach can be aligned early.
- **Sign your commits.** All commits must be cryptographically signed via GPG or SSH ([see guide](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits)) and signed off using `git commit -s`, which appends a `Signed-off-by: Name <email>` trailer certifying you have the right to submit the contribution.
- **Describe your changes.** Include the motivation, relevant context, and any documentation or test updates in your pull request description.
- **Tests and CI.** New functionality should be covered by tests where applicable. If no CI pipeline exists, adding one is encouraged. Note that CI may require maintainer approval to run on first-time contributions.
- **AI assistance.** You are responsible for everything you submit. Review AI-generated changes carefully for correctness, security, and licensing before opening a pull request.

## Licensing and CLA

Most repositories in this organization use a single open-source license (for example Apache-2.0). For those projects, the commit signature and `Signed-off-by` line above are sufficient: by contributing, you license your contribution under that repository's license terms.

**Dual-licensed repositories** (for example projects whose SPDX expression is `GPL-3.0-only OR LicenseRef-NeroDuality-Commercial`, or that otherwise offer both an open-source and a Nero Duality commercial license) have an additional requirement:

- You must accept the [Contributor License Agreement (CLA)](./CLA.md) (Individual CLA) before your pull request can be merged — via the CLA bot when enabled, or otherwise as maintainers request. Acceptance covers present and future contributions under that GitHub identity.
- The CLA is a license grant to Nero Duality, LLC (not a copyright assignment) so the contribution can be distributed under **either** side of the dual license, including the commercial license.
- Contributions made on behalf of an employer or other entity also need a **Corporate CLA** on file — email **legal@neroduality.com** (see [CLA.md](./CLA.md)). A Corporate CLA does not replace each individual's Individual CLA.
- Check the target repository's `LICENSE` (and any `LICENSES/` directory) to confirm whether it is dual-licensed.

Signed commits and `Signed-off-by` remain required for dual-licensed repositories; the CLA is **in addition**, not a replacement.

By participating in this organization, you agree to follow the [Code of Conduct](./CODE_OF_CONDUCT.md).
