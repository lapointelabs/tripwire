# Governance

Tripwire is maintained by Lapointe Labs. Maintainers merge changes, manage releases, and
make final decisions on scope and security posture.

Project decisions should be made in public issues or pull requests whenever disclosure is
safe. Security reports remain private until a coordinated release. Significant changes to
finding semantics, data transmission, engine execution, or compatibility require documented
rationale and tests.

Releases are cut from version tags through the repository workflow, use npm trusted
publishing, and include provenance. Deprecations should be documented for at least one minor
release before removal unless keeping the behavior would preserve a vulnerability.

Maintainer access follows least privilege. A future maintainer is added after sustained,
high-quality contributions and explicit agreement from the existing maintainers. If the
project becomes inactive, Lapointe Labs may appoint a successor or archive it rather than
leave an apparently supported security tool unattended.
