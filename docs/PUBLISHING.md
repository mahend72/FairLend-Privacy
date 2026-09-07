# Publishing `fairlend-privacy` (PyPI and GitHub Container Registry)

This document records the intended future publishing process for both
distribution channels: the `fairlend-privacy` PyPI package and the
`ghcr.io/mahend72/fairlend-privacy` container image. **No step in this
document has been executed.** Neither is currently published. Do not
claim otherwise, and do not run any upload/tag/push step below without
a separate, explicit decision to publish.

## Manual release flow (not yet executed)

This is the intended sequence once a release is actually decided. Every
step below is manual and deliberate — nothing in this repository runs
it automatically:

1. Ensure `main` CI (`.github/workflows/tests.yml`) is green.
2. Create an annotated tag:
   ```bash
   git tag -a v0.1.0 -m "FairLend-Privacy v0.1.0"
   ```
3. Push the tag:
   ```bash
   git push origin v0.1.0
   ```
4. `.github/workflows/release.yml` builds the wheel/sdist, runs
   `twine check`, and attaches both to a GitHub Release for that tag
   (no PyPI upload).
5. `.github/workflows/container.yml` builds the Docker image, runs an
   `import fairlend` smoke test, and pushes it to
   `ghcr.io/mahend72/fairlend-privacy:v0.1.0` (and `:latest`).
6. Verify the package appears under the repository's GitHub Packages
   tab (and/or the owner profile's Packages section).
7. GHCR packages default to the same visibility as tag-push publishing
   permits; if the package is not public, change its visibility to
   Public from the GitHub Packages UI if that is desired.

## PyPI publication

### Before the first publication

1. **Check name availability.** Do not assume `fairlend-privacy` is
   free on PyPI — verify at `https://pypi.org/project/fairlend-privacy/`
   immediately before publishing, not when this document was written.
   If the name is taken, stop and report alternatives; do not silently
   rename the project.
2. Confirm `pyproject.toml` version is the intended release version
   (currently `0.1.0`) and that it has not already been used for a
   public release.
3. Run the full validation sequence:
   ```bash
   python -m pip install --upgrade build twine
   python -m build
   python -m twine check dist/*
   ```
4. Install the built wheel in a clean virtual environment (outside the
   repository) and run the package-level smoke tests
   (`tests/unit/test_package_installed.py` and a manual
   `import fairlend` / `secure_compute` check).

### Recommended mechanism: Trusted Publishing

Prefer PyPI's [Trusted Publishing](https://docs.pypi.org/trusted-publishers/)
(OpenID Connect from GitHub Actions) over a long-lived PyPI API token:

- No secret to store, rotate, or leak in repository/organization
  settings.
- Scoped automatically to the specific GitHub repository + workflow
  that is registered as the trusted publisher.

Setup (performed on pypi.org, not in this repository, and not part of
this task):

1. Create the `fairlend-privacy` project on PyPI (first publish must
   still be done manually or via a one-off trusted-publisher-enabled
   workflow run, per PyPI's pending-publisher flow).
2. Under the project's PyPI settings, add a trusted publisher pointing
   at this GitHub repository, the `release.yml` workflow filename, and
   the environment used to gate publishing (e.g. `pypi`).
3. Add a `publish` job to (a new, separate) publishing workflow that
   runs only on a tag push, requests the `id-token: write` permission,
   and uses `pypa/gh-action-pypi-publish` with no explicit token —
   trusted publishing exchanges the workflow's OIDC token for a
   short-lived upload credential automatically.

### What this task deliberately does NOT do

- It does not create a PyPI project.
- It does not configure a trusted publisher.
- It does not add a PyPI-uploading step to any workflow in this
  repository (`.github/workflows/release.yml` builds and attaches
  artifacts to a **GitHub Release** only).
- It does not store or reference any PyPI API token.

Enabling actual PyPI publication is a separate, explicit follow-up
decision.

## GitHub Container Registry (GHCR)

`.github/workflows/container.yml` is configured to build and push
`ghcr.io/mahend72/fairlend-privacy` on a `v*` tag push, using only the
repository owner's `${{ github.actor }}` and the automatically-issued
`${{ secrets.GITHUB_TOKEN }}` — no personal access token, Docker Hub
account, or manually stored registry secret is required.

### What this task deliberately does NOT do

- It does not push any image to GHCR.
- It does not create or configure a GitHub Package.
- It does not change package visibility via the GitHub API (visibility
  can be changed manually from the GitHub Packages UI after a real
  publish, per the manual release flow above).
- It does not request any permission beyond `contents: read` and
  `packages: write`.

Enabling actual container publication happens automatically only when
a `v*` tag is pushed — a separate, explicit, manual action.
