# Mirror and verification

Kanidm publishes no signed packages (checked 2026-11-11): GitHub releases carry no files, the tag `v1.12.0` and its commit are unsigned, the containers are unsigned, and the Debian PPA is community-made and still at 1.11.2. So FreeSynergy builds from source (ADR 0068, "built only where a format is missing"):

1. `mirror.toml` pins the release tag and the **commit SHA**. The workflow stops unless the upstream tag still points to exactly that commit.
2. GitHub Actions builds the binaries (profile `release_debian`) and the source tarball of the same version (Kanidm is MPL-2.0: the source travels with the binary), plus an SBOM.
3. Every file gets an OpenPGP signature (`.asc`) from the FreeSynergy release key, `SHA256SUMS.txt` lists the files, and GitHub adds build provenance.

Check a release yourself:

```sh
scripts/verify-mirror.sh <directory-with-the-release-files>
```

The script verifies the signatures against the key with the fingerprint in `mirror.toml` (`16A4 A3EE 563A EF51 FCF0 C55D ED7B 57C4 A190 4342`) and the checksums. It prints no secrets because there are none.

Not mirrored: the PPA package 1.11.2 (older, signed by a single person) and the unsigned container images (used for local tests only).

Language: [Deutsch](../de/mirror.md)
