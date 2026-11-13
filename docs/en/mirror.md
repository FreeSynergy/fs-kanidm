# Mirror and verification

Kanidm publishes no signed packages (checked 2026-11-11): GitHub releases carry no files, the tag `v1.12.1` and its commit are unsigned, the containers are unsigned, and the Debian PPA is community-made and still at 1.11.2. So FreeSynergy builds from source (ADR 0068, "built only where a format is missing"):

1. `mirror.toml` pins the release tag and the **commit SHA**. The workflow stops unless the upstream tag still points to exactly that commit.
2. GitHub Actions builds the binaries (profile `release_debian`) in an AlmaLinux 9 container pinned by digest, the `.deb` of the server, and the source tarball of the same version (Kanidm is MPL-2.0: the source travels with the binary), plus an SBOM.
3. Every file gets an OpenPGP signature (`.asc`) from the FreeSynergy release key, `SHA256SUMS.txt` lists the files, and GitHub adds build provenance.

## Package formats

| File | What it is |
|---|---|
| `kanidmd_1.12.1-1_amd64.deb` | **deb**, server only (x86_64): `kanidmd`, upstream's systemd unit (unchanged: `DynamicUser=yes`, group `kanidmd`), the sysusers file that creates the group, the default `/etc/kanidmd/server.toml`, the web UI files. Package name, metadata, unit and maintainer scripts are upstream's own (`server/daemon/Cargo.toml` `[package.metadata.deb]`, `server/daemon/debian/`); `cargo-deb` only packs them. |
| `kanidm-1.12.1-linux-x86_64.tar.gz` | all binaries (server, client, unix daemons, PAM/NSS modules) as a tar |
| `kanidm-1.12.1-source.tar.gz` | source of the same version (MPL-2.0) |

**Package version** (ADR 0077): `<upstream version>-<revision>`, here `1.12.1-1`. The revision rises (`-2`, ...) only when our packaging changes and upstream's version does not.

**Minimum platform:** everything is built in one container pinned by digest (AlmaLinux 9, glibc 2.34), so the binaries and the `.deb` run on Debian 12, Ubuntu 22.04, Enterprise Linux 9 and anything newer. After every build the `smoke` job installs the `.deb` in Debian 12, Ubuntu 22.04 and Ubuntu 24.04 containers (images pinned by digest in `mirror.toml`), checks the contents, the group `kanidmd`, the unit file and runs `kanidmd --version` (`scripts/smoke-deb.sh`; systemd itself is not started there).

**Install (Debian, Ubuntu):**

```sh
scripts/verify-mirror.sh <directory-with-the-release-files>      # first: signature and checksum
sudo apt install ./kanidmd_1.12.1-1_amd64.deb
```

`apt` does **not** check our signature: it only checks signed apt repositories, and this is a single file. The signature that counts is the detached OpenPGP signature `kanidmd_1.12.1-1_amd64.deb.asc` (check with `verify-mirror.sh` or `gpg --verify`); a signed apt repository is planned. A signature inside the `.deb` itself (`dpkg-sig`) is not relied on: `dpkg-sig` is no longer in Ubuntu 24.04 or Debian 12, so the signing action cannot add it.

Upstream's own postinst calls `systemd-sysusers`, but the package does not depend on `systemd`; every server this package is for runs systemd. The package is installed but not enabled: edit `/etc/kanidmd/server.toml` (domain, origin, certificates) first, then `systemctl enable --now kanidmd`.

Check a release yourself:

```sh
scripts/verify-mirror.sh <directory-with-the-release-files>
```

The script verifies the signatures against the key with the fingerprint in `mirror.toml` (`16A4 A3EE 563A EF51 FCF0 C55D ED7B 57C4 A190 4342`) and the checksums. It prints no secrets because there are none.

Not mirrored: the PPA package 1.11.2 (older, signed by a single person) and the unsigned container images (used for local tests only).

Security: Kanidm 1.12.1 (2026-11-13) fixes one issue rated HIGH by upstream: the SCIM filter parser had an incomplete earlier fix, so crafted queries could exhaust the stack and cause a denial of service by an unauthenticated user (no known exploitation). It affects 1.12.0 even when SCIM is not used; this mirror is raised to 1.12.1 for that reason. Release text: <https://github.com/kanidm/kanidm/releases/tag/v1.12.1>.

Language: [Deutsch](../de/mirror.md)
