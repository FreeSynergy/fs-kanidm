#!/usr/bin/env bash
# Runs INSIDE the digest-pinned AlmaLinux 9 container (glibc 2.34: the binaries then run on Debian 12, Ubuntu 22.04, EL9 and newer).
# Called by .github/workflows/mirror.yml (job build); never run it on a developer machine. No secrets exist in this job.
# Input (env, all from mirror.toml): RUST_VERSION RUSTUP_INIT_SHA256 CARGO_DEB_VERSION CARGO_DEB_SHA256 DEB_VERSION VERSION
#   KANIDM_BUILD_PROFILE SOURCE_DATE_EPOCH COMMIT HOST_UID HOST_GID
# Mounts: /work/src (the pinned upstream checkout), /work/dist (output: tarball + .deb).
set -euo pipefail
: "${RUST_VERSION:?}" "${RUSTUP_INIT_SHA256:?}" "${CARGO_DEB_VERSION:?}" "${CARGO_DEB_SHA256:?}" "${DEB_VERSION:?}" "${VERSION:?}"
: "${KANIDM_BUILD_PROFILE:?}" "${SOURCE_DATE_EPOCH:?}" "${COMMIT:?}" "${HOST_UID:?}" "${HOST_GID:?}"
# Files written below belong to the runner user again (the container runs as root).
trap 'chown -R "$HOST_UID:$HOST_GID" /work/src /work/dist' EXIT

# 1. Build dependencies, all from AlmaLinux's own AppStream/BaseOS repositories (rpm signatures are checked by dnf; no EPEL, no CRB).
#    Upstream's .cargo/config.toml links with `clang -fuse-ld=lld` => clang AND lld are required. The rest follows upstream's own lists
#    (scripts/install_ubuntu_dependencies.sh, server/Dockerfile, tools/Dockerfile): gcc, make, cmake, pam-devel, sqlite-devel,
#    udev (systemd-devel), openssl-devel, pkg-config, automake/autoconf/gawk. Package VERSIONS are those of the day (not pinned; the image digest is).
dnf -y -q install gcc gcc-c++ make cmake clang lld pkgconf-pkg-config openssl-devel pam-devel sqlite-devel systemd-devel automake autoconf gawk binutils git-core tar gzip xz findutils
clang --version | head -n1; ld.lld --version
ldd --version | head -n1   # glibc must be 2.34 here

# 2. Rust toolchain: the exact version, rustup-init checked against a pinned sha256.
export CARGO_HOME=/opt/cargo RUSTUP_HOME=/opt/rustup PATH=/opt/cargo/bin:$PATH
curl -fsSL --proto '=https' --tlsv1.2 -o /tmp/rustup-init https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init
echo "$RUSTUP_INIT_SHA256  /tmp/rustup-init" | sha256sum --check --strict -
chmod +x /tmp/rustup-init
/tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain "$RUST_VERSION"
# upstream's rust-toolchain.toml says `stable`; this variable wins over it, so the pinned version is the one that builds
export RUSTUP_TOOLCHAIN="$RUST_VERSION-x86_64-unknown-linux-gnu"
cargo --version; rustc --version

# 3. cargo-deb: crate downloaded and checked against the pinned sha256 (as in crates.io's index), then built from that exact source.
curl -fsSL --proto '=https' --tlsv1.2 -o /tmp/cargo-deb.crate "https://static.crates.io/crates/cargo-deb/cargo-deb-$CARGO_DEB_VERSION.crate"
echo "$CARGO_DEB_SHA256  /tmp/cargo-deb.crate" | sha256sum --check --strict -
mkdir /tmp/cargo-deb && tar -xzf /tmp/cargo-deb.crate -C /tmp/cargo-deb
cargo install --locked --path "/tmp/cargo-deb/cargo-deb-$CARGO_DEB_VERSION"

# 4. Build (same targets as upstream Makefile release/*)
cd /work/src
export KANIDM_BUILD_PROFILE
cargo build --release -p kanidm_tools --bin kanidm
cargo build --release -p daemon --bin kanidmd
cargo build --release --bin kanidm_ssh_authorizedkeys --bin kanidm_ssh_authorizedkeys_direct
cargo build --release -p pam_kanidm -p nss_kanidm
cargo build --release --features unix -p kanidm_unix_int --bin kanidm_unixd --bin kanidm_unixd_tasks --bin kanidm-unix
# Upstream's Cargo.lock at this commit is not fully current (--locked fails, as in upstream's own Makefile targets). Show what cargo changed.
git config --global --add safe.directory /work/src
git diff --stat -- Cargo.lock

# 5. Tarball (reproducible tar)
t=/work/src/target/release; s=/work/stage
install -d "$s/usr/sbin" "$s/usr/bin" "$s/usr/lib/security" "$s/usr/share/kanidmd"
install -m755 "$t/kanidmd" "$t/kanidm_unixd" "$t/kanidm_unixd_tasks" "$s/usr/sbin/"
install -m755 "$t/kanidm" "$t/kanidm-unix" "$t/kanidm_ssh_authorizedkeys" "$t/kanidm_ssh_authorizedkeys_direct" "$s/usr/bin/"
install -m644 "$t/libpam_kanidm.so" "$s/usr/lib/security/pam_kanidm.so"
install -m644 "$t/libnss_kanidm.so" "$s/usr/lib/libnss_kanidm.so.2"
cp -r /work/src/server/core/static "$s/usr/share/kanidmd/static"
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" -C "$s" -czf "/work/dist/kanidm-$VERSION-linux-x86_64.tar.gz" .

# 6. .deb of the server from the finished binary and UPSTREAM's metadata (server/daemon/Cargo.toml [package.metadata.deb],
#    server/daemon/debian/{kanidmd.service,group.conf,server.toml,postinst}); nothing of it is changed. Same call as upstream's
#    kanidm_ppa_automation/scripts/build_debs.sh (`cargo deb -p daemon --no-build --deb-version`). --no-build: the binary above is packed as it is.
#    The metadata names a changelog that upstream's script generates; we write the same kind of file (reproducible date).
mkdir -p target/debian
{
  echo "kanidmd ($DEB_VERSION) UNRELEASED; urgency=medium"; echo
  echo "  * Built by FreeSynergy from upstream Kanidm $VERSION, commit ${COMMIT:0:7}"; echo
  echo " -- FreeSynergy mirror build  $(date -u -R -d "@$SOURCE_DATE_EPOCH")"
} > target/debian/changelog
cargo deb -p daemon --no-build --deb-version "$DEB_VERSION" --output /work/dist/
ls -l /work/dist
