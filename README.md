# fs-kanidm

FreeSynergy.Kanidm: everything FreeSynergy needs to ship the [Kanidm](https://kanidm.github.io/kanidm/stable/) identity server (login for people and programs).

- **Signed build mirror** (ADR 0068): `mirror.toml` pins the upstream release (`v1.12.0`, commit `a52b723c…`). GitHub Actions builds it from that commit, adds the source tarball of the same version (Kanidm is MPL-2.0) and an SBOM, and signs everything with the FreeSynergy release key.
- **Public configuration** `config/server.toml` with defaults. It is a template: secrets are `${vault:…}` placeholders, filled from the vault (ADR 0067); no secret is ever stored here (ADR 0054).
- **Capability tags** `capabilities.toml` for the catalog (OIDC, OAuth2, LDAP, RADIUS, PAM, SSH keys, passkeys, SCIM: yes / no / unstable, each with its upstream source).
- **Docs** in English and German (`docs/en`, `docs/de`) and an **export** of the configuration (`export/config-export.json`).

```text
mirror.toml  capabilities.toml  config/{server.toml,schema.toml}  docs/{en,de}/  export/  scripts/  .github/workflows/
```

```sh
python3 -I scripts/repo_tool.py check    # validate everything; secrets must be placeholders
python3 -I scripts/repo_tool.py docs     # regenerate capabilities.md and configuration.md (en + de)
python3 -I scripts/repo_tool.py export   # regenerate export/config-export.json
scripts/verify-mirror.sh <release-dir>   # check checksums and signatures of a downloaded release
```

Packages are release files, not Git content. Kanidm itself is not changed; fixes go upstream (ADR 0015).

Licence of this repository: MIT OR Apache-2.0. Kanidm is MPL-2.0 (`LICENSE-MPL-2.0.md` ships with every release).
