# Capabilities

Capability tags for the FreeSynergy catalog (ADR 0068). `provides` = offers it, `requires` = needs it, `recommends` = can use it. Support is `yes`, `no` or `unstable`; every `yes` and `unstable` cites the upstream source. Generated from `capabilities.toml`; checked on version Kanidm 1.12.1 (2026-11-13).

| Tag | Relation | Support | Meaning | Source |
|---|---|---|---|---|
| `identity.oidc` | provides | yes | OpenID Connect Core 1.0 and Discovery; ES256 id_token signatures, PKCE S256; RS256 only as an explicit exception per client. | [link](https://github.com/kanidm/kanidm/blob/v1.12.1/book/src/supported_features.md) |
| `identity.oauth2` | provides | yes | OAuth 2.0 authorisation code grant and client credentials, token introspection, revocation, token exchange (RFC 8693). | [link](https://github.com/kanidm/kanidm/blob/v1.12.1/book/src/integrations/oauth2.md) |
| `identity.ldap` | provides | yes | Read-only LDAP and LDAPS (bind, search, compare, whoami). No writes through LDAP. | [link](https://github.com/kanidm/kanidm/blob/v1.12.1/book/src/integrations/ldap.md) |
| `identity.radius` | provides | yes | RADIUS through the separate kanidm/radius component (MSCHAPv2, EAP-TLS); each account has its own RADIUS credential. | [link](https://github.com/kanidm/kanidm/blob/v1.12.1/book/src/integrations/radius.md) |
| `identity.pam` | provides | yes | PAM and nsswitch for Linux and BSD clients through kanidm-unixd (pam_kanidm, nss_kanidm). | [link](https://github.com/kanidm/kanidm/blob/v1.12.1/book/src/integrations/pam_and_nsswitch.md) |
| `identity.ssh-keys` | provides | yes | Public SSH keys on persons and service accounts, distributed with kanidm_ssh_authorizedkeys. | [link](https://github.com/kanidm/kanidm/blob/v1.12.1/book/src/integrations/ssh_key_distribution.md) |
| `identity.passkeys` | provides | yes | WebAuthn Level 3 passkeys, attested passkeys with FIDO MDS checks. | [link](https://github.com/kanidm/kanidm/blob/v1.12.1/book/src/supported_features.md) |
| `identity.scim` | provides | unstable | SCIM only for importing from another identity provider (RFC 7644 bulk) and a young /scim/v1 interface; no stable provisioning server. Not used (ADR 0047). Upstream fixed a denial-of-service in the SCIM filter parser in 1.12.1 (security: high); use 1.12.1 or later. | [link](https://github.com/kanidm/kanidm/blob/v1.12.1/book/src/supported_features.md) |
| `identity.accounts` | provides | yes | Persons, service accounts and groups; managed through the REST API and client (ADR 0047: FreeSynergy sets the truth, Kanidm follows). | [link](https://github.com/kanidm/kanidm/blob/v1.12.1/book/src/accounts/intro.md) |
| `people.persons` | recommends | yes | Kanidm can use something that manages persons and groups (fs-people, fs-groups); it also runs alone. | [link](https://github.com/FreeSynergy/fs-documentation/blob/main/conventions/decisions/0068-faehigkeiten-und-spiegel.md) |
