# Fähigkeiten

Fähigkeiten-Tags für den FreeSynergy-Katalog (ADR 0068). `provides` = bietet an, `requires` = braucht, `recommends` = kann nutzen. Unterstützung ist `yes`, `no` oder `unstable` (ja, nein, instabil); jedes `yes` und `unstable` nennt die Quelle beim Hersteller. Erzeugt aus `capabilities.toml`; geprüft für Version Kanidm 1.12.1 (2026-11-13).

| Tag | Beziehung | Unterstützung | Bedeutung | Quelle |
|---|---|---|---|---|
| `identity.oidc` | provides | ja | OpenID Connect Core 1.0 und Discovery; ES256-id_token, PKCE S256; RS256 nur als ausdrückliche Ausnahme je Client. | [link](https://github.com/kanidm/kanidm/blob/v1.12.1/book/src/supported_features.md) |
| `identity.oauth2` | provides | ja | OAuth 2.0 Authorization-Code und Client-Credentials, Introspection, Widerruf, Token-Exchange (RFC 8693). | [link](https://github.com/kanidm/kanidm/blob/v1.12.1/book/src/integrations/oauth2.md) |
| `identity.ldap` | provides | ja | LDAP und LDAPS nur lesend (Bind, Suche, Vergleich, whoami). Kein Schreiben über LDAP. | [link](https://github.com/kanidm/kanidm/blob/v1.12.1/book/src/integrations/ldap.md) |
| `identity.radius` | provides | ja | RADIUS über die getrennte Komponente kanidm/radius (MSCHAPv2, EAP-TLS); jedes Konto hat ein eigenes RADIUS-Passwort. | [link](https://github.com/kanidm/kanidm/blob/v1.12.1/book/src/integrations/radius.md) |
| `identity.pam` | provides | ja | PAM und nsswitch für Linux- und BSD-Clients über kanidm-unixd (pam_kanidm, nss_kanidm). | [link](https://github.com/kanidm/kanidm/blob/v1.12.1/book/src/integrations/pam_and_nsswitch.md) |
| `identity.ssh-keys` | provides | ja | Öffentliche SSH-Schlüssel an Personen und Dienstkonten, verteilt mit kanidm_ssh_authorizedkeys. | [link](https://github.com/kanidm/kanidm/blob/v1.12.1/book/src/integrations/ssh_key_distribution.md) |
| `identity.passkeys` | provides | ja | WebAuthn-Level-3-Passkeys, bestätigte Passkeys mit FIDO-MDS-Prüfung. | [link](https://github.com/kanidm/kanidm/blob/v1.12.1/book/src/supported_features.md) |
| `identity.scim` | provides | instabil | SCIM nur zum Einlesen aus einem anderen Anbieter (RFC 7644 Bulk) und eine junge /scim/v1-Schnittstelle; kein stabiler Provisionierungs-Server. Wird nicht genutzt (ADR 0047). Der Hersteller hat in 1.12.1 einen Denial-of-Service im SCIM-Filter-Parser behoben (Sicherheit: hoch); 1.12.1 oder neuer nutzen. | [link](https://github.com/kanidm/kanidm/blob/v1.12.1/book/src/supported_features.md) |
| `identity.accounts` | provides | ja | Personen, Dienstkonten und Gruppen; verwaltet über REST-API und Client (ADR 0047: FreeSynergy legt fest, Kanidm gleicht an). | [link](https://github.com/kanidm/kanidm/blob/v1.12.1/book/src/accounts/intro.md) |
| `people.persons` | recommends | ja | Kanidm kann etwas nutzen, das Personen und Gruppen verwaltet (fs-people, fs-groups); es läuft auch allein. | [link](https://github.com/FreeSynergy/fs-documentation/blob/main/conventions/decisions/0068-faehigkeiten-und-spiegel.md) |
