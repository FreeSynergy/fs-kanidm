# Configuration

Public default configuration in `config/server.toml`. It holds placeholders only: values for secrets come from the vault (ADR 0067) when the file is rendered on the server. Generated from `config/schema.toml`.

| Setting | Type | Default | Secret | Description |
|---|---|---|---|---|
| `version` | string | `2` | no | Configuration file version. |
| `domain` | string | - | no | DNS name of the server. Must match the real name; changing it later needs `kanidmd domain rename`. Value from the vault (per installation). |
| `origin` | string | - | no | WebAuthn origin: https:// plus the domain. |
| `bindaddress` | string | `127.0.0.1:8443` | no | HTTPS listen address; loopback, because Zentinel is the public gate. |
| `db_path` | path | `/srv/freesynergy/kanidm/kanidm.db` | no | Database file; all data lives under /srv/freesynergy (encrypted, backed up). |
| `db_fs_type` | string | `other` | no | File system tuning: `zfs` (64k pages, needs recordsize=64k) or `other`. |
| `tls_chain` | path | `/etc/kanidmd/tls/chain.pem` | no | Public certificate chain (PEM). |
| `tls_key` | path | - | yes (from vault: `fs/kanidm/tls-key#file`) | Private TLS key (PEM). The vault writes the file; the path in the template is a placeholder. |
| `log_level` | string | `info` | no | Log level: info, debug or trace. Logs never contain secrets. |
| `http_client_address_info.x-forward-for` | list | `["127.0.0.1"]` | no | Trusted proxies whose X-Forwarded-For header is believed (Zentinel on the same host). |
| `online_backup.path` | path | `/srv/freesynergy/kanidm/backups/` | no | Where online backups are written. |
| `online_backup.schedule` | cron | `00 22 * * *` | no | Backup schedule (UTC). |
| `online_backup.versions` | integer | `7` | no | Number of backups kept. |
