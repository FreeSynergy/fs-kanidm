# Konfiguration

Öffentliche Voreinstellungen in `config/server.toml`. Die Datei enthält nur Platzhalter: Werte für Geheimnisse kommen aus dem Tresor (ADR 0067), wenn die Datei auf dem Server erzeugt wird. Erzeugt aus `config/schema.toml`.

| Einstellung | Typ | Standard | Geheimnis | Beschreibung |
|---|---|---|---|---|
| `version` | string | `2` | nein | Version der Konfigurationsdatei. |
| `domain` | string | - | nein | DNS-Name des Servers. Muss dem echten Namen entsprechen; späteres Ändern braucht `kanidmd domain rename`. Wert aus dem Tresor (je Installation). |
| `origin` | string | - | nein | WebAuthn-Origin: https:// plus Domain. |
| `bindaddress` | string | `127.0.0.1:8443` | nein | HTTPS-Adresse; nur Loopback, weil Zentinel das öffentliche Tor ist. |
| `db_path` | path | `/srv/freesynergy/kanidm/kanidm.db` | nein | Datenbankdatei; alle Daten liegen unter /srv/freesynergy (verschlüsselt, gesichert). |
| `db_fs_type` | string | `other` | nein | Dateisystem-Abstimmung: `zfs` (64k-Seiten, recordsize=64k nötig) oder `other`. |
| `tls_chain` | path | `/etc/kanidmd/tls/chain.pem` | nein | Öffentliche Zertifikatskette (PEM). |
| `tls_key` | path | - | ja (aus dem Tresor: `fs/kanidm/tls-key#file`) | Privater TLS-Schlüssel (PEM). Der Tresor schreibt die Datei; der Pfad im Muster ist ein Platzhalter. |
| `log_level` | string | `info` | nein | Log-Stufe: info, debug oder trace. Logs enthalten keine Geheimnisse. |
| `http_client_address_info.x-forward-for` | list | `["127.0.0.1"]` | nein | Vertrauenswürdige Proxys, deren X-Forwarded-For geglaubt wird (Zentinel auf demselben Rechner). |
| `online_backup.path` | path | `/srv/freesynergy/kanidm/backups/` | nein | Ziel der Online-Sicherungen. |
| `online_backup.schedule` | cron | `00 22 * * *` | nein | Zeitplan der Sicherung (UTC). |
| `online_backup.versions` | integer | `7` | nein | Anzahl der behaltenen Sicherungen. |
