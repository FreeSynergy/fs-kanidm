# Lokaler Test des Server-Aufbaus

`scripts/test/podman-stack.sh` startet Zentinel, Kanidm und Tuwunel in einem Podman-Pod ohne root (gemeinsame Loopback-Adresse wie auf dem Server) und prüft: Zentinel validiert und bedient unser gerendertes KDL; Kanidm läuft dahinter; eine Person meldet sich mit Passwort und TOTP an und durchläuft einen OIDC-Authorization-Code-Ablauf mit PKCE (id_token-Angaben, ES256, userinfo); Tuwunel bietet Single Sign-on mit Kanidm an und schließt es ab.

Was das Skript erzwingt:

- **SELinux bleibt Enforcing.** Bind-Mounts tragen `:Z` und enthalten nur nicht geheime, gerenderte Konfigurationen (RAM-Verzeichnis unter `/dev/shm`). Nach dem Lauf liest das Skript das Journal (`journalctl -b -t setroubleshoot --since <Start>`, ohne root); jeder Alarm macht den Test rot. Ein nicht lesbares Journal macht ihn ebenfalls rot: Das Skript schreibt per `logger` eine zufällige Markerzeile und muss sie wiederfinden. `test_avc_check.sh` prüft das mit einem nachgebauten `journalctl` (sauber, deutscher und englischer Alarm, unlesbarer Hinweis, fehlender Marker, Fehler).
- **Geheimnisse leben nur in Containern.** TLS-Schlüssel entstehen in einem Container (tmpfs, Modus 0700) und werden als Podman-Secrets aus stdin übergeben; das Kanidm-Administratorpasswort geht aus der Wiederherstellungsausgabe ohne Ausgabe in ein Podman-Secret; Passwort und TOTP-Geheimnis der Testperson und das OAuth2-Client-Geheimnis entstehen und bleiben im Runner-Container (tmpfs, Dateien 0600). Nichts landet in Host-Dateien oder Umgebungsvariablen. Am Ende werden alle Secrets entfernt.
- **Härtung.** Jeder Container: `--restart=no`, `--pids-limit`, `--cap-drop=all` (kein `--cap-add` nötig), `--security-opt no-new-privileges`, Speicherlimit höchstens 1 GiB. Nur ein Lauf gleichzeitig (Sperrdatei und Pod-Prüfung). Ein abgestürzter Container bleibt aus, der Test ist rot.
- **Muster-Scan** (`scan_secrets.sh`, ADR 0054): vor dem Test über alle drei Repos, am Ende über die Ausgabe des Laufs. Sein Selbsttest beweist, dass jedes Muster ein vorbereitetes Beispiel erkennt. In der CI läuft zusätzlich gitleaks (`.github/workflows/secrets-scan.yml`).
- **Festgelegtes Image.** Das Tuwunel-Image ist per Digest festgelegt, sein Revisions-Label muss dem Commit in `fs-tuwunel/mirror.toml` entsprechen.

Trockenlauf ohne Container: `shellcheck scripts/test/*.sh`, `scripts/test/test_avc_check.sh`, `scripts/test/scan_secrets.sh --selftest`, `python3 -I scripts/test/oidc_flow.py selftest`.

Sprache: [English](../en/testing.md)
