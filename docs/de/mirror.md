# Spiegel und Prüfung

Kanidm bietet keine signierten Pakete an (geprüft am 11.11.2026): GitHub-Releases enthalten keine Dateien, der Tag `v1.12.1` und sein Commit sind unsigniert, die Container sind unsigniert, und das Debian-PPA stammt aus der Gemeinschaft und steht noch bei 1.11.2. FreeSynergy baut deshalb aus dem Quellcode (ADR 0068, „gebaut wird nur, wo ein Format fehlt“):

1. `mirror.toml` legt Release-Tag und **Commit-SHA** fest. Der Workflow bricht ab, wenn der Upstream-Tag nicht mehr genau auf diesen Commit zeigt.
2. GitHub Actions baut die Programme (Profil `release_debian`) in einem per Digest festgelegten AlmaLinux-9-Container, das `.deb` des Servers und das Quellcode-Archiv derselben Version (Kanidm steht unter MPL-2.0: der Quellcode reist mit dem Programm), dazu eine SBOM.
3. Jede Datei bekommt eine OpenPGP-Signatur (`.asc`) vom FreeSynergy-Release-Schlüssel, `SHA256SUMS.txt` listet die Dateien, GitHub fügt die Herkunft des Baus hinzu.

## Paketformate

| Datei | Was es ist |
|---|---|
| `kanidmd_1.12.1-1_amd64.deb` | **deb**, nur Server (x86_64): `kanidmd`, die systemd-Unit von Upstream (unverändert: `DynamicUser=yes`, Gruppe `kanidmd`), die sysusers-Datei, die die Gruppe anlegt, die Standard-`/etc/kanidmd/server.toml`, die Dateien der Web-Oberfläche. Paketname, Metadaten, Unit und Maintainer-Skripte stammen von Upstream (`server/daemon/Cargo.toml` `[package.metadata.deb]`, `server/daemon/debian/`); `cargo-deb` packt sie nur ein. |
| `kanidm-1.12.1-linux-x86_64.tar.gz` | alle Programme (Server, Client, Unix-Dienste, PAM/NSS-Module) als Tar |
| `kanidm-1.12.1-source.tar.gz` | Quellcode derselben Version (MPL-2.0) |

**Paketversion** (ADR 0077): `<Upstream-Version>-<Revision>`, hier `1.12.1-1`. Die Revision steigt (`-2`, ...) nur, wenn sich unser Paketbau ändert, die Upstream-Version aber nicht.

**Mindestplattform:** Alles wird in einem per Digest festgelegten Container gebaut (AlmaLinux 9, glibc 2.34); die Programme und das `.deb` laufen daher auf Debian 12, Ubuntu 22.04, Enterprise Linux 9 und neueren Systemen. Nach jedem Bau installiert der Job `smoke` das `.deb` in Containern mit Debian 12, Ubuntu 22.04 und Ubuntu 24.04 (Images in `mirror.toml` per Digest festgelegt), prüft Inhalt, Gruppe `kanidmd` und Unit-Datei und startet `kanidmd --version` (`scripts/smoke-deb.sh`; systemd selbst läuft dort nicht).

**Installation (Debian, Ubuntu):**

```sh
scripts/verify-mirror.sh <Verzeichnis-mit-den-Release-Dateien>      # zuerst: Signatur und Prüfsumme
sudo apt install ./kanidmd_1.12.1-1_amd64.deb
```

`apt` prüft unsere Signatur **nicht**: Es prüft nur signierte apt-Paketquellen, dies ist eine einzelne Datei. Maßgeblich ist die abgetrennte OpenPGP-Signatur `kanidmd_1.12.1-1_amd64.deb.asc` (mit `verify-mirror.sh` oder `gpg --verify` prüfen); eine signierte apt-Paketquelle ist geplant. Auf eine Signatur im `.deb` selbst (`dpkg-sig`) stützen wir uns nicht: `dpkg-sig` gibt es in Ubuntu 24.04 und Debian 12 nicht mehr, die Signier-Aktion kann sie daher nicht anbringen.

Das postinst von Upstream ruft `systemd-sysusers` auf, das Paket hängt aber nicht von `systemd` ab; jeder Server, für den das Paket gedacht ist, läuft mit systemd. Das Paket wird ohne Autostart installiert: erst `/etc/kanidmd/server.toml` anpassen (Domain, Origin, Zertifikate), dann `systemctl enable --now kanidmd`.

Selbst prüfen:

```sh
scripts/verify-mirror.sh <Verzeichnis-mit-den-Release-Dateien>
```

Das Skript prüft die Signaturen gegen den Schlüssel mit dem Fingerabdruck aus `mirror.toml` (`16A4 A3EE 563A EF51 FCF0 C55D ED7B 57C4 A190 4342`) und die Prüfsummen. Es gibt keine Geheimnisse aus, weil keine beteiligt sind.

Nicht gespiegelt: das PPA-Paket 1.11.2 (älter, von einer einzelnen Person signiert) und die unsignierten Container-Images (nur für lokale Tests).

Sicherheit: Kanidm 1.12.1 (13.11.2026) behebt ein vom Hersteller als HOCH eingestuftes Problem: Beim SCIM-Filter-Parser war eine frühere Korrektur unvollständig, sodass präparierte Anfragen den Stack erschöpfen und einen Denial-of-Service durch nicht angemeldete Personen auslösen konnten (keine bekannte Ausnutzung). Betroffen ist auch 1.12.0, selbst wenn SCIM nicht benutzt wird; der Spiegel wird deshalb auf 1.12.1 gehoben. Release-Text: <https://github.com/kanidm/kanidm/releases/tag/v1.12.1>.

Sprache: [English](../en/mirror.md)
