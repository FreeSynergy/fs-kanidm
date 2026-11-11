# Spiegel und Prüfung

Kanidm bietet keine signierten Pakete an (geprüft am 11.11.2026): GitHub-Releases enthalten keine Dateien, der Tag `v1.12.0` und sein Commit sind unsigniert, die Container sind unsigniert, und das Debian-PPA stammt aus der Gemeinschaft und steht noch bei 1.11.2. FreeSynergy baut deshalb aus dem Quellcode (ADR 0068, „gebaut wird nur, wo ein Format fehlt“):

1. `mirror.toml` legt Release-Tag und **Commit-SHA** fest. Der Workflow bricht ab, wenn der Upstream-Tag nicht mehr genau auf diesen Commit zeigt.
2. GitHub Actions baut die Programme (Profil `release_debian`) und das Quellcode-Archiv derselben Version (Kanidm steht unter MPL-2.0: der Quellcode reist mit dem Programm), dazu eine SBOM.
3. Jede Datei bekommt eine OpenPGP-Signatur (`.asc`) vom FreeSynergy-Release-Schlüssel, `SHA256SUMS.txt` listet die Dateien, GitHub fügt die Herkunft des Baus hinzu.

Selbst prüfen:

```sh
scripts/verify-mirror.sh <Verzeichnis-mit-den-Release-Dateien>
```

Das Skript prüft die Signaturen gegen den Schlüssel mit dem Fingerabdruck aus `mirror.toml` (`16A4 A3EE 563A EF51 FCF0 C55D ED7B 57C4 A190 4342`) und die Prüfsummen. Es gibt keine Geheimnisse aus, weil keine beteiligt sind.

Nicht gespiegelt: das PPA-Paket 1.11.2 (älter, von einer einzelnen Person signiert) und die unsignierten Container-Images (nur für lokale Tests).

Sprache: [English](../en/mirror.md)
