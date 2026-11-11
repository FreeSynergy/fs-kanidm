# FreeSynergy.Kanidm

Kanidm ist der Anmeldedienst von FreeSynergy: Menschen und Programme melden sich hier an (OIDC, Passkeys); weitere Wege (LDAP, RADIUS, PAM, SSH-Schlüssel) gibt es, wenn ein Programm sie braucht.

- [Fähigkeiten](capabilities.md): was Kanidm je Protokoll bietet, mit Quellen.
- [Konfiguration](configuration.md): die öffentlichen Voreinstellungen und was aus dem Tresor kommt.
- [Spiegel](mirror.md): woher das Paket kommt und wie man es prüft.
- [Test](testing.md): der lokale Podman-Test des Aufbaus.

Im FreeSynergy-Aufbau hört Kanidm nur auf der Loopback-Adresse; [Zentinel](https://github.com/FreeSynergy/fs-zentinel) ist das öffentliche Tor davor. FreeSynergy legt fest, was es gibt, und gleicht Kanidm daran an (ADR 0047); Programme laufen auch ohne Kanidm weiter (ADR 0024).

Sprache: [English](../en/index.md)
