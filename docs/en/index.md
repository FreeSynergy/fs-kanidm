# FreeSynergy.Kanidm

Kanidm is the login service of FreeSynergy: people and programs sign in here (OIDC, passkeys); other protocols (LDAP, RADIUS, PAM, SSH keys) are available when a program needs them.

- [Capabilities](capabilities.md): what Kanidm offers, per protocol, with sources.
- [Configuration](configuration.md): the public defaults and what comes from the vault.
- [Mirror](mirror.md): where the package comes from and how to check it.

In the FreeSynergy setup Kanidm listens on the loopback only; [Zentinel](https://github.com/FreeSynergy/fs-zentinel) is the public gate in front of it. FreeSynergy decides what exists and aligns Kanidm to it (ADR 0047); programs without Kanidm keep working (ADR 0024).

Language: [Deutsch](../de/index.md)
