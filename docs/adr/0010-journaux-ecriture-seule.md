# ADR 0010 — Journaux centralisés en écriture seule

- **Statut** : accepté — 16 octobre 2026 · **Domaine** : infrastructure cible
- **Contexte** : Un attaquant qui compromet l'application cherchera à effacer ses traces. Des journaux locaux seraient effaçables par le même compte.
- **Décision** : Toutes les traces (alertes, changements d'état, refus, rejets) partent vers le collecteur de la zone sécurité en syslog TLS. Le compte applicatif n'y a qu'un droit d'écriture ; stockage immuable conservé un an. Les secrets ne sont jamais journalisés.
- **Conséquences** : + l'application ne peut pas effacer ses journaux ; la preuve survit à une compromission. − un composant de plus à exploiter ; une copie tampon locale est nécessaire en cas de coupure.
- **Menace STRIDE et propriété** : R, T · Preuve · **Preuve** : `test_audit_decorator_logs`, `test_abuse_refusal_is_audited`, `test_analyst_move_is_audited`