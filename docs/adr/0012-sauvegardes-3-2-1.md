# ADR 0012 — Sauvegardes 3-2-1 tirées depuis la zone sécurité

- **Statut** : accepté — 16 octobre 2026 · **Domaine** : infrastructure cible
- **Contexte** : La base des incidents est la preuve des attaques. Un rançongiciel ou une compromission de la base ne doit pas pouvoir détruire aussi les sauvegardes.
- **Décision** : Sauvegardes tirées depuis la zone sécurité avec un compte en lecture seule ; règle 3-2-1 dont une copie immuable hors site ; RPO 15 min, RTO 4 h, disponibilité visée 99,5 % ; test de reprise mensuel.
- **Conséquences** : + une base compromise ne connaît aucun accès aux sauvegardes ; reprise mesurée et vérifiée. − coût de stockage ; le test mensuel mobilise l'équipe.
- **Menace STRIDE et propriété** : D, R · Disponibilité, Preuve · **Preuve** : scénario de test de reprise, `docs/infrastructure.md` section 5