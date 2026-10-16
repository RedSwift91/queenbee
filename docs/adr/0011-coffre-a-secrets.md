# ADR 0011 — Secrets dans un coffre, une identité par service

- **Statut** : accepté — 16 octobre 2026 · **Domaine** : infrastructure cible
- **Contexte** : Le script hérité et la variante de laboratoire contenaient des secrets écrits dans le code et partagés. Un secret dans Git est un secret compromis.
- **Décision** : Les secrets sont stockés dans un coffre (zone d'administration) et injectés au démarrage ; une clé par service et par lien ; rotation planifiée ; l'application refuse de démarrer si un secret manque.
- **Conséquences** : + une fuite ne compromet qu'un service ; rotation possible sans modifier le code. − dépendance au coffre au démarrage ; procédure de rotation à outiller.
- **Menace STRIDE et propriété** : I, S · Confidentialité · **Preuve** : `test_missing_secret_refuses_to_start`, `test_secret_never_printed`, `test_faille1_corrigee_*` ; gitleaks sur tout l'historique : aucune fuite