# ADR 0002 — Une clé par service, injectée au démarrage (faille 1)

- **Statut** : accepté — 16 octobre 2026 · **Couche** : variante de laboratoire `labs/vulnerable_queenbee.py`
- **Contexte** : La variante de laboratoire contenait la clé `qb-admin-2026` écrite dans le code et partagée par tous les services : quiconque lisait le dépôt obtenait l'accès, et une fuite compromettait tous les services à la fois.
- **Décision** : Chaque service lit sa propre clé (`QUEENBEE_<SERVICE>_KEY`, au moins 32 caractères) dans l'environnement au démarrage ; aucune valeur par défaut, refus de démarrer si elle manque.
- **Conséquences** : + une fuite n'ouvre qu'un service ; la clé n'est plus dans Git. − il faut distribuer et faire tourner une clé par service. L'ancienne clé reste dans l'historique Git : elle est considérée comme révoquée.
- **Menace STRIDE et propriété** : S, I · Confidentialité · **Preuve** : `test_faille1_corrigee_no_hardcoded_secret_one_key_per_service`, `test_faille1_corrigee_missing_or_short_key_refuses_to_start`