# ADR 0005 — Requêtes SQL paramétrées dans la persistance (faille 4)

- **Statut** : accepté — 16 octobre 2026 · **Couche** : variante de laboratoire `labs/vulnerable_queenbee.py`
- **Contexte** : La recherche d'incidents construisait sa requête par f-string : `x' OR '1'='1` renvoyait toute la table.
- **Décision** : Toutes les requêtes passent les valeurs en paramètres (`?`), séparément du texte SQL.
- **Conséquences** : + une donnée ne peut plus devenir du code SQL. − aucune, hormis la discipline de ne jamais concaténer (vérifiée par bandit et ruff).
- **Menace STRIDE et propriété** : T, I · Intégrité, Confidentialité · **Preuve** : `test_faille4_corrigee_sql_injection_returns_nothing`