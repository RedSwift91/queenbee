# ADR 0003 — Validation des noms sans retour arrière exponentiel (faille 2)

- **Statut** : accepté — 16 octobre 2026 · **Couche** : variante de laboratoire `labs/vulnerable_queenbee.py`
- **Contexte** : Le motif `^([a-zA-Z0-9]+\s?)*$` imbriquait deux répétitions : une entrée piégée de quelques dizaines de caractères bloquait le processeur (ReDoS).
- **Décision** : Longueur bornée à 32 caractères AVANT la regex, puis motif `[A-Za-z0-9]+(?: [A-Za-z0-9]+)*` vérifié avec `fullmatch` : une seule façon de découper la chaîne.
- **Conséquences** : + coût linéaire, quelle que soit l'entrée. − les noms ne peuvent plus contenir de tabulations ni d'espaces doubles.
- **Menace STRIDE et propriété** : D · Disponibilité · **Preuve** : `test_faille2_corrigee_redos_cost_stays_linear`