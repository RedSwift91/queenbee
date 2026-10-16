# ADR 0008 — Comparaison des jetons en temps constant (faille 7)

- **Statut** : accepté — 16 octobre 2026 · **Couche** : variante de laboratoire `labs/vulnerable_queenbee.py`
- **Contexte** : Le jeton était comparé avec `==`, qui s'arrête au premier caractère différent : le temps de réponse permettait de deviner la clé caractère par caractère.
- **Décision** : Comparaison avec `hmac.compare_digest`, dont la durée ne dépend pas de la position de la première différence ; un jeton qui n'est pas du texte est refusé.
- **Conséquences** : + plus de fuite par le temps de réponse. − aucune notable.
- **Menace STRIDE et propriété** : I, S · Confidentialité · **Preuve** : `test_faille7_corrigee_token_is_compared_in_constant_time`