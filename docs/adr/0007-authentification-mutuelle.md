# ADR 0007 — Authentification mutuelle des appels inter-services (faille 6)

- **Statut** : accepté — 16 octobre 2026 · **Couche** : variante de laboratoire `labs/vulnerable_queenbee.py`
- **Contexte** : L'appel au service d'enrichissement ne présentait et ne vérifiait aucune identité : n'importe qui pouvait l'appeler, et n'importe qui pouvait se faire passer pour lui.
- **Décision** : Le client signe sa requête et le service la vérifie ; le service signe sa réponse et le client la vérifie (HMAC, clé propre à ce lien). En production, ce rôle est tenu par mTLS.
- **Conséquences** : + un client inconnu et un faux service sont tous deux refusés. − une clé de plus à gérer par lien ; en production, une infrastructure de certificats.
- **Menace STRIDE et propriété** : S, T · Intégrité (authenticité) · **Preuve** : `test_faille6_corrigee_unknown_client_is_refused`, `test_faille6_corrigee_impostor_service_is_refused`