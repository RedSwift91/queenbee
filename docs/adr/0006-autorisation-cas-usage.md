# ADR 0006 — Autorisation vérifiée dans le cas d'usage (faille 5)

- **Statut** : accepté — 16 octobre 2026 · **Couche** : variante de laboratoire `labs/vulnerable_queenbee.py`
- **Contexte** : `close_incident` n'effectuait aucun contrôle : n'importe quel utilisateur pouvait clore un incident.
- **Décision** : Le cas d'usage reçoit un `Principal` et exige le rôle analyste en première étape, avant tout accès aux données ; chaque refus est écrit dans le journal d'audit.
- **Conséquences** : + une nouvelle interface ne peut pas contourner le contrôle. − la signature de la fonction change : chaque appelant doit fournir l'identité.
- **Menace STRIDE et propriété** : E, R · Intégrité, Preuve · **Preuve** : `test_faille5_corrigee_viewer_cannot_close_an_incident`