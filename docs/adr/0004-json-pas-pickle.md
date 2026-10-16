# ADR 0004 — Des données JSON, jamais pickle sur une entrée externe (faille 3)

- **Statut** : accepté — 16 octobre 2026 · **Couche** : variante de laboratoire `labs/vulnerable_queenbee.py`
- **Contexte** : Les messages des agents étaient lus avec `pickle.loads` : la simple lecture d'un message forgé exécutait du code sur la reine.
- **Décision** : Les messages sont lus avec `json.loads` (données uniquement), taille bornée à 4 Kio, puis schéma strict : exactement les quatre champs attendus, tous textuels.
- **Conséquences** : + plus aucune exécution de code possible à la lecture. − les agents doivent envoyer du JSON ; les objets Python ne peuvent plus être transmis tels quels.
- **Menace STRIDE et propriété** : T, E · Intégrité · **Preuve** : `test_faille3_corrigee_pickle_payload_is_refused`, `test_faille3_corrigee_valid_json_message_is_accepted`