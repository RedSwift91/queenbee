# ADR 0009 — Segmentation en zones et refus par défaut

- **Statut** : accepté — 16 octobre 2026 · **Domaine** : infrastructure cible
- **Contexte** : Queen Bee reçoit des données non fiables (agents, flux de menaces) et pilote un pare-feu de production. Un réseau plat laisserait une API compromise atteindre directement la base, les secrets et les journaux.
- **Décision** : Six zones par niveau de confiance (Z0 à Z5), une matrice de flux explicite où chaque flux est justifié par un élément d'architecture, et tout autre flux refusé. L'administration passe uniquement par le bastion.
- **Conséquences** : + une compromission reste confinée à sa zone ; chaque ouverture réseau est justifiée. − davantage de règles de pare-feu à maintenir ; tout nouveau besoin impose de mettre à jour la matrice.
- **Menace STRIDE et propriété** : E, I, S · toutes propriétés · **Preuve** : matrice des flux de `docs/infrastructure.md` ; schéma `docs/uml/c4_container.puml`