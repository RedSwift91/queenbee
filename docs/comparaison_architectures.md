# Comparaison de deux architectures (J2 · A2)

Contexte qui pèse sur le choix :

- **Volume** : quelques dizaines d'agents, quelques milliers d'événements par heure. Un seul processus suffit largement.
- **Équipe** : 3 à 4 personnes, en formation, sur 3 jours.
- **Délai** : un rendu par jour ; il faut que tout soit testable sans infrastructure.

## Les deux options

**A · Monolithe hexagonal** : un seul processus Python. Le domaine au centre, des ports
(`Protocol`) et des adapters autour. Les couches communiquent par appels de fonctions.

**B · Microservices** : quatre services séparés (ingestion, détection, incidents, notification),
chacun avec son propre déploiement, qui communiquent par HTTP ou par une file de messages.

## Comparaison

| Critère | A · Monolithe hexagonal | B · Microservices |
|---|---|---|
| **Maintenabilité** | un seul dépôt, un seul jeu de tests ; changer d'adapter ne touche pas au domaine ; `lint-imports` empêche l'architecture de se dégrader | chaque service évolue seul, mais tout changement de contrat entre services demande une coordination et un versionnement d'API |
| **Frontières réseau** | une seule entrée réseau (TB1, API des agents) ; les autres frontières sont des appels internes | chaque flèche entre services devient une frontière réseau : 3 à 4 frontières de plus, chacune à authentifier et chiffrer |
| **Secrets** | un seul secret applicatif (clé HMAC des agents), lu une fois au démarrage | un secret par lien inter-services (jetons, certificats mTLS), plus leur rotation : bien plus de secrets à gérer et à faire fuiter |
| **Failles typiques** | une faille dans un adapter donne accès à tout le processus (pas d'isolation entre couches) ; un module peut importer ce qu'il ne devrait pas (bloqué par `lint-imports`) | appel inter-services non authentifié (exactement la FAILLE-6 de `labs/`) ; désérialisation de messages entre services ; configuration incohérente entre services |
| **Tests** | toute la suite tourne en moins d'1 s, sans base ni réseau, grâce aux doublures | tests d'intégration lourds : il faut démarrer plusieurs services et un bus de messages |
| **Disponibilité** | un plantage arrête tout | un service en panne n'arrête pas les autres |
| **Adapté à notre volume, équipe, délai ?** | **oui** | **non** : surdimensionné pour quelques milliers d'événements par heure et une équipe de 4 sur 3 jours |

## Conclusion

On retient **A, le monolithe hexagonal**. Il donne la séparation des responsabilités qu'on
cherchait (domaine isolé, adapters remplaçables) sans payer le coût réseau et sécurité des
microservices. Si le volume devenait très grand, les ports existants permettraient de sortir un
adapter dans un service séparé sans réécrire le domaine. Décision formalisée dans
`docs/adr/0001-architecture-hexagonale.md`.
