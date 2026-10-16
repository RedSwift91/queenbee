# Trace de release

## Versions rendues

| Étiquette | Date | Contenu |
|---|---|---|
| `j1-rendu` | 14/10/2026 | modèle de menaces ; domaine extrait du script hérité ; 3 corrections de sécurité ; patterns de création ; 72 tests |
| `j2-rendu` | 15/10/2026 | architecture hexagonale complète ; 5 patterns défensifs ; parcours, ADR 0001, C4 niveau 1 ; 134 tests ; `make check` entièrement vert |
| `j3-rendu` | 16/10/2026 | revue de sécurité : 7 failles prouvées, corrigées et testées ; infrastructure cible ; 11 ADR supplémentaires ; C4 niveaux 2 et 3 ; dossier complet ; 145 tests |

L'historique complet, un commit par étape, est consultable avec `git log`. Les refactorings et les
corrections de sécurité n'ont jamais été mélangés dans un même commit.

## Écarts par rapport aux consignes

| Écart | Justification |
|---|---|
| Au J1, `make check` complet était interrompu par deux fichiers de tests du J2 | ces tests importaient des modules du J2 ; une note de rendu (`docs/rendu_j1.md`) l'expliquait, comme le prévoit la consigne ; résolu au J2 |
| Les tests de preuve de `tests/test_lab_vulnerable.py` (fournis) ont été modifiés | demandé explicitement par ce fichier et par la consigne du J3 : « après correction, l'étudiant inverse l'assertion » ; chaque test inversé porte « _corrigee_ » dans son nom et rappelle la preuve d'origine |
| `parse_sshd_line`, prévu au J2, a été écrit dès le J1 | c'est la reprise de la lecture des journaux du script hérité, nécessaire à la correction « regex ancrée » du J1 |
| Ajout de `known-first-party` dans la configuration de ruff | sans ce réglage, ruff classait les modules pas encore écrits comme externes et signalait à tort l'ordre des imports des tests fournis ; aucune règle désactivée, aucun seuil abaissé |
| Ajout d'un fichier `.gitleaksignore` | un seul faux positif : la ligne `QUEENBEE_AGENT_KEY=` **vide** de `.env.example` ; empreinte exacte documentée, toute autre détection reste active |
| Le bonus « même démarche sur un script de Python Scripting Sécu » n'a pas été fait | facultatif |

## Dette assumée

| Dette | Impact | Priorité |
|---|---|---|
| Pas d'adapter de pare-feu réel (seulement `InMemoryFirewall`) | le blocage d'IP n'agit pas encore sur un vrai pare-feu | haute avant production |
| Pas d'adapter SMTP : en production, les alertes vont au journal applicatif | les analystes ne reçoivent pas de courriel | haute avant production |
| L'API des agents valide les messages mais n'est pas exposée par un serveur HTTP | ingestion réseau à brancher | haute avant production |
| Le limiteur de débit est propre à chaque processus | plusieurs instances nécessiteraient un compteur partagé | moyenne |
| Processus unique : un seul point de défaillance (ADR 0001) | arrêt total si le processus tombe | moyenne, à revoir si le volume augmente |
| L'authentification mutuelle des services est simulée par HMAC dans le laboratoire | en production, mTLS avec une PKI (ADR 0007) | moyenne |
| Le test de reprise mensuel n'a pas encore été joué | RTO de 4 h non encore mesuré | moyenne |
| `legacy/log_watcher.py` conserve ses défauts | aucun : jamais exécuté ni déployé | faible |
