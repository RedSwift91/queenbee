# Recette — décision Go / No-Go (rendu j3-rendu, 16 octobre 2026)

## Critères et résultats

| # | Critère | Seuil | Résultat mesuré | Verdict |
|---|---|---|---|---|
| 1 | Style et règles de sécurité (`ruff check`, `ruff format --check`) | aucune erreur | aucune erreur | ✅ |
| 2 | Typage strict (`mypy`) | aucune erreur | aucune erreur (20 fichiers ; variante de labo aussi en strict) | ✅ |
| 3 | Tests (`pytest`) | tous verts | 145 verts | ✅ |
| 4 | Couverture | ≥ 90 % | 100 % | ✅ |
| 5 | Durée de la suite, sans base réelle | < 2 s | ≈ 1 s | ✅ |
| 6 | Preuves de laboratoire (`pytest -m lab`) | toutes vertes, inversées | 14 vertes, 7 failles sur 7 inversées | ✅ |
| 7 | Analyse statique de `src` (`bandit`) | aucune alerte | aucune alerte | ✅ |
| 8 | Analyse statique de `labs` (`bandit`) | aucune alerte Medium ou High | aucune alerte (2 Medium avant correction) | ✅ |
| 9 | Dépendances (`pip-audit`) | aucune vulnérabilité connue | aucune | ✅ |
| 10 | Contrat d'architecture (`lint-imports`) | 1 kept, 0 broken | 1 kept, 0 broken | ✅ |
| 11 | Secrets (`gitleaks`), fichiers et historique complet | aucune fuite | aucune fuite (un faux positif documenté dans `.gitleaksignore`) | ✅ |
| 12 | Exigences EX-01 à EX-09 couvertes par un test vert | 9 / 9 | 9 / 9 (`docs/tracabilite.md`) | ✅ |
| 13 | Intégration continue GitHub Actions (`make check`) | verte | verte | ✅ |
| 14 | Dossier : 8 pièces présentes dans `docs/` | 8 / 8 | 8 / 8 (`docs/README.md`) | ✅ |

## Réserves

| Réserve | Gravité | Traitement |
|---|---|---|
| `legacy/log_watcher.py` garde une alerte bandit Medium (SQL par f-string) | faible | script de départ conservé comme référence pédagogique, jamais exécuté ni déployé ; réécrit dans `src/` |
| Adapters réels manquants : pare-feu, messagerie SMTP, serveur HTTP de l'API des agents | moyenne | inscrits à la dette (`docs/release.md`) ; les ports existent, seuls les adapters sont à écrire |

## Décision

**GO** pour le rendu et une démonstration en environnement de test : tous les critères sont remplis et
les réserves n'affectent pas la sécurité du code livré.

**NO-GO pour une mise en production réelle** tant que les adapters de production manquants (pare-feu,
SMTP, serveur HTTP) ne sont pas écrits, testés et déployés selon l'infrastructure cible
(`docs/infrastructure.md`), et qu'un premier test de reprise n'a pas été réalisé.
