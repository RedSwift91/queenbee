# Dossier de conception sécurisée — Queen Bee

Les 8 pièces demandées, et où les trouver.

| # | Pièce | Où |
|---|---|---|
| 1 | **Modèle de menaces** | [`threat_model.md`](threat_model.md) : actifs, acteurs, DFD, 7 frontières, STRIDE, exigences EX-01 à EX-09, revue des 7 failles du laboratoire |
| 2 | **Code hexagonal testé** | [`../src/queenbee/`](../src/queenbee/) et [`../tests/`](../tests/) : 145 tests, couverture 100 % ; variante de laboratoire corrigée dans [`../labs/`](../labs/) |
| 3 | **Traçabilité exigence ↔ test** | [`tracabilite.md`](tracabilite.md) |
| 4 | **ADR** | [`adr/`](adr/) : 0001 architecture hexagonale ; 0002 à 0008 failles du laboratoire ; 0009 à 0012 infrastructure |
| 5 | **Infrastructure** | [`infrastructure.md`](infrastructure.md) : zones, matrice des flux, secrets, journalisation, sauvegarde et reprise |
| 6 | **Diagrammes** | [`uml/`](uml/) : C4 contexte (niveau 1), conteneurs et zones (niveau 2), composants (niveau 3), classes, séquence d'ingestion ; sources `.puml` et rendus `.png` |
| 7 | **Recette (Go / No-Go)** | [`recette.md`](recette.md) |
| 8 | **Trace de release (écarts, dette)** | [`release.md`](release.md) |

Documents complémentaires : [`refactoring_legacy.md`](refactoring_legacy.md) (problèmes du script
hérité), [`parcours.md`](parcours.md) (parcours utilisateur et tranche verticale),
[`comparaison_architectures.md`](comparaison_architectures.md), [`rendu_j1.md`](rendu_j1.md).

## Vérifier soi-même

```bash
pip install -e ".[dev]"
make check                          # ruff, mypy, pytest + couverture, bandit, pip-audit, lint-imports
python -m pytest -m lab -q          # les 7 failles corrigées (14 tests)
pip install pre-commit && pre-commit run gitleaks --all-files
```
