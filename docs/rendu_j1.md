# Rendu J1 — note sur l'état des portes qualité

## Ce qui est vert

| Porte | Commande | Résultat |
|---|---|---|
| Style | `ruff check . ; ruff format --check .` | ✅ |
| Typage | `mypy` | ✅ strict, 16 fichiers |
| Tests J1 | voir ci-dessous | ✅ 72 tests, couverture 100 % (seuil 90 %) |
| Sécurité du code | `bandit -q -r src -c pyproject.toml` | ✅ aucun problème |
| Dépendances | `pip-audit` | ✅ aucune vulnérabilité connue |
| Architecture | `$env:PYTHONPATH="src"; lint-imports` | ✅ contrat hexagonal respecté |

Commande de test du J1 :

```powershell
python -m pytest tests/test_domain.py tests/test_creational.py tests/test_legacy_characterization.py `
  tests/test_j1_group.py tests/test_lab_vulnerable.py --cov=src/queenbee --cov-fail-under=90
```

## Ce qui reste rouge, et pourquoi

`python -m pytest` lancé sans argument (donc `make check`) s'arrête à la collecte sur
`tests/test_services.py` et `tests/test_adapters.py`. Ces fichiers importent des modules du **J2**
qui n'existent pas encore : `AuditedNotifier`, `RateLimitedNotifier`, `response`, `access`,
`IncidentService`, `Principal`, `agent_api`, `threat_feed`. Ce n'est pas une régression : c'est le
travail du 15 octobre. Les tests fournis n'ont pas été modifiés.

## Choix à signaler

- `pyproject.toml` : ajout de `known-first-party = ["queenbee", "tests"]` pour ruff (isort). Sans ce
  réglage, ruff classe les modules du J2, pas encore créés, comme des paquets externes et signale un
  ordre d'imports faux dans les tests fournis. Aucune règle n'a été désactivée et aucun seuil n'a été
  baissé.
- `parse_sshd_line` (prévu au J2) est déjà écrit : c'est la reprise de la lecture des logs du script
  hérité, avec la correction « regex ancrée » demandée en A2.
