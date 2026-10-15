# Parcours utilisateur et tranche verticale (J2 · A2)

## 1. Parcours : de « attaque détectée » à « incident clos »

Scénario : un attaquant essaie des mots de passe sur le serveur `srv-web-01` depuis `10.0.0.66`.
Les frontières de confiance (TB) sont celles de `docs/threat_model.md`.

| # | Étape | Composant | Frontière | Menace STRIDE | Contre-mesure |
|---|---|---|---|---|---|
| 1 | L'attaquant rate 5 connexions SSH ; sshd les écrit dans le journal | hôte surveillé, `sshd` | — (zone non fiable) | **T** : il choisit le nom d'utilisateur, donc il écrit dans nos logs (`root'; DROP`) | tout ce qui vient du log est traité comme hostile à l'étape 3 |
| 2 | L'agent envoie les 5 événements à la reine, chacun signé | agent → `parse_agent_message` | **TB1** | **S** : un faux agent sans la clé · **D** : message géant | HMAC-SHA256 comparé en temps constant ; corps ≤ 4 Kio vérifié avant tout calcul |
| 3 | La reine vérifie le schéma et construit des `SecurityEvent` | `parse_agent_message`, `SecurityEvent` | TB1 | **T** : champ en trop (`is_admin`), IP piégée | schéma strict (ni plus, ni moins de champs) ; le domaine revalide IP, nom, action, fuseau |
| 4 | Les règles détectent une force brute et produisent une alerte HIGH | `DetectionService`, `RuleSet` | **TB6** (règles et seuils viennent de la config) | **T** / **E** : règle inconnue ou seuil `True` injecté par la config | `build_rule` n'accepte que les noms du registre ; seuil entier entre 1 et 10 000 |
| 5 | Un incident OPEN est enregistré | `SqliteIncidentRepository` | **TB2** | **T** / **I** : injection SQL via l'IP ou le message | requêtes paramétrées (`?`) |
| 6 | L'alerte part vers le SOC, tracée et limitée | `AuditedNotifier` → `RateLimitedNotifier` → notificateur | **TB5** | **D** : inondation d'alertes · **R** : alerte non tracée | 3 alertes par minute maximum, le reste compté ; chaque alerte écrite dans `queenbee.audit` |
| 7 | Alice (analyste) trie l'incident ; Bob (lecteur) essaie aussi et est refusé | `IncidentService.move` | **TB4** | **E** : un lecteur qui modifie · **R** : « ce n'est pas moi » | rôle vérifié en première étape du cas d'usage ; refus et changements écrits dans l'audit |
| 8 | Alice bloque l'IP, confine, puis clôt l'incident | `BlockIpCommand`, `CommandHistory`, `Incident` | **TB3** | **T** : IP piégée `10.0.0.66; iptables -F` · **R** : blocage non tracé | IP validée dans le constructeur de la commande ; commande tracée et annulable ; machine à états OPEN → TRIAGED → CONTAINED → CLOSED |

Le parcours traverse **six frontières** (TB1 à TB6). Il est rejoué par
`tests/test_j2_group.py::test_facade_full_journey_from_signed_messages_to_closed_incident`.

## 2. Tranche verticale : « seul un analyste fait avancer un incident, sans sauter le triage »

Une seule règle métier, suivie à travers toutes les couches.

| Couche | Où | Ce qui est fait |
|---|---|---|
| **Gestion** (règle métier) | `domain/model.py` : `Incident.transition_to`, table `_TRANSITIONS` | seules les flèches OPEN → TRIAGED → (CONTAINED →) CLOSED existent ; tout le reste lève `DomainError` |
| **Contrat d'interface** | `application/services.py` : `IncidentService.move(who, incident_id, to) -> Incident` | entrée : un `Principal`, un identifiant, un statut cible. Sorties possibles : l'incident modifié, `AccessDeniedError` (pas le rôle), `DomainError` (incident inconnu ou transition interdite) |
| **Persistance** | port `IncidentRepository.save` ; `SqliteIncidentRepository` (prod), `InMemoryIncidentRepository` (tests) | `UPDATE incident SET status = ? WHERE id = ?`, paramétré ; erreur si l'incident n'existe pas |
| **Restitution** | `QueenBee.move_incident`, `QueenBee.open_incidents` ; journal `queenbee.audit` | l'analyste voit la liste des incidents ouverts ; l'audit indique « alice : incident … passé à triaged » |
| **Recette** | tests | `test_domain.py::test_state_forbids_skipping_triage` · `test_services.py::test_analyst_moves_incident` · `test_services.py::test_abuse_viewer_cannot_close_incident` · `test_j2_group.py::test_analyst_move_is_audited` |

L'ordre dans le cas d'usage est imposé : **autoriser → vérifier → règle métier → persister**.
Si on inversait les deux premières étapes, un lecteur pourrait savoir si un identifiant d'incident
existe (fuite d'information) avant même d'être refusé.
