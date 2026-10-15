# ADR 0001 — Monolithe en architecture hexagonale (ports et adapters)

- **Statut** : accepté — 15 octobre 2026
- **Décideurs** : groupe Queen Bee (noms à compléter : …)

## Contexte

Queen Bee reçoit des données **non fiables** : les lignes de journal sshd (dont le contenu,
comme le nom d'utilisateur, est choisi par l'attaquant), les messages des agents (un agent peut être
compromis) et un flux de menaces externe. Il écrit dans une base d'incidents, alerte le SOC et peut
bloquer des IP sur un pare-feu.

Le script hérité (`legacy/log_watcher.py`) mélangeait tout dans une classe : lecture, détection,
SQL par f-string, mot de passe en dur, envoi de mail. Impossible à tester sans vraie base et vrai
serveur mail, et chaque correction de sécurité touchait tout le reste.

Contraintes : quelques milliers d'événements par heure, une équipe de 3 à 4 personnes, un rendu
par jour pendant 3 jours, des tests qui doivent tourner sans infrastructure.

## Décision

Un **seul processus**, organisé en **architecture hexagonale** : un domaine sans dépendance
technique au centre, des cas d'usage qui dépendent de ports (`typing.Protocol`), et des adapters à
l'extérieur qui valident toute entrée. Le sens des dépendances est vérifié par `import-linter`.

## Alternatives écartées

1. **Microservices** (ingestion, détection, incidents, notification séparés). Écartée : chaque lien
   entre services devient une frontière réseau à authentifier (risque d'appel non authentifié,
   cf. FAILLE-6 dans `labs/`), avec un secret de plus par lien. Surdimensionné pour notre volume et
   notre équipe. Détail dans `docs/comparaison_architectures.md`.
2. **Monolithe en couches classique, sans ports** (la logique appelle directement `sqlite3` et
   `smtplib`). Écartée : le métier dépend de la technique, donc impossible de tester sans vraie base,
   et rien n'empêche une couche d'appeler n'importe quelle autre.
3. **Garder le script en le corrigeant sur place.** Écartée : les failles sont liées à la structure
   (une classe qui fait tout) ; les corriger une à une ne règle pas le problème de fond.

## Conséquences

**Positives**

- Le domaine est testable seul : 134 tests en moins d'1 seconde, sans base ni réseau.
- Chaque entrée non fiable passe par un adapter qui la borne et la valide, puis par le domaine qui
  la revalide : deux contrôles successifs.
- Changer de base ou de canal d'alerte ne touche qu'un adapter.
- L'architecture ne peut pas se dégrader en silence : `lint-imports` fait échouer la chaîne.

**Négatives (assumées)**

- **Plus de fichiers et d'indirections** : pour suivre une alerte, il faut passer par le parser,
  le service, le port et l'adapter. Plus long à lire pour un nouveau venu que l'ancien script.
- **Duplication de validations** : l'adapter et le domaine vérifient tous deux certaines données
  (par exemple l'IP), ce qui fait du code en plus à maintenir.
- **Un seul processus = un seul point de défaillance** : si Queen Bee plante, la détection s'arrête
  entièrement. Aucune isolation non plus entre couches : une faille dans un adapter donne accès au
  processus entier.
- **Pas de passage à l'échelle horizontal** sans travail supplémentaire, si le volume explose.
- Le pare-feu n'a pour l'instant qu'un adapter **en mémoire** ; un adapter réel reste à écrire.

## Menaces STRIDE traitées

| Lettre | Propriété DICP | Mécanisme |
|---|---|---|
| **S** | Intégrité (authenticité) | adapter `parse_agent_message` : HMAC-SHA256, comparaison en temps constant |
| **T** | Intégrité | objets du domaine figés et validés à la construction ; SQL paramétré dans l'adapter SQLite ; schéma strict |
| **R** | Preuve | décorateur `AuditedNotifier` et audit des changements d'état dans `IncidentService` |
| **I** | Confidentialité | secret lu une seule fois dans `config.py`, jamais affiché (`repr=False`) ; Proxy de lecture |
| **D** | Disponibilité | tailles bornées dans les adapters d'entrée ; décorateur `RateLimitedNotifier` |
| **E** | Intégrité | contrôle du rôle en première étape du cas d'usage `IncidentService.move` |

## Preuve

- Contrat d'architecture : `lint-imports` → `1 kept, 0 broken`
- `tests/test_creational.py::test_service_runs_with_any_family` (le service tourne avec n'importe quelle famille d'adapters)
- `tests/test_j1_group.py::test_repository_contract` (les deux dépôts respectent le même port)
- `tests/test_adapters.py::test_abuse_forged_signature_rejected`, `test_abuse_extra_field_rejected`
- `tests/test_services.py::test_abuse_viewer_cannot_close_incident`, `test_sqlite_repo_resists_injection`
- `tests/test_j2_group.py::test_facade_full_journey_from_signed_messages_to_closed_incident`
