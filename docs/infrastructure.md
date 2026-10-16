# Infrastructure cible (J3 · A2)

Schéma des zones : `docs/uml/c4_container.puml` (rendu : `docs/uml/c4_container.png`).
Principe directeur : **refus par défaut**. Un flux n'existe que s'il est justifié par un élément
de l'architecture ; un composant n'existe que s'il a au moins un flux.

## 1. Zones

Une zone par niveau de confiance, plus une zone sécurité et une zone d'administration.

| Zone | Niveau de confiance | Contenu | Pourquoi une zone à part |
|---|---|---|---|
| **Z0** · non fiable | aucun | agents sur les hôtes surveillés, fournisseur de flux de menaces, Internet | les données y sont écrites par l'attaquant ou un tiers (TB1, TB7) |
| **Z1** · DMZ d'ingestion | faible | API d'ingestion, proxy sortant | seule zone exposée ; une compromission ici ne donne accès ni aux données ni aux secrets |
| **Z2** · applicative | moyen | cœur Queen Bee (détection, incidents, API des analystes), service d'enrichissement | logique métier ; n'accepte que des flux authentifiés venant de Z1 et des analystes |
| **Z3** · données | élevé | base des incidents | aucune entrée directe depuis Z0 ou Z1 (TB2) |
| **Z4** · sécurité | élevé | collecteur de journaux / SIEM, sauvegardes | doit survivre à la compromission de l'application : l'application y écrit, mais ne peut ni lire ni effacer |
| **Z5** · administration | élevé | bastion, coffre à secrets | seul chemin d'administration ; sessions enregistrées |

## 2. Matrice des flux

| Flux | Source → Destination | Protocole / port | Justifié par (élément d'architecture) | STRIDE |
|---|---|---|---|---|
| F1 | Agents (Z0) → API d'ingestion (Z1) | HTTPS 443, TLS 1.3 | port d'entrée `parse_agent_message` (taille, HMAC, schéma) | S, T, D |
| F2 | API d'ingestion (Z1) → Cœur (Z2) | HTTPS 8443, mTLS | cas d'usage `DetectionService.ingest` | S, T |
| F3 | Cœur (Z2) → Base des incidents (Z3) | SQL 5432, TLS | port `IncidentRepository` (adapter SQL, requêtes paramétrées) | T, I |
| F4 | Analystes (poste interne) → Cœur (Z2) | HTTPS 443 + MFA | `IncidentService.move`, `IncidentReadProxy` | S, E, R |
| F5 | Cœur (Z2) → Service d'enrichissement (Z2) | HTTPS 8444, requête et réponse signées | `call_enrichment_service` (ADR 0007) | S, T |
| F6a | Cœur (Z2) → Proxy sortant (Z1) | HTTPS 3128 | `ThreatFeedTranslator` (couche anti-corruption, TB7) | S, T |
| F6b | Proxy sortant (Z1) → Fournisseur de flux (Z0) | HTTPS 443, domaine du fournisseur seul | idem | S, T |
| F7 | Cœur (Z2) → Pare-feu périmétrique | HTTPS 443, compte limité à bloquer / débloquer | port `Firewall`, `BlockIpCommand` | T, E, R |
| F8 | Cœur (Z2) → Messagerie du SOC | SMTP 587, STARTTLS | port `Notifier` (`RateLimitedNotifier`, `AuditedNotifier`) | D, I |
| F9 | Cœur, API, enrichissement → Collecteur de journaux (Z4) | syslog 6514, TLS, écriture seule | journal `queenbee.audit` (ADR 0010) | R, T |
| F10 | Sauvegardes (Z4) → Base des incidents (Z3) | TLS, compte en lecture seule | sauvegarde tirée depuis Z4 (ADR 0012) | D, R |
| F11a | Administrateur → Bastion (Z5) | SSH 22 + MFA | administration (ADR 0009) | S, E, R |
| F11b | Bastion (Z5) → Cœur, API, base | SSH 22 | maintenance, sessions enregistrées | E, R |
| F12 | Cœur, API, enrichissement → Coffre à secrets (Z5) | HTTPS 8200, mTLS | `settings_from_env` / `load_service_key` au démarrage (ADR 0011) | S, I |
| — | **tout le reste** | — | **refusé (refus par défaut)** | — |

Les flux sont **à sens unique** : la flèche indique qui ouvre la connexion. La sauvegarde est
*tirée* depuis Z4 (F10) : la base ne connaît aucun identifiant de la zone sauvegarde, et une base
compromise ne peut donc pas effacer ses sauvegardes.

## 3. Secrets et identités

| Secret | Où il est stocké | Qui y accède | Rotation |
|---|---|---|---|
| Clé HMAC d'un agent | coffre à secrets (Z5) ; copie sur l'agent | l'agent et l'API d'ingestion, au démarrage | 90 jours ; immédiate si l'agent est compromis |
| Clé du lien cœur ↔ enrichissement | coffre à secrets | ces deux services uniquement (une clé par lien, ADR 0002 et 0007) | 90 jours |
| Certificats mTLS | PKI interne | chaque service possède le sien | automatique, 30 jours |
| Compte de base de données applicatif | coffre à secrets | le cœur ; droits limités aux lectures et écritures d'incidents, sans suppression de table | 90 jours |
| Compte de l'API du pare-feu | coffre à secrets | le cœur ; droits limités à bloquer et débloquer | 90 jours |
| Identifiants SMTP | coffre à secrets | le cœur | 180 jours |
| Comptes des analystes | annuaire de l'entreprise | les analystes, avec MFA | politique de l'entreprise |

Règles : **aucun secret dans le code ni dans Git** (gitleaks en pre-commit et sur l'historique) ;
les secrets sont **injectés au démarrage** et l'application refuse de démarrer s'ils manquent ; ils ne
sont **jamais journalisés** (`repr=False`). Le fichier `.env` sert uniquement au poste de développement.

## 4. Journalisation

| On journalise | On ne journalise jamais |
|---|---|
| qui, quoi, quand, d'où | secrets, clés, jetons, mots de passe |
| chaque alerte émise (`AuditedNotifier`) | contenu complet des messages d'agent |
| chaque changement d'état d'incident, avec l'analyste | données personnelles inutiles à l'enquête |
| chaque refus d'accès (`require`) | |
| chaque rejet d'entrée (compteurs `rejected`, `dropped`, `denied`) | |
| chaque blocage ou déblocage d'IP (`CommandHistory`) | |

**Où partent les journaux** : vers le collecteur de la zone sécurité (F9), en syslog sur TLS. Le
compte de l'application n'y a qu'un droit d'**écriture** : il ne peut ni relire ni effacer. Le
stockage est immuable (WORM) et conservé un an. Une copie locale tampon couvre une coupure réseau.

## 5. Sauvegarde et reprise

| Indicateur | Valeur | Ce que cela impose |
|---|---|---|
| Disponibilité visée | **99,5 %** | au plus 3 h 36 d'arrêt par mois de 30 jours |
| **RPO** (perte de données tolérée) | **15 minutes** | une sauvegarde incrémentale au moins toutes les 15 minutes, plus une complète par nuit |
| **RTO** (durée d'arrêt tolérée) | **4 heures** | une restauration testée et documentée en moins de 4 heures |
| Règle 3-2-1 | 3 copies, 2 supports, 1 hors site | dont une copie **immuable**, hors d'atteinte d'un rançongiciel |

**Scénario de test de reprise (chaque mois)** :
1. Restaurer la dernière sauvegarde dans un environnement isolé, sans accès au réseau de production.
2. Vérifier l'intégrité : nombre d'incidents comparé à la production, statuts cohérents, aucune
   transition interdite dans les données.
3. Démarrer Queen Bee sur la base restaurée et lancer `make check` et un parcours de bout en bout.
4. Mesurer la durée totale (objectif < 4 h) et l'âge de la dernière donnée restaurée
   (objectif < 15 min).
5. Consigner le résultat ; tout écart ouvre une action corrective.

## 6. Décisions d'infrastructure

| ADR | Décision |
|---|---|
| 0009 | Segmentation en zones et refus par défaut |
| 0010 | Journaux centralisés en écriture seule : l'application ne peut pas effacer ses traces |
| 0011 | Secrets dans un coffre, une identité par service, injectés au démarrage |
| 0012 | Sauvegardes 3-2-1 tirées depuis la zone sécurité, RPO 15 min et RTO 4 h |
