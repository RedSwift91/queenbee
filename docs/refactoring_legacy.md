# Refactoring de `legacy/log_watcher.py` (J1 · A2)

Filet posé avant de toucher au code : `tests/test_legacy_characterization.py`
(5 échecs depuis la même IP = une alerte, une seule ; des échecs répartis sur plusieurs IP = aucune).

## Relevé des problèmes

| Ligne | Problème (SOLID / sécurité) | Conséquence | Correction dans `src/queenbee/` |
|---|---|---|---|
| 10 | Sécurité : secret SMTP écrit en dur, versionné | toute personne qui lit le dépôt (ou son historique) a le mot de passe | secret lu dans l'environnement, refus de démarrer s'il manque (`config.settings_from_env`), `repr=False` |
| 11 | DIP + état global : connexion SQLite créée à l'import | effet de bord à l'import, impossible de tester sans vraie base, objet partagé par tout le monde (Singleton de fait) | port `IncidentRepository` reçu par le constructeur de `DetectionService` ; création dans `bootstrap.build_app` |
| 13 | SRP : *God class* qui lit, parse, compte, détecte, stocke, alerte et formate | chaque changement (format de log, base, canal d'alerte) touche la même classe | `log_parser` (entrée) · `SecurityEvent` (domaine) · `BruteForceRule` (règle) · `DetectionService` (cas d'usage) · repositories et notifiers (sortie) |
| 19 | Sécurité (D) : fichier jamais fermé, aucune limite de taille de ligne | fuite de descripteurs ; une ligne géante consomme mémoire et CPU | lignes bornées à 512 caractères avant toute regex (`parse_sshd_line`) |
| 20 | Sécurité : regex `.*` gourmande et non ancrée | `user` et `ip` acceptent n'importe quoi (espaces, quotes, `<script>`, `OR 1=1`) | regex ancrée (`fullmatch`), classes de caractères bornées, puis validation par le domaine |
| 22 | Sécurité (T) : aucune validation des données issues du log | des données de l'attaquant circulent telles quelles jusqu'à la base et au mail | `SecurityEvent` figé et validé à la construction : IP réelle, nom en allowlist, action en allowlist, horodatage avec fuseau |
| 24 | OCP : seuil `5` codé en dur, une seule règle possible | ajouter une détection = modifier la classe | stratégie `DetectionRule`, seuil paramétrable et validé, composite `RuleSet`, fabrique `build_rule` |
| 26 | Sécurité : injection SQL par f-string avec `ip` et `user` venant du log | lecture/destruction de la base par une simple ligne de log | requêtes paramétrées (`?`) dans `SqliteIncidentRepository` |
| 26 | Bug : la table `incidents` n'est jamais créée | le script plante à la 5ᵉ tentative, donc aucune alerte en conditions réelles | schéma créé par le repository |
| 30 | DIP : `smtplib.SMTP` instancié dans la méthode | impossible de tester ou de changer de canal | port `Notifier` (`MemoryNotifier`, `LogNotifier`) |
| 34 | OCP : `if/elif` par format de rapport | chaque nouveau format modifie la méthode | hors périmètre J1 (un formateur par classe si besoin) |
| 38 | Sécurité : rapport HTML sans échappement | XSS si un nom ou une IP contient du HTML | les données sont validées à l'entrée ; tout rendu HTML devra échapper (`html.escape`) |

## Ordre des commits

1. `test:` caractérisation du script hérité
2. `refactor:` extraction du domaine, des règles, des ports et des adapters (même comportement)
3. `fix:` corrections, une par commit : SQL paramétré, secret lu dans l'environnement, regex ancrée
