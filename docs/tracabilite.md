# Traçabilité exigence ↔ test

Chaque exigence de sécurité et chaque faille corrigée est reliée au test qui en apporte la preuve.
Tous les tests ci-dessous sont **verts** au rendu `j3-rendu` (`python -m pytest`, 145 tests ;
`python -m pytest -m lab`, 14 tests).

## Exigences du modèle de menaces

| Exigence | Résumé | Menace | Test(s) de preuve |
|---|---|---|---|
| EX-01 | Message d'agent authentifié (HMAC-SHA256, temps constant) | S · TB1 | `tests/test_adapters.py::test_abuse_forged_signature_rejected` · `tests/test_j2_group.py::test_abuse_bad_signature_rejected` |
| EX-02 | Ligne piégée rejetée ; 1 000 lignes en moins d'1 s ; ligne ≤ 512 caractères | D · TB1 | `tests/test_adapters.py::test_parser_is_fast_on_adversarial_input` · `tests/test_adapters.py::test_malicious_lines_rejected` · `tests/test_j1_group.py::test_abuse_parser_rejects` |
| EX-03 | Événement invalide impossible à construire, puis non modifiable | T · TB1 | `tests/test_domain.py::test_invalid_event_cannot_exist` · `tests/test_domain.py::test_event_is_immutable` · `tests/test_domain.py::test_naive_timestamp_rejected` |
| EX-04 | Requêtes SQL paramétrées | T, I · TB2 | `tests/test_j1_group.py::test_sqlite_stores_injection_payload_as_data` · `tests/test_services.py::test_sqlite_repo_resists_injection` |
| EX-05 | Clé jamais affichée ; refus de démarrer sans clé de 32 octets | I · TB6 | `tests/test_j1_group.py::test_secret_never_in_str_or_repr` · `tests/test_adapters.py::test_secret_never_printed` · `tests/test_adapters.py::test_missing_secret_refuses_to_start` |
| EX-06 | Un non-analyste ne change pas le statut d'un incident | E · TB4 | `tests/test_services.py::test_abuse_viewer_cannot_close_incident` · `tests/test_j2_group.py::test_abuse_viewer_can_read_but_not_write_through_proxy` |
| EX-07 | Pas de clôture sans triage ; chaque alerte auditée | R · TB4, TB5 | `tests/test_domain.py::test_state_forbids_skipping_triage` · `tests/test_services.py::test_audit_decorator_logs` · `tests/test_j2_group.py::test_analyst_move_is_audited` |
| EX-08 | Règles créées uniquement depuis le registre, seuil entier borné | T, E · TB6 | `tests/test_domain.py::test_factory_rejects_unknown_rule` · `tests/test_j1_group.py::test_abuse_unknown_rule_name_rejected` · `tests/test_j1_group.py::test_abuse_bad_threshold_rejected` |
| EX-09 | Flux de menaces traduit et validé par la couche anti-corruption | T · TB7 | `tests/test_adapters.py::test_anti_corruption_layer_translates_and_rejects` · `tests/test_j2_group.py::test_abuse_threat_feed_rejects` |

## Failles de la variante de laboratoire

| Faille | Preuve d'origine (avant correction) | Test inversé (non-régression) | ADR |
|---|---|---|---|
| 1 · secret en dur partagé | la clé `qb-admin-2026` figurait dans le code et donnait l'accès | `tests/test_lab_review.py::test_faille1_corrigee_no_hardcoded_secret_one_key_per_service` · `test_faille1_corrigee_missing_or_short_key_refuses_to_start` | 0002 |
| 2 · ReDoS | `cost(22) > 4 * cost(18)` | `tests/test_lab_vulnerable.py::test_faille2_corrigee_redos_cost_stays_linear` | 0003 |
| 3 · pickle | la lecture affichait « PWNED » | `tests/test_lab_vulnerable.py::test_faille3_corrigee_pickle_payload_is_refused` · `test_faille3_corrigee_valid_json_message_is_accepted` | 0004 |
| 4 · SQL par f-string | `x' OR '1'='1` renvoyait toute la table | `tests/test_lab_vulnerable.py::test_faille4_corrigee_sql_injection_returns_nothing` | 0005 |
| 5 · pas d'autorisation | « mallory » closait un incident | `tests/test_lab_review.py::test_faille5_corrigee_viewer_cannot_close_an_incident` | 0006 |
| 6 · services non authentifiés | appel sans aucun secret | `tests/test_lab_review.py::test_faille6_corrigee_unknown_client_is_refused` · `test_faille6_corrigee_impostor_service_is_refused` · `test_faille6_corrigee_mutual_authentication_between_services` · `test_faille6_corrigee_ip_is_validated` | 0007 |
| 7 · comparaison non constante | le jeton passait par `==` | `tests/test_lab_review.py::test_faille7_corrigee_token_is_compared_in_constant_time` | 0008 |

## Exigences d'architecture

| Exigence | Preuve |
|---|---|
| Les couches ne s'inversent pas (domaine sans dépendance technique) | `lint-imports` → 1 kept, 0 broken |
| Les deux dépôts respectent le même contrat | `tests/test_j1_group.py::test_repository_contract` |
| Le service fonctionne avec n'importe quelle famille d'adapters | `tests/test_creational.py::test_service_runs_with_any_family` |
| Parcours complet, de l'attaque à la clôture | `tests/test_j2_group.py::test_facade_full_journey_from_signed_messages_to_closed_incident` |
