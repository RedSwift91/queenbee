"""Jour 3 — revue de sécurité en laboratoire : preuves des failles 1, 5, 6 et 7 (groupe).

Les preuves des failles 2, 3 et 4 sont fournies dans test_lab_vulnerable.py. Chaque test PROUVE la
faille ; une fois la faille corrigée, il est inversé pour devenir un test de non-régression.
"""

import inspect
from collections.abc import Mapping

import pytest

from labs import vulnerable_queenbee as vuln
from queenbee.application.access import AccessDeniedError
from queenbee.domain.model import DomainError, Principal

pytestmark = pytest.mark.lab


KEY_A, KEY_B = "a" * 64, "b" * 64


def test_faille1_corrigee_no_hardcoded_secret_one_key_per_service() -> None:
    # Avant : la clé « qb-admin-2026 » était écrite dans le code et donnait l'accès à tous.
    assert "qb-admin-2026" not in inspect.getsource(vuln)
    env = {"QUEENBEE_INGEST_KEY": KEY_A, "QUEENBEE_ENRICH_KEY": KEY_B}
    ingest, enrich = vuln.load_service_key("ingest", env), vuln.load_service_key("enrich", env)
    assert ingest != enrich  # une clé par service : en voler une n'ouvre pas les autres
    assert not vuln.check_token("qb-admin-2026", ingest)


@pytest.mark.parametrize("env", [{}, {"QUEENBEE_INGEST_KEY": ""}, {"QUEENBEE_INGEST_KEY": "court"}])
def test_faille1_corrigee_missing_or_short_key_refuses_to_start(env: dict[str, str]) -> None:
    with pytest.raises(DomainError):
        vuln.load_service_key("ingest", env)  # aucune valeur par défaut


def _status(incident_id: int) -> str:
    row = vuln.conn.execute("SELECT status FROM incident WHERE id = ?", (incident_id,)).fetchone()
    return str(row[0])


def test_faille5_corrigee_viewer_cannot_close_an_incident() -> None:
    cur = vuln.conn.execute("INSERT INTO incident (ip, status) VALUES ('10.0.0.5', 'open')")
    assert cur.lastrowid is not None
    # Preuve d'origine : close_incident("mallory", id) passait l'incident à « closed ».
    for intruder in (Principal("mallory", frozenset({"viewer"})), Principal("guest")):
        with pytest.raises(AccessDeniedError):
            vuln.close_incident(intruder, cur.lastrowid)
    assert _status(cur.lastrowid) == "open"  # aucun effet de bord
    vuln.close_incident(Principal("alice", frozenset({"analyst"})), cur.lastrowid)
    assert _status(cur.lastrowid) == "closed"


def _real_service(request: Mapping[str, str]) -> Mapping[str, str]:
    return vuln.enrichment_service(request, KEY_A)


def test_faille6_corrigee_mutual_authentication_between_services() -> None:
    # Preuve d'origine : call_enrichment_service(ip) n'attendait et ne vérifiait aucun secret.
    assert vuln.call_enrichment_service("10.0.0.1", KEY_A, _real_service)["reputation"] == "unknown"


def test_faille6_corrigee_unknown_client_is_refused() -> None:
    with pytest.raises(vuln.UnauthenticatedError):  # le client n'a pas la bonne clé
        vuln.call_enrichment_service("10.0.0.1", KEY_B, _real_service)
    with pytest.raises(vuln.UnauthenticatedError):  # requête sans aucune signature
        vuln.enrichment_service({"ip": "10.0.0.1"}, KEY_A)


def test_faille6_corrigee_impostor_service_is_refused() -> None:
    def impostor(request: Mapping[str, str]) -> Mapping[str, str]:
        return {"ip": request["ip"], "reputation": "clean"}  # réponse forgée, non signée

    with pytest.raises(vuln.UnauthenticatedError):
        vuln.call_enrichment_service("10.0.0.1", KEY_A, impostor)


def test_faille6_corrigee_ip_is_validated() -> None:
    with pytest.raises(ValueError, match="does not appear"):
        vuln.call_enrichment_service("10.0.0.1; rm -rf /", KEY_A, _real_service)


def test_faille7_corrigee_token_is_compared_in_constant_time() -> None:
    compared: list[object] = []

    class SpyToken(str):
        __hash__ = str.__hash__

        def __eq__(self, other: object) -> bool:
            compared.append(other)  # « == » s'arrête au premier caractère différent :
            return str.__eq__(self, other)  # son temps de réponse révèle la clé

    # Preuve d'origine : « compared » n'était pas vide, la clé passait par « == ».
    assert not vuln.check_token(SpyToken(KEY_B), KEY_A)
    assert compared == []  # hmac.compare_digest ne s'arrête jamais en route
    assert vuln.check_token(KEY_A, KEY_A)
    assert not vuln.check_token(None, KEY_A)  # type: ignore[arg-type]
