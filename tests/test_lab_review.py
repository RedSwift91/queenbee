"""Jour 3 — revue de sécurité en laboratoire : preuves des failles 1, 5, 6 et 7 (groupe).

Les preuves des failles 2, 3 et 4 sont fournies dans test_lab_vulnerable.py. Chaque test PROUVE la
faille ; une fois la faille corrigée, il est inversé pour devenir un test de non-régression.
"""

import inspect

import pytest

from labs import vulnerable_queenbee as vuln
from queenbee.domain.model import DomainError

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


def test_faille5_anyone_can_close_an_incident() -> None:
    cur = vuln.conn.execute("INSERT INTO incident (ip, status) VALUES ('10.0.0.5', 'open')")
    vuln.close_incident("mallory", cur.lastrowid)  # un simple lecteur, sans aucun rôle
    status = vuln.conn.execute("SELECT status FROM incident WHERE id = ?", (cur.lastrowid,))
    assert status.fetchone() == ("closed",)


def test_faille6_inter_service_call_is_not_authenticated() -> None:
    # Aucun secret n'est présenté ni vérifié : n'importe qui peut appeler le service, et
    # n'importe qui peut se faire passer pour lui.
    assert list(inspect.signature(vuln.call_enrichment_service).parameters) == ["ip"]
    assert vuln.call_enrichment_service("10.0.0.1")["reputation"] == "unknown"


def test_faille7_token_comparison_is_not_constant_time() -> None:
    compared: list[object] = []

    class SpyToken(str):
        __hash__ = str.__hash__

        def __eq__(self, other: object) -> bool:
            compared.append(other)  # « == » s'arrête au premier caractère différent :
            return str.__eq__(self, other)  # son temps de réponse révèle la clé

    vuln.check_token(SpyToken(KEY_B), KEY_A)
    assert compared  # la clé a bien été comparée avec « == »
