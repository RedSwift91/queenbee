"""Jour 3 — revue de sécurité en laboratoire : preuves des failles 1, 5, 6 et 7 (groupe).

Les preuves des failles 2, 3 et 4 sont fournies dans test_lab_vulnerable.py. Chaque test PROUVE la
faille ; une fois la faille corrigée, il est inversé pour devenir un test de non-régression.
"""

import inspect

import pytest

from labs import vulnerable_queenbee as vuln

pytestmark = pytest.mark.lab


def test_faille1_hardcoded_shared_secret_grants_access() -> None:
    # La clé est écrite dans le code, donc dans Git : quiconque lit le dépôt obtient l'accès.
    assert "qb-admin-2026" in inspect.getsource(vuln)
    assert vuln.check_token("qb-admin-2026")


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

    vuln.check_token(SpyToken("qb-admin-2025"))
    assert compared  # la clé a bien été comparée avec « == »
