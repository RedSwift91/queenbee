"""Jour 3 — démonstrations d'exploitation SUR LA VARIANTE DE LABORATOIRE (labs/).

Chaque test PROUVE la faille. Après correction, l'étudiant inverse l'assertion.
Les tests nommés « _corrigee_ » ont été inversés : ils prouvent désormais que l'attaque échoue.
"""

import pickle
import time

import pytest

from labs import vulnerable_queenbee as vuln
from queenbee.domain.model import DomainError

pytestmark = pytest.mark.lab


def test_faille3_corrigee_pickle_payload_is_refused(capsys: pytest.CaptureFixture[str]) -> None:
    class Payload:  # charge utile INOFFENSIVE : un simple print
        def __reduce__(self) -> tuple[object, tuple[str]]:
            return (print, ("PWNED: code exécuté pendant la désérialisation",))

    # Preuve d'origine : la lecture affichait « PWNED », du code avait été exécuté.
    with pytest.raises(DomainError):
        vuln.receive_agent_message(pickle.dumps(Payload()))
    assert "PWNED" not in capsys.readouterr().out  # aucun code exécuté


def test_faille3_corrigee_valid_json_message_is_accepted() -> None:
    body = (
        b'{"source_ip": "10.0.0.66", "username": "root", "action": "login_failed", '
        b'"timestamp": "2026-10-16T09:00:00+00:00"}'
    )
    assert vuln.receive_agent_message(body)["username"] == "root"
    with pytest.raises(DomainError):
        vuln.receive_agent_message(body.replace(b'"root"', b'"root", "is_admin": "true"'))


def test_faille2_corrigee_redos_cost_stays_linear() -> None:
    # Preuve d'origine : assert cost(22) > 4 * cost(18), le temps explosait avec la longueur.
    start = time.perf_counter()
    for n in (18, 22, 10_000):
        for _ in range(1_000):
            assert not vuln.is_valid_username("a" * n + "!")
    assert time.perf_counter() - start < 0.5  # 3 000 entrées piégées, même très longues
    assert vuln.is_valid_username("jean dupont")  # les noms légitimes passent toujours


def test_faille4_corrigee_sql_injection_returns_nothing() -> None:
    vuln.conn.execute("INSERT INTO incident (ip, status) VALUES ('10.0.0.1', 'open')")
    # Preuve d'origine : « x' OR '1'='1 » renvoyait TOUTES les lignes de la table.
    assert vuln.find_incidents("x' OR '1'='1") == []
    assert vuln.find_incidents("10.0.0.1")  # une vraie recherche fonctionne toujours
