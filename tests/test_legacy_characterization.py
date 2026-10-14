"""J1-A2 — tests de caractérisation : le filet posé AVANT de refactorer legacy/log_watcher.py.

Ils décrivent ce que fait le script hérité aujourd'hui (pas ce qu'il devrait faire) :
5 échecs depuis la même IP déclenchent une alerte, une seule.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from types import ModuleType

import pytest

FAILED = "Oct 14 09:00:00 host sshd[42]: Failed password for {user} from {ip}\n"


@pytest.fixture
def legacy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.chdir(tmp_path)  # l'import crée incidents.db dans le dossier courant
    from legacy import log_watcher  # noqa: PLC0415

    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE incidents (ip TEXT, user TEXT)")
    monkeypatch.setattr(log_watcher, "DB", db)
    return log_watcher


def _run(legacy: ModuleType, tmp_path: Path, lines: list[str]) -> list[str]:
    log = tmp_path / "auth.log"
    log.write_text("".join(lines), encoding="utf-8")
    alerts: list[str] = []
    watcher = legacy.LogWatcher(str(log))
    watcher.alert = alerts.append  # pas de SMTP pendant les tests
    watcher.run()
    return alerts


def test_legacy_five_failures_same_ip_raise_one_alert(legacy: ModuleType, tmp_path: Path) -> None:
    lines = [FAILED.format(user="root", ip="10.0.0.66")] * 6
    assert _run(legacy, tmp_path, lines) == ["10.0.0.66"]
    assert legacy.DB.execute("SELECT ip, user FROM incidents").fetchall() == [
        ("10.0.0.66", "root")
    ]


def test_legacy_failures_spread_over_ips_raise_nothing(legacy: ModuleType, tmp_path: Path) -> None:
    lines = [FAILED.format(user="root", ip=f"10.0.0.{n}") for n in range(5)]
    lines += [FAILED.format(user="root", ip="10.0.0.99")] * 4
    assert _run(legacy, tmp_path, lines) == []
