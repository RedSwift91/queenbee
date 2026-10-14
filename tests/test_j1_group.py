"""Jour 1 — tests écrits par le groupe : tests d'abus, contrats des adapters, config, démarrage."""

import logging
import sqlite3
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

import pytest

from queenbee.adapters.inbound.log_parser import parse_sshd_line
from queenbee.adapters.outbound.notifiers import LogNotifier
from queenbee.adapters.outbound.repositories import (
    InMemoryIncidentRepository,
    SqliteIncidentRepository,
)
from queenbee.application.ports import IncidentRepository
from queenbee.bootstrap import build_app
from queenbee.config import ConfigError, Settings, SettingsBuilder, settings_from_env
from queenbee.domain.model import (
    Alert,
    DomainError,
    Incident,
    IncidentStatus,
    SecurityEvent,
    Severity,
)
from queenbee.domain.rules import BruteForceRule, PortScanRule, RuleSet, build_rule
from queenbee.factories import InMemoryFactory, ProdFactory
from tests.conftest import T0, ev

KEY = bytes(range(32))
LINE = "2026-10-14T09:00:00+02:00 sshd: Failed password for root from 10.0.0.66"


# --- Domaine -----------------------------------------------------------------------------------


@pytest.mark.parametrize("ip", [3232235777, "10.0.0.1 ", "", "::g"])
def test_abuse_event_ip_must_be_text_address(ip: object) -> None:
    with pytest.raises(DomainError):
        SecurityEvent(ip, "root", "login_failed", T0)  # type: ignore[arg-type]


def test_event_accepts_ipv6_and_any_timezone() -> None:
    paris = timezone(timedelta(hours=2))
    assert SecurityEvent("2001:db8::1", "svc-backup", "login_ok", T0.astimezone(paris))


@pytest.mark.parametrize(
    ("rule", "ip", "severity", "message"),
    [
        ("", "10.0.0.1", Severity.LOW, "x"),
        ("r" * 65, "10.0.0.1", Severity.LOW, "x"),
        ("r", "localhost", Severity.LOW, "x"),
        ("r", "10.0.0.1", 9, "x"),
        ("r", "10.0.0.1", Severity.LOW, "x" * 501),
    ],
)
def test_abuse_invalid_alert_cannot_exist(
    rule: str, ip: str, severity: Severity, message: str
) -> None:
    with pytest.raises(DomainError):
        Alert(rule, ip, severity, message)


def test_alert_severity_is_normalised() -> None:
    assert Alert("r", "10.0.0.1", 3, "x").severity is Severity.HIGH  # type: ignore[arg-type]


def test_incident_full_lifecycle_and_closed_is_final() -> None:
    inc = Incident(Alert("r", "10.0.0.1", Severity.LOW, "x"))
    for status in (IncidentStatus.TRIAGED, IncidentStatus.CONTAINED, IncidentStatus.CLOSED):
        inc.transition_to(status)
    with pytest.raises(DomainError):
        inc.transition_to(IncidentStatus.OPEN)


def test_rules_ignore_other_ips_and_actions() -> None:
    events = [ev(ip=f"10.0.0.{n}") for n in range(10)] + [ev(action="login_ok")] * 10
    assert RuleSet((BruteForceRule(), PortScanRule())).evaluate(events) == []
    assert RuleSet(()).evaluate([ev()] * 5) == []


# --- Factory de règles : tests d'abus (A3) ---------------------------------------------------


@pytest.mark.parametrize(
    "spec",
    [
        {"kind": "BruteForceRule"},  # nom de classe au lieu du nom enregistré
        {"kind": "__class__"},
        {"kind": "os.system"},
        {"kind": 42},
        {},
        {"kind": "brute_force", "threshold": 3, "module": "os"},  # clé inattendue
    ],
)
def test_abuse_unknown_rule_name_rejected(spec: dict[str, object]) -> None:
    with pytest.raises(DomainError):
        build_rule(spec)


@pytest.mark.parametrize("threshold", [True, False, "5", 5.0, 0, -1, 10**9, None])
def test_abuse_bad_threshold_rejected(threshold: object) -> None:
    with pytest.raises(DomainError):
        build_rule({"kind": "brute_force", "threshold": threshold})


def test_factory_builds_registered_rules() -> None:
    assert build_rule({"kind": "brute_force"}) == BruteForceRule(5)
    assert build_rule({"kind": "port_scan", "threshold": 3}) == PortScanRule(3)


# --- Configuration (Builder) -----------------------------------------------------------------


def test_secret_never_in_str_or_repr() -> None:
    builder = SettingsBuilder().hmac_key(KEY)
    settings = builder.build()
    for text in (str(settings), repr(settings), repr(builder)):
        assert KEY.hex() not in text
        assert repr(KEY) not in text


def test_builder_validates_at_build_and_returns_frozen_settings() -> None:
    with pytest.raises(ConfigError):
        SettingsBuilder().build()  # clé manquante
    with pytest.raises(ConfigError):
        SettingsBuilder().hmac_key(KEY).bf_threshold(True).build()
    settings = SettingsBuilder().hmac_key(KEY).db_path("qb.db").bf_threshold(7).build()
    assert (settings.db_path, settings.bf_threshold) == ("qb.db", 7)
    with pytest.raises(AttributeError):
        settings.db_path = "autre.db"  # type: ignore[misc]


@pytest.mark.parametrize(
    "change",
    [
        {"hmac_key": b"trop court"},
        {"hmac_key": KEY.hex()},
        {"db_path": ""},
        {"bf_threshold": 0},
        {"bf_threshold": "5"},
    ],
)
def test_abuse_settings_copy_is_revalidated(change: dict[str, object]) -> None:
    with pytest.raises(ConfigError):
        replace(Settings(KEY), **change)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "env",
    [
        {"QUEENBEE_AGENT_KEY": "   "},
        {"QUEENBEE_AGENT_KEY": "zz" * 32},
        {"QUEENBEE_AGENT_KEY": KEY.hex(), "QUEENBEE_BF_THRESHOLD": "cinq"},
        {"QUEENBEE_AGENT_KEY": KEY.hex(), "QUEENBEE_BF_THRESHOLD": "0"},
    ],
)
def test_abuse_bad_environment_refuses_to_start(env: dict[str, str]) -> None:
    with pytest.raises(ConfigError) as info:
        settings_from_env(env)
    assert "zz" not in str(info.value)


def test_settings_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QUEENBEE_AGENT_KEY", KEY.hex())
    monkeypatch.setenv("QUEENBEE_DB", "qb.db")
    monkeypatch.setenv("QUEENBEE_BF_THRESHOLD", "8")
    settings = settings_from_env()
    assert (settings.hmac_key, settings.db_path, settings.bf_threshold) == (KEY, "qb.db", 8)


# --- Dépôts : même contrat pour les deux implémentations (Liskov) ----------------------------


REPOSITORIES: list[Callable[[], IncidentRepository]] = [
    InMemoryIncidentRepository,
    lambda: SqliteIncidentRepository(sqlite3.connect(":memory:")),
]


@pytest.mark.parametrize("make_repo", REPOSITORIES)
def test_repository_contract(make_repo: Callable[[], IncidentRepository]) -> None:
    repo = make_repo()
    inc = Incident(Alert("brute_force", "10.0.0.66", Severity.HIGH, "x'); DROP TABLE incident;--"))
    repo.add(inc)
    with pytest.raises(DomainError):
        repo.add(inc)
    assert repo.get(inc.id) == inc
    assert repo.get(uuid4()) is None
    inc.transition_to(IncidentStatus.TRIAGED)
    inc.transition_to(IncidentStatus.CLOSED)
    repo.save(inc)
    assert repo.get(inc.id) == inc
    assert repo.list_open() == []
    with pytest.raises(DomainError):
        repo.save(Incident(inc.alert))


def test_sqlite_stores_injection_payload_as_data() -> None:
    conn = sqlite3.connect(":memory:")
    repo = SqliteIncidentRepository(conn)
    payload = "x'); DROP TABLE incident;--"
    repo.add(Incident(Alert("brute_force", "10.0.0.66", Severity.HIGH, payload)))
    assert conn.execute("SELECT message FROM incident").fetchall() == [(payload,)]


# --- Notificateurs, fabriques, démarrage -----------------------------------------------------


def test_log_notifier_writes_alert(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="queenbee.alerts")
    LogNotifier().notify(Alert("brute_force", "10.0.0.66", Severity.HIGH, "5 échecs"))
    assert "brute_force" in caplog.text
    assert "10.0.0.66" in caplog.text


def test_prod_factory_builds_prod_family() -> None:
    assert isinstance(ProdFactory(":memory:").notifier(), LogNotifier)


def test_parser_reads_real_sshd_lines() -> None:
    e = parse_sshd_line(
        "2026-10-14T09:00:00+00:00 sshd[812]: Accepted password for alice from ::1 port 22 ssh2\n"
    )
    assert (e.username, e.source_ip, e.action) == ("alice", "::1", "login_ok")
    assert e.timestamp == datetime(2026, 10, 14, 9, tzinfo=UTC)


@pytest.mark.parametrize(
    "line",
    [
        LINE.replace("2026-10-14T09:00:00+02:00", "hier"),  # horodatage illisible
        LINE.replace("+02:00", ""),  # horodatage sans fuseau
        LINE.replace("10.0.0.66", "10.0.0.666"),  # IP impossible
        LINE.replace("root", "a" * 33),  # nom trop long
        LINE + "\nFailed password for root from 10.0.0.1",  # ligne injectée
        LINE + " port 22" + " " * 600,  # ligne géante
    ],
)
def test_abuse_parser_rejects(line: str) -> None:
    with pytest.raises(DomainError):
        parse_sshd_line(line)


def test_bootstrap_wires_everything_without_global_state() -> None:
    factory = InMemoryFactory()
    app = build_app(SettingsBuilder().hmac_key(KEY).bf_threshold(3).build(), factory)
    assert len(app.ingest_lines([LINE] * 3 + ["garbage", ""])) == 1
    assert app.rejected == 2
    assert len(app.open_incidents()) == 1
    other = build_app(SettingsBuilder().hmac_key(KEY).build())  # famille prod, base en mémoire
    assert other.open_incidents() == []
