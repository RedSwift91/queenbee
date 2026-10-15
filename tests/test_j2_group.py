"""Jour 2 — tests écrits par le groupe : patterns défensifs et entrées malveillantes."""

import json
import logging

import pytest

from queenbee.adapters.inbound.agent_api import (
    MAX_BODY,
    UnauthenticatedError,
    parse_agent_message,
    sign,
)
from queenbee.adapters.inbound.threat_feed import ThreatFeedTranslator
from queenbee.adapters.outbound.notifiers import (
    AlertBroadcaster,
    MemoryNotifier,
    RateLimitedNotifier,
)
from queenbee.adapters.outbound.repositories import InMemoryIncidentRepository
from queenbee.adapters.outbound.response import BlockIpCommand, CommandHistory, InMemoryFirewall
from queenbee.application.access import AccessDeniedError, IncidentReadProxy
from queenbee.application.services import DetectionService, IncidentService
from queenbee.bootstrap import build_app
from queenbee.config import SettingsBuilder
from queenbee.domain.model import (
    Alert,
    DomainError,
    Incident,
    IncidentStatus,
    Principal,
    SecurityEvent,
    Severity,
    ThreatIndicator,
)
from queenbee.domain.rules import BruteForceRule
from queenbee.factories import InMemoryFactory

KEY = bytes(range(32))
ANALYST = Principal("alice", frozenset({"analyst"}))
VIEWER = Principal("bob", frozenset({"viewer"}))
ALERT = Alert("brute_force", "10.0.0.66", Severity.HIGH, "5 échecs")


def _msg(**over: object) -> bytes:
    data = {
        "source_ip": "10.0.0.66",
        "username": "root",
        "action": "login_failed",
        "timestamp": "2026-10-15T09:00:00+00:00",
    } | over
    return json.dumps(data).encode()


# --- Proxy : lecture protégée (C) ------------------------------------------------------------


def test_abuse_viewer_can_read_but_not_write_through_proxy() -> None:
    repo = InMemoryIncidentRepository()
    inc = Incident(ALERT)
    as_analyst = IncidentReadProxy(repo, ANALYST)
    as_analyst.add(inc)
    as_analyst.save(inc)
    proxy = IncidentReadProxy(repo, VIEWER)
    assert proxy.list_open() == [inc]
    assert proxy.get(inc.id) == inc
    with pytest.raises(AccessDeniedError):
        proxy.save(inc)
    with pytest.raises(AccessDeniedError):
        proxy.add(Incident(ALERT))
    assert proxy.denied == 2
    assert repo.list_open() == [inc]  # aucun effet de bord


def test_abuse_refusal_is_audited(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="queenbee.audit")
    with pytest.raises(AccessDeniedError):
        IncidentReadProxy(InMemoryIncidentRepository(), Principal("eve")).list_open()
    assert "eve" in caplog.text


def test_analyst_move_is_audited(
    five_failures: list[SecurityEvent], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="queenbee.audit")
    repo = InMemoryIncidentRepository()
    [inc] = DetectionService(BruteForceRule(), repo, []).ingest(five_failures)
    IncidentService(repo).move(ANALYST, inc.id, IncidentStatus.TRIAGED)
    assert "alice" in caplog.text
    assert "triaged" in caplog.text


@pytest.mark.parametrize(
    ("user", "roles"),
    [("", frozenset()), ("a b", frozenset()), ("alice", {"analyst"}), ("alice", frozenset({1}))],
)
def test_abuse_invalid_principal_cannot_exist(user: str, roles: object) -> None:
    with pytest.raises(DomainError):
        Principal(user, roles)  # type: ignore[arg-type]


# --- Adapter d'entrée : API des agents (S, T, D) ---------------------------------------------


def test_abuse_oversized_message_rejected_before_signature_check() -> None:
    body = _msg(username="a" * MAX_BODY)
    with pytest.raises(DomainError):
        parse_agent_message(body, sign(body, KEY), KEY)


@pytest.mark.parametrize("signature", ["", "00" * 32, "é" * 64, None])
def test_abuse_bad_signature_rejected(signature: object) -> None:
    with pytest.raises(UnauthenticatedError):
        parse_agent_message(_msg(), signature, KEY)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "body",
    [
        b"pas du json",
        b"[" * 4000,  # imbrication profonde
        b'["une", "liste"]',
        _msg(timestamp="hier"),
        _msg(timestamp="2026-10-15T09:00:00"),  # sans fuseau
        json.dumps(
            {"source_ip": "10.0.0.66", "username": "root", "action": "login_failed"}
        ).encode(),
        _msg(username=42),
        _msg(source_ip="10.0.0.66' OR 1=1"),
    ],
)
def test_abuse_malformed_signed_message_rejected(body: bytes) -> None:
    with pytest.raises(DomainError):
        parse_agent_message(body, sign(body, KEY), KEY)


# --- Couche anti-corruption ------------------------------------------------------------------


def test_threat_feed_accepts_any_case_and_ignores_unknown_fields() -> None:
    indicator = ThreatFeedTranslator().translate(
        {"indicator": "2001:db8::1", "risk_level": "CRITICAL", "vendor_secret": "x"}
    )
    assert indicator == ThreatIndicator("2001:db8::1", 100)


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "203.0.113.9",
        {"risk_level": "high"},
        {"indicator": 42, "risk_level": "high"},
        {"indicator": "203.0.113.9", "risk_level": "extrême"},
    ],
)
def test_abuse_threat_feed_rejects(raw: object) -> None:
    with pytest.raises(DomainError):
        ThreatFeedTranslator().translate(raw)


@pytest.mark.parametrize("score", [-1, 101, True, "80"])
def test_abuse_invalid_threat_score(score: object) -> None:
    with pytest.raises(DomainError):
        ThreatIndicator("203.0.113.9", score)  # type: ignore[arg-type]


# --- Decorator et Observer (D) ---------------------------------------------------------------


@pytest.mark.parametrize(("limit", "window"), [(0, 60), (3, 0)])
def test_rate_limiter_rejects_absurd_settings(limit: int, window: float) -> None:
    with pytest.raises(ValueError, match="positives"):
        RateLimitedNotifier(MemoryNotifier(), max_per_window=limit, window_s=window)


class _BrokenNotifier:
    def notify(self, alert: Alert) -> None:
        raise ConnectionError("serveur mail injoignable")


def test_abuse_broken_subscriber_does_not_block_others() -> None:
    first, last = MemoryNotifier(), MemoryNotifier()
    broadcaster = AlertBroadcaster([first, _BrokenNotifier()])
    broadcaster.subscribe(last)
    broadcaster.notify(ALERT)
    assert (first.received, last.received) == ([ALERT], [ALERT])
    assert broadcaster.failures == 1


# --- Command (I, P) --------------------------------------------------------------------------


@pytest.mark.parametrize("ip", ["10.0.0.1 && rm -rf /", "$(reboot)", "", 167772161])
def test_abuse_block_command_refuses_injection(ip: object) -> None:
    fw = InMemoryFirewall()
    with pytest.raises(DomainError):
        BlockIpCommand(fw, ip)  # type: ignore[arg-type]
    assert fw.blocked == set()


def test_undo_with_empty_history_is_refused() -> None:
    with pytest.raises(DomainError):
        CommandHistory().undo_last()


# --- Facade : parcours complet ---------------------------------------------------------------


def test_facade_full_journey_from_signed_messages_to_closed_incident() -> None:
    factory = InMemoryFactory()
    app = build_app(SettingsBuilder().hmac_key(KEY).build(), factory)
    good = _msg()
    forged = _msg(username="mallory")
    messages = [(good, sign(good, KEY))] * 5 + [(forged, sign(forged, b"x" * 32))]
    [inc] = app.ingest_agent_messages(messages)
    assert app.rejected == 1
    with pytest.raises(AccessDeniedError):
        app.move_incident(VIEWER, inc.id, IncidentStatus.TRIAGED)
    app.move_incident(ANALYST, inc.id, IncidentStatus.TRIAGED)
    app.move_incident(ANALYST, inc.id, IncidentStatus.CLOSED)
    assert app.open_incidents() == []
