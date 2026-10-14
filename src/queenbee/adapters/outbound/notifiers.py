"""Notificateurs : implémentations du port Notifier."""

from __future__ import annotations

import logging

from queenbee.domain.model import Alert

_alerts_log = logging.getLogger("queenbee.alerts")


class MemoryNotifier:
    """Garde les alertes en mémoire (tests, démonstrations)."""

    def __init__(self) -> None:
        self.received: list[Alert] = []

    def notify(self, alert: Alert) -> None:
        self.received.append(alert)


class LogNotifier:
    """Écrit les alertes dans le journal applicatif (canal de production par défaut)."""

    def notify(self, alert: Alert) -> None:
        _alerts_log.warning(
            "alerte %s depuis %s (gravité %s) : %s",
            alert.rule,
            alert.source_ip,
            alert.severity.name,
            alert.message,
        )
