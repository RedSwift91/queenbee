"""Notificateurs : implémentations du port Notifier."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable

from queenbee.application.ports import Notifier
from queenbee.domain.model import Alert

_alerts_log = logging.getLogger("queenbee.alerts")
_audit_log = logging.getLogger("queenbee.audit")


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


# Decorator : chaque classe ci-dessous a la même méthode notify() que le Notifier qu'elle
# enveloppe. On peut donc les empiler (audit autour de limite autour de mail) sans que
# DetectionService voie la différence.
class AuditedNotifier:
    """Decorator : trace chaque alerte dans le journal d'audit, puis délègue."""

    def __init__(self, inner: Notifier, log: logging.Logger = _audit_log) -> None:
        self._inner = inner
        self._log = log

    def notify(self, alert: Alert) -> None:
        self._log.info(
            "alerte %s depuis %s (gravité %s)", alert.rule, alert.source_ip, alert.severity.name
        )
        self._inner.notify(alert)


class RateLimitedNotifier:
    """Decorator : au plus `max_per_window` alertes par fenêtre ; les autres sont comptées."""

    def __init__(
        self,
        inner: Notifier,
        max_per_window: int = 3,
        window_s: float = 60.0,
        clock: Callable[[], float] = time.monotonic,  # injectée : aucun time.sleep dans les tests
    ) -> None:
        if max_per_window < 1 or window_s <= 0:
            raise ValueError("limite et fenêtre doivent être positives")
        self._inner = inner
        self._max = max_per_window
        self._window_s = window_s
        self._clock = clock
        self._window_start = clock()
        self._sent = 0
        self.dropped = 0

    def notify(self, alert: Alert) -> None:
        now = self._clock()
        if now - self._window_start >= self._window_s:
            self._window_start, self._sent = now, 0
        if self._sent >= self._max:
            self.dropped += 1  # un rejet est toujours compté
            return
        self._sent += 1
        self._inner.notify(alert)


class AlertBroadcaster:
    """Observer : diffuse l'alerte à chaque abonné ; un abonné en panne ne bloque pas les autres."""

    def __init__(self, subscribers: Iterable[Notifier] = ()) -> None:
        self._subscribers = list(subscribers)
        self.failures = 0

    def subscribe(self, subscriber: Notifier) -> None:
        self._subscribers.append(subscriber)

    def notify(self, alert: Alert) -> None:
        for subscriber in tuple(self._subscribers):
            try:
                subscriber.notify(alert)
            except Exception:
                self.failures += 1
                _alerts_log.exception("abonné en échec : %s", type(subscriber).__name__)
