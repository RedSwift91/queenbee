"""Cas d'usage. Les dépendances sont reçues par le constructeur (inversion de dépendances)."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from queenbee.application.ports import IncidentRepository, Notifier
from queenbee.domain.model import Incident, SecurityEvent
from queenbee.domain.rules import DetectionRule


class DetectionService:
    """Évalue les événements, ouvre un incident par alerte et prévient les notificateurs."""

    def __init__(
        self,
        rule: DetectionRule,
        repository: IncidentRepository,
        notifiers: Iterable[Notifier],
    ) -> None:
        self._rule = rule
        self._repository = repository
        self._notifiers = tuple(notifiers)

    def ingest(self, events: Sequence[SecurityEvent]) -> list[Incident]:
        created: list[Incident] = []
        for alert in self._rule.evaluate(events):
            incident = Incident(alert)
            self._repository.add(incident)
            created.append(incident)
            for notifier in self._notifiers:
                notifier.notify(alert)
        return created
