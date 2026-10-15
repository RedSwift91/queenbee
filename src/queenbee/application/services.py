"""Cas d'usage. Les dépendances sont reçues par le constructeur (inversion de dépendances)."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from uuid import UUID

from queenbee.application.access import ANALYST, AccessDeniedError, require
from queenbee.application.ports import IncidentRepository, Notifier
from queenbee.domain.model import DomainError, Incident, IncidentStatus, Principal, SecurityEvent
from queenbee.domain.rules import DetectionRule

__all__ = ["AccessDeniedError", "DetectionService", "IncidentService"]

_audit = logging.getLogger("queenbee.audit")


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


class IncidentService:
    """Fait avancer un incident dans son cycle de vie, pour un utilisateur autorisé."""

    def __init__(self, incidents: IncidentRepository) -> None:
        self._incidents = incidents

    def move(self, who: Principal, incident_id: UUID, to: IncidentStatus) -> Incident:
        require(who, ANALYST, "changer le statut d'un incident")  # 1. autoriser
        incident = self._incidents.get(incident_id)
        if incident is None:  # 2. vérifier
            raise DomainError("incident introuvable")
        incident.transition_to(to)  # 3. règle métier
        self._incidents.save(incident)  # 4. persister
        _audit.info("%s : incident %s passé à %s", who.user, incident.id, to.value)
        return incident
