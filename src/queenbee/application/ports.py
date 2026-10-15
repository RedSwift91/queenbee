"""Ports de sortie : les contrats que les adapters (SQLite, mail, mémoire...) doivent remplir."""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from queenbee.domain.model import Alert, Incident


class IncidentRepository(Protocol):
    def add(self, incident: Incident) -> None: ...

    def get(self, incident_id: UUID) -> Incident | None: ...

    def save(self, incident: Incident) -> None: ...

    def list_open(self) -> list[Incident]: ...


class Notifier(Protocol):
    def notify(self, alert: Alert) -> None: ...


class Firewall(Protocol):
    def block(self, ip: str) -> None: ...

    def unblock(self, ip: str) -> None: ...
