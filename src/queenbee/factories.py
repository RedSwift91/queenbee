"""Fabrique abstraite : chaque fabrique livre une famille cohérente d'adapters."""

from __future__ import annotations

import sqlite3
from typing import Protocol

from queenbee.adapters.outbound.notifiers import LogNotifier, MemoryNotifier
from queenbee.adapters.outbound.repositories import (
    InMemoryIncidentRepository,
    SqliteIncidentRepository,
)
from queenbee.application.ports import IncidentRepository, Notifier


class ComponentFactory(Protocol):
    def repository(self) -> IncidentRepository: ...

    def notifier(self) -> Notifier: ...


class InMemoryFactory:
    """Famille « mémoire » : rien ne sort du processus (tests, démonstrations)."""

    def repository(self) -> InMemoryIncidentRepository:
        return InMemoryIncidentRepository()

    def notifier(self) -> MemoryNotifier:
        return MemoryNotifier()


class ProdFactory:
    """Famille « production » : base SQLite et alertes dans le journal applicatif."""

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path

    def repository(self) -> SqliteIncidentRepository:
        return SqliteIncidentRepository(sqlite3.connect(self._db_path))

    def notifier(self) -> LogNotifier:
        return LogNotifier()
