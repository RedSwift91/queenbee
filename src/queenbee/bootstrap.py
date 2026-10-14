"""Composition root : le seul endroit qui crée et relie les objets. Remplace l'état global."""

from __future__ import annotations

from collections.abc import Iterable

from queenbee.adapters.inbound.log_parser import parse_sshd_line
from queenbee.application.ports import IncidentRepository
from queenbee.application.services import DetectionService
from queenbee.config import Settings
from queenbee.domain.model import DomainError, Incident, SecurityEvent
from queenbee.domain.rules import BruteForceRule, PortScanRule, RuleSet
from queenbee.factories import ComponentFactory, ProdFactory


class QueenBee:
    """Facade : un point d'entrée simple devant le parser, la détection et le dépôt."""

    def __init__(self, detection: DetectionService, repository: IncidentRepository) -> None:
        self._detection = detection
        self._repository = repository
        self.rejected = 0

    def ingest_lines(self, lines: Iterable[str]) -> list[Incident]:
        events: list[SecurityEvent] = []
        for line in lines:
            try:
                events.append(parse_sshd_line(line))
            except DomainError:
                self.rejected += 1
        return self._detection.ingest(events)

    def open_incidents(self) -> list[Incident]:
        return self._repository.list_open()


def build_app(settings: Settings, factory: ComponentFactory | None = None) -> QueenBee:
    factory = ProdFactory(settings.db_path) if factory is None else factory
    repository = factory.repository()
    rules = RuleSet((BruteForceRule(settings.bf_threshold), PortScanRule()))
    detection = DetectionService(rules, repository, [factory.notifier()])
    return QueenBee(detection, repository)
