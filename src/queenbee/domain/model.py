"""Objets métier : immuables quand c'est possible, toujours validés à la construction."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, IntEnum
from types import MappingProxyType
from uuid import UUID, uuid4

USERNAME_RE = re.compile(r"[A-Za-z0-9._-]{1,32}")
ALLOWED_ACTIONS = frozenset({"login_failed", "login_ok", "port_probe"})
MAX_RULE_NAME = 64
MAX_MESSAGE = 500
MAX_SCORE = 100


class DomainError(ValueError):
    """Une règle métier est violée : l'objet demandé ne peut pas exister."""


def check_ip(value: object) -> str:
    """Renvoie l'IP si c'est une adresse IPv4/IPv6 écrite en texte, sinon DomainError."""
    if not isinstance(value, str):  # ip_address() accepte aussi des entiers
        raise DomainError("adresse IP attendue sous forme de texte")
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise DomainError("adresse IP invalide") from exc
    return value


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """Un événement remonté par un agent. Un SecurityEvent invalide ne peut pas être construit."""

    source_ip: str
    username: str
    action: str
    timestamp: datetime

    def __post_init__(self) -> None:
        check_ip(self.source_ip)
        if not isinstance(self.username, str) or not USERNAME_RE.fullmatch(self.username):
            raise DomainError("nom d'utilisateur hors allowlist")
        if self.action not in ALLOWED_ACTIONS:
            raise DomainError("action inconnue")
        if not isinstance(self.timestamp, datetime) or self.timestamp.utcoffset() is None:
            raise DomainError("horodatage sans fuseau")


@dataclass(frozen=True, slots=True)
class Alert:
    """Résultat d'une règle de détection."""

    rule: str
    source_ip: str
    severity: Severity
    message: str

    def __post_init__(self) -> None:
        if not isinstance(self.rule, str) or not 0 < len(self.rule) <= MAX_RULE_NAME:
            raise DomainError("nom de règle invalide")
        check_ip(self.source_ip)
        try:
            object.__setattr__(self, "severity", Severity(self.severity))
        except ValueError as exc:
            raise DomainError("gravité inconnue") from exc
        if not isinstance(self.message, str) or len(self.message) > MAX_MESSAGE:
            raise DomainError("message invalide")


class IncidentStatus(Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    CONTAINED = "contained"
    CLOSED = "closed"


# Machine à états : on ne clôt jamais un incident sans l'avoir trié.
_TRANSITIONS: MappingProxyType[IncidentStatus, frozenset[IncidentStatus]] = MappingProxyType(
    {
        IncidentStatus.OPEN: frozenset({IncidentStatus.TRIAGED}),
        IncidentStatus.TRIAGED: frozenset({IncidentStatus.CONTAINED, IncidentStatus.CLOSED}),
        IncidentStatus.CONTAINED: frozenset({IncidentStatus.CLOSED}),
        IncidentStatus.CLOSED: frozenset(),
    }
)


@dataclass(slots=True)
class Incident:
    """Incident ouvert à partir d'une alerte ; son statut ne change que par transition_to()."""

    alert: Alert
    id: UUID = field(default_factory=uuid4)
    status: IncidentStatus = IncidentStatus.OPEN

    def transition_to(self, new: IncidentStatus) -> None:
        if new not in _TRANSITIONS[self.status]:
            raise DomainError(f"transition interdite : {self.status.value} -> {new.value}")
        self.status = new


@dataclass(frozen=True, slots=True)
class Principal:
    """Qui agit, et avec quels rôles (« analyst », « viewer »...)."""

    user: str
    roles: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.user, str) or not USERNAME_RE.fullmatch(self.user):
            raise DomainError("identifiant d'utilisateur invalide")
        if not isinstance(self.roles, frozenset) or not all(
            isinstance(r, str) for r in self.roles
        ):
            raise DomainError("les rôles doivent être un frozenset de textes")

    def has(self, role: str) -> bool:
        return role in self.roles


@dataclass(frozen=True, slots=True)
class ThreatIndicator:
    """Indicateur de menace dans NOTRE vocabulaire : une IP et un score de 0 à 100."""

    ip: str
    score: int

    def __post_init__(self) -> None:
        check_ip(self.ip)
        if isinstance(self.score, bool) or not isinstance(self.score, int):
            raise DomainError("le score doit être un entier")
        if not 0 <= self.score <= MAX_SCORE:
            raise DomainError(f"le score doit être compris entre 0 et {MAX_SCORE}")
