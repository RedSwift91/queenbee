"""Règles de détection : Strategy (une classe par règle), Composite (RuleSet), Factory (build_rule)."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol

from queenbee.domain.model import Alert, DomainError, SecurityEvent, Severity

MAX_THRESHOLD = 10_000


class DetectionRule(Protocol):
    def evaluate(self, events: Sequence[SecurityEvent]) -> list[Alert]: ...


def _check_threshold(value: object) -> None:
    # bool est une sous-classe de int : True passerait pour un seuil de 1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise DomainError("le seuil doit être un entier")
    if not 1 <= value <= MAX_THRESHOLD:
        raise DomainError(f"le seuil doit être compris entre 1 et {MAX_THRESHOLD}")


def _count_by_ip(events: Sequence[SecurityEvent], action: str) -> Counter[str]:
    return Counter(e.source_ip for e in events if e.action == action)


@dataclass(frozen=True, slots=True)
class BruteForceRule:
    """Au moins `threshold` échecs de connexion depuis la même IP."""

    threshold: int = 5

    def __post_init__(self) -> None:  # rejoué par dataclasses.replace : la copie est revalidée
        _check_threshold(self.threshold)

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[Alert]:
        return [
            Alert("brute_force", ip, Severity.HIGH, f"{n} échecs de connexion")
            for ip, n in _count_by_ip(events, "login_failed").items()
            if n >= self.threshold
        ]


@dataclass(frozen=True, slots=True)
class PortScanRule:
    """Au moins `threshold` sondes de ports depuis la même IP."""

    threshold: int = 20

    def __post_init__(self) -> None:
        _check_threshold(self.threshold)

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[Alert]:
        return [
            Alert("port_scan", ip, Severity.MEDIUM, f"{n} ports sondés")
            for ip, n in _count_by_ip(events, "port_probe").items()
            if n >= self.threshold
        ]


@dataclass(frozen=True, slots=True)
class RuleSet:
    """Composite : un ensemble de règles se comporte comme une seule règle."""

    rules: tuple[DetectionRule, ...]

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[Alert]:
        return [alert for rule in self.rules for alert in rule.evaluate(events)]


# Seuls ces noms peuvent être créés depuis une configuration externe (jamais getattr/importlib).
_REGISTRY: Mapping[str, Callable[..., DetectionRule]] = MappingProxyType(
    {"brute_force": BruteForceRule, "port_scan": PortScanRule}
)
_ALLOWED_KEYS = frozenset({"kind", "threshold"})


def build_rule(spec: Mapping[str, object]) -> DetectionRule:
    """Factory : crée une règle depuis un dictionnaire venu d'un fichier ou d'une API."""
    if not set(spec) <= _ALLOWED_KEYS:
        raise DomainError("clé de configuration inconnue")
    kind = spec.get("kind")
    if not isinstance(kind, str) or kind not in _REGISTRY:
        raise DomainError("type de règle inconnu")
    if "threshold" not in spec:
        return _REGISTRY[kind]()
    threshold = spec["threshold"]
    _check_threshold(threshold)
    return _REGISTRY[kind](threshold)
