"""Couche anti-corruption : traduit le vocabulaire d'un flux de menaces externe dans le nôtre."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from queenbee.domain.model import DomainError, ThreatIndicator

_SCORES: Mapping[str, int] = MappingProxyType(
    {"low": 20, "medium": 50, "high": 80, "critical": 100}
)


class ThreatFeedTranslator:
    """Le modèle du fournisseur ne pénètre jamais dans le domaine : on garde ce qu'on comprend."""

    def translate(self, raw: object) -> ThreatIndicator:
        if not isinstance(raw, Mapping):
            raise DomainError("entrée de flux invalide")
        level = raw.get("risk_level")
        if not isinstance(level, str) or level.lower() not in _SCORES:
            raise DomainError("niveau de risque inconnu")
        indicator = raw.get("indicator")
        if not isinstance(indicator, str):
            raise DomainError("indicateur absent")
        return ThreatIndicator(indicator, _SCORES[level.lower()])  # le domaine vérifie que c'est une IP
