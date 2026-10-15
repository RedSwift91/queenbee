"""Contrôle d'accès : vérifié dans l'application, jamais seulement dans l'interface."""

from __future__ import annotations

import logging
from uuid import UUID

from queenbee.application.ports import IncidentRepository
from queenbee.domain.model import Incident, Principal

ANALYST = frozenset({"analyst"})
READERS = frozenset({"analyst", "viewer"})

_audit = logging.getLogger("queenbee.audit")


class AccessDeniedError(Exception):
    """L'utilisateur n'a pas le rôle nécessaire pour cette action."""

    def __init__(self, user: str, action: str) -> None:
        super().__init__(f"accès refusé à {user} : {action}")
        self.user = user


def require(who: Principal, roles: frozenset[str], action: str) -> None:
    if not who.roles & roles:
        _audit.warning("accès refusé : %s a tenté de %s", who.user, action)
        raise AccessDeniedError(who.user, action)


class IncidentReadProxy:
    """Proxy : même interface que IncidentRepository ; vérifie le rôle avant de déléguer."""

    def __init__(self, inner: IncidentRepository, who: Principal) -> None:
        self._inner = inner
        self._who = who
        self.denied = 0  # un rejet est toujours compté

    def _check(self, roles: frozenset[str], action: str) -> None:
        try:
            require(self._who, roles, action)
        except AccessDeniedError:
            self.denied += 1
            raise

    def add(self, incident: Incident) -> None:
        self._check(ANALYST, "créer un incident")
        self._inner.add(incident)

    def get(self, incident_id: UUID) -> Incident | None:
        self._check(READERS, "lire un incident")
        return self._inner.get(incident_id)

    def save(self, incident: Incident) -> None:
        self._check(ANALYST, "modifier un incident")
        self._inner.save(incident)

    def list_open(self) -> list[Incident]:
        self._check(READERS, "lister les incidents")
        return self._inner.list_open()
