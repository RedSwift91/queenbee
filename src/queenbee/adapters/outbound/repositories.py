"""Dépôts d'incidents : implémentations du port IncidentRepository."""

from __future__ import annotations

import sqlite3
from uuid import UUID

from queenbee.domain.model import Alert, DomainError, Incident, IncidentStatus, Severity


class InMemoryIncidentRepository:
    def __init__(self) -> None:
        self._items: dict[UUID, Incident] = {}

    def add(self, incident: Incident) -> None:
        if incident.id in self._items:
            raise DomainError("incident déjà enregistré")
        self._items[incident.id] = incident

    def get(self, incident_id: UUID) -> Incident | None:
        return self._items.get(incident_id)

    def save(self, incident: Incident) -> None:
        if incident.id not in self._items:
            raise DomainError("incident inconnu")
        self._items[incident.id] = incident

    def list_open(self) -> list[Incident]:
        return [i for i in self._items.values() if i.status is not IncidentStatus.CLOSED]


_SCHEMA = """
CREATE TABLE IF NOT EXISTS incident (
    id TEXT PRIMARY KEY,
    rule TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    severity INTEGER NOT NULL,
    message TEXT NOT NULL,
    status TEXT NOT NULL
)
"""
# Les ? sont remplis par sqlite3 lui-même, séparément du texte de la requête : une donnée
# comme « x'); DROP TABLE incident;-- » reste une donnée et ne devient jamais du SQL.
_INSERT = (
    "INSERT INTO incident (id, rule, source_ip, severity, message, status) "
    "VALUES (?, ?, ?, ?, ?, ?)"
)
_SELECT = "SELECT id, rule, source_ip, severity, message, status FROM incident"
_Row = tuple[str, str, str, int, str, str]


class SqliteIncidentRepository:
    """Toutes les requêtes sont paramétrées (?) : aucune donnée n'est collée dans le SQL."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        with self._conn:
            self._conn.execute(_SCHEMA)

    def add(self, incident: Incident) -> None:
        a = incident.alert
        try:
            with self._conn:  # transaction : validée si tout passe, annulée en cas d'erreur
                self._conn.execute(
                    _INSERT,
                    (
                        str(incident.id),
                        a.rule,
                        a.source_ip,
                        int(a.severity),
                        a.message,
                        incident.status.value,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise DomainError("incident déjà enregistré") from exc

    def get(self, incident_id: UUID) -> Incident | None:
        row = self._conn.execute(_SELECT + " WHERE id = ?", (str(incident_id),)).fetchone()
        return None if row is None else _to_incident(row)

    def save(self, incident: Incident) -> None:
        with self._conn:
            cur = self._conn.execute(
                "UPDATE incident SET status = ? WHERE id = ?",
                (incident.status.value, str(incident.id)),
            )
        if cur.rowcount != 1:
            raise DomainError("incident inconnu")

    def list_open(self) -> list[Incident]:
        rows = self._conn.execute(
            _SELECT + " WHERE status != ? ORDER BY rowid", (IncidentStatus.CLOSED.value,)
        ).fetchall()
        return [_to_incident(r) for r in rows]


def _to_incident(row: _Row) -> Incident:
    incident_id, rule, ip, severity, message, status = row
    # Relecture : les données repassent par la validation du domaine.
    alert = Alert(rule, ip, Severity(severity), message)
    return Incident(alert, id=UUID(incident_id), status=IncidentStatus(status))
