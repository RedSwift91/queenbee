"""Lecture des journaux sshd. Une ligne est soit un SecurityEvent valide, soit une DomainError."""

from __future__ import annotations

import re
from datetime import datetime

from queenbee.domain.model import DomainError, SecurityEvent

MAX_LINE = 512

# Ancrée (fullmatch), sans .* : chaque champ a une classe de caractères et une longueur bornées.
_SSHD_LINE = re.compile(
    r"(?P<ts>\S{1,40}) sshd(?:\[\d{1,10}\])?: "
    r"(?P<verdict>Failed|Accepted) password for (?P<user>[A-Za-z0-9._-]{1,32}) "
    r"from (?P<ip>[0-9A-Fa-f:.]{2,45})(?: port \d{1,5})?(?: ssh2)?"
)
_ACTIONS = {"Failed": "login_failed", "Accepted": "login_ok"}


def parse_sshd_line(line: str) -> SecurityEvent:
    if len(line) > MAX_LINE:  # bornée avant toute regex
        raise DomainError("ligne trop longue")
    match = _SSHD_LINE.fullmatch(line.rstrip("\r\n"))
    if match is None:
        raise DomainError("ligne sshd non reconnue")
    try:
        timestamp = datetime.fromisoformat(match["ts"])
    except ValueError as exc:
        raise DomainError("horodatage invalide") from exc
    return SecurityEvent(match["ip"], match["user"], _ACTIONS[match["verdict"]], timestamp)
