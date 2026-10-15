"""Messages des agents : taille bornée, puis signature HMAC, puis schéma strict, dans cet ordre."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime

from queenbee.domain.model import DomainError, SecurityEvent

MAX_BODY = 4096  # 4 Kio
_FIELDS = frozenset({"source_ip", "username", "action", "timestamp"})


class UnauthenticatedError(Exception):
    """La signature ne correspond pas : le message ne vient pas d'un agent connu."""


def sign(body: bytes, key: bytes) -> str:
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def parse_agent_message(body: bytes, signature: str, key: bytes) -> SecurityEvent:
    if not isinstance(body, bytes) or len(body) > MAX_BODY:  # 1. taille, avant tout calcul
        raise DomainError("message absent ou trop gros")
    expected = sign(body, key).encode()
    received = signature.encode() if isinstance(signature, str) else b""
    if not hmac.compare_digest(expected, received):  # 2. authenticité, en temps constant
        raise UnauthenticatedError("signature invalide")
    try:  # 3. on ne lit le contenu qu'une fois l'auteur authentifié
        data = json.loads(body)
    except (ValueError, RecursionError) as exc:
        raise DomainError("JSON invalide") from exc
    if not isinstance(data, dict) or set(data) != _FIELDS:  # 4. schéma strict : ni plus, ni moins
        raise DomainError("champs inattendus ou manquants")
    if not all(isinstance(v, str) for v in data.values()):
        raise DomainError("tous les champs doivent être du texte")
    try:
        timestamp = datetime.fromisoformat(data["timestamp"])
    except ValueError as exc:
        raise DomainError("horodatage invalide") from exc
    return SecurityEvent(data["source_ip"], data["username"], data["action"], timestamp)
