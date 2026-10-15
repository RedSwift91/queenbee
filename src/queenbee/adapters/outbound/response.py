"""Réponse à incident : le blocage d'IP est une Commande validée, tracée et annulable."""

from __future__ import annotations

import ipaddress
import logging
from typing import Protocol

from queenbee.application.ports import Firewall
from queenbee.domain.model import DomainError

_audit = logging.getLogger("queenbee.audit")


class InMemoryFirewall:
    """Pare-feu de test : retient les IP bloquées."""

    def __init__(self) -> None:
        self.blocked: set[str] = set()

    def block(self, ip: str) -> None:
        self.blocked.add(ip)

    def unblock(self, ip: str) -> None:
        self.blocked.discard(ip)


class Command(Protocol):
    def execute(self) -> None: ...

    def undo(self) -> None: ...


class BlockIpCommand:
    """Validation dans le constructeur : une commande invalide n'existe jamais."""

    def __init__(self, firewall: Firewall, ip: str) -> None:
        if not isinstance(ip, str):
            raise DomainError("adresse IP attendue sous forme de texte")
        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise DomainError(str(exc)) from exc  # « 10.0.0.1; iptables -F » est refusé ici
        self._firewall = firewall
        self.ip = ip

    def execute(self) -> None:
        self._firewall.block(self.ip)

    def undo(self) -> None:
        self._firewall.unblock(self.ip)


class CommandHistory:
    """Exécute les commandes, les trace et permet d'annuler la dernière."""

    def __init__(self) -> None:
        self._done: list[Command] = []

    def run(self, command: Command) -> None:
        command.execute()
        self._done.append(command)
        _audit.info("commande exécutée : %r", command)

    def undo_last(self) -> None:
        if not self._done:
            raise DomainError("aucune commande à annuler")
        command = self._done.pop()
        command.undo()
        _audit.info("commande annulée : %r", command)
