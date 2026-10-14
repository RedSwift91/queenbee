"""Configuration : Builder -> Settings figé et validé. Les secrets viennent de l'environnement."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Self

MIN_KEY_BYTES = 32
MAX_THRESHOLD = 10_000


class ConfigError(Exception):
    """Configuration absente ou invalide : l'application refuse de démarrer."""


@dataclass(frozen=True, slots=True)
class Settings:
    hmac_key: bytes = field(repr=False)  # jamais dans print(), repr() ni les journaux
    db_path: str = ":memory:"
    bf_threshold: int = 5

    def __post_init__(self) -> None:  # aussi rejoué par dataclasses.replace
        if not isinstance(self.hmac_key, bytes) or len(self.hmac_key) < MIN_KEY_BYTES:
            raise ConfigError(f"la clé HMAC doit faire au moins {MIN_KEY_BYTES} octets")
        if not isinstance(self.db_path, str) or not self.db_path:
            raise ConfigError("chemin de base invalide")
        threshold = self.bf_threshold
        if isinstance(threshold, bool) or not isinstance(threshold, int):
            raise ConfigError("le seuil force brute doit être un entier")
        if not 1 <= threshold <= MAX_THRESHOLD:
            raise ConfigError(f"le seuil force brute doit être compris entre 1 et {MAX_THRESHOLD}")


class SettingsBuilder:
    """Monteur : on assemble pièce par pièce, build() valide tout et rend un objet figé."""

    __slots__ = ("_bf_threshold", "_db_path", "_hmac_key")

    def __init__(self) -> None:
        self._hmac_key: bytes | None = None
        self._db_path = ":memory:"
        self._bf_threshold = 5

    def __repr__(self) -> str:
        return f"SettingsBuilder(db_path={self._db_path!r}, bf_threshold={self._bf_threshold!r})"

    def hmac_key(self, key: bytes) -> Self:
        self._hmac_key = key
        return self

    def db_path(self, path: str) -> Self:
        self._db_path = path
        return self

    def bf_threshold(self, threshold: int) -> Self:
        self._bf_threshold = threshold
        return self

    def build(self) -> Settings:
        if self._hmac_key is None:
            raise ConfigError("clé HMAC des agents manquante")
        return Settings(self._hmac_key, self._db_path, self._bf_threshold)


def settings_from_env(env: Mapping[str, str] | None = None) -> Settings:
    """Lit QUEENBEE_AGENT_KEY (hex), QUEENBEE_DB et QUEENBEE_BF_THRESHOLD."""
    env = os.environ if env is None else env
    raw_key = env.get("QUEENBEE_AGENT_KEY", "").strip()
    if not raw_key:
        raise ConfigError("QUEENBEE_AGENT_KEY manquante")
    try:
        key = bytes.fromhex(raw_key)
    except ValueError:
        raise ConfigError("QUEENBEE_AGENT_KEY doit être en hexadécimal") from None  # sans la clé
    try:
        threshold = int(env.get("QUEENBEE_BF_THRESHOLD", "5"))
    except ValueError:
        raise ConfigError("QUEENBEE_BF_THRESHOLD doit être un entier") from None
    builder = SettingsBuilder().hmac_key(key).bf_threshold(threshold)
    if "QUEENBEE_DB" in env:
        builder.db_path(env["QUEENBEE_DB"])
    return builder.build()
