# ruff: noqa
"""VARIANTE VOLONTAIREMENT FRAGILE de Queen Bee — usage LABORATOIRE uniquement (J3-A1).

Sept failles d'architecture à exploiter (en local), corriger, puis vérifier avec bandit/pip-audit.
Chaque faille porte un numéro FAILLE-n ; la correction de référence est dans src/queenbee.
"""
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sqlite3
from collections.abc import Callable, Mapping

from queenbee.application.access import ANALYST, require
from queenbee.domain.model import DomainError, Principal

MIN_KEY_LEN = 32


def load_service_key(service: str, env: Mapping[str, str] | None = None) -> str:
    # CORRECTIF-1 : une clé par service (QUEENBEE_<SERVICE>_KEY), injectée au démarrage,
    # jamais écrite dans le code et sans valeur par défaut.
    env = os.environ if env is None else env
    key = env.get(f"QUEENBEE_{service.upper()}_KEY", "")
    if len(key) < MIN_KEY_LEN:
        raise DomainError(f"clé du service {service} absente ou trop courte")
    return key


# CORRECTIF-2 : plus de quantificateurs imbriqués (le séparateur est obligatoire entre deux mots,
# donc une seule façon de découper la chaîne), et la longueur est bornée AVANT la regex.
USER_RE = re.compile(r"[A-Za-z0-9]+(?: [A-Za-z0-9]+)*")
MAX_USERNAME = 32

conn = sqlite3.connect(":memory:")
conn.execute("CREATE TABLE incident (id INTEGER PRIMARY KEY, ip TEXT, status TEXT)")


MAX_MESSAGE = 4096
_FIELDS = frozenset({"source_ip", "username", "action", "timestamp"})


def receive_agent_message(raw: bytes) -> dict[str, str]:
    # CORRECTIF-3 : on accepte des DONNÉES (JSON), jamais du code. pickle.loads exécutait ce que
    # l'expéditeur voulait pendant la simple lecture. Taille bornée, puis schéma strict.
    if not isinstance(raw, bytes) or len(raw) > MAX_MESSAGE:
        raise DomainError("message absent ou trop gros")
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError) as exc:  # JSON invalide, ou octets non UTF-8
        raise DomainError("message illisible") from exc
    if not isinstance(data, dict) or set(data) != _FIELDS:
        raise DomainError("champs inattendus ou manquants")
    if not all(isinstance(v, str) for v in data.values()):
        raise DomainError("tous les champs doivent être du texte")
    return data


def is_valid_username(name: str) -> bool:
    if not isinstance(name, str) or len(name) > MAX_USERNAME:
        return False
    return USER_RE.fullmatch(name) is not None


def find_incidents(ip: str):
    # CORRECTIF-4 : requête paramétrée ; « x' OR '1'='1 » est cherché comme une IP, pas exécuté.
    return conn.execute("SELECT * FROM incident WHERE ip = ?", (ip,)).fetchall()


def close_incident(who: Principal, incident_id: int) -> None:
    # CORRECTIF-5 : le rôle est vérifié dans le cas d'usage, en premier, et non dans l'interface :
    # une interface qui oublierait le contrôle ne peut pas le contourner. Le refus est audité.
    require(who, ANALYST, "clore un incident")
    conn.execute("UPDATE incident SET status='closed' WHERE id=?", (incident_id,))


# CORRECTIF-6 : authentification MUTUELLE des appels inter-services. Le client signe sa requête,
# le service la vérifie puis signe sa réponse, que le client vérifie à son tour. En production,
# le même rôle est tenu par mTLS (un certificat de chaque côté) ; la clé est propre à ce lien.
class UnauthenticatedError(Exception):
    """L'autre partie n'a pas prouvé son identité."""


def _sign(payload: Mapping[str, str], key: str) -> str:
    body = json.dumps(dict(payload), sort_keys=True).encode()
    return hmac.new(key.encode(), body, hashlib.sha256).hexdigest()


def _signed_by(message: Mapping[str, str], key: str) -> bool:
    received = message.get("sig")
    content = {k: v for k, v in message.items() if k != "sig"}
    return isinstance(received, str) and hmac.compare_digest(
        _sign(content, key).encode(), received.encode()
    )


def enrichment_service(request: Mapping[str, str], key: str) -> dict[str, str]:
    """Côté service : refuse tout client non authentifié, puis signe sa réponse."""
    if not _signed_by(request, key):
        raise UnauthenticatedError("client non authentifié")
    response = {"ip": request["ip"], "reputation": "unknown"}
    return response | {"sig": _sign(response, key)}


def call_enrichment_service(
    ip: str, key: str, transport: Callable[[Mapping[str, str]], Mapping[str, str]]
) -> dict[str, str]:
    """Côté client : signe la requête et n'accepte qu'une réponse signée par le vrai service."""
    if not isinstance(ip, str):
        raise DomainError("adresse IP attendue sous forme de texte")
    ipaddress.ip_address(ip)  # ValueError si ce n'est pas une IP
    request = {"ip": ip}
    response = transport(request | {"sig": _sign(request, key)})
    if not _signed_by(response, key):
        raise UnauthenticatedError("le service n'a pas prouvé son identité")
    return {k: v for k, v in response.items() if k != "sig"}


def check_token(token: str, expected: str) -> bool:
    # La clé attendue est fournie par load_service_key (CORRECTIF-1).
    return token == expected                          # FAILLE-7 : comparaison non constante (timing)
