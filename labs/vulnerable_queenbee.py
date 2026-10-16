# ruff: noqa
"""VARIANTE VOLONTAIREMENT FRAGILE de Queen Bee — usage LABORATOIRE uniquement (J3-A1).

Sept failles d'architecture à exploiter (en local), corriger, puis vérifier avec bandit/pip-audit.
Chaque faille porte un numéro FAILLE-n ; la correction de référence est dans src/queenbee.
"""
import json
import os
import re
import sqlite3
from collections.abc import Mapping

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


def call_enrichment_service(ip: str) -> dict:
    # FAILLE-6 : appel inter-services sans authentification mutuelle (ni mTLS, ni jeton)
    return {"ip": ip, "reputation": "unknown"}


def check_token(token: str, expected: str) -> bool:
    # La clé attendue est fournie par load_service_key (CORRECTIF-1).
    return token == expected                          # FAILLE-7 : comparaison non constante (timing)
