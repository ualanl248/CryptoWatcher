"""
Validador estructural de keystores Web3 Secret Storage V3.

A diferencia de BIP39 y WIF, aquí no verificamos un checksum criptográfico
propio — la clave real está cifrada con AES y sin la contraseña del usuario
es inaccesible por diseño. Lo que sí podemos hacer es:

1. Verificar que el JSON tiene la estructura exacta del estándar V3.
2. Extraer los metadatos que NO están cifrados: dirección pública Ethereum,
   algoritmo de cifrado, parámetros KDF.
3. Estimar la resistencia a fuerza bruta basándonos en el valor de 'n'
   de scrypt (cuanto mayor, más lento de atacar).

Esto es suficiente para un informe forense: confirma que había una wallet
Ethereum activa en el sistema y proporciona la dirección pública trazable.
"""

import json
import re

REQUIRED_FIELDS = {"ciphertext", "cipherparams", "cipher", "kdf", "kdfparams", "mac"}
KNOWN_CIPHERS = {"aes-128-ctr", "aes-256-cbc"}
KNOWN_KDFS = {"scrypt", "pbkdf2"}
ETH_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")


def parse_keystore(raw: str) -> dict | None:
    """
    Intenta parsear un fragmento de texto como JSON de keystore V3.
    Devuelve el dict parseado o None si no es JSON válido.
    """
    try:
        data = json.loads(raw.strip())
        return data if isinstance(data, dict) else None
    except (json.JSONDecodeError, ValueError):
        return None


def is_valid_keystore(data: dict) -> bool:
    """
    Verifica que el dict tiene la estructura mínima de un keystore V3:
    - version == 3
    - crypto/Crypto presente con todos los campos obligatorios
    """
    if not isinstance(data, dict):
        return False

    # MetaMask usa "crypto", Geth usa "Crypto" — aceptamos ambos
    crypto = data.get("crypto") or data.get("Crypto")
    if not isinstance(crypto, dict):
        return False

    if data.get("version") != 3:
        return False

    if not REQUIRED_FIELDS.issubset(set(crypto.keys())):
        return False

    if crypto.get("cipher", "").lower() not in KNOWN_CIPHERS:
        return False

    if crypto.get("kdf", "").lower() not in KNOWN_KDFS:
        return False

    return True


def extract_metadata(data: dict) -> dict:
    """
    Extrae los metadatos no cifrados del keystore: lo que podemos reportar
    sin necesidad de la contraseña del usuario.
    """
    crypto = data.get("crypto") or data.get("Crypto") or {}
    kdfparams = crypto.get("kdfparams") or {}

    metadata = {
        "address": None,
        "cipher": crypto.get("cipher", "desconocido"),
        "kdf": crypto.get("kdf", "desconocido"),
        "wallet_id": data.get("id"),
        "version": data.get("version"),
        "bruteforce_resistance": _estimate_bf_resistance(kdfparams),
    }

    # La dirección puede estar en distintos niveles según la wallet
    addr = data.get("address") or data.get("Address")
    if addr:
        metadata["address"] = addr if addr.startswith("0x") else f"0x{addr}"

    return metadata


def _estimate_bf_resistance(kdfparams: dict) -> str:
    """
    Estima la resistencia a fuerza bruta basándose en los parámetros KDF.
    scrypt con n=262144 (MetaMask por defecto) es muy resistente.
    """
    n = kdfparams.get("n", 0)
    c = kdfparams.get("c", 0)  # iteraciones para pbkdf2

    if n >= 262144 or c >= 1000000:
        return "alta (atacar por fuerza bruta es muy costoso)"
    if n >= 8192 or c >= 10000:
        return "media"
    return "baja (parámetros KDF débiles)"


def confidence_label(data: dict) -> str:
    """Etiqueta legible para el informe forense."""
    if is_valid_keystore(data):
        meta = extract_metadata(data)
        addr = meta.get("address") or "dirección no encontrada"
        return f"ALTA - keystore V3 válido, dirección: {addr}"
    return "BAJA - estructura similar a keystore pero incompleta o malformada"
