"""
Validador criptográfico de claves privadas en formato WIF (Wallet Import Format).

Estructura de un WIF (antes de Base58):
    [1 byte prefijo de red] + [32 bytes clave privada] + [1 byte opcional 0x01 si comprimida] + [4 bytes checksum]

El checksum son los primeros 4 bytes de SHA256(SHA256(payload)), donde "payload"
es todo lo anterior al propio checksum. Esto permite verificar matemáticamente
si una cadena Base58 candidata es una clave WIF válida, sin necesidad de red
ni de conocer la wallet de origen.

Prefijos de red más comunes (mainnet):
    0x80 -> Bitcoin mainnet (la clave WIF empieza por '5', 'K' o 'L' en Base58)
"""

import hashlib

# Alfabeto Base58 estándar (sin 0, O, I, l para evitar confusión visual)
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}

VALID_PREFIXES = {0x80}  # Bitcoin mainnet; testnet (0xEF) se podría añadir aquí
WIF_LENGTH_RANGE = (51, 52)  # sin comprimir: 51 chars, comprimida: 52 chars


def b58decode(s: str) -> bytes:
    """Decodifica una cadena Base58 a bytes, preservando ceros iniciales."""
    if not s:
        return b""

    num = 0
    for char in s:
        if char not in _B58_INDEX:
            raise ValueError(f"Carácter no válido en Base58: {char!r}")
        num = num * 58 + _B58_INDEX[char]

    # Convertir el entero grande a bytes
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""

    # Cada '1' inicial en Base58 representa un byte 0x00 en el resultado
    leading_zeros = len(s) - len(s.lstrip("1"))
    return b"\x00" * leading_zeros + raw


def is_valid_wif(candidate: str) -> bool:
    """
    Verifica si una cadena es una clave privada WIF matemáticamente válida.

    Comprueba: longitud correcta, alfabeto Base58 válido, prefijo de red
    conocido, y que el checksum (doble SHA-256) coincida.
    """
    if len(candidate) not in range(WIF_LENGTH_RANGE[0], WIF_LENGTH_RANGE[1] + 1):
        return False

    if not all(c in _B58_INDEX for c in candidate):
        return False

    try:
        decoded = b58decode(candidate)
    except ValueError:
        return False

    # payload (prefijo + clave + flag opcional) + 4 bytes de checksum
    if len(decoded) not in (37, 38):  # 1+32+4 sin comprimir, 1+32+1+4 comprimida
        return False

    payload, checksum = decoded[:-4], decoded[-4:]

    if payload[0] not in VALID_PREFIXES:
        return False

    expected_checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

    return checksum == expected_checksum


def is_compressed(candidate: str) -> bool:
    """Indica si la clave WIF corresponde al formato comprimido (52 chars)."""
    return len(candidate) == 52


def confidence_label(candidate: str) -> str:
    """Etiqueta legible para el informe forense."""
    if is_valid_wif(candidate):
        tipo = "comprimida" if is_compressed(candidate) else "sin comprimir"
        return f"ALTA - checksum WIF válido ({tipo})"
    return "BAJA - formato similar a WIF sin checksum válido (probable falso positivo)"
