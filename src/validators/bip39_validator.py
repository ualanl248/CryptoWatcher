"""
Validador criptográfico de frases semilla BIP39.

Una seed BIP39 no es solo "12 palabras al azar": la última palabra (o las
últimas, en el caso de 24) incrustan un checksum calculado a partir de un
hash SHA-256 de la entropía original. Esto permite verificar, sin red y sin
conocer la wallet origen, si una combinación de palabras es una seed
matemáticamente válida o pura coincidencia textual.

Longitudes válidas según el estándar: 12, 15, 18, 21 o 24 palabras.
"""

import hashlib
from pathlib import Path

WORDLIST_PATH = Path(__file__).parent.parent / "detectors" / "bip39_wordlist.txt"
VALID_LENGTHS = {12, 15, 18, 21, 24}


def load_wordlist() -> list[str]:
    return WORDLIST_PATH.read_text().strip().split("\n")


_WORDLIST = load_wordlist()
_WORD_TO_INDEX = {w: i for i, w in enumerate(_WORDLIST)}


def is_valid_mnemonic(words: list[str]) -> bool:
    """
    Verifica el checksum de una posible seed BIP39.

    Devuelve True solo si:
    1. La longitud es una de las permitidas (12/15/18/21/24).
    2. Todas las palabras existen en el wordlist oficial.
    3. El checksum incrustado en los últimos bits coincide con el hash
       SHA-256 calculado sobre la entropía representada por el resto.
    """
    if len(words) not in VALID_LENGTHS:
        return False

    if not all(w in _WORD_TO_INDEX for w in words):
        return False

    # Cada palabra representa 11 bits (2^11 = 2048 = tamaño del wordlist)
    bits = "".join(f"{_WORD_TO_INDEX[w]:011b}" for w in words)

    # División entropía / checksum según el estándar:
    # checksum_length = longitud_total_bits / 33
    checksum_length = len(bits) // 33
    entropy_length = len(bits) - checksum_length

    entropy_bits = bits[:entropy_length]
    checksum_bits = bits[entropy_length:]

    entropy_bytes = int(entropy_bits, 2).to_bytes(entropy_length // 8, "big")
    hash_digest = hashlib.sha256(entropy_bytes).digest()
    hash_bits = "".join(f"{b:08b}" for b in hash_digest)

    expected_checksum = hash_bits[:checksum_length]

    return checksum_bits == expected_checksum


def confidence_label(words: list[str]) -> str:
    """Etiqueta legible para el informe forense."""
    if is_valid_mnemonic(words):
        return "ALTA - checksum BIP39 válido"
    return "BAJA - palabras del wordlist sin checksum válido (probable falso positivo)"
