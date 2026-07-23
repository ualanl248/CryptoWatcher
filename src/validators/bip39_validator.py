"""
Validador criptográfico de frases semilla BIP39.

Una seed BIP39 no es solo "12 palabras al azar": la última palabra (o las
últimas, en el caso de 24) incrustan un checksum calculado a partir de un
hash SHA-256 de la entropía original. Esto permite verificar, sin red y sin
conocer la wallet origen, si una combinación de palabras es una seed
matemáticamente válida o pura coincidencia textual.

Longitudes válidas según el estándar: 12, 15, 18, 21 o 24 palabras.

Filtros anti-falsos-positivos adicionales (basados en análisis de dumps reales):
  1. Unicidad: una seed real tiene todas las palabras distintas. Si más del
     25% de las palabras se repiten, es texto de UI o código, no una seed.
  2. Diversidad léxica: una seed real tiene tantas palabras únicas como
     palabras totales. Un ratio bajo indica texto repetitivo (CSS, JSON...).
"""

import hashlib
from pathlib import Path

WORDLIST_PATH = Path(__file__).parent.parent / "detectors" / "bip39_wordlist.txt"
VALID_LENGTHS = {12, 15, 18, 21, 24}

# Umbral de unicidad: si las palabras únicas son menos de este porcentaje
# del total, consideramos el candidato como falso positivo.
# Una seed real tiene prácticamente 100% de palabras únicas.
MIN_UNIQUE_RATIO = 0.85  # al menos el 85% de palabras deben ser distintas

# Palabras muy comunes en texto de UI/CSS/JSON que raramente aparecen
# en seeds reales pero sí en texto de interfaz de usuario.
# No las bloqueamos directamente, pero si dominan la frase es sospechoso.
UI_WORDS = {
    "left", "right", "top", "bottom", "border", "style", "width", "height",
    "color", "index", "name", "type", "value", "class", "focus", "hover",
    "entry", "icon", "search", "action", "view", "sort", "target", "object",
    "property", "false", "true", "none", "auto", "size", "list", "item",
}

# Si más de este porcentaje de palabras son UI_WORDS, es probablemente ruido
MAX_UI_RATIO = 0.5  # máximo 50% de palabras de UI en una seed válida


def load_wordlist() -> list[str]:
    return WORDLIST_PATH.read_text().strip().split("\n")


_WORDLIST = load_wordlist()
_WORD_TO_INDEX = {w: i for i, w in enumerate(_WORDLIST)}


def _passes_heuristics(words: list[str]) -> bool:
    """
    Filtros heurísticos para reducir falsos positivos en dumps de Linux/Windows.

    Estos filtros se aplican ANTES del checksum criptográfico para descartar
    candidatos obvios sin necesidad de hacer el cálculo SHA-256.
    """
    total = len(words)

    # 1. Filtro de unicidad: seeds reales tienen casi todas las palabras distintas
    unique_count = len(set(words))
    unique_ratio = unique_count / total
    if unique_ratio < MIN_UNIQUE_RATIO:
        return False

    # 2. Filtro de palabras UI: si la mayoría son términos de interfaz, es ruido
    ui_count = sum(1 for w in words if w in UI_WORDS)
    ui_ratio = ui_count / total
    if ui_ratio > MAX_UI_RATIO:
        return False

    return True


def _verify_checksum(words: list[str]) -> bool:
    """
    Verifica el checksum criptográfico BIP39.
    Cada palabra representa 11 bits; los últimos N bits son el checksum SHA-256.
    """
    bits = "".join(f"{_WORD_TO_INDEX[w]:011b}" for w in words)

    checksum_length = len(bits) // 33
    entropy_length = len(bits) - checksum_length

    entropy_bits = bits[:entropy_length]
    checksum_bits = bits[entropy_length:]

    entropy_bytes = int(entropy_bits, 2).to_bytes(entropy_length // 8, "big")
    hash_digest = hashlib.sha256(entropy_bytes).digest()
    hash_bits = "".join(f"{b:08b}" for b in hash_digest)

    return checksum_bits == hash_bits[:checksum_length]


def is_valid_mnemonic(words: list[str]) -> bool:
    """
    Verifica que una secuencia de palabras es una seed BIP39 válida.

    Aplica tres capas de validación en orden de menor a mayor coste:
      1. Longitud válida (12/15/18/21/24)
      2. Todas las palabras en el wordlist oficial
      3. Filtros heurísticos anti-falsos-positivos
      4. Checksum criptográfico SHA-256
    """
    if len(words) not in VALID_LENGTHS:
        return False

    if not all(w in _WORD_TO_INDEX for w in words):
        return False

    if not _passes_heuristics(words):
        return False

    return _verify_checksum(words)


def confidence_label(words: list[str]) -> str:
    """Etiqueta legible para el informe forense."""
    if is_valid_mnemonic(words):
        return "ALTA - checksum BIP39 válido"
    return "BAJA - palabras del wordlist sin checksum válido (probable falso positivo)"