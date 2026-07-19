"""
Detector de frases semilla BIP39 sobre volcados de memoria o ficheros.

Flujo:
  1. YARA escanea el blob de bytes buscando >=11 palabras del wordlist
     (filtro rápido a nivel de fichero completo).
  2. Por cada match, se toma una ventana de contexto y se localizan dentro
     "rachas" de palabras consecutivas del wordlist.
  3. Dentro de cada racha se prueban las longitudes válidas de mnemonic
     (12/15/18/21/24) en todas las posiciones posibles.
  4. Cada combinación se valida con el checksum BIP39 real. Si una racha
     contiene una combinación válida, se reporta solo esa (alta confianza).
     Si ninguna combinación de la racha es válida pero la racha es larga
     (>=12 palabras), se reporta como candidata de baja confianza.
"""

import re
from pathlib import Path

import yara

from src.validators.bip39_validator import is_valid_mnemonic, confidence_label, VALID_LENGTHS

RULE_PATH = Path(__file__).parent.parent.parent / "rules" / "bip39.yar"
CONTEXT_WINDOW = 512  # bytes alrededor de cada match para capturar la racha completa
MIN_CANDIDATE_LENGTH = min(VALID_LENGTHS)  # 12

_WORDLIST = set(
    (Path(__file__).parent / "bip39_wordlist.txt").read_text().strip().split("\n")
)


class BIP39Hit:
    def __init__(self, offset: int, words: list[str], valid: bool):
        self.offset = offset
        self.words = words
        self.valid = valid

    def to_dict(self) -> dict:
        return {
            "type": "BIP39_SEED",
            "offset": hex(self.offset),
            "words": " ".join(self.words),
            "word_count": len(self.words),
            "valid_checksum": self.valid,
            "confidence": confidence_label(self.words),
        }

    def __repr__(self):
        status = "VÁLIDA" if self.valid else "candidata"
        return f"<BIP39Hit offset={hex(self.offset)} words={len(self.words)} {status}>"


def _find_runs(text: str) -> list[list[tuple[str, int]]]:
    """
    Encuentra rachas de palabras consecutivas del wordlist BIP39 en un texto.
    Cada racha es una lista de tuplas (palabra, offset_en_texto).
    """
    tokens = [(m.group(), m.start()) for m in re.finditer(r"[a-z]+", text.lower())]

    runs = []
    i = 0
    while i < len(tokens):
        if tokens[i][0] not in _WORDLIST:
            i += 1
            continue
        j = i
        while j < len(tokens) and tokens[j][0] in _WORDLIST:
            j += 1
        if j - i >= MIN_CANDIDATE_LENGTH:
            runs.append(tokens[i:j])
        i = j
    return runs


def _best_candidate_in_run(run: list[tuple[str, int]]) -> tuple[list[str], int, bool]:
    """
    Dada una racha, busca la primera ventana de longitud válida que pase el
    checksum BIP39. Si ninguna pasa, devuelve la ventana más larga posible
    como candidata de baja confianza.
    """
    run_length = len(run)
    fallback = None

    for length in sorted(VALID_LENGTHS, reverse=True):
        if length > run_length:
            continue
        for start in range(0, run_length - length + 1):
            window = run[start:start + length]
            words = [w for w, _ in window]
            char_offset = window[0][1]
            if is_valid_mnemonic(words):
                return words, char_offset, True
            if fallback is None:
                fallback = (words, char_offset)

    if fallback is not None:
        return fallback[0], fallback[1], False
    return [], run[0][1], False


def scan_buffer(data: bytes) -> list[BIP39Hit]:
    """Escanea un buffer de bytes (dump de memoria, fichero, etc.)."""
    rules = yara.compile(filepath=str(RULE_PATH))
    matches = rules.match(data=data)

    raw_hits = []
    processed_windows = set()

    for match in matches:
        for string_match in match.strings:
            for instance in string_match.instances:
                offset = instance.offset
                start = max(0, offset - CONTEXT_WINDOW)
                end = min(len(data), offset + CONTEXT_WINDOW)

                # Redondeamos a bloques para agrupar ventanas que se solapan
                # casi del todo (varias palabras de la misma seed disparan
                # YARA en offsets muy próximos entre sí).
                bucket = start // CONTEXT_WINDOW
                if bucket in processed_windows:
                    continue
                processed_windows.add(bucket)

                try:
                    context = data[start:end].decode("utf-8", errors="ignore")
                except Exception:
                    continue

                for run in _find_runs(context):
                    words, char_offset, valid = _best_candidate_in_run(run)
                    if not words:
                        continue
                    abs_offset = start + char_offset
                    raw_hits.append(BIP39Hit(abs_offset, words, valid))

    # Deduplicación final por contenido exacto (mismo offset absoluto y
    # mismas palabras) por si dos ventanas distintas reconstruyen el mismo hit.
    seen = set()
    hits = []
    for h in raw_hits:
        key = (h.offset, tuple(h.words))
        if key in seen:
            continue
        seen.add(key)
        hits.append(h)

    return hits


def scan_file(path: str) -> list[BIP39Hit]:
    """Escanea un fichero completo (dump .raw, .vmem, etc.)."""
    with open(path, "rb") as f:
        data = f.read()
    return scan_buffer(data)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Uso: python bip39_detector.py <fichero_a_escanear>")
        sys.exit(1)

    results = scan_file(sys.argv[1])
    print(f"\n{len(results)} candidato(s) encontrado(s):\n")
    for hit in results:
        print(hit)
        print(f"   -> {' '.join(hit.words)}")
