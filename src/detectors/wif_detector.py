"""
Detector de claves privadas WIF sobre volcados de memoria o ficheros.

Flujo:
  1. YARA escanea el blob de bytes buscando patrones que encajen con el
     formato WIF (prefijo + longitud + alfabeto Base58).
  2. Cada match se valida criptográficamente con el checksum real (doble
     SHA-256), descartando coincidencias de longitud/alfabeto que no sean
     claves WIF matemáticamente válidas.

A diferencia de BIP39, aquí no hace falta reconstruir "rachas de palabras":
el propio match de YARA ya es la cadena completa candidata, porque WIF no
tiene separadores ni longitud variable real (51 o 52 caracteres fijos).
"""

from pathlib import Path

import yara

from src.validators.wif_validator import is_valid_wif, confidence_label

RULE_PATH = Path(__file__).parent.parent.parent / "rules" / "wif.yar"


class WIFHit:
    def __init__(self, offset: int, candidate: str, valid: bool):
        self.offset = offset
        self.candidate = candidate
        self.valid = valid

    def to_dict(self) -> dict:
        return {
            "type": "WIF_PRIVATE_KEY",
            "offset": hex(self.offset),
            "value": self.candidate,
            "valid_checksum": self.valid,
            "confidence": confidence_label(self.candidate),
        }

    def __repr__(self):
        status = "VÁLIDA" if self.valid else "candidata"
        return f"<WIFHit offset={hex(self.offset)} {status}>"


def scan_buffer(data: bytes) -> list[WIFHit]:
    """Escanea un buffer de bytes (dump de memoria, fichero, etc.)."""
    rules = yara.compile(filepath=str(RULE_PATH))
    matches = rules.match(data=data)

    hits = []
    seen = set()  # (offset, candidato) ya procesado, por si varias strings solapan

    for match in matches:
        for string_match in match.strings:
            for instance in string_match.instances:
                offset = instance.offset
                try:
                    candidate = instance.matched_data.decode("ascii")
                except UnicodeDecodeError:
                    continue

                key = (offset, candidate)
                if key in seen:
                    continue
                seen.add(key)

                valid = is_valid_wif(candidate)
                hits.append(WIFHit(offset, candidate, valid))

    return hits


def scan_file(path: str) -> list[WIFHit]:
    """Escanea un fichero completo (dump .raw, .vmem, etc.)."""
    with open(path, "rb") as f:
        data = f.read()
    return scan_buffer(data)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Uso: python wif_detector.py <fichero_a_escanear>")
        sys.exit(1)

    results = scan_file(sys.argv[1])
    print(f"\n{len(results)} candidato(s) encontrado(s):\n")
    for hit in results:
        print(hit)
        print(f"   -> {hit.candidate}")
