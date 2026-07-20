"""
Detector de keystores Web3 Secret Storage V3 en volcados de memoria.

El reto específico de los keystores respecto a BIP39/WIF es que son objetos
JSON de varias líneas que en memoria pueden aparecer:
  - Completos y contiguos (caso ideal)
  - Partidos entre páginas de memoria (caso frecuente)
  - Con basura binaria alrededor pero con el JSON intacto

Flujo:
  1. YARA localiza zonas de memoria donde coexisten los campos clave del
     estándar V3 (ciphertext, kdf, mac, cipher, version).
  2. Alrededor de cada match se extrae una ventana de contexto amplia.
  3. Se buscan objetos JSON completos ({...}) dentro de esa ventana.
  4. Cada objeto JSON candidato se valida estructuralmente con el validador.
  5. Se extraen los metadatos no cifrados (dirección pública, algoritmos).
"""

import re
from pathlib import Path

import yara

from src.validators.keystore_validator import (
    parse_keystore,
    is_valid_keystore,
    extract_metadata,
    confidence_label,
)

RULE_PATH = Path(__file__).parent.parent.parent / "rules" / "keystore.yar"
CONTEXT_WINDOW = 4096  # keystores son más grandes que seeds BIP39


class KeystoreHit:
    def __init__(self, offset: int, raw_json: str, valid: bool, metadata: dict):
        self.offset = offset
        self.raw_json = raw_json
        self.valid = valid
        self.metadata = metadata

    def to_dict(self) -> dict:
        return {
            "type": "METAMASK_KEYSTORE",
            "offset": hex(self.offset),
            "valid_structure": self.valid,
            "confidence": confidence_label(
                parse_keystore(self.raw_json) or {}
            ),
            **self.metadata,
        }

    def __repr__(self):
        addr = self.metadata.get("address") or "sin dirección"
        status = "VÁLIDO" if self.valid else "candidato"
        return f"<KeystoreHit offset={hex(self.offset)} {status} addr={addr}>"


def _extract_json_objects(text: str) -> list[tuple[str, int]]:
    """
    Extrae objetos JSON completos ({...}) de un fragmento de texto,
    respetando anidamiento. Devuelve lista de (json_str, offset_en_texto).
    Salta candidatos malformados (con basura binaria) y sigue buscando.
    """
    results = []
    i = 0
    while i < len(text):
        if text[i] != "{":
            i += 1
            continue

        depth = 0
        obj_start = i
        in_string = False
        escaped = False
        found_end = False

        for j in range(i, min(i + 8192, len(text))):  # límite de 8KB por objeto
            c = text[j]
            if escaped:
                escaped = False
                continue
            if c == "\\" and in_string:
                escaped = True
                continue
            if c == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[obj_start:j + 1]
                    results.append((candidate, obj_start))
                    i = j + 1
                    found_end = True
                    break

        if not found_end:
            i += 1  # esta { no cerró bien, probamos la siguiente

    return results


def scan_buffer(data: bytes) -> list[KeystoreHit]:
    """Escanea un buffer de bytes buscando keystores V3."""
    rules = yara.compile(filepath=str(RULE_PATH))
    matches = rules.match(data=data)

    hits = []
    seen = set()

    for match in matches:
        # Recogemos todos los offsets de esta regla y tomamos el mínimo
        # como ancla — así la ventana empieza antes del primer campo
        # y captura el JSON completo sin importar qué string disparó primero
        all_offsets = [
            inst.offset
            for sm in match.strings
            for inst in sm.instances
        ]
        if not all_offsets:
            continue

        first_field = min(all_offsets)
        last_field = max(all_offsets)
        # Expandimos en ambas direcciones para capturar el { inicial y el } final
        start = max(0, first_field - 512)
        end = min(len(data), last_field + 512)

        try:
            context = data[start:end].decode("utf-8", errors="ignore")
        except Exception:
            continue

        for json_str, rel_offset in _extract_json_objects(context):
            key = json_str[:64]
            if key in seen:
                continue
            seen.add(key)

            parsed = parse_keystore(json_str)
            if parsed is None:
                continue

            valid = is_valid_keystore(parsed)
            metadata = extract_metadata(parsed) if valid else {}
            abs_offset = start + rel_offset

            hits.append(KeystoreHit(abs_offset, json_str, valid, metadata))

    return hits


def scan_file(path: str) -> list[KeystoreHit]:
    """Escanea un fichero completo (dump .raw, .vmem, etc.)."""
    with open(path, "rb") as f:
        data = f.read()
    return scan_buffer(data)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Uso: python keystore_detector.py <fichero_a_escanear>")
        sys.exit(1)

    results = scan_file(sys.argv[1])
    print(f"\n{len(results)} candidato(s) encontrado(s):\n")
    for hit in results:
        print(hit)
        if hit.valid:
            for k, v in hit.metadata.items():
                print(f"   {k}: {v}")
