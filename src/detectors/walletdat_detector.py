"""
Detector de wallet.dat de Bitcoin Core en volcados de memoria.

wallet.dat es binario puro (Berkeley DB), por lo que el enfoque es
completamente distinto al de BIP39/WIF (texto) o keystore (JSON):

1. YARA localiza regiones con la firma BDB + campos de wallet.dat.
2. Por cada match se extrae una ventana de contexto binaria (no se
   decodifica a texto — trabajamos con bytes directamente).
3. El validador analiza los bytes para confirmar estructura BDB y
   extraer los metadatos disponibles.

La dificultad específica: en memoria, wallet.dat aparece en páginas BDB
de 4096 bytes cada una, posiblemente dispersas. Trabajamos con lo que
YARA encuentre, sin intentar reconstruir la estructura BDB completa.
"""

from pathlib import Path

import yara

from src.validators.walletdat_validator import (
    is_valid_walletdat,
    extract_metadata,
    confidence_label,
)

RULE_PATH = Path(__file__).parent.parent.parent / "rules" / "walletdat.yar"
CONTEXT_WINDOW = 8192  # páginas BDB son de 4096 bytes, cogemos 2 por si acaso


class WalletDatHit:
    def __init__(self, offset: int, fragment: bytes, valid: bool, metadata: dict):
        self.offset = offset
        self.fragment = fragment
        self.valid = valid
        self.metadata = metadata

    def to_dict(self) -> dict:
        return {
            "type": "BITCOIN_CORE_WALLET_DAT",
            "offset": hex(self.offset),
            "fragment_size": len(self.fragment),
            "valid_structure": self.valid,
            "confidence": confidence_label(self.fragment),
            **self.metadata,
        }

    def __repr__(self):
        status = "VÁLIDO" if self.valid else "candidato"
        note = self.metadata.get("severity_note", "")
        return f"<WalletDatHit offset={hex(self.offset)} {status} | {note}>"


def scan_buffer(data: bytes) -> list[WalletDatHit]:
    """Escanea un buffer de bytes buscando fragmentos de wallet.dat."""
    rules = yara.compile(filepath=str(RULE_PATH))
    matches = rules.match(data=data)

    hits = []
    seen_offsets = set()

    for match in matches:
        all_offsets = [
            inst.offset
            for sm in match.strings
            for inst in sm.instances
        ]
        if not all_offsets:
            continue

        anchor = min(all_offsets)
        # Redondeamos al inicio de la página BDB más cercana (múltiplo de 4096)
        page_start = (anchor // 4096) * 4096
        start = max(0, page_start)
        end = min(len(data), start + CONTEXT_WINDOW)

        # Deduplicar por página BDB (no por offset exacto)
        page_key = start // CONTEXT_WINDOW
        if page_key in seen_offsets:
            continue
        seen_offsets.add(page_key)

        fragment = data[start:end]

        valid = is_valid_walletdat(fragment)
        metadata = extract_metadata(fragment) if valid else {}

        hits.append(WalletDatHit(start, fragment, valid, metadata))

    return hits


def scan_file(path: str) -> list[WalletDatHit]:
    """Escanea un fichero completo (dump .raw, .vmem, etc.)."""
    with open(path, "rb") as f:
        data = f.read()
    return scan_buffer(data)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Uso: python walletdat_detector.py <fichero_a_escanear>")
        sys.exit(1)

    results = scan_file(sys.argv[1])
    print(f"\n{len(results)} candidato(s) encontrado(s):\n")
    for hit in results:
        print(hit)
        if hit.valid:
            for k, v in hit.metadata.items():
                print(f"   {k}: {v}")
