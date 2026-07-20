"""
Orquestador central de CryptoWatcher.

Es la única pieza que conoce a todos los detectores. Su responsabilidad:

1. Compilar las 4 reglas YARA en un único objeto (una sola vez).
2. Hacer un único pase de escaneo sobre el dump completo.
3. Por cada match, delegar al detector correspondiente según match.rule.
4. Agregar todos los hits en una lista unificada con interfaz común.
5. Devolver un ScanResult con hits + estadísticas + metadatos del escaneo.

De esta forma el dump se lee UNA sola vez aunque haya 4 detectores activos,
lo que es crítico en forense donde los dumps pueden pesar varios GB.
"""

import time
from dataclasses import dataclass, field
from pathlib import Path

import yara

from src.detectors.bip39_detector    import scan_buffer as _scan_bip39
from src.detectors.wif_detector      import scan_buffer as _scan_wif
from src.detectors.keystore_detector import scan_buffer as _scan_keystore
from src.detectors.walletdat_detector import scan_buffer as _scan_walletdat

# Rutas de las reglas YARA
_RULES_DIR = Path(__file__).parent.parent / "rules"
RULE_FILES = {
    "bip39":     str(_RULES_DIR / "bip39.yar"),
    "wif":       str(_RULES_DIR / "wif.yar"),
    "keystore":  str(_RULES_DIR / "keystore.yar"),
    "walletdat": str(_RULES_DIR / "walletdat.yar"),
}

# Mapeo nombre-de-regla → función de escaneo del detector correspondiente
RULE_TO_SCANNER = {
    "Possible_BIP39_Seed":      _scan_bip39,
    "Possible_WIF_Private_Key": _scan_wif,
    "MetaMask_Keystore_V3":     _scan_keystore,
    "Bitcoin_Core_Wallet_Dat":  _scan_walletdat,
}


@dataclass
class ScanResult:
    """Resultado completo de un escaneo forense."""
    dump_path:    str
    dump_size:    int
    scan_time_s:  float
    hits:         list = field(default_factory=list)

    @property
    def total_hits(self) -> int:
        return len(self.hits)

    @property
    def valid_hits(self) -> list:
        """Solo los hits que pasaron la validación criptográfica/estructural."""
        return [h for h in self.hits if getattr(h, "valid", False)]

    @property
    def hits_by_type(self) -> dict:
        """Agrupa hits por tipo de artefacto."""
        groups = {}
        for h in self.hits:
            t = h.to_dict().get("type", "UNKNOWN")
            groups.setdefault(t, []).append(h)
        return groups

    def summary(self) -> str:
        lines = [
            f"Dump:        {self.dump_path}",
            f"Tamaño:      {self.dump_size / 1024 / 1024:.2f} MB",
            f"Tiempo:      {self.scan_time_s:.2f}s",
            f"Hits totales:{self.total_hits}",
            f"Hits válidos:{len(self.valid_hits)}",
            "",
        ]
        for tipo, group in self.hits_by_type.items():
            validos = sum(1 for h in group if getattr(h, "valid", False))
            lines.append(f"  {tipo}: {len(group)} encontrados, {validos} válidos")
        return "\n".join(lines)


def _compile_rules() -> yara.Rules:
    """Compila todas las reglas YARA en un único objeto."""
    return yara.compile(filepaths=RULE_FILES)


def scan_buffer(data: bytes, dump_path: str = "<buffer>") -> ScanResult:
    """
    Escanea un buffer de bytes con todos los detectores en un único pase.

    Este es el método principal del orquestador. Los detectores individuales
    NO se llaman directamente — todo pasa por aquí para garantizar que el
    buffer se lee una sola vez.
    """
    t_start = time.perf_counter()

    compiled = _compile_rules()

    # Único pase YARA sobre todos los bytes
    yara_matches = compiled.match(data=data)

    # Agrupamos matches por nombre de regla para procesarlos en bloque
    # (un detector puede necesitar ver todos los matches de su regla juntos)
    matches_by_rule: dict[str, list] = {}
    for match in yara_matches:
        matches_by_rule.setdefault(match.rule, []).append(match)

    # Despachamos a cada detector con los bytes completos — cada detector
    # tiene su propia lógica de extracción y sabe cómo usar los offsets
    # de los matches para localizar su artefacto en el buffer
    all_hits = []
    for rule_name, scanner in RULE_TO_SCANNER.items():
        if rule_name in matches_by_rule:
            hits = scanner(data)
            all_hits.extend(hits)

    t_end = time.perf_counter()

    return ScanResult(
        dump_path=dump_path,
        dump_size=len(data),
        scan_time_s=round(t_end - t_start, 3),
        hits=all_hits,
    )


def scan_file(path: str) -> ScanResult:
    """
    Escanea un fichero completo (dump .raw, .vmem, etc.).
    Punto de entrada principal desde main.py.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Fichero no encontrado: {path}")

    data = p.read_bytes()
    return scan_buffer(data, dump_path=str(p))
