"""
Capa de enriquecimiento con Volatility3 para CryptoWatcher.

Funciona en dos niveles según lo que esté disponible:

NIVEL BÁSICO (sin perfil ISF — siempre disponible):
  - Identifica el SO y kernel del dump (banners.Banners)
  - Extrae contexto textual alrededor de cada offset donde YARA encontró
    un hit: strings cercanos que puedan indicar el proceso o aplicación
    de origen (referencias a "chrome", "bitcoin-qt", "python", etc.)

NIVEL COMPLETO (con perfil ISF — opcional):
  - Lista procesos activos (linux.pslist / windows.pslist)
  - Mapea cada hit al proceso propietario de esa región de memoria
  - Se activa automáticamente si el ISF está disponible en:
      a) El directorio de símbolos por defecto de Volatility3
      b) La ruta especificada con --symbols en la línea de comandos

Selección de perfil:
  - Sin --symbols: Volatility3 busca automáticamente en sus directorios
    internos (volatility3/volatility3/symbols/linux|windows|mac/)
  - Con --symbols /ruta/: busca primero en esa ruta, luego en los internos
  - El perfil correcto se identifica por el banner del dump — Volatility3
    compara la cadena del kernel con el nombre del fichero ISF disponible
"""

import re
import subprocess
import sys
from pathlib import Path

# Palabras clave que sugieren el proceso de origen del artefacto
PROCESS_HINTS = {
    "chrome":      "Google Chrome",
    "brave":       "Brave Browser",
    "firefox":     "Firefox",
    "metamask":    "MetaMask",
    "bitcoin":     "Bitcoin Core",
    "electrum":    "Electrum Wallet",
    "python":      "Python",
    "node":        "Node.js",
    "java":        "Java",
    "wallet":      "aplicación de wallet",
    "exodus":      "Exodus Wallet",
    "atomic":      "Atomic Wallet",
    "trust":       "Trust Wallet",
}

CONTEXT_RADIUS = 512


class VolatilityContext:
    """Contexto extraído por Volatility para un hit concreto."""

    def __init__(self):
        self.os_banner:        str       = "desconocido"
        self.process_hint:     str       = "desconocido"
        self.nearby_strings:   list[str] = []
        self.profile_available:bool      = False
        self.process_name:     str|None  = None
        self.pid:              int|None  = None
        self.symbols_path:     str|None  = None

    def to_dict(self) -> dict:
        return {
            "os_banner":         self.os_banner,
            "process_hint":      self.process_hint,
            "nearby_strings":    self.nearby_strings[:5],
            "profile_available": self.profile_available,
            "process_name":      self.process_name,
            "pid":               self.pid,
            "symbols_path":      self.symbols_path,
        }

    def summary(self) -> str:
        if self.process_name:
            return f"{self.process_name} (PID {self.pid})"
        if self.process_hint != "desconocido":
            level = "con perfil ISF" if self.profile_available else "sin perfil ISF"
            return f"posiblemente {self.process_hint} ({level})"
        return "proceso no identificado (sin perfil ISF)"


def _vol_script() -> Path | None:
    """Localiza el script vol.py de Volatility3."""
    candidate = Path(__file__).parent.parent.parent / "volatility3" / "vol.py"
    return candidate if candidate.exists() else None


def _run_vol(dump_path: str, plugin: str,
             symbols_path: str | None = None,
             extra_args: list[str] | None = None) -> str:
    """
    Ejecuta un plugin de Volatility3 y devuelve su salida como string.

    symbols_path: directorio adicional donde buscar ficheros ISF.
                  Se pasa a Volatility con el flag -s.
    """
    vol = _vol_script()
    if vol is None:
        return ""

    cmd = [sys.executable, str(vol), "-f", dump_path]

    # Añadir directorio de símbolos si se especificó
    if symbols_path:
        cmd += ["-s", symbols_path]

    cmd.append(plugin)

    if extra_args:
        cmd.extend(extra_args)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def _profile_available(dump_path: str, symbols_path: str | None = None) -> bool:
    """
    Comprueba si hay un perfil ISF disponible para este dump.
    Intenta ejecutar linux.pslist o windows.pslist y ve si responde.
    """
    for plugin in ("linux.pslist.PsList", "windows.pslist.PsList"):
        out = _run_vol(dump_path, plugin, symbols_path=symbols_path)
        if out and "Unsatisfied requirement" not in out and "Error" not in out:
            return True
    return False


def _detect_os(banner: str) -> str:
    """Determina si el dump es Linux o Windows a partir del banner."""
    if "Linux" in banner:
        return "linux"
    if "Windows" in banner:
        return "windows"
    return "unknown"


def get_os_banner(dump_path: str, symbols_path: str | None = None) -> str:
    """
    Extrae la cadena de versión del SO del dump usando banners.Banners.
    Funciona siempre, sin necesidad de perfil ISF.
    """
    output = _run_vol(dump_path, "banners.Banners", symbols_path=symbols_path)
    if not output:
        return "desconocido"

    for line in output.splitlines():
        if "Linux version" in line or "Windows" in line:
            match = re.search(r"(Linux version \S+|Windows \S+[^\(]*)", line)
            if match:
                return match.group(1).strip()

    return "desconocido"


def _get_process_list(dump_path: str, os_type: str,
                      symbols_path: str | None = None) -> list[dict]:
    """
    Obtiene la lista de procesos del dump si el perfil ISF está disponible.
    Devuelve lista de {pid, name, ppid, offset} o [] si no hay perfil.
    """
    plugin = {
        "linux":   "linux.pslist.PsList",
        "windows": "windows.pslist.PsList",
    }.get(os_type)

    if not plugin:
        return []

    output = _run_vol(dump_path, plugin, symbols_path=symbols_path)
    if not output or "Unsatisfied requirement" in output:
        return []

    processes = []
    for line in output.splitlines():
        parts = line.split()
        # Formato típico: PID  PPID  ImageFileName  Offset  ...
        if len(parts) >= 3 and parts[0].isdigit():
            try:
                processes.append({
                    "pid":    int(parts[0]),
                    "ppid":   int(parts[1]) if parts[1].isdigit() else 0,
                    "name":   parts[2],
                    "offset": parts[3] if len(parts) > 3 else "0x0",
                })
            except (ValueError, IndexError):
                continue

    return processes


def _find_owner_process(hit_offset: int, processes: list[dict]) -> dict | None:
    """
    Intenta atribuir un hit a un proceso basándose en el offset de memoria.
    Heurística simple: busca el proceso cuyo offset de inicio sea el más
    cercano al offset del hit sin superarlo.
    """
    if not processes:
        return None

    candidates = []
    for proc in processes:
        try:
            proc_offset = int(proc["offset"], 16)
            if proc_offset <= hit_offset:
                candidates.append((hit_offset - proc_offset, proc))
        except (ValueError, TypeError):
            continue

    if not candidates:
        return None

    # El más cercano por debajo
    candidates.sort(key=lambda x: x[0])
    return candidates[0][1]


def _extract_nearby_strings(data: bytes, offset: int,
                             radius: int = CONTEXT_RADIUS) -> list[str]:
    """Extrae strings ASCII legibles de la región alrededor de un offset."""
    start = max(0, offset - radius)
    end = min(len(data), offset + radius)
    region = data[start:end]

    strings = re.findall(rb"[\x20-\x7e]{4,80}", region)
    decoded = []
    for s in strings:
        try:
            text = s.decode("ascii").strip()
            if text and not text.isspace():
                decoded.append(text)
        except UnicodeDecodeError:
            continue

    return decoded[:20]


def _detect_process_hint(strings: list[str]) -> str:
    """Identifica la aplicación de origen por strings cercanos."""
    combined = " ".join(strings).lower()
    for keyword, app_name in PROCESS_HINTS.items():
        if keyword in combined:
            return app_name
    return "desconocido"


def enrich_hits(hits: list, dump_path: str, dump_data: bytes,
                symbols_path: str | None = None) -> list:
    """
    Enriquece los hits del orquestador con contexto de Volatility.

    symbols_path: directorio adicional de ISF especificado por el usuario
                  con --symbols en la línea de comandos. Si es None,
                  Volatility3 usa solo sus directorios internos.

    Para cada hit añade .vol_context con:
      - Banner del SO (siempre disponible)
      - Strings cercanos al offset
      - Hint del proceso de origen
      - Atribución exacta a proceso (solo si el perfil ISF está disponible)
    """
    # Banner del SO — una sola llamada para todos los hits
    os_banner = get_os_banner(dump_path, symbols_path=symbols_path)
    os_type   = _detect_os(os_banner)

    # Comprobar si hay perfil disponible e intentar listar procesos
    has_profile = _profile_available(dump_path, symbols_path=symbols_path)
    processes   = _get_process_list(dump_path, os_type,
                                    symbols_path=symbols_path) if has_profile else []

    for hit in hits:
        ctx = VolatilityContext()
        ctx.os_banner        = os_banner
        ctx.profile_available = has_profile
        ctx.symbols_path     = symbols_path

        # Strings cercanos al offset del hit
        raw_offset = hit.to_dict().get("offset", "0x0")
        offset = int(raw_offset, 16) if isinstance(raw_offset, str) else raw_offset
        nearby = _extract_nearby_strings(dump_data, offset)
        ctx.nearby_strings = nearby
        ctx.process_hint   = _detect_process_hint(nearby)

        # Atribución a proceso si hay perfil ISF
        if has_profile and processes:
            owner = _find_owner_process(offset, processes)
            if owner:
                ctx.process_name = owner["name"]
                ctx.pid          = owner["pid"]

        hit.vol_context = ctx

    return hits


def enrich_file(hits: list, dump_path: str,
                symbols_path: str | None = None) -> list:
    """
    Versión de enrich_hits que lee el dump desde disco.
    Punto de entrada principal desde el orquestador.
    """
    data = Path(dump_path).read_bytes()
    return enrich_hits(hits, dump_path, data, symbols_path=symbols_path)
