"""
CryptoWatcher - Crypto Forensics Memory Scanner
================================================
Punto de entrada principal. Uso:

    python3 main.py --dump <fichero> [--output <informe.txt>] [--verbose]

Argumentos:
    --dump      Ruta al volcado de memoria (.raw, .vmem, .mem, .bin)
    --output    Ruta del informe de salida (por defecto: cryptowatcher_<timestamp>.txt)
    --verbose   Muestra el informe completo en pantalla además de guardarlo
    --no-file   No guarda el informe en disco, solo muestra por pantalla
"""

import argparse
import hashlib
import sys
import time
from datetime import datetime
from pathlib import Path

# Colores ANSI para la terminal (se desactivan si no hay TTY)
_TTY = sys.stdout.isatty()
RED    = "\033[91m" if _TTY else ""
YELLOW = "\033[93m" if _TTY else ""
GREEN  = "\033[92m" if _TTY else ""
CYAN   = "\033[96m" if _TTY else ""
RESET  = "\033[0m"  if _TTY else ""
BOLD   = "\033[1m"  if _TTY else ""


def _banner():
    print(f"{BOLD}################################################################{RESET}")
    print(f"{BOLD}##                                                            ##{RESET}")
    print(f"{BOLD}##   CRYPTOWATCHER - Crypto Forensics Memory Scanner          ##{RESET}")
    print(f"{BOLD}##                                                            ##{RESET}")
    print(f"{BOLD}################################################################{RESET}")
    print()


def _info(msg: str):
    print(f"{CYAN}[*]{RESET} {msg}")


def _ok(msg: str):
    print(f"{GREEN}[+]{RESET} {msg}")


def _warn(msg: str):
    print(f"{YELLOW}[!]{RESET} {msg}")


def _critical(msg: str):
    print(f"{RED}[-]{RESET} {msg}")


def _error(msg: str):
    print(f"{RED}[ERROR]{RESET} {msg}", file=sys.stderr)


def _sha256(path: Path) -> str:
    """Calcula el SHA-256 del dump — parte de la cadena de custodia forense."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _default_output(dump_path: Path) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return str(dump_path.parent / f"cryptowatcher_{ts}.txt")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="cryptowatcher",
        description="Escanea volcados de memoria buscando artefactos de wallets de criptomonedas.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
ejemplos:
  python3 main.py --dump memdump.raw
  python3 main.py --dump memdump.raw --output informe.txt --verbose
  python3 main.py --dump memdump.raw --no-file
        """,
    )
    parser.add_argument(
        "--dump", "-d",
        required=True,
        metavar="FICHERO",
        help="Volcado de memoria a analizar (.raw, .vmem, .mem, .bin)",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="INFORME",
        help="Ruta del informe de salida (por defecto: cryptowatcher_<timestamp>.txt)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Muestra el informe completo en pantalla",
    )
    parser.add_argument(
        "--symbols", "-s",
        metavar="DIRECTORIO",
        help="Directorio con ficheros ISF de Volatility3 para enriquecimiento completo (opcional)",
    )
    parser.add_argument(
        "--no-file",
        action="store_true",
        help="No guarda el informe en disco (implica --verbose)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    _banner()

    # ── Validar el dump ───────────────────────────────────────
    dump_path = Path(args.dump)
    if not dump_path.exists():
        _error(f"Fichero no encontrado: {dump_path}")
        sys.exit(1)

    size_mb = dump_path.stat().st_size / 1024 / 1024
    _info(f"Dump     : {dump_path.resolve()}")
    _info(f"Tamaño   : {size_mb:.2f} MB")
    if args.symbols:
        _info(f"Símbolos : {args.symbols}")
    else:
        _info("Símbolos : automático (usar --symbols para especificar ruta ISF)")

    # ── Hash SHA-256 para cadena de custodia ──────────────────
    _info("Calculando SHA-256 del dump (cadena de custodia)...")
    t0 = time.perf_counter()
    sha256 = _sha256(dump_path)
    _info(f"SHA-256  : {sha256}")
    _info(f"Hash calculado en {time.perf_counter()-t0:.2f}s")
    print()

    # ── Escaneo ───────────────────────────────────────────────
    _info("Cargando reglas YARA y lanzando escaneo...")

    try:
        from src.orchestrator import scan_file
        result = scan_file(str(dump_path), symbols_path=args.symbols)
    except Exception as e:
        _error(f"Error durante el escaneo: {e}")
        sys.exit(1)

    _info(f"Escaneo completado en {result.scan_time_s:.2f}s")
    print()

    # ── Resumen rápido en pantalla ────────────────────────────
    if result.total_hits == 0:
        _ok("No se encontraron artefactos de wallets en este dump.")
    else:
        hits_by_type = result.hits_by_type
        for tipo, hits in hits_by_type.items():
            validos = sum(1 for h in hits if getattr(h, "valid", False)
                          or h.to_dict().get("valid_structure", False))
            criticos = sum(
                1 for h in hits
                if _severity_level(h) == "CRÍTICO"
            )
            altos = sum(
                1 for h in hits
                if _severity_level(h) == "ALTO"
            )
            if criticos:
                _critical(f"{tipo}: {len(hits)} encontrado(s), {criticos} CRÍTICO(s)")
            elif altos:
                _warn(f"{tipo}: {len(hits)} encontrado(s), {altos} ALTO(s)")
            else:
                _ok(f"{tipo}: {len(hits)} encontrado(s), {validos} válido(s)")

    print()

    # ── Generar informe ───────────────────────────────────────
    try:
        from src.reporters.txt_reporter import generate
    except Exception as e:
        _error(f"No se pudo cargar el reporter: {e}")
        sys.exit(1)

    if args.no_file:
        report_text = generate(result)
        print(report_text)
        return

    output_path = args.output or _default_output(dump_path)
    generate(result, output_path=output_path)
    _ok(f"Informe guardado en: {output_path}")

    if args.verbose:
        print()
        print(open(output_path).read())


def _severity_level(hit) -> str:
    """Replica la lógica de severidad del reporter para el resumen de pantalla."""
    d = hit.to_dict()
    tipo = d.get("type", "")
    valid = getattr(hit, "valid", False) or d.get("valid_structure", False)

    if not valid:
        return "BAJO"
    if tipo == "METAMASK_KEYSTORE":
        return "ALTO"
    if tipo == "BITCOIN_CORE_WALLET_DAT":
        return "BAJO" if d.get("encrypted", False) else "CRÍTICO"
    return "CRÍTICO"


if __name__ == "__main__":
    main()
