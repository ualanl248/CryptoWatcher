"""
Reporter de texto plano para CryptoWatcher.

Genera informes forenses en formato .txt con el estilo de herramientas
como Chipsec o Volatility: cabeceras con marcos de #, prefijos de estado
[+]/[-]/[!]/[*], secciones bien delimitadas, y resumen numérico al final.

Prefijos usados:
    [-]  CRÍTICO  — artefacto válido de máxima severidad (seed, WIF, wallet sin cifrar)
    [!]  ALTO     — artefacto válido de alta severidad (keystore cifrado)
    [~]  BAJO     — candidato sin checksum válido (posible falso positivo)
    [*]  INFO     — metadato o línea informativa
"""

import textwrap
from datetime import datetime
from pathlib import Path

from src.orchestrator import ScanResult

_WIDTH = 64  # anchura del marco de #


def _line(char: str = "#") -> str:
    return char * _WIDTH


def _box(text: str) -> str:
    """Genera una línea de cabecera centrada dentro del marco ##."""
    inner = _WIDTH - 4  # descuenta '## ' y ' ##'
    padded = text.center(inner)
    return f"## {padded} ##"


def _wrap(text: str, indent: int = 4, width: int = 56) -> str:
    """Parte texto largo en varias líneas con indentación fija."""
    prefix = " " * indent
    return textwrap.fill(text, width=width, initial_indent=prefix,
                         subsequent_indent=prefix)


def _severity(hit) -> tuple[str, str]:
    """
    Devuelve (prefijo, etiqueta_severidad) según el tipo y validez del hit.
    """
    d = hit.to_dict()
    tipo = d.get("type", "")
    valid = getattr(hit, "valid", False) or d.get("valid_structure", False)

    if not valid:
        return "[~]", "BAJO"

    if tipo == "METAMASK_KEYSTORE":
        return "[!]", "ALTO"

    if tipo == "BITCOIN_CORE_WALLET_DAT":
        encrypted = d.get("encrypted", False)
        if not encrypted:
            return "[-]", "CRÍTICO"
        return "[!]", "ALTO"

    # BIP39 y WIF válidos son siempre críticos
    return "[-]", "CRÍTICO"


def _format_hit(hit) -> list[str]:
    """Formatea un hit individual como bloque de líneas."""
    d = hit.to_dict()
    tipo = d.get("type", "UNKNOWN")
    offset = d.get("offset", "?")
    confianza = d.get("confidence", "desconocida")
    prefix, severity = _severity(hit)

    lines = [f"{prefix} {tipo}"]
    lines.append(f"    offset     : {offset}")
    lines.append(f"    severidad  : {severity}")
    lines.append(f"    confianza  : {confianza}")

    # Campos específicos por tipo
    if tipo == "BIP39_SEED":
        words = d.get("words", "")
        word_list = words.split()
        line1 = " ".join(word_list[:6])
        line2 = " ".join(word_list[6:])
        lines.append(f"    palabras   : {line1}")
        if line2:
            lines.append(f"                 {line2}")
        lines.append(f"    checksum   : {'válido (SHA-256)' if d.get('valid_checksum') else 'inválido'}")
        lines.append(f"    num_palabras: {d.get('word_count', '?')}")

    elif tipo == "WIF_PRIVATE_KEY":
        val = d.get("value", "")
        # Truncamos la clave en el informe por seguridad (primeros/últimos 8 chars)
        if len(val) > 20:
            val_display = f"{val[:8]}...{val[-8:]}"
        else:
            val_display = val
        lines.append(f"    clave      : {val_display}")
        lines.append(f"    checksum   : {'válido (SHA-256x2)' if d.get('valid_checksum') else 'inválido'}")

    elif tipo == "METAMASK_KEYSTORE":
        lines.append(f"    dirección  : {d.get('address') or 'no encontrada'}")
        lines.append(f"    cifrado    : {d.get('cipher', '?')} · {d.get('kdf', '?')}")
        lines.append(f"    resist.BF  : {d.get('bruteforce_resistance', '?')}")
        lines.append(f"    wallet_id  : {d.get('wallet_id') or '?'}")

    elif tipo == "BITCOIN_CORE_WALLET_DAT":
        fields = ", ".join(d.get("fields_found", []))
        lines.append(f"    formato    : {d.get('bdb_format', '?')}")
        lines.append(f"    campos     : {fields}")
        lines.append(f"    cifrado    : {'sí (passphrase detectada)' if d.get('encrypted') else 'NO (claves en claro)'}")
        lines.append(f"    nota       : {d.get('severity_note', '')}")

    # Contexto de Volatility (si está disponible)
    lines.extend(_format_vol_context(hit))
    lines.append("")  # línea en blanco entre hits
    return lines


def generate(result: ScanResult, output_path: str | None = None) -> str:
    """
    Genera el informe completo en texto plano.

    Si output_path es None devuelve el texto como string.
    Si output_path es una ruta, escribe el fichero y devuelve la ruta.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []

    # ── Cabecera ──────────────────────────────────────────────
    lines += [
        _line(),
        _box(""),
        _box("CRYPTOWATCHER - Crypto Forensics Memory Scanner"),
        _box(""),
        _line(),
        "",
        f"[*] Generado  : {now}",
        f"[*] Dump      : {result.dump_path}",
        f"[*] Tamaño    : {result.dump_size / 1024 / 1024:.2f} MB",
        f"[*] Tiempo    : {result.scan_time_s:.2f}s",
        f"[*] Hits total: {result.total_hits}",
        f"[*] Válidos   : {len(result.valid_hits)}",
        "",
    ]

    # ── Hallazgos ─────────────────────────────────────────────
    lines += [
        _line(),
        _box("HALLAZGOS"),
        _line(),
        "",
    ]

    if not result.hits:
        lines.append("[*] No se encontraron artefactos de wallets en este dump.")
        lines.append("")
    else:
        # Primero los críticos, luego altos, luego bajos
        def sort_key(h):
            _, sev = _severity(h)
            return {"CRÍTICO": 0, "ALTO": 1, "BAJO": 2}.get(sev, 3)

        for hit in sorted(result.hits, key=sort_key):
            lines.extend(_format_hit(hit))

    # ── Resumen ───────────────────────────────────────────────
    criticos = sum(1 for h in result.hits if _severity(h)[1] == "CRÍTICO")
    altos    = sum(1 for h in result.hits if _severity(h)[1] == "ALTO")
    bajos    = sum(1 for h in result.hits if _severity(h)[1] == "BAJO")

    lines += [
        _line(),
        _box("RESUMEN"),
        _line(),
        "",
        f"[-]  CRÍTICO  : {criticos}",
        f"[!]  ALTO     : {altos}",
        f"[~]  BAJO     : {bajos}",
        "",
    ]

    # ── Recomendaciones ───────────────────────────────────────
    lines += [
        _line(),
        _box("RECOMENDACIONES"),
        _line(),
        "",
    ]

    if criticos > 0:
        lines += [
            "[-] Se encontraron artefactos de criticidad máxima.",
            "    Acciones sugeridas:",
            "    · Preservar el dump como evidencia (hash SHA-256).",
            "    · Revocar/transferir fondos de las wallets afectadas.",
            "    · Investigar el proceso de origen con Volatility.",
            "",
        ]
    if altos > 0:
        lines += [
            "[!] Se encontraron keystores o wallets cifrados.",
            "    Acciones sugeridas:",
            "    · Registrar las direcciones públicas para trazado en blockchain.",
            "    · Conservar el keystore para análisis posterior si se obtiene",
            "      la contraseña por otras vías (keylogger, ingeniería social).",
            "",
        ]
    if criticos == 0 and altos == 0:
        lines += [
            "[+] No se encontraron artefactos válidos de alta severidad.",
            "    El dump no contiene evidencia de wallets activas o",
            "    las claves están suficientemente protegidas.",
            "",
        ]

    lines += [_line(), ""]

    report = "\n".join(lines)

    if output_path:
        Path(output_path).write_text(report, encoding="utf-8")
        return output_path

    return report


def _format_vol_context(hit) -> list[str]:
    """
    Añade sección de contexto de Volatility al hit si está disponible.
    """
    ctx = getattr(hit, "vol_context", None)
    if ctx is None:
        return []

    lines = ["    -- contexto Volatility --"]
    lines.append(f"    SO detectado : {ctx.os_banner}")
    lines.append(f"    Origen       : {ctx.summary()}")

    if ctx.nearby_strings:
        # Filtramos strings que contengan palabras clave relevantes
        relevant = [s for s in ctx.nearby_strings
                    if any(k in s.lower() for k in
                           ["chrome","bitcoin","wallet","metamask","python",
                            "brave","firefox","electrum","key","seed","crypto"])]
        if relevant:
            lines.append(f"    Strings clave: {relevant[0][:60]}")
            for s in relevant[1:3]:
                lines.append(f"                   {s[:60]}")

    return lines
