"""
Validador estructural de fragmentos de wallet.dat de Bitcoin Core.

wallet.dat es un fichero Berkeley DB binario. Su detección en un volcado
de memoria es diferente a BIP39/WIF/keystore porque:

1. Es completamente binario — no hay texto legible como las seeds BIP39.
2. Puede aparecer fragmentado en memoria (páginas BDB no contiguas).
3. La validación principal es la presencia de los magic bytes BDB y de
   campos internos reconocibles del esquema de wallet.dat.
4. Las claves privadas pueden estar cifradas (si el usuario puso passphrase
   con 'encryptwallet') o en claro (si la wallet estaba sin cifrar o
   desbloqueada en el momento del volcado de memoria).

Lo que podemos extraer sin descifrar nada:
- Confirmación de presencia de BDB (evidencia de wallet Bitcoin Core)
- Tipo de cifrado si está presente (AES-256-CBC + PBKDF2 en Bitcoin Core)
- Potencialmente claves en claro si la wallet no tenía passphrase
"""

# Magic bytes de Berkeley DB en los primeros bytes de cada página BDB
BDB_MAGIC_BTREE = b"\x00\x05\x31\x62"  # formato Btree (el estándar)
BDB_MAGIC_HASH  = b"\x00\x05\x31\x61"  # formato Hash (versiones antiguas)
BDB_MAGICS = (BDB_MAGIC_BTREE, BDB_MAGIC_HASH)

# Campos conocidos del esquema interno de wallet.dat
KNOWN_FIELDS = {
    b"\x03key":         "clave privada EC",
    b"\x04name":        "etiqueta de dirección",
    b"\x07version":     "versión del wallet",
    b"\x04pool":        "pool de claves de reserva",
    b"\x0Adefaultkey":  "dirección por defecto",
    b"\x04mkey":        "clave maestra cifrada (wallet cifrado)",
    b"\x08keymeta":     "metadatos de clave",
}

# Prefijo DER de clave privada EC secp256k1 en claro
EC_PRIVKEY_DER_PREFIX = b"\x30\x74\x02\x01\x01\x04\x20"

# Campo 'mkey' indica que el wallet tiene passphrase (está cifrado)
ENCRYPTED_WALLET_MARKER = b"mkey"


def has_bdb_magic(fragment: bytes) -> bool:
    """Verifica que el fragmento contiene la firma de Berkeley DB."""
    return any(magic in fragment for magic in BDB_MAGICS)


def detect_fields(fragment: bytes) -> list[str]:
    """Identifica qué campos de wallet.dat son reconocibles en el fragmento."""
    found = []
    for field_bytes, description in KNOWN_FIELDS.items():
        if field_bytes in fragment:
            found.append(description)
    return found


def is_encrypted(fragment: bytes) -> bool:
    """Detecta si el wallet tiene passphrase (campo mkey presente)."""
    return ENCRYPTED_WALLET_MARKER in fragment


def has_plaintext_keys(fragment: bytes) -> bool:
    """
    Detecta si hay claves privadas en claro en el fragmento.
    Esto ocurre si el wallet no tiene passphrase, o si se volcó
    la memoria mientras el wallet estaba desbloqueado.
    """
    return EC_PRIVKEY_DER_PREFIX in fragment


def is_valid_walletdat(fragment: bytes) -> bool:
    """
    Verifica que el fragmento tiene características reconocibles de wallet.dat.
    Criterio mínimo: firma BDB + al menos un campo conocido.
    """
    if not has_bdb_magic(fragment):
        return False
    return len(detect_fields(fragment)) > 0


def extract_metadata(fragment: bytes) -> dict:
    """
    Extrae los metadatos que podemos recuperar del fragmento sin descifrar.
    """
    fields = detect_fields(fragment)
    encrypted = is_encrypted(fragment)
    plaintext_keys = has_plaintext_keys(fragment)

    bdb_type = "Btree"
    if BDB_MAGIC_HASH in fragment:
        bdb_type = "Hash (versión antigua)"

    severity_note = ""
    if plaintext_keys and not encrypted:
        severity_note = "CRÍTICO: claves privadas posiblemente en claro"
    elif encrypted:
        severity_note = "Wallet cifrado con passphrase (AES-256-CBC)"
    else:
        severity_note = "Sin passphrase detectada, claves potencialmente recuperables"

    return {
        "bdb_format": bdb_type,
        "fields_found": fields,
        "encrypted": encrypted,
        "plaintext_keys_possible": plaintext_keys,
        "severity_note": severity_note,
    }


def confidence_label(fragment: bytes) -> str:
    """Etiqueta legible para el informe forense."""
    if is_valid_walletdat(fragment):
        fields = detect_fields(fragment)
        return f"ALTA - wallet.dat BDB detectado, campos: {', '.join(fields)}"
    return "BAJA - firma BDB sin campos reconocibles de wallet.dat"
