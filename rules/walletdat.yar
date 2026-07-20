rule Bitcoin_Core_Wallet_Dat
{
    meta:
        description = "Detecta fragmentos de wallet.dat de Bitcoin Core (Berkeley DB)"
        author      = "CryptoWatcher"
        reference   = "https://en.bitcoin.it/wiki/Wallet"
        severity    = "critical"

    strings:
        // Magic bytes de Berkeley DB (Btree, el formato que usa Bitcoin Core)
        $bdb_magic_btree = { 00 05 31 62 }

        // Magic bytes Berkeley DB Hash (versiones antiguas)
        $bdb_magic_hash  = { 00 05 31 61 }

        // Cadena de versión que Bitcoin Core escribe en el wallet
        $bitcoin_version = "Bitcoin Core version" ascii

        // Cadena de copyright presente en el header del wallet
        $bitcoin_str     = "Bitcoin" ascii wide

        // Tipo de campo 'key' en la base de datos BDB de la wallet
        // Bitcoin Core usa la clave "\x03key" para indexar claves privadas
        $key_field       = { 03 6B 65 79 }

        // Tipo de campo 'name' — relaciona direcciones con etiquetas
        $name_field      = { 04 6E 61 6D 65 }

        // Tipo de campo 'defaultkey' — la dirección por defecto de la wallet
        $defaultkey      = { 0A 64 65 66 61 75 6C 74 6B 65 79 }

        // Prefijo DER de clave privada EC (secp256k1) en claro
        // Secuencia: 0x30 (SEQUENCE) + longitud + 0x02 (INTEGER) + ...
        $ec_privkey_der  = { 30 74 02 01 01 04 20 }

    condition:
        // La firma BDB es la evidencia principal
        // Combinada con cualquier campo interno de wallet.dat
        (1 of ($bdb_magic_*)) and
        (1 of ($key_field, $name_field, $defaultkey, $bitcoin_str, $bitcoin_version, $ec_privkey_der))
}
