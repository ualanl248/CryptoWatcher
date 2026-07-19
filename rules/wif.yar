rule Possible_WIF_Private_Key
{
    meta:
        description = "Detecta posibles claves privadas Bitcoin en formato WIF"
        author = "CryptoWatcher"
        reference = "https://en.bitcoin.it/wiki/Wallet_import_format"
        severity = "critical"

    strings:
        // WIF sin comprimir: empieza por '5', longitud total 51 caracteres
        $wif_uncompressed = /5[1-9A-HJ-NP-Za-km-z]{50}/

        // WIF comprimida: empieza por 'K' o 'L', longitud total 52 caracteres
        $wif_compressed = /[KL][1-9A-HJ-NP-Za-km-z]{51}/

    condition:
        any of them
}
