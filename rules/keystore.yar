rule MetaMask_Keystore_V3
{
    meta:
        description = "Detecta keystores Web3 Secret Storage V3 (MetaMask, Geth, MyCrypto...)"
        author      = "CryptoWatcher"
        reference   = "https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition"
        severity    = "high"

    strings:
        // Campos obligatorios del estándar V3
        $f_ciphertext  = "\"ciphertext\""  ascii wide nocase
        $f_cipher      = "\"cipher\""      ascii wide nocase
        $f_kdf         = "\"kdf\""         ascii wide nocase
        $f_mac         = "\"mac\""         ascii wide nocase
        $f_version     = "\"version\""     ascii wide nocase

        // Valores conocidos del estándar
        $v_aes         = "aes-128-ctr"     ascii wide nocase
        $v_scrypt      = "scrypt"          ascii wide nocase
        $v_pbkdf2      = "pbkdf2"          ascii wide nocase

    condition:
        // Todos los campos estructurales obligatorios + algoritmo conocido
        // La ventana real la controla el detector Python (CONTEXT_WINDOW)
        all of ($f_*) and 1 of ($v_*)
}
