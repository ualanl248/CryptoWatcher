# CryptoWatcher

CryptoWatcher es una herramienta de forense de memoria que implementa reglas YARA para la detección de claves privadas (WIF), frases semilla (BIP39), estructuras keystore y archivos wallet.dat en volcados de RAM. Permite identificar y clasificar material criptográfico sensible directamente sobre evidencia sin modificarla, generando un informe forense en texto plano con los hallazgos, su nivel de confianza y recomendaciones de actuación.

---

## ¿Qué detecta?

| Artefacto | Descripción | Severidad |
|---|---|---|
| **BIP39 seed phrase** | Frases de 12/15/18/21/24 palabras que dan acceso completo a una wallet HD | Crítica |
| **Clave privada WIF** | Claves privadas Bitcoin en formato Wallet Import Format, listas para importar | Crítica |
| **Keystore MetaMask** | Ficheros JSON cifrados de MetaMask/Geth (Web3 Secret Storage V3) | Alta |
| **wallet.dat** | Base de datos Berkeley DB de Bitcoin Core, con o sin passphrase | Crítica |

Cada artefacto detectado se valida criptográficamente (checksum BIP39, doble SHA-256 para WIF, estructura V3 para keystores, magic bytes BDB para wallet.dat) para minimizar falsos positivos antes de incluirlo en el informe.

---

## Requisitos

- Python 3.10 o superior
- Ubuntu/Debian (probado en Ubuntu 24.04)
- Entorno virtual Python (`venv`)

Dependencias Python (instaladas automáticamente con el paso de instalación):

```
yara-python
hdwallet
construct
colorama
jinja2
pytest
volatility3
```

---

## Instalación

```bash
# 1. Clona el repositorio
git clone https://github.com/tuusuario/CryptoWatcher.git
cd CryptoWatcher

# 2. Crea el entorno virtual
python3 -m venv .venv
source .venv/bin/activate

# 3. Instala las dependencias
pip install -r requirements.txt

# 4. (Opcional) Clona Volatility3 para usar sus plugins directamente
git clone https://github.com/volatilityfoundation/volatility3.git
```

---

## Estructura del proyecto

```
CryptoWatcher/
├── main.py                          # Punto de entrada principal
├── requirements.txt
├── README.md
├── rules/                           # Reglas YARA por tipo de artefacto
│   ├── bip39.yar
│   ├── wif.yar
│   ├── keystore.yar
│   └── walletdat.yar
├── src/
│   ├── orchestrator.py              # Escaneo unificado (un único pase YARA)
│   ├── detectors/                   # Extracción y procesamiento por tipo
│   │   ├── bip39_detector.py
│   │   ├── bip39_wordlist.txt
│   │   ├── wif_detector.py
│   │   ├── keystore_detector.py
│   │   └── walletdat_detector.py
│   ├── validators/                  # Validación criptográfica/estructural
│   │   ├── bip39_validator.py
│   │   ├── wif_validator.py
│   │   ├── keystore_validator.py
│   │   └── walletdat_validator.py
│   ├── volatility_plugins/          # Capa de enriquecimiento con Volatility3
│   │   └── enricher.py
│   └── reporters/
│       └── txt_reporter.py          # Informe en texto plano estilo Chipsec
├── evidence/
│   └── dumps/                       # Coloca aquí los volcados a analizar
├── volatility3/                     # Repositorio de Volatility3 (opcional)
└── tests/                           # Tests unitarios con pytest
```

---

## Uso

### Sintaxis básica

```bash
python3 main.py --dump evidence/dumps/memdump.raw
```

### Opciones disponibles

```
--dump     / -d   Ruta al volcado de memoria (.raw, .vmem, .mem, .bin)  [obligatorio]
--output   / -o   Ruta del informe de salida (por defecto: cryptowatcher_<timestamp>.txt)
--verbose  / -v   Muestra el informe completo en pantalla además de guardarlo
--symbols  / -s   Directorio con ficheros ISF de Volatility3 (enriquecimiento completo)
--no-file         No guarda el informe en disco, solo muestra por pantalla
```

### Ejemplos

```bash
# Uso básico — guarda el informe automáticamente con timestamp
python3 main.py --dump evidence/dumps/memdump.raw

# Con informe en pantalla también
python3 main.py --dump evidence/dumps/memdump.raw --verbose

# Solo pantalla, sin guardar fichero
python3 main.py --dump evidence/dumps/memdump.raw --no-file

# Especificar nombre del informe
python3 main.py --dump evidence/dumps/memdump.raw --output informes/caso_01.txt

# Con perfil ISF de Volatility3 para enriquecimiento completo por proceso
python3 main.py --dump evidence/dumps/memdump.raw --symbols /ruta/a/mis/isf/
```

### Enriquecimiento con Volatility3 y perfiles ISF

La capa de Volatility3 funciona en dos niveles:

**Nivel básico (sin perfil ISF — siempre disponible):** identifica el SO del dump mediante `banners.Banners` y extrae strings cercanos al offset de cada hallazgo para inferir el proceso de origen.

**Nivel completo (con perfil ISF):** lista los procesos activos y atribuye cada hallazgo al proceso propietario de esa región de memoria (nombre + PID). Requiere el fichero ISF correspondiente al kernel del dump.

Para activar el nivel completo, coloca el fichero ISF en el directorio de símbolos de Volatility3 o indícalo con `--symbols`:

```bash
# Opción A — directorio interno de Volatility3 (detección automática)
cp mi_perfil.json.xz volatility3/volatility3/symbols/linux/
python3 main.py --dump evidence/dumps/memdump.raw

# Opción B — directorio externo especificado por argumento
python3 main.py --dump evidence/dumps/memdump.raw --symbols /ruta/a/mis/isf/
```

Si no hay perfil ISF disponible, la herramienta funciona igualmente en nivel básico sin mostrar errores.

---

### Ejemplo de salida

```
################################################################
##                                                            ##
##   CRYPTOWATCHER - Crypto Forensics Memory Scanner          ##
##                                                            ##
################################################################

[*] Dump     : /evidence/dumps/memdump.raw
[*] Tamaño   : 1023.49 MB
[*] Símbolos : automático (usar --symbols para especificar ruta ISF)
[*] SHA-256  : 3eb202361a8b6963330e8bd4c9d7e81ceff07d81e3c1bffb1b47ef678bf01717
[*] Escaneo completado en 3.42s

[-] BIP39_SEED: 1 encontrado(s), 1 CRÍTICO(s)
[-] WIF_PRIVATE_KEY: 1 encontrado(s), 1 CRÍTICO(s)
[!] METAMASK_KEYSTORE: 1 encontrado(s), 1 ALTO(s)
```

El informe completo incluye offset de memoria, nivel de confianza, metadatos extraídos por tipo de artefacto, contexto de Volatility, resumen de severidad y recomendaciones forenses.

---

## Notas forenses

- La herramienta es **no destructiva**: solo lee el volcado, nunca lo modifica.
- El hash SHA-256 calculado al inicio sirve como elemento de **cadena de custodia**.
- Las claves WIF se muestran truncadas en el informe (`5HueCGU8...vbTLvyTJ`) para evitar exponer material sensible en logs.
- Un keystore MetaMask detectado **no implica acceso a fondos** — la clave privada está cifrada con la contraseña del usuario. Su valor forense es la dirección pública (trazable en blockchain) y la posibilidad de ataque offline si se obtiene la contraseña por otras vías.
- Las semillas BIP39 y claves WIF encontradas con checksum válido **sí implican acceso directo a fondos** si el sistema fue comprometido.
- Los resultados BIP39 aplican filtros heurísticos (unicidad de palabras, ratio de términos de UI) además del checksum criptográfico para reducir falsos positivos en dumps con texto de aplicaciones.

---

## Aviso legal

Esta herramienta está diseñada exclusivamente para uso en investigaciones forenses legítimas sobre sistemas de los que se tiene autorización expresa. El uso sobre sistemas ajenos sin autorización puede constituir un delito. El autor no se responsabiliza del uso indebido de esta herramienta.
