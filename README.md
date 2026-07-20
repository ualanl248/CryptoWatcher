# CryptoWatcher

CryptoWatcher es una herramienta que implementa reglas YARA para la 
detección de claves privadas (WIF), frases semilla (BIP39), estructuras keystore y 
archivos wallet.dat en blobs de bytes. 

Asimismo queda pendiente la implementación de una capa de Volatility para una detección
más precisa que tenga en cuenta también la estructura de la memoria del volcado, no 
limitándose solo al blob de bytes.

Sintáxis básica:

## Uso básico — guarda el informe automáticamente
python3 main.py --dump evidence/dumps/memdump.raw

## Con informe en pantalla también
python3 main.py --dump evidence/dumps/memdump.raw --verbose

## Solo pantalla, sin guardar fichero
python3 main.py --dump evidence/dumps/memdump.raw --no-file

## Especificar nombre del informe
python3 main.py --dump evidence/dumps/memdump.raw --output informes/caso_01.txt
