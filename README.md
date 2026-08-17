# scan-dlls-sospechosas

Herramienta de línea de comandos en Python para ayudar a detectar DLLs
potencialmente maliciosas (spyware, adware, etc.) en sistemas Windows.

## ⚠️ Descargo de responsabilidad

Esta herramienta es de **triage y apoyo al diagnóstico**. No reemplaza un
antivirus real, no elimina archivos automáticamente y puede generar falsos
positivos (DLLs legítimas sin firma o con metadatos vacíos). Revisá siempre
manualmente cada resultado antes de tomar acción sobre un archivo.

## Qué hace

- Recorre una carpeta (opcionalmente de forma recursiva) buscando archivos `.dll`.
- Calcula el hash **SHA256** de cada archivo.
- Verifica la **firma digital** (Authenticode) vía PowerShell.
- Extrae **metadatos** básicos (compañía, descripción, versión).
- Opcionalmente consulta el hash contra **VirusTotal** (requiere API key propia).
- Genera un reporte en JSON marcando qué archivos son sospechosos y por qué.

## Requisitos

- Python 3.8+
- Windows (la verificación de firma y metadatos usa PowerShell; en otros
  sistemas operativos esas partes no funcionan, pero el hash y VirusTotal sí).
- (Opcional) API key gratuita de [VirusTotal](https://www.virustotal.com/) para
  la consulta de reputación.

No requiere dependencias externas de Python — usa solo la librería estándar.

## Instalación

```bash
git clone https://github.com/TU_USUARIO/scan-dlls-sospechosas.git
cd scan-dlls-sospechosas
```

No hace falta `pip install` nada (ver `requirements.txt`, está vacío a propósito).

## Uso

Escaneo simple de una carpeta:

```bash
python scan_dlls_sospechosas.py "C:\Windows\System32"
```

Escaneo recursivo (incluye subcarpetas):

```bash
python scan_dlls_sospechosas.py "C:\ruta\a\revisar" --recursivo
```

Con consulta a VirusTotal:

```bash
python scan_dlls_sospechosas.py "C:\ruta" --recursivo --vt-api-key TU_API_KEY
```

Cambiar el nombre del archivo de salida:

```bash
python scan_dlls_sospechosas.py "C:\ruta" --salida mi_reporte.json
```

## Salida

El script imprime el progreso en consola y genera un archivo JSON
(`reporte_dlls.json` por defecto) con el detalle de cada DLL analizada:
hash, estado de firma, metadatos, resultado de VirusTotal (si aplica) y
las razones por las que fue marcado como sospechoso, si corresponde.

## Procedimiento manual recomendado

Además de esta herramienta, para una investigación completa se recomienda:

1. **Autoruns** (Sysinternals) — revisar persistencia (Logon, Services, Scheduled Tasks).
2. **Process Explorer** (Sysinternals) — inspeccionar DLLs cargadas por proceso.
3. **Process Monitor** (Sysinternals) — analizar comportamiento en tiempo real.
4. Escaneo final con un antivirus actualizado (Windows Defender Offline, Malwarebytes, etc.).

## Licencia

MIT — ver [LICENSE](LICENSE).
