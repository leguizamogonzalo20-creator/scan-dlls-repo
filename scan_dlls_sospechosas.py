"""
scan_dlls_sospechosas.py

Herramienta defensiva para ayudar a detectar DLLs potencialmente
maliciosas (spyware, adware, etc.) en Windows.

Qué hace:
  1. Recorre una carpeta (o el directorio de un proceso) buscando archivos .dll
  2. Calcula el hash SHA256 de cada uno
  3. Verifica si el archivo tiene firma digital válida (usando PowerShell
     Get-AuthenticodeSignature, disponible en cualquier Windows)
  4. Extrae metadatos básicos (compañía, versión) si están disponibles
  5. (Opcional) Consulta el hash contra VirusTotal si tenés una API key
  6. Genera un reporte marcando cuáles archivos son sospechosos

Qué NO hace:
  - No elimina ni modifica archivos automáticamente (revisión manual
    antes de borrar es más seguro)
  - No reemplaza un antivirus real; es una herramienta de triage

Uso:
    python scan_dlls_sospechosas.py "C:\\ruta\\a\\revisar" [--vt-api-key TU_KEY] [--recursivo]

Requiere: Python 3.8+, Windows (usa PowerShell internamente para firmas)
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error


def calcular_sha256(ruta_archivo, chunk_size=8192):
    """Calcula el hash SHA256 de un archivo sin cargarlo entero en memoria."""
    sha256 = hashlib.sha256()
    try:
        with open(ruta_archivo, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, OSError) as e:
        return None


def verificar_firma_digital(ruta_archivo):
    """
    Usa PowerShell (Get-AuthenticodeSignature) para verificar si el DLL
    está firmado digitalmente y si la firma es válida.
    Devuelve un dict con 'estado' y 'firmante'.
    """
    try:
        ps_cmd = (
            f"$r = Get-AuthenticodeSignature -FilePath '{ruta_archivo}'; "
            "Write-Output ($r.Status.ToString() + '|' + "
            "$(if ($r.SignerCertificate) {$r.SignerCertificate.Subject} else {'Sin firmante'}))"
        )
        resultado = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=15
        )
        salida = resultado.stdout.strip()
        if "|" in salida:
            estado, firmante = salida.split("|", 1)
            return {"estado": estado, "firmante": firmante}
        return {"estado": "Desconocido", "firmante": "N/A"}
    except Exception as e:
        return {"estado": f"Error: {e}", "firmante": "N/A"}


def obtener_metadatos(ruta_archivo):
    """Extrae metadatos básicos del DLL (compañía, versión) vía PowerShell."""
    try:
        ps_cmd = (
            f"$f = Get-Item '{ruta_archivo}'; "
            "$vi = $f.VersionInfo; "
            "Write-Output ($vi.CompanyName + '|' + $vi.FileDescription + '|' + $vi.FileVersion)"
        )
        resultado = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=15
        )
        partes = resultado.stdout.strip().split("|")
        while len(partes) < 3:
            partes.append("")
        return {
            "compania": partes[0].strip() or "(vacío)",
            "descripcion": partes[1].strip() or "(vacío)",
            "version": partes[2].strip() or "(vacío)",
        }
    except Exception:
        return {"compania": "(error)", "descripcion": "(error)", "version": "(error)"}


def consultar_virustotal(hash_sha256, api_key):
    """
    Consulta el hash contra la API pública de VirusTotal v3.
    Requiere una API key gratuita de virustotal.com
    """
    url = f"https://www.virustotal.com/api/v3/files/{hash_sha256}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "encontrado": True,
                "maliciosos": stats.get("malicious", 0),
                "sospechosos": stats.get("suspicious", 0),
                "total_motores": sum(stats.values()),
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"encontrado": False, "nota": "Hash no encontrado en VirusTotal"}
        return {"encontrado": False, "nota": f"Error HTTP {e.code}"}
    except Exception as e:
        return {"encontrado": False, "nota": f"Error: {e}"}


def evaluar_sospecha(firma, metadatos, vt_resultado):
    """Aplica heurísticas simples para marcar un archivo como sospechoso."""
    razones = []

    if firma["estado"] not in ("Valid",):
        razones.append(f"Firma digital no válida (estado: {firma['estado']})")

    if metadatos["compania"] == "(vacío)" and metadatos["descripcion"] == "(vacío)":
        razones.append("Sin metadatos de compañía/descripción")

    if vt_resultado:
        if vt_resultado.get("maliciosos", 0) > 0:
            razones.append(
                f"VirusTotal: {vt_resultado['maliciosos']} motores lo marcan como malicioso"
            )
        if vt_resultado.get("sospechosos", 0) > 0:
            razones.append(
                f"VirusTotal: {vt_resultado['sospechosos']} motores lo marcan como sospechoso"
            )

    return razones


def escanear_carpeta(carpeta, recursivo, vt_api_key):
    resultados = []

    if recursivo:
        caminador = os.walk(carpeta)
    else:
        caminador = [(carpeta, [], os.listdir(carpeta))]

    archivos_dll = []
    for raiz, _, archivos in caminador:
        for archivo in archivos:
            if archivo.lower().endswith(".dll"):
                archivos_dll.append(os.path.join(raiz, archivo))

    print(f"Encontrados {len(archivos_dll)} archivos .dll. Analizando...\n")

    for i, ruta in enumerate(archivos_dll, 1):
        print(f"[{i}/{len(archivos_dll)}] {ruta}")

        hash_sha256 = calcular_sha256(ruta)
        if hash_sha256 is None:
            print("  -> No se pudo leer el archivo (permisos)\n")
            continue

        firma = verificar_firma_digital(ruta)
        metadatos = obtener_metadatos(ruta)

        vt_resultado = None
        if vt_api_key:
            vt_resultado = consultar_virustotal(hash_sha256, vt_api_key)
            time.sleep(15)  # límite de la API pública: 4 consultas/minuto

        razones = evaluar_sospecha(firma, metadatos, vt_resultado)

        item = {
            "ruta": ruta,
            "sha256": hash_sha256,
            "firma": firma,
            "metadatos": metadatos,
            "virustotal": vt_resultado,
            "sospechoso": len(razones) > 0,
            "razones": razones,
        }
        resultados.append(item)

        if razones:
            print(f"  ⚠ SOSPECHOSO: {'; '.join(razones)}")
        else:
            print("  ✓ Sin indicadores de riesgo")
        print()

    return resultados


def generar_reporte(resultados, ruta_salida="reporte_dlls.json"):
    sospechosos = [r for r in resultados if r["sospechoso"]]

    with open(ruta_salida, "w", encoding="utf-8") as f:
        json.dump(resultados, f, indent=2, ensure_ascii=False)

    print("=" * 60)
    print(f"RESUMEN: {len(sospechosos)} de {len(resultados)} DLLs marcados como sospechosos")
    print(f"Reporte completo guardado en: {ruta_salida}")
    print("=" * 60)

    if sospechosos:
        print("\nArchivos sospechosos:")
        for r in sospechosos:
            print(f"  - {r['ruta']}")
            for razon in r["razones"]:
                print(f"      · {razon}")

    print(
        "\nIMPORTANTE: revisá manualmente cada archivo antes de eliminarlo. "
        "Este script NO borra nada automáticamente."
    )


def main():
    parser = argparse.ArgumentParser(
        description="Escanea DLLs en busca de indicadores de spyware/malware."
    )
    parser.add_argument("carpeta", help="Carpeta a analizar")
    parser.add_argument(
        "--recursivo", action="store_true",
        help="Analizar también subcarpetas"
    )
    parser.add_argument(
        "--vt-api-key", default=None,
        help="API key de VirusTotal (opcional, gratuita en virustotal.com)"
    )
    parser.add_argument(
        "--salida", default="reporte_dlls.json",
        help="Nombre del archivo de reporte JSON"
    )

    args = parser.parse_args()

    if not os.path.isdir(args.carpeta):
        print(f"Error: '{args.carpeta}' no es una carpeta válida.")
        sys.exit(1)

    if sys.platform != "win32":
        print(
            "Aviso: la verificación de firma digital y metadatos usa PowerShell "
            "y está pensada para Windows. En otros sistemas, esas partes fallarán "
            "silenciosamente pero el hash y VirusTotal seguirán funcionando."
        )

    resultados = escanear_carpeta(args.carpeta, args.recursivo, args.vt_api_key)
    generar_reporte(resultados, args.salida)


if __name__ == "__main__":
    main()
