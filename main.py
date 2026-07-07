import sys
import os
import requests
from datetime import datetime
from bs4 import BeautifulSoup

class VulnerabilityScanner:
    """Escáner profesional avanzado para auditar seguridad web básica."""
    
    def __init__(self):
        self.headers_to_check = {
            "X-Frame-Options": "Vulnerable a Clickjacking (Falta protección de marcos).",
            "X-XSS-Protection": "Falta protección nativa contra XSS en navegadores antiguos.",
            "Content-Security-Policy": "Falta política CSP (Riesgo alto de inyección de scripts/XSS)."
        }

    def verificar_cabeceras(self, headers, reporte) -> int:
        """Analiza la presencia de cabeceras de seguridad críticas."""
        print("\n=== [1] Analizando Cabeceras de Seguridad ===")
        reporte.append("\n=== [1] Analizando Cabeceras de Seguridad ===")
        fallos = 0
        
        for cabecera, riesgo in self.headers_to_check.items():
            if cabecera not in headers:
                msg = f"[ALERTA] Faltante: {cabecera}\n         Riesgo: {riesgo}"
                print(msg)
                reporte.append(msg)
                fallos += 1
                
        if fallos == 0:
            msg = "[OK] Todas las cabeceras base de seguridad están presentes."
            print(msg)
            reporte.append(msg)
        return fallos

    def extraer_formularios(self, url, html_content):
        """Busca y extrae de forma automática todos los formularios e inputs de la web."""
        soup = BeautifulSoup(html_content, 'html.parser')
        forms = soup.find_all('form')
        lista_formularios = []
        
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = []
            for input_tag in form.find_all('input'):
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                if input_name:
                    inputs.append({"name": input_name, "type": input_type})
            
            lista_formularios.append({
                "action": action,
                "method": method,
                "inputs": inputs
            })
        return lista_formularios

    def probar_xss_avanzado(self, url, formularios, reporte) -> int:
        """Inyecta payloads XSS dinámicamente en los formularios mapeados."""
        print("\n=== [2] Probando Inyección XSS Avanzada ===")
        reporte.append("\n=== [2] Probando Inyección XSS Avanzada ===")
        
        if not formularios:
            msg = "[INFO] No se encontraron formularios HTML interactivos visibles para probar XSS."
            print(msg)
            reporte.append(msg)
            return 0
            
        payload = "<script>alert(1)</script>"
        vulnerabilidades = 0
        
        for idx, form in enumerate(formularios, 1):
            target_url = url if not form['action'] else requests.compat.urljoin(url, form['action'])
            datos_prueba = {}
            
            for inp in form['inputs']:
                if inp['type'] in ['text', 'search', 'password', 'email']:
                    datos_prueba[inp['name']] = payload
                else:
                    datos_prueba[inp['name']] = "test"
            
            try:
                if form['method'] == 'post':
                    respuesta = requests.post(target_url, data=datos_prueba, timeout=5)
                else:
                    respuesta = requests.get(target_url, params=datos_prueba, timeout=5)
                    
                if payload in respuesta.text:
                    msg = f"[CRÍTICO] ¡XSS Reflejado Detectado! En Formulario #{idx} -> Campo destino: {target_url}"
                    print(msg)
                    reporte.append(msg)
                    vulnerabilidades += 1
            except requests.RequestException:
                continue
                
        if vulnerabilidades == 0:
            msg = "[OK] Los formularios analizados parecen sanitizar las entradas de XSS."
            print(msg)
            reporte.append(msg)
            
        return vulnerabilidades

    def probar_sqli_avanzado(self, url, formularios, reporte) -> int:
        """Busca fallas de SQL Injection enviando comillas a los formularios mapeados."""
        print("\n=== [3] Probando Inyección SQL (SQLi) Avanzada ===")
        reporte.append("\n=== [3] Probando Inyección SQL (SQLi) Avanzada ===")
        
        if not formularios:
            msg = "[INFO] No se encontraron formularios interactivos para probar SQLi."
            print(msg)
            reporte.append(msg)
            return 0
            
        payload = "'"
        vulnerabilidades = 0
        errores_sql = ["sql syntax", "mysql_fetch", "ora-", "postgres", "microsoft oledb", "driver error"]
        
        for idx, form in enumerate(formularios, 1):
            target_url = url if not form['action'] else requests.compat.urljoin(url, form['action'])
            datos_prueba = {inp['name']: payload for inp in form['inputs']}
            
            try:
                if form['method'] == 'post':
                    respuesta = requests.post(target_url, data=datos_prueba, timeout=5)
                else:
                    respuesta = requests.get(target_url, params=datos_prueba, timeout=5)
                    
                for error in errores_sql:
                    if error in respuesta.text.lower():
                        msg = f"[CRÍTICO] ¡Fallo potencial de SQLi en Formulario #{idx}!\n          Error de base de datos expuesto en: {target_url}\n          Firma: '{error}'"
                        print(msg)
                        reporte.append(msg)
                        vulnerabilidades += 1
                        break
            except requests.RequestException:
                continue
                
        if vulnerabilidades == 0:
            msg = "[OK] No se detectaron firmas estructurales de errores SQL en formularios."
            print(msg)
            reporte.append(msg)
            
        return vulnerabilidades

    def guardar_reporte_txt(self, url, lineas_reporte):
        """Crea un archivo .txt con un formato de reporte limpio y ordenado."""
        nombre_limpio = url.replace("http://", "").replace("https://", "").replace("/", "_").replace(":", "")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        nombre_archivo = f"reporte_{nombre_limpio}_{timestamp}.txt"
        
        try:
            with open(nombre_archivo, "w", encoding="utf-8") as archivo:
                archivo.write("\n".join(lineas_reporte))
            print(f"\n[📁 REPORTES] Guardado con éxito como: '{nombre_archivo}'")
        except IOError as e:
            print(f"\n[!] Error al intentar generar el archivo de reporte técnico: {e}")

    def escanear(self, url):
        """Controlador maestro de la auditoría."""
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
            
        # Almacenamiento dinámico de datos para el reporte txt
        lineas_reporte = [
            "==================================================",
            "        REPORTE TÉCNICO DE VULNERABILIDADES       ",
            "==================================================",
            f"Fecha del análisis: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Objetivo auditado : {url}",
            "=================================================="
        ]
            
        print(f"\n[+] Iniciando auditoría automatizada avanzada en: {url}")
        try:
            respuesta = requests.get(url, timeout=5, headers={"User-Agent": "VulnScanner/3.0"})
            
            # Descubrimiento automático de la estructura web
            formularios = self.extraer_formularios(url, respuesta.text)
            print(f"[INFO] Se mapearon automáticamente {len(formularios)} formularios interactivos en la página.")
            lineas_reporte.append(f"[INFO] Se mapearon automáticamente {len(formularios)} formularios interactivos.")
            
            vulnerabilidades = 0
            vulnerabilidades += self.verificar_cabeceras(respuesta.headers, lineas_reporte)
            vulnerabilidades += self.probar_xss_avanzado(url, formularios, lineas_reporte)
            vulnerabilidades += self.probar_sqli_avanzado(url, formularios, lineas_reporte)
            
            resumen = f"\n[Análisis Terminado] Hallazgos potenciales totales: {vulnerabilidades}"
            print(resumen)
            lineas_reporte.append(resumen)
            
            # Guardamos la auditoría
            self.guardar_reporte_txt(url, lineas_reporte)
            
        except requests.exceptions.ConnectionError:
            print("[ERROR] No se pudo establecer conexión. El servidor está caído o la URL no existe.")
        except requests.exceptions.Timeout:
            print("[ERROR] La petición excedió el tiempo límite (Timeout).")
        except Exception as e:
            print(f"[ERROR INESPERADO] {e}")

def seguir() -> bool:
    entrada = input('\n[ENTER] Escanear otra URL | [Cualquier tecla + ENTER] Salir: ')
    if entrada == "":
        return True
    print("\nCerrando el detector. ¡Mantente seguro!")
    return False

def main():
    print("==================================================")
    print("      🛡️  DETECTOR DE VULNERABILIDADES V3.0  🛡️")
    print("==================================================")
    
    escanner = VulnerabilityScanner()
    
    while True:
        objetivo = input("\nIntroduce la URL objetivo (ej: testfire.net): ").strip()
        if objetivo:
            escanner.escanear(objetivo)
        else:
            print("[!] La URL no puede estar vacía.")
            
        if not seguir():
            sys.exit(0)

if __name__ == "__main__":
    main()

