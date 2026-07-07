import requests

# Titulo
print('=================================')
print('   Detector de Vulnerabilidades  ')
print('=================================')

def seguir():
    # Pausa el flujo y valida si el usuario quiere continuar o salir
    respuesta = input('\n[ENTER] para escanear otro sitio o [Cualquier letra] para salir: ')
    if respuesta == "":
        return True  # Continúa
    else:
        print("Saliendo del detector. ¡Mantente seguro!")
        return False  # Detiene el programa

def escanear_vulnerabilidades(url):
    print(f"\n[+] Iniciando análisis en: {url}")
    if not url.startswith("http"):
        url = "http://" + url

    try:
        # Realizamos la petición web
        respuesta = requests.get(url, timeout=5)
        cabeceras = respuesta.headers
        
        # 1. Verificación de Cabeceras de Seguridad Faltantes
        print("\n--- Analizando Cabeceras de Seguridad ---")
        cabeceras_criticas = {
            "X-Frame-Options": "Vulnerable a Clickjacking (Falta protección de marcos).",
            "X-XSS-Protection": "Falta protección nativa contra XSS en navegadores antiguos.",
            "Content-Security-Policy": "Falta política CSP (Riesgo alto de inyección de scripts/XSS)."
        }
        
        vulnerabilidades_encontradas = 0
        for cabecera, riesgo in cabeceras_criticas.items():
            if cabecera not in cabeceras:
                print(f"[ALERTA] Misión crítica: {cabecera} no está presente.")
                print(f"         Riesgo: {riesgo}")
                vulnerabilidades_encontradas += 1
        
        # 2. Prueba básica de Inyección XSS en parámetros reflejados
        print("\n--- Probando Inyección XSS Básica ---")
        payload_xss = "<script>alert(1)</script>"
        # Probamos enviando el payload en un parámetro común de búsqueda (?q=)
        url_test = f"{url}?q={payload_xss}"
        respuesta_xss = requests.get(url_test, timeout=5)
        
        if payload_xss in respuesta_xss.text:
            print("[CRÍTICO] ¡Posible vulnerabilidad de XSS Reflejado detectada!")
            print(f"          El script malicioso se reflejó intacto en el HTML de la página.")
            vulnerabilidades_encontradas += 1
        else:
            print("[OK] El parámetro de prueba parece sanitizar el contenido o no lo refleja.")

        # Resumen
        print(f"\n[Análisis Terminado] Se detectaron {vulnerabilidades_encontradas} vulnerabilidades potenciales.")

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] No se pudo conectar al sitio web: {e}")

# --- Bucle Principal del Programa ---
ejecutando = True
while ejecutando:
    sitio = input("\nIntroduce la URL del sitio objetivo (ej: https://example.com): ")
    if sitio.strip() != "":
        escanear_vulnerabilidades(sitio)
    else:
        print("[!] Por favor introduce una URL válida.")
        
    # Llamamos a tu función para decidir si el bucle continúa activo
    ejecutando = seguir()

