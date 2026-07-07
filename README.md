# 🛡️ Detector de Vulnerabilidades Web (VulnScanner)

Un escáner de vulnerabilidades web básico e interactivo desarrollado en Python. Este script analiza cabeceras de seguridad críticas ausentes en servidores web y realiza pruebas automatizadas de inyección de scripts (XSS Reflejado).

## 🚀 Características
- **Control de Flujo Dinámico:** Permite pausar y continuar el escaneo en múltiples sitios interactuando con la tecla `[ENTER]`.
- **Análisis de Cabeceras:** Detecta la ausencia de `X-Frame-Options`, `X-XSS-Protection` y `Content-Security-Policy`.
- **Módulo XSS Básico:** Envía payloads de prueba para verificar la sanitización de parámetros reflejados.

## 🛠️ Instalación y Requisitos

1. Clona este repositorio:
   ```bash
   git clone https://github.com
   ```
2. Accede al directorio del proyecto:
   ```bash
   cd TU_REPOSITORIO
   ```
3. Instala las dependencias necesarias:
   ```bash
   pip install -r requirements.txt
   ```

## 💻 Uso
Para ejecutar el escáner, simplemente corre el archivo principal:
```bash
python main.py
```

## ⚠️ Descargo de Responsabilidad (Disclaimer)
Este proyecto fue desarrollado exclusivamente con fines educativos y de aprendizaje en ciberseguridad. El autor no se hace responsable del uso indebido de esta herramienta en entornos o servidores sin la autorización previa y explícita de sus propietarios.
