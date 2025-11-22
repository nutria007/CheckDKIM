# Verificador de Autenticación de Email (DKIM/ARC/SPF)

Una aplicación en Python para verificar firmas digitales DKIM, cadenas ARC y registros SPF en correos electrónicos. Esta herramienta proporciona análisis detallado y verificación criptográfica de la autenticidad e integridad de mensajes de correo electrónico.

## Características

- **Verificación DKIM**: Valida firmas DKIM para confirmar la autenticidad del remitente
- **Verificación ARC**: Verifica cadenas ARC (Authenticated Received Chain) para correos reenviados
- **Verificación SPF**: Valida registros SPF para verificar que el servidor está autorizado a enviar correos
- **Análisis detallado**: Proporciona información exhaustiva sobre cabeceras de autenticación
- **Diagnósticos**: Explica las causas de fallos en la verificación
- **Formato visual**: Salida organizada y fácil de leer con separadores y códigos de estado
- **Registro de resultados**: Guarda automáticamente un archivo de texto con todos los resultados en el mismo directorio del email analizado

## Instalación

### Requisitos previos

- Python 3.6 o superior
- pip (gestor de paquetes de Python)

### Instalar dependencias

```bash
pip install dkimpy pyspf
```

**Nota**: La biblioteca `pyspf` es opcional pero recomendada para verificación SPF completa.

## Uso

### Sintaxis básica

```bash
# Modo simple (por defecto)
python check_email.py <ruta_al_archivo_email>

# Modo verbose (detallado)
python check_email.py -v <ruta_al_archivo_email>
```

### Opciones

- `-v, --verbose`: Muestra información detallada del proceso de verificación, incluyendo todas las cabeceras, parámetros de firma y diagnósticos completos.

Sin la opción `-v`, el script muestra solo un resumen conciso con la información esencial.

### Ejemplos

```bash
# Verificar un archivo .eml (modo simple)
python check_email.py "C:\ruta\al\email.eml"

# Verificar con información detallada (modo verbose)
python check_email.py -v "C:\ruta\al\email.eml"

# Verificar un archivo de texto con contenido de email
python check_email.py "/home/usuario/mensaje.txt"

# Verificar con todos los detalles
python check_email.py --verbose "/home/usuario/mensaje.txt"
```

**Nota**: El script genera automáticamente un archivo de texto con los resultados en el mismo directorio que el archivo de entrada. El nombre del archivo de salida incluye un timestamp para evitar sobrescribir resultados anteriores:
- Formato: `[nombre_archivo]_verification_YYYYMMDD_HHMMSS.txt`
- Ejemplo: `email_verification_20251114_153045.txt`

## Formatos de archivo soportados

- Archivos `.eml` (formato estándar de email)
- Archivos de texto plano con contenido completo del email (incluyendo cabeceras)
- Cualquier archivo que contenga un mensaje de correo con cabeceras RFC 2822

## Interpretación de resultados

### Estados de verificación

- **✓ SUCCESS**: La firma digital es válida y el mensaje es auténtico
- **✗ FAIL**: La verificación falló o no se encontraron firmas válidas
- **⚠ WARNING**: Se encontraron firmas pero hay limitaciones en la verificación

### Información mostrada

#### Modo simple (sin `-v`)
- Información completa del mensaje (From, To, Subject, Date, Message-ID)
- Resumen de cabeceras de autenticación encontradas
- Resultado de la verificación (✓ SUCCESS o ✗ FAIL)
- Método de verificación utilizado (ARC o DKIM)
- Ubicación del archivo de resultados

#### Modo verbose (con `-v`)
1. **Análisis inicial del mensaje**
   - Información completa (From, To, Subject, Date, Message-ID)
   - Tamaño del archivo
   - Todas las cabeceras de autenticación encontradas

2. **Verificación ARC** (si está presente)
   - Todas las cabeceras ARC-Seal encontradas
   - Todas las cabeceras ARC-Message-Signature
   - Todas las cabeceras ARC-Authentication-Results
   - Detalles del resultado de verificación automática
   - Análisis de cada componente de la cadena ARC

3. **Verificación DKIM** (si está presente)
   - Todas las cabeceras DKIM-Signature encontradas
   - Parámetros completos de cada firma (algoritmo, dominio, selector, timestamps, etc.)
   - Hash del cuerpo del mensaje
   - Resultado de verificación criptográfica

4. **Verificación SPF** (si pyspf está instalado)
   - IP del servidor remitente
   - Dominio del remitente
   - Resultado de la verificación SPF (pass/fail/softfail/neutral/none)
   - Explicación del resultado

5. **Resultado final detallado**
   - Estado general de la verificación
   - Método utilizado (ARC o DKIM)
   - Diagnósticos completos y posibles causas de fallo
   - Recomendaciones para solución de problemas

## Casos de uso

### Análisis forense
Ideal para investigaciones de seguridad y análisis forense de correos electrónicos sospechosos.

### Verificación de autenticidad
Confirmar que un mensaje proviene realmente del remitente declarado y no ha sido alterado.

### Auditoría de sistemas de correo
Verificar que los sistemas de correo están configurando correctamente las firmas DKIM/ARC.

### Troubleshooting
Diagnosticar problemas con la configuración de DKIM/ARC en servidores de correo.

## Limitaciones

- **Verificación ARC completa**: Requiere implementación específica para validación criptográfica completa
- **Conectividad DNS**: Necesita acceso a internet para obtener claves públicas de DNS
- **Formato del archivo**: El archivo debe contener el mensaje completo con todas las cabeceras

## Solución de problemas

### Error: "No se encontraron firmas"
- Verifique que el archivo contiene las cabeceras completas del email
- Algunos clientes de correo pueden no incluir todas las cabeceras al exportar

### Error: "La verificación DKIM falló"
Posibles causas:
- El mensaje fue modificado después de ser firmado
- La clave pública no está disponible en DNS
- Problemas de conectividad de red
- La firma está malformada o corrupta

### Error: "Archivo no encontrado"
- Verifique la ruta del archivo
- Use comillas si la ruta contiene espacios
- Asegúrese de que tiene permisos de lectura

## Estructura del proyecto

```
CheckDKIM/
├── check_email.py         # Script principal de verificación
├── export_email.py         # Exportador a PDF
├── export_email_gui.py     # Interfaz gráfica
├── README.md               # Este archivo
├── export_email.md         # Documentación del exportador
└── requirements.txt        # Dependencias (opcional)
```

## Dependencias

- **dkimpy**: Biblioteca principal para verificación DKIM/ARC
- **pyspf**: Biblioteca para verificación SPF (opcional pero recomendada)
- **email**: Módulo estándar de Python para parsing de emails
- **argparse**: Módulo estándar para parsing de argumentos

## Tecnologías utilizadas

- **Python 3.6+**
- **DKIM (DomainKeys Identified Mail)**: RFC 6376
- **ARC (Authenticated Received Chain)**: RFC 8617
- **SPF (Sender Policy Framework)**: RFC 7208
- **DNS**: Para obtención de claves públicas y registros SPF

## Contribución

Si encuentra errores o tiene sugerencias de mejora, puede:

1. Reportar issues describiendo el problema
2. Proponer mejoras en la funcionalidad
3. Contribuir con código para nuevas características

## Licencia

Este proyecto está disponible para uso educativo y profesional.

## Autor

Desarrollado para análisis forense y verificación de autenticidad de correos electrónicos.

---

**Nota**: Esta herramienta está diseñada para fines de verificación y análisis. Los resultados deben interpretarse en el contexto apropiado y con conocimiento técnico sobre protocolos de autenticación de email.