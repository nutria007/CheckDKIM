# Verificador de Firmas DKIM/ARC

Una aplicación en Python para verificar firmas digitales DKIM y ARC en correos electrónicos. Esta herramienta proporciona análisis detallado y verificación criptográfica de la autenticidad e integridad de mensajes de correo electrónico.

## Características

- **Verificación DKIM**: Valida firmas DKIM para confirmar la autenticidad del remitente
- **Verificación ARC**: Verifica cadenas ARC (Authenticated Received Chain) para correos reenviados
- **Análisis detallado**: Proporciona información exhaustiva sobre cabeceras de autenticación
- **Diagnósticos**: Explica las causas de fallos en la verificación
- **Formato visual**: Salida organizada y fácil de leer con separadores y códigos de estado

## Instalación

### Requisitos previos

- Python 3.6 o superior
- pip (gestor de paquetes de Python)

### Instalar dependencias

```bash
pip install dkimpy
```

## Uso

### Sintaxis básica

```bash
python check_dkim.py <ruta_al_archivo_email>
```

### Ejemplos

```bash
# Verificar un archivo .eml
python check_dkim.py "C:\ruta\al\email.eml"

# Verificar un archivo de texto con contenido de email
python check_dkim.py "/home/usuario/mensaje.txt"
```

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

1. **Análisis inicial del mensaje**
   - Información básica (From, To, Subject, Date, Message-ID)
   - Tamaño del archivo
   - Presencia de cabeceras de autenticación

2. **Verificación ARC** (si está presente)
   - Cabeceras ARC-Seal encontradas
   - Cabeceras ARC-Message-Signature
   - Cabeceras ARC-Authentication-Results
   - Resultado de verificación automática

3. **Verificación DKIM** (si está presente)
   - Cabeceras DKIM-Signature
   - Parámetros de firma (algoritmo, dominio, selector, etc.)
   - Resultado de verificación criptográfica

4. **Resultado final**
   - Estado general de la verificación
   - Método utilizado (ARC o DKIM)
   - Diagnósticos y posibles causas de fallo

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
├── check_dkim.py          # Script principal
├── README.md              # Este archivo
└── requirements.txt       # Dependencias (opcional)
```

## Dependencias

- **dkimpy**: Biblioteca principal para verificación DKIM/ARC
- **email**: Módulo estándar de Python para parsing de emails
- **argparse**: Módulo estándar para parsing de argumentos

## Tecnologías utilizadas

- **Python 3.6+**
- **DKIM (DomainKeys Identified Mail)**: RFC 6376
- **ARC (Authenticated Received Chain)**: RFC 8617
- **DNS**: Para obtención de claves públicas

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