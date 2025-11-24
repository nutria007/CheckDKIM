# Verificador de Autenticación de Email (DKIM/ARC)

Una aplicación en Python para verificar firmas digitales DKIM y cadenas ARC en correos electrónicos. Esta herramienta proporciona análisis detallado y verificación criptográfica de la autenticidad e integridad de mensajes de correo electrónico.

## Características

- **Verificación DKIM**: Valida firmas DKIM para confirmar la autenticidad del remitente
- **Verificación ARC**: Verifica cadenas ARC (Authenticated Received Chain) para correos reenviados
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
pip install dkimpy
```

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

4. **Resultado final detallado**
   - Estado general de la verificación
   - Método utilizado (ARC o DKIM)
   - Diagnósticos completos y posibles causas de fallo
   - Recomendaciones para solución de problemas

## Causas comunes de fallo en la verificación DKIM/ARC

### 1. Modificaciones del mensaje

#### Reenvíos (Forwards)
Cuando un correo es reenviado, el cliente de correo puede modificar:
- **Asunto**: Agregar prefijos como "Fwd:", "Re:", "RV:"
- **Cuerpo**: Añadir texto introductorio, firmas o disclaimers
- **Cabeceras**: Agregar información de reenvío
- **Formato**: Cambiar encoding o estructura MIME

**Impacto**: La firma DKIM original se invalida porque el hash del cuerpo ya no coincide. En estos casos, **ARC puede ayudar** ya que preserva la cadena de autenticación original.

#### Modificaciones por sistemas intermediarios
- **Servidores antivirus/antispam**: Pueden agregar disclaimers, modificar enlaces o agregar marcas de agua
- **Sistemas de archivo**: Algunos sistemas modifican el formato o codificación al archivar
- **Gateways de correo**: Pueden alterar cabeceras o formato del mensaje
- **Clientes de correo**: Al guardar como .eml pueden omitir o modificar cabeceras

**Solución**: Verificar en el modo verbose (`-v`) la sección "Causas específicas detectadas" que indica exactamente qué falló.

### 2. Vencimiento de firmas DKIM

Las firmas DKIM pueden incluir un parámetro de expiración (`x=`):

```
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1;
                x=1234567890; ...
```

**¿Por qué expiran las firmas?**
- **Seguridad**: Limitar el tiempo de validez reduce el riesgo si la clave privada se compromete
- **Política del dominio**: Algunos dominios establecen períodos cortos (días o semanas)
- **Rotación de claves**: Facilita la transición a nuevas claves criptográficas

**Comportamiento del verificador**:
- ✗ **FALLO**: Si `x=` (timestamp de expiración) está en el pasado
- El mensaje dice: "La firma ha expirado (parámetro x=)"

**Importante**: Una firma expirada NO significa que el correo sea fraudulento. Solo indica que:
1. El correo es auténtico pero antiguo
2. La verificación debe hacerse considerando la fecha original del mensaje
3. Para análisis forense, la firma sigue siendo válida como evidencia de que el mensaje no fue alterado

**Nota legal**: En contextos forenses, una firma expirada pero válida criptográficamente sigue siendo evidencia de autenticidad en la fecha de envío original.

### 3. Problemas de configuración DNS

#### Clave pública no disponible
- **DNS no configurado**: El registro TXT con la clave pública no existe
- **Selector incorrecto**: El parámetro `s=` apunta a un selector que no está en DNS
- **Propagación DNS**: Cambios recientes en DNS aún no se han propagado
- **TTL expirado**: Cache DNS desactualizado

**Mensaje de error**: "No se puede obtener la clave pública del DNS" o "could not parse RSA public key"

**Verificación manual**:
```bash
# Para verificar el registro DNS (Windows PowerShell):
Resolve-DnsName -Name "selector._domainkey.example.com" -Type TXT

# Para verificar el registro DNS (Linux/Mac):
dig selector._domainkey.example.com TXT
```

### 4. Problemas de formato

#### Formato de clave pública inválido
- **Clave corrupta en DNS**: El registro TXT está malformado
- **Formato incorrecto**: La clave no cumple con el estándar RSA/Ed25519
- **Encoding incorrecto**: Problemas con Base64 encoding

**Mensaje de error**: "La clave pública DKIM no tiene el formato correcto"

#### Formato de firma inválido
- **Firma corrupta**: La cabecera DKIM-Signature está malformada
- **Parámetros faltantes**: Faltan campos obligatorios (v, a, d, s, b, bh, h)
- **Sintaxis incorrecta**: Errores en el formato de la cabecera

**Mensaje de error**: "La firma DKIM no tiene el formato correcto"

### 5. Body Hash Mismatch

El "body hash" (parámetro `bh=`) es un hash del cuerpo del mensaje:

**Causas del fallo**:
1. **Modificación del cuerpo**: Cualquier cambio en el contenido invalida el hash
2. **Cambios de encoding**: Conversión entre diferentes encodings (UTF-8, ISO-8859-1, etc.)
3. **Normalización de líneas**: Cambios en terminadores de línea (CRLF vs LF)
4. **Espacios en blanco**: Agregado o eliminación de espacios/tabs al final de líneas
5. **Conversión HTML/Plain Text**: Cambios entre formatos

**Mensaje de error**: "El cuerpo del mensaje fue modificado después de la firma (body hash mismatch)"

**En modo verbose**: Se muestra tanto el hash esperado como el calculado para comparación.

### 6. Cadenas ARC rotas

ARC (Authenticated Received Chain) mantiene una cadena de validaciones:

**Causas de fallo**:
- **Saltos en la cadena**: Índices no consecutivos (i=1, i=3 sin i=2)
- **Firmas inválidas**: Algún eslabón de la cadena tiene firma criptográfica inválida
- **Falta de sellos**: No hay suficientes ARC-Seal para completar la cadena
- **Orden incorrecto**: Los índices no están en el orden esperado

**Mensaje de error**: "La cadena ARC está rota o tiene índices no consecutivos"

### 7. Problemas de conectividad

- **Sin acceso a Internet**: No se pueden consultar registros DNS
- **Firewall/Proxy**: Bloquea consultas DNS
- **Timeout DNS**: El servidor DNS no responde a tiempo
- **DNS no confiable**: Respuestas DNS incorrectas o manipuladas

**Mensaje de error**: "Error de timeout al consultar DNS" o errores de conexión

## Casos de uso

### Análisis forense
Ideal para investigaciones de seguridad y análisis forense de correos electrónicos sospechosos. Las firmas DKIM expiradas siguen siendo válidas como evidencia de autenticidad en la fecha original.

### Verificación de autenticidad
Confirmar que un mensaje proviene realmente del remitente declarado y no ha sido alterado.

### Auditoría de sistemas de correo
Verificar que los sistemas de correo están configurando correctamente las firmas DKIM/ARC.

### Troubleshooting
Diagnosticar problemas con la configuración de DKIM/ARC en servidores de correo. El modo verbose (`-v`) proporciona diagnósticos detallados.

## Limitaciones

- **Verificación ARC completa**: Requiere implementación específica para validación criptográfica completa
- **Conectividad DNS**: Necesita acceso a internet para obtener claves públicas de DNS
- **Formato del archivo**: El archivo debe contener el mensaje completo con todas las cabeceras

## Solución de problemas

### Error: "No se encontraron firmas"
- Verifique que el archivo contiene las cabeceras completas del email
- Algunos clientes de correo pueden no incluir todas las cabeceras al exportar
- Use la opción `-v` para ver qué cabeceras están presentes

### Error: "La verificación DKIM falló"
Use el modo verbose (`-v`) para ver la sección **"Causas específicas detectadas"** que indica exactamente qué falló:

Posibles causas:
- **Firma expirada**: El parámetro `x=` indica que la firma ya expiró (ver sección "Vencimiento de firmas DKIM")
- **Body hash mismatch**: El mensaje fue modificado después de ser firmado
- **Clave pública no disponible**: No se puede obtener la clave desde DNS
- **Formato inválido**: La firma o clave pública está corrupta o malformada
- **Problemas de conectividad**: No hay acceso a DNS para verificar

**Recomendación**: Ejecute siempre con `-v` para obtener diagnósticos detallados sobre la causa específica del fallo.

### Error: "La firma ha expirado (parámetro x=)"
Esto **NO indica que el correo sea fraudulento**. Solo significa que:
- El correo es auténtico pero antiguo
- La firma DKIM tenía un tiempo de validez limitado
- La verificación criptográfica sigue siendo válida como evidencia

**Para análisis forense**: Una firma expirada pero criptográficamente válida sigue siendo evidencia de que el mensaje no fue alterado desde su envío original.

### Error: "could not parse RSA public key"
- El registro DNS con la clave pública está malformado
- Verifique manualmente el registro DNS del dominio
- Contacte al administrador del dominio remitente

### Error: "Body hash mismatch"
El cuerpo del mensaje fue modificado. Causas comunes:
- Reenvío con texto adicional agregado
- Sistema antivirus/antispam que agregó disclaimer
- Cliente de correo que modificó el formato
- Conversión entre formatos (HTML ↔ Plain Text)

**Para correos reenviados**: Verifique si hay cadena ARC que preserve la autenticación original.

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