# Export Email - Exportador de Correos a PDF

Herramienta para exportar correos electrónicos desde archivos .eml a formato PDF con verificación de autenticidad DKIM/ARC/SPF.

## Características Principales

- **Verificación DKIM/ARC/SPF**: Valida la autenticidad de cada correo antes de exportar
- **Exportación a PDF**: Genera documentos PDF profesionales con formato legible
- **Procesamiento por lotes**: Procesa múltiples correos en una sola operación
- **Modos de exportación**: PDF único para todos los correos o PDFs individuales
- **Registro detallado**: Genera log completo de todas las verificaciones
- **Formato personalizable**: Encabezados con título personalizado, numeración y metadatos
- **Advertencias de seguridad**: Marca claramente correos no verificados

## Requisitos

### Dependencias

```bash
pip install reportlab
```

### Archivos necesarios

- `check_email.py`: Script de verificación DKIM/ARC/SPF (debe estar en el mismo directorio)
- `dkimpy`: Biblioteca para verificación DKIM/ARC
- `pyspf`: Biblioteca para verificación SPF (opcional pero recomendada)

## Instalación

1. Asegúrese de tener Python 3.6 o superior instalado
2. Instale las dependencias:
   ```bash
   pip install reportlab dkimpy pyspf
   ```
3. Coloque `export_email.py` en el mismo directorio que `check_email.py`

## Uso

### Sintaxis Básica

```bash
python export_email.py <archivo_o_carpeta> [opciones]
```

### Opciones Disponibles

| Opción | Descripción |
|--------|-------------|
| `input` | Archivo .eml o carpeta con archivos .eml (obligatorio) |
| `-o, --output` | Nombre del archivo PDF de salida |
| `-t, --title` | Título personalizado para el encabezado del PDF |
| `--separate` | Genera un PDF separado para cada correo |
| `--force` | Exporta incluso si la verificación DKIM/ARC falla |
| `-v, --verbose` | Incluye detalles adicionales en el registro |
| `--log` | Nombre del archivo de registro de verificación |

## Ejemplos de Uso

### Ejemplo 1: Exportar un solo correo

```bash
python export_email.py "correo.eml"
```

Resultado:
- `emails_export_20251122_143052.pdf`: PDF con el correo
- `verification_log_20251122_143052.txt`: Registro de verificación

### Ejemplo 2: Exportar múltiples correos a un único PDF

```bash
python export_email.py "C:\Correos" -t "Caso Legal 2025-001"
```

Resultado:
- Un PDF con todos los correos de la carpeta
- Título personalizado en el encabezado
- Numeración secuencial de correos

### Ejemplo 3: PDFs separados por correo

```bash
python export_email.py "C:\Correos" --separate
```

Resultado:
- Un PDF individual por cada archivo .eml
- Cada PDF con el nombre del archivo original

### Ejemplo 4: Exportar con nombre específico

```bash
python export_email.py "correo.eml" -o "evidencia_caso_123.pdf"
```

### Ejemplo 5: Forzar exportación de correos no verificados

```bash
python export_email.py "correos_sospechosos" --force -v
```

Resultado:
- Exporta todos los correos, verificados o no
- Marca claramente los no verificados con advertencias
- Genera log verbose con detalles completos

### Ejemplo 6: Exportación completa con todas las opciones

```bash
python export_email.py "D:\Pericias\Caso_2025" -t "Pericia Judicial - Caso 2025/045" -o "pericia_correos.pdf" --force -v --log "pericia_log.txt"
```

## Formato del PDF Generado

### Encabezado de cada página

- **Título personalizado**: Definido por el usuario (o "Correos Electrónicos" por defecto)
- **Numeración**: "Correo X de Y"
- **Metadatos del correo**:
  - De (remitente)
  - Asunto
  - Fecha

### Primera página de cada correo

1. **Título y numeración**
2. **Estado de verificación**:
   - ✓ Verificación EXITOSA (verde) - con método usado (ARC/DKIM/SPF)
   - ✗ Verificación FALLIDA (rojo) - con advertencia de seguridad
3. **Tabla de información**:
   - De
   - Para
   - Asunto
   - Fecha
   - Message-ID
4. **Cuerpo del mensaje**: Texto completo formateado

### Pie de página

- Número de página actual
- Título del documento

## Archivo de Registro

El archivo de registro (`.txt`) incluye:

### Información por correo

- Nombre del archivo .eml
- Encabezados completos (From, To, Subject, Date, Message-ID)
- Estado de verificación (EXITOSA/FALLIDA)
- Método de verificación usado (ARC/DKIM/SPF o combinación)
- Firmas encontradas (ARC-Seal, DKIM-Signature, SPF)
- Errores o advertencias

### Modo Verbose

Con la opción `-v`, el registro incluye además:

- Salida completa de `check_dkim.py`
- Detalles de cada intento de verificación
- Parámetros de las firmas
- Diagnósticos completos

### Ejemplo de registro

```
================================================================================
REGISTRO DE VERIFICACIÓN DE CORREOS ELECTRÓNICOS
================================================================================
Fecha: 2025-11-22 14:30:52
Total de correos procesados: 3
================================================================================

Correo #1: notificacion_banco.eml
--------------------------------------------------------------------------------
De: banco@example.com
Para: usuario@example.com
Asunto: Notificación de Movimiento
Fecha: Wed, 20 Nov 2025 10:15:30 +0000
Message-ID: <abc123@example.com>

Estado: ✓ EXITOSA
Método: DKIM+SPF
Firma DKIM encontrada: Sí
Verificación SPF: pass

================================================================================
```

## Casos de Uso

### 1. Análisis Forense

Exportar correos para pericias judiciales con verificación de autenticidad:

```bash
python export_email.py "evidencias" -t "Pericia Judicial" --force -v
```

**Ventajas**:
- Documentación profesional en PDF
- Verificación de autenticidad certificada
- Registro detallado para el expediente
- Marca claramente correos no auténticos

### 2. Auditorías de Seguridad

Revisar correos sospechosos en lote:

```bash
python export_email.py "correos_sospechosos" --separate -v
```

**Ventajas**:
- PDF individual por correo para análisis separado
- Verificación DKIM/ARC de cada uno
- Log detallado de hallazgos

### 3. Archivo de Comunicaciones

Archivar correos importantes en formato PDF:

```bash
python export_email.py "comunicaciones_2025" -t "Archivo 2025" -o "comunicaciones_2025.pdf"
```

**Ventajas**:
- Formato PDF profesional
- Todos los correos en un documento
- Fácil búsqueda y referencia

### 4. Presentación de Evidencias

Preparar evidencias para presentación legal:

```bash
python export_email.py "evidencia.eml" -t "Evidencia Caso #12345" -o "evidencia_12345.pdf"
```

**Ventajas**:
- Verificación de autenticidad incluida
- Formato profesional para presentación
- Registro de verificación como respaldo

## Interpretación de Resultados

### Verificación Exitosa (✓)

- **Color verde** en el PDF
- El correo pasó la verificación DKIM o ARC
- El mensaje es auténtico y no ha sido alterado
- Seguro para considerar como evidencia válida

### Verificación Fallida (✗)

- **Color rojo** en el PDF
- Advertencia visible: "ADVERTENCIA: Verificación fallida"
- Posibles causas:
  - El correo fue modificado después de ser enviado
  - No tiene firmas DKIM/ARC
  - Las firmas son inválidas
  - Problemas con las claves DNS
- **Precaución**: La autenticidad no puede ser garantizada

### Sin Verificación (con --force)

- Se exporta de todos modos con advertencia prominente
- Útil para documentar correos sospechosos
- El registro indica claramente el fallo de verificación

## Solución de Problemas

### Error: "No se encontró check_email.py"

**Causa**: El script check_email.py no está en el mismo directorio

**Solución**:
```bash
# Copie check_email.py al mismo directorio que export_email.py
cp check_email.py /ruta/a/export_email/
```

### Error: "Se requiere la biblioteca 'reportlab'"

**Causa**: La biblioteca reportlab no está instalada

**Solución**:
```bash
pip install reportlab
```

### Advertencia: "Verificación fallida. Use --force"

**Causa**: El correo no pasó la verificación DKIM/ARC/SPF

**Solución**:
- Revise por qué falló la verificación
- Use `--force` si necesita exportar de todos modos:
  ```bash
  python export_email.py archivo.eml --force
  ```

### Error: "No se encontraron archivos .eml"

**Causa**: La carpeta no contiene archivos .eml

**Solución**:
- Verifique que los archivos tengan extensión `.eml`
- Verifique la ruta de la carpeta

### PDF con caracteres extraños

**Causa**: Problemas de codificación en el correo original

**Solución**:
- El script intenta manejar múltiples codificaciones
- Si persiste, revise el archivo .eml original

## Formato Técnico del PDF

### Especificaciones

- **Tamaño de página**: Carta (Letter)
- **Márgenes**: 1 pulgada (izquierda, derecha, inferior), 1.5 pulgadas (superior)
- **Fuentes**: Helvetica y Helvetica-Bold
- **Codificación**: UTF-8

### Estilos

- **Título**: Helvetica-Bold 16pt, centrado
- **Encabezados**: Helvetica-Bold 10pt
- **Cuerpo**: Helvetica 9pt, interlineado 14pt
- **Verificación exitosa**: Verde
- **Verificación fallida**: Rojo

### Paginación

- Cada correo comienza en nueva página (en modo lote)
- Numeración continua de páginas
- Información del correo en cada página

## Preguntas Frecuentes

**P: ¿Puedo exportar correos sin verificación?**  
R: Sí, use la opción `--force`. Los correos se exportarán con advertencia de verificación fallida.

**P: ¿Qué pasa si un correo no tiene firma DKIM/ARC ni pasa SPF?**  
R: Sin `--force`, no se exportará. Con `--force`, se exportará con advertencia clara.

**P: ¿Puedo personalizar el formato del PDF?**  
R: Actualmente el formato está predefinido. Para personalizaciones avanzadas, edite el código fuente.

**P: ¿Cuántos correos puedo procesar a la vez?**  
R: No hay límite técnico, pero archivos muy grandes pueden tomar tiempo. Se recomienda procesar en lotes de hasta 100 correos.

**P: ¿Se incluyen los adjuntos en el PDF?**  
R: No, solo se exporta el cuerpo del mensaje. Los adjuntos no se incluyen actualmente.

**P: ¿Puedo usar esto como evidencia legal?**  
R: La verificación DKIM/ARC proporciona autenticidad técnica. Consulte con su asesor legal sobre requisitos específicos de su jurisdicción.

## Limitaciones Conocidas

- No exporta adjuntos (solo texto del correo)
- HTML complejo puede perder formato
- Imágenes embebidas no se incluyen
- Firmas digitales S/MIME no son verificadas (solo DKIM/ARC/SPF)
- Verificación SPF requiere cabeceras 'Received' con IP del remitente

## Mejoras Futuras

Posibles mejoras planeadas:
- Soporte para exportar adjuntos
- Mejor renderizado de HTML
- Exportación a otros formatos (Word, HTML)
- Integración con clientes de correo
- API para automatización

## Soporte y Contacto

Para reportar problemas o sugerir mejoras, contacte al desarrollador o reporte un issue en el repositorio del proyecto.

---

**Nota Legal**: Esta herramienta se proporciona "tal cual" para fines de análisis y documentación. Los usuarios son responsables de cumplir con las leyes aplicables de privacidad y protección de datos al procesar correos electrónicos.
